# scripts/classify_threats.py

import sqlite3
import pandas as pd
import logging

logging.basicConfig(filename='pipeline.log', level=logging.INFO)

# Define threat keywords
threat_keywords = {
    'Phishing': ['phishing', 'spoof', 'fake login'],
    'Ransomware': ['ransom', 'encrypt', 'decrypt'],
    'DDoS': ['ddos', 'botnet', 'flood'],
    'Malware': ['malware', 'trojan', 'virus'],
    'Exploitation': ['cve', 'exploit', 'vulnerability'],
}

# MITRE technique mapping
mitre_mapping = {
    'Phishing': 'TA0001: Initial Access → T1566 (Phishing)',
    'Ransomware': 'TA0040: Impact → T1486 (Data Encrypted)',
    'DDoS': 'TA0040: Impact → T1499 (Endpoint DoS)',
    'Malware': 'TA0002: Execution → T1059 (Scripting)',
    'Exploitation': 'TA0001: Initial Access → T1203 (Exploit Client)',
}

def classify_threat(text):
    tags = []
    for category, words in threat_keywords.items():
        if any(word in text.lower() for word in words):
            tags.append(category)
    return ', '.join(tags) if tags else 'Uncategorized'

def map_mitre(threat_type):
    types = threat_type.split(', ')
    mapped = []
    for t in types:
        if t in mitre_mapping:
            mapped.append(mitre_mapping[t])
        else:
            mapped.append("Unknown")
    return '; '.join(mapped)

def main():
    logging.info("Starting threat classification...")
    conn = sqlite3.connect("threat_feeds.db")
    df = pd.read_sql_query("SELECT * FROM threat_data", conn)

    df['threat_type'] = df['title'].apply(classify_threat)
    df['mitre_ttp'] = df['threat_type'].apply(map_mitre)

    df.to_sql("classified_threats", conn, if_exists='replace', index=False)
    conn.close()
    logging.info("Threat classification completed.")

if __name__ == "__main__":
    main()
