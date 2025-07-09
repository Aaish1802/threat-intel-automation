import sqlite3
import re

# === Connect to the database ===
conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()

# === Create classified_threats table if not exists ===
cursor.execute('''
    CREATE TABLE IF NOT EXISTS classified_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_type TEXT,
        description TEXT,
        cve TEXT,
        mitre_technique TEXT
    )
''')

# === Helper Functions ===

def classify_threat(description):
    if 'CVE' in description:
        return 'Vulnerability'
    elif re.search(r'\b(?:192\.168|10\.)\.\d+\.\d+\b', description):
        return 'Internal IP'
    elif 'ransom' in description.lower():
        return 'Ransomware'
    elif 'phish' in description.lower():
        return 'Phishing'
    elif 'exploit' in description.lower():
        return 'Exploit'
    else:
        return 'Generic Threat'

def map_to_mitre(threat_type):
    mapping = {
        'Vulnerability': 'T1203: Exploitation for Client Execution',
        'Ransomware': 'T1486: Data Encrypted for Impact',
        'Phishing': 'T1566: Phishing',
        'Exploit': 'T1068: Exploitation for Privilege Escalation',
        'Internal IP': 'T1071: Application Layer Protocol',
        'Generic Threat': 'T1082: System Information Discovery'
    }
    return mapping.get(threat_type, 'T1082: System Information Discovery')

# === Fetch all extracted IOCs ===
cursor.execute('SELECT id, ioc_type, ioc_value, description, cve FROM extracted_iocs')
rows = cursor.fetchall()

# === Process each and insert into classified_threats ===
for row in rows:
    _id, ioc_type, ioc_value, description, cve = row
    threat_type = classify_threat(description)
    mitre = map_to_mitre(threat_type)

    cursor.execute('''
        INSERT INTO classified_threats (threat_type, description, cve, mitre_technique)
        VALUES (?, ?, ?, ?)
    ''', (threat_type, description, cve, mitre))

# === Finalize ===
conn.commit()
conn.close()

print(f"[✔] Classified {len(rows)} threats successfully into 'classified_threats' table.")
