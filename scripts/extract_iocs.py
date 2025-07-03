# scripts/extract_iocs.py

import re
import pandas as pd
import sqlite3
import logging

logging.basicConfig(filename='pipeline.log', level=logging.INFO)

def extract():
    logging.info("Extracting IOCs...")
    conn = sqlite3.connect("threat_feeds.db")

    df = pd.read_sql_query("SELECT * FROM threat_data", conn)

    indicators = []
    for _, row in df.iterrows():
        text = row['summary']
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        domains = re.findall(r'\b[\w\.-]+\.(com|net|org|gov|edu)\b', text)
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)

        for ioc in ips + domains + hashes:
            indicators.append((ioc, 'IP' if '.' in ioc else 'HASH'))

    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS ioc_data (
                        ioc TEXT,
                        type TEXT
                    )""")

    for ioc, typ in indicators:
        cursor.execute("INSERT INTO ioc_data (ioc, type) VALUES (?, ?)", (ioc, typ))

    conn.commit()
    conn.close()
    logging.info("IOC extraction completed.")

if __name__ == "__main__":
    extract()
