# scripts/extract_iocs.py

import sqlite3
from datetime import datetime

# Sample extracted IOC data (you can replace this with real parsed feed data)
extracted_data = [
    {"ioc_type": "ip", "ioc_value": "192.168.1.1", "description": "Suspicious IP", "cve": "CVE-2024-12345"},
    {"ioc_type": "domain", "ioc_value": "malicious.example.com", "description": "Malicious domain", "cve": "CVE-2024-11111"},
    {"ioc_type": "hash", "ioc_value": "abc123def456ghi789", "description": "Malware hash", "cve": "CVE-2024-22222"}
]

# Connect to database
conn = sqlite3.connect("threat_intel.db")
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS extracted_iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT,
        ioc_value TEXT,
        description TEXT,
        cve TEXT,
        extracted_at TEXT
    )
''')

# Insert each IOC
for entry in extracted_data:
    cursor.execute('''
        INSERT INTO extracted_iocs (ioc_type, ioc_value, description, cve, extracted_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        entry["ioc_type"],
        entry["ioc_value"],
        entry["description"],
        entry["cve"],
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))

conn.commit()
conn.close()
print("[+] IOC Extraction Complete")
