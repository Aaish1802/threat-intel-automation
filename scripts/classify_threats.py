import sqlite3
import re

# Connect to the SQLite database
conn = sqlite3.connect("threat_intel.db")
cursor = conn.cursor()

# Create the table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS classified_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT,
    description TEXT,
    cve TEXT,
    mitre_id TEXT
)
''')
conn.commit()

# Fetch IOCs from extracted_iocs
cursor.execute('SELECT id, ioc_type, ioc_value, description, cve FROM extracted_iocs')
ioc_rows = cursor.fetchall()

# Simple logic to classify based on IOC type or value
for row in ioc_rows:
    ioc_id, ioc_type, ioc_value, description, cve = row

    # Default classifications
    threat_type = "Unknown"
    mitre_id = "TBD"  # Placeholder — replace with mapping if needed

    if "phish" in description.lower() or "phishing" in ioc_value.lower():
        threat_type = "Phishing"
        mitre_id = "T1566.001"

    elif ioc_type == "ip" and ioc_value.startswith("192."):
        threat_type = "Internal Network"
        mitre_id = "T1071"

    elif "ransom" in description.lower():
        threat_type = "Ransomware"
        mitre_id = "T1486"

    elif ioc_type == "domain" and "login" in ioc_value:
        threat_type = "Credential Harvesting"
        mitre_id = "T1555"

    # Insert into the classified threats table
    cursor.execute('''
        INSERT INTO classified_threats (threat_type, description, cve, mitre_id)
        VALUES (?, ?, ?, ?)
    ''', (threat_type, description, cve, mitre_id))

conn.commit()
conn.close()
print("[✓] Threat classification complete and saved.")
