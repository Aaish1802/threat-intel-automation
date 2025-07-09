import sqlite3

# Connect to the SQLite DB
conn = sqlite3.connect("threat_intel.db")
cursor = conn.cursor()

# Check if data exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='classified_threats'")
if not cursor.fetchone():
    print("⚠️ No classified_threats table found. Skipping report.")
    exit(0)

# Fetch data
cursor.execute("SELECT * FROM classified_threats")
rows = cursor.fetchall()

if not rows:
    print("⚠️ No data in classified_threats table. Skipping report.")
    exit(0)

# Create markdown report
with open("report.md", "w") as f:
    f.write("# 🛡️ Daily Threat Intelligence Report\n\n")
    f.write(f"Total Threats Classified: **{len(rows)}**\n\n")

    f.write("| Type | IOC | Severity |\n")
    f.write("|------|-----|----------|\n")
    for row in rows:
        f.write(f"| {row[1]} | `{row[2]}` | {row[3]} |\n")

print("✅ Report generated: report.md")

conn.close()
