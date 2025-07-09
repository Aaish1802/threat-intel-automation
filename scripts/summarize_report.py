import sqlite3
import pandas as pd
from datetime import datetime

# Connect to your threat intelligence SQLite database
conn = sqlite3.connect("threat_intel.db")

# Read classified threat data
df = pd.read_sql_query("SELECT * FROM classified_threats", conn)

# Summarize threat types
summary = df['threat_type'].value_counts().reset_index()
summary.columns = ['Threat Type', 'Count']

# Top 5 MITRE Techniques
if 'mitre_ttp' in df.columns:
    top_ttps = df['mitre_ttp'].value_counts().head(5).reset_index()
    top_ttps.columns = ['MITRE TTP', 'Count']
else:
    top_ttps = pd.DataFrame(columns=['MITRE TTP', 'Count'])

# Extract CVE mentions
cve_entries = df[df['title'].str.contains("CVE", case=False, na=False)]

# Create Markdown report
today = datetime.now().strftime("%Y-%m-%d")

report_md = f"# 🛡️ Threat Intelligence Report ({today})\n\n"

report_md += "## 🔍 Summary by Threat Type\n"
report_md += summary.to_markdown(index=False)
report_md += "\n\n"

report_md += "## 🎯 Top 5 MITRE Techniques\n"
report_md += top_ttps.to_markdown(index=False)
report_md += "\n\n"

report_md += f"## 📌 Notable CVEs Mentioned ({len(cve_entries)})\n"
for _, row in cve_entries.iterrows():
    report_md += f"- **{row['title']}**\n"

# Save as report.md
with open("report.md", "w") as f:
    f.write(report_md)

conn.close()
print("✅ Threat report generated successfully: report.md")
