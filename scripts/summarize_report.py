# scripts/summarize_report.py

import sqlite3
from datetime import datetime
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

DB_FILE = "threat_intel.db"
REPORT_FILE = "report.md"

def generate_report():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    report_lines = ["# 🛡️ Daily Threat Intelligence Summary\n"]
    report_lines.append(f"_Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_\n")

    # Threat Type Summary
    cursor.execute("SELECT threat_type, COUNT(*) FROM classified_threats GROUP BY threat_type")
    threats = cursor.fetchall()
    report_lines.append("## 🔥 Threat Types Summary")
    for ttype, count in threats:
        report_lines.append(f"- **{ttype}**: {count} instances")

    # CVE Summary
    cursor.execute("SELECT cve, COUNT(*) FROM classified_threats WHERE cve IS NOT NULL GROUP BY cve")
    cves = cursor.fetchall()
    report_lines.append("\n## 🧩 Top CVEs")
    for cve, count in cves:
        report_lines.append(f"- `{cve}`: {count} detections")

    # MITRE Summary
    cursor.execute("SELECT mitre_id, COUNT(*) FROM classified_threats WHERE mitre_id IS NOT NULL GROUP BY mitre_id")
    mitres = cursor.fetchall()
    report_lines.append("\n## 🎯 Top MITRE Techniques")
    for mitre, count in mitres:
        report_lines.append(f"- `{mitre}`: {count} indicators")

    with open(REPORT_FILE, "w") as f:
        f.write("\n".join(report_lines))

    print("✅ Report generated as report.md")

def send_email():
    sender_email = os.environ["EMAIL_USER"]
    password = os.environ["EMAIL_PASS"]
    recipient_email = os.environ["EMAIL_TO"]

    subject = "📩 Daily Threat Intelligence Report"
    with open(REPORT_FILE, "r") as f:
        body = f.read()

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, password)
    server.send_message(msg)
    server.quit()

    print("✅ Email sent to", recipient_email)

# MAIN
generate_report()
send_email()
