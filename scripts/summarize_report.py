import sqlite3
from datetime import datetime
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Step 1: Generate Markdown Report
def generate_report():
    conn = sqlite3.connect('threat_intel.db')
    cursor = conn.cursor()

    report_lines = []
    report_lines.append(f"# 🛡️ Daily Threat Intelligence Report – {datetime.now().strftime('%Y-%m-%d')}\n")

    # Summary of threats
    cursor.execute("SELECT threat_type, COUNT(*) FROM classified_threats GROUP BY threat_type")
    threats = cursor.fetchall()
    report_lines.append("## 📊 Threat Summary\n")
    for threat_type, count in threats:
        report_lines.append(f"- **{threat_type}**: {count} threats")

    # Top CVEs
    cursor.execute("SELECT cve FROM classified_threats WHERE cve IS NOT NULL LIMIT 5")
    cves = [row[0] for row in cursor.fetchall()]
    if cves:
        report_lines.append("\n## 🚨 Top CVEs")
        for cve in cves:
            report_lines.append(f"- {cve}")

    # MITRE Techniques
    cursor.execute("SELECT mitre_technique FROM classified_threats WHERE mitre_technique IS NOT NULL LIMIT 5")
    mitres = [row[0] for row in cursor.fetchall()]
    if mitres:
        report_lines.append("\n## 🧠 MITRE ATT&CK Techniques")
        for m in mitres:
            report_lines.append(f"- {m}")

    conn.close()

    # Save to report.md
    with open("report.md", "w") as f:
        f.write("\n".join(report_lines))

    print("✅ Report generated as report.md")

# Step 2: Email Report
def send_email():
    sender_email = os.environ['EMAIL_USER']
    sender_password = os.environ['EMAIL_PASS']
    receiver_email = "c0939066@mylambton.ca"  # prof’s or personal email

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "📄 Daily Threat Intelligence Report"

    body = "Hi Team,\n\nPlease find attached today's generated threat intelligence report.\n\nBest,\nUnnatiBot"
    msg.attach(MIMEText(body, 'plain'))

    # Attach report
    with open("report.md", "r") as f:
        report_content = f.read()
    msg.attach(MIMEText(report_content, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print("✅ Email sent successfully.")
    except Exception as e:
        print("❌ Failed to send email:", str(e))

# Run both parts
generate_report()
send_email()
