import sqlite3
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

DB_PATH = "threat_intel.db"
REPORT_PATH = "report.md"

def generate_report():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    report_lines = ["# 📊 Daily Threat Intelligence Report\n"]

    try:
        # 1. Threat Type Summary
        cursor.execute("SELECT threat_type, COUNT(*) FROM classified_threats GROUP BY threat_type")
        threat_summary = cursor.fetchall()
        report_lines.append("## 🛡️ Threat Type Summary\n")
        for row in threat_summary:
            report_lines.append(f"- **{row[0]}**: {row[1]} occurrences")

        # 2. Top MITRE Techniques (Optional)
        try:
            cursor.execute("SELECT mitre_id, COUNT(*) FROM classified_threats WHERE mitre_id IS NOT NULL GROUP BY mitre_id")
            mitre_summary = cursor.fetchall()
            report_lines.append("\n## 🧠 Top MITRE Techniques\n")
            for row in mitre_summary:
                report_lines.append(f"- {row[0]}: {row[1]} events")
        except sqlite3.OperationalError:
            report_lines.append("\nℹ️ Note: No MITRE ID column found in the table.")

        # 3. Recent CVEs
        cursor.execute("SELECT cve, COUNT(*) FROM classified_threats WHERE cve IS NOT NULL GROUP BY cve ORDER BY COUNT(*) DESC LIMIT 5")
        cve_summary = cursor.fetchall()
        report_lines.append("\n## 🚨 Emerging CVEs\n")
        for row in cve_summary:
            report_lines.append(f"- {row[0]}: {row[1]} sightings")

    except sqlite3.OperationalError as e:
        print(f"[!] SQLite Error: {e}")
        conn.close()
        return

    conn.close()

    # Save to Markdown file
    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(report_lines))
    print(f"[✓] Report generated as {REPORT_PATH}")

    import os

if os.getenv("EMAIL_USER"):
    send_email()
else:
    print("[!] Skipping email delivery – EMAIL_USER not set.")


def send_email():
    sender_email = os.environ['EMAIL_USER']
    password = os.environ['EMAIL_PASS']
    receiver_email = os.environ['EMAIL_TO']

    with open(REPORT_PATH, "r") as file:
        report_content = file.read()

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "📢 Daily Threat Intel Summary"

    msg.attach(MIMEText(report_content, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("[✓] Email sent successfully.")
    except smtplib.SMTPAuthenticationError as e:
        print(f"[✗] SMTP Authentication Error: {e}")
    except Exception as e:
        print(f"[✗] Failed to send email: {e}")

if __name__ == "__main__":
    generate_report()
