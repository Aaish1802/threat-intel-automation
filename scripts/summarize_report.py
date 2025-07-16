import sqlite3
from jinja2 import Template
import markdown
from weasyprint import HTML
import logging
import os
import smtplib
from email.message import EmailMessage

# Logging setup
logging.basicConfig(filename='pipeline.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def generate_report():
    logging.info("Generating summary report...")
    conn = sqlite3.connect("threat_feeds.db")
    c = conn.cursor()

    # Fetch top categories
    categories = {}
    for row in c.execute("SELECT category FROM classified_threats"):
        cat = row[0]
        categories[cat] = categories.get(cat, 0) + 1

    # Fetch recent CVEs
    cves = [row[0] for row in c.execute("SELECT DISTINCT title FROM threat_data WHERE title LIKE '%CVE%'")]

    # Fetch MITRE mappings
    mitre_ids = [row[0] for row in c.execute("SELECT DISTINCT mitre_id FROM classified_threats")]

    conn.close()

    # Jinja2 Markdown template
    template = Template("""# Weekly Threat Report

## 📊 Top Threat Categories
{% for category, count in categories.items() %}
- **{{ category }}**: {{ count }}
{% endfor %}

## 🛡️ Recent CVEs
{% for cve in cves %}
- {{ cve }}
{% endfor %}

## 🎯 MITRE Techniques Observed
{% for mitre in mitre_ids %}
- {{ mitre }}
{% endfor %}
""")

    rendered = template.render(categories=categories, cves=cves, mitre_ids=mitre_ids)

    with open("weekly_report.md", "w", encoding="utf-8") as f:
        f.write(rendered)

    logging.info("Report generated as weekly_report.md")


def convert_to_pdf():
    logging.info("Converting to PDF...")
    with open("weekly_report.md", "r", encoding="utf-8") as md_file:
        html_content = markdown.markdown(md_file.read())

    with open("report.html", "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    HTML("report.html").write_pdf("report.pdf")
    logging.info("PDF saved as report.pdf")


def send_email():
    logging.info("Preparing to send email...")
    sender_email = os.environ['EMAIL_USER']
    sender_pass = os.environ['EMAIL_PASS']
    recipient = "recipient@example.com"  # Change to desired recipient

    msg = EmailMessage()
    msg['Subject'] = "🔐 Weekly Threat Intelligence Report"
    msg['From'] = sender_email
    msg['To'] = recipient
    msg.set_content("Attached is this week's automatically generated threat intelligence report.")

    with open("report.pdf", "rb") as f:
        msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename="report.pdf")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, sender_pass)
        smtp.send_message(msg)

    logging.info("✅ Email sent successfully.")


if __name__ == "__main__":
    try:
        generate_report()
        convert_to_pdf()
        logging.info("✅ Report process complete.")
        
        # Optional email delivery
        if os.getenv("EMAIL_USER") and os.getenv("EMAIL_PASS"):
            send_email()
        else:
            logging.warning("🔕 Skipping email: EMAIL_USER or EMAIL_PASS not set.")

    except Exception as e:
        logging.error(f"❌ Failed during summarize_report.py: {e}")
        print(f"[!] Error: {e}")
