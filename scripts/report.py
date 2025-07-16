import markdown
from weasyprint import HTML
import logging
import os

# Set up logging
logging.basicConfig(filename='pipeline.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

try:
    # Convert Markdown to HTML
    with open("weekly_report.md", "r", encoding="utf-8") as md_file:
        md_content = md_file.read()
    html_content = markdown.markdown(md_content)

    # Save HTML preview
    with open("report.html", "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    # Convert HTML to PDF
    HTML("report.html").write_pdf("report.pdf")
    logging.info("PDF report successfully generated as 'report.pdf'.")

except Exception as e:
    logging.error(f"Error generating PDF report: {e}")
    print("Something went wrong while generating the PDF report. Check logs.")
