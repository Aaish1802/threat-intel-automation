# scripts/ingest_feeds.py

import feedparser
import sqlite3
import logging

logging.basicConfig(filename='pipeline.log', level=logging.INFO)

def ingest():
    logging.info("Starting feed ingestion...")

    feeds = [
        "https://www.us-cert.gov/ncas/alerts.xml",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.xml"
    ]

    conn = sqlite3.connect("threat_feeds.db")
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS threat_data (
                        title TEXT,
                        link TEXT,
                        published TEXT,
                        summary TEXT
                    )""")

    for url in feeds:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            cursor.execute("INSERT INTO threat_data (title, link, published, summary) VALUES (?, ?, ?, ?)", (
                entry.title, entry.link, entry.published, entry.summary))
            logging.info(f"Ingested: {entry.title}")

    conn.commit()
    conn.close()
    logging.info("Feed ingestion completed.")

if __name__ == "__main__":
    ingest()
