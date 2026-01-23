import requests
import logging
from typing import List, Set

logger = logging.getLogger("ThreatIntel")

class FeedManager:
    """
    Manages the collection of IOCs from external sources.
    """

    # Default public feeds
    DEFAULT_SOURCES = [
        "https://urlhaus.abuse.ch/downloads/text_online/",  # URLHaus Online URLs
        "https://openphish.com/feed.txt"                    # OpenPhish Free Feed
    ]

    def __init__(self, sources: List[str] = None):
        self.sources = sources or self.DEFAULT_SOURCES

    def fetch_feed(self, url: str) -> Set[str]:
        """
        Fetches a single feed and extracts IOCs.
        """
        iocs = set()
        try:
            logger.info(f"Fetching feed: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                iocs.add(line)

            logger.info(f"Fetched {len(iocs)} indicators from {url}")

        except Exception as e:
            logger.error(f"Error fetching feed {url}: {e}")

        return iocs

    def fetch_all(self) -> Set[str]:
        """
        Fetches all configured feeds and returns a combined set of raw IOCs.
        """
        all_iocs = set()
        for source in self.sources:
            feed_iocs = self.fetch_feed(source)
            all_iocs.update(feed_iocs)

        logger.info(f"Total raw indicators fetched: {len(all_iocs)}")
        return all_iocs
