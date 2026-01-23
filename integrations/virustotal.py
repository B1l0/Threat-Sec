import os
import time
import requests
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("ThreatIntel")

class VirusTotalClient:
    """
    Client for VirusTotal API v3.
    """
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            logger.warning("VirusTotal API Key not found. Validation skipped.")

        # Conservative rate limit: 4 requests per minute => 15 seconds delay
        self.request_interval = 15.0
        self.last_request_time = 0.0

    def _enforce_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_interval:
            sleep_time = self.request_interval - elapsed
            logger.debug(f"VirusTotal rate limit: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the report for a domain.
        Returns None if API key is missing or request fails.
        """
        if not self.api_key:
            return None

        self._enforce_rate_limit()

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        url = f"{self.BASE_URL}/domains/{domain}"

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("VirusTotal API quota exceeded (429).")
                return None
            elif response.status_code == 404:
                # Domain not found in VT
                return None
            else:
                logger.error(f"VirusTotal API Error {response.status_code}: {response.text}")
                return None

        except Exception as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def is_malicious(self, domain: str, threshold: int = 2) -> bool:
        """
        Checks if a domain is considered malicious based on detection count.
        Returns False if check fails or domain is safe.
        """
        report = self.get_domain_report(domain)
        if not report:
            return False

        try:
            stats = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return (malicious + suspicious) >= threshold
        except Exception as e:
            logger.error(f"Error parsing VirusTotal report for {domain}: {e}")
            return False
