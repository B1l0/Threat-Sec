import os
import time
import requests
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("ThreatIntel")

class AbuseIPDBClient:
    """
    Client for AbuseIPDB API v2.
    """
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            logger.warning("AbuseIPDB API Key not found. Validation skipped.")

        # Conservative rate limit
        self.request_interval = 1.0
        self.last_request_time = 0.0

    def _enforce_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_interval:
            time.sleep(self.request_interval - elapsed)
        self.last_request_time = time.time()

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
        """
        Checks an IP address against AbuseIPDB.
        """
        if not self.api_key:
            return None

        self._enforce_rate_limit()

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days
        }

        try:
            response = requests.get(f"{self.BASE_URL}/check", headers=headers, params=params)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("AbuseIPDB API quota exceeded.")
                return None
            else:
                logger.error(f"AbuseIPDB API Error {response.status_code}: {response.text}")
                return None
        except Exception as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return None

    def is_malicious(self, ip_address: str, confidence_threshold: int = 50) -> bool:
        """
        Checks if an IP is malicious based on abuse confidence score.
        """
        report = self.check_ip(ip_address)
        if not report:
            return False

        try:
            score = report.get("data", {}).get("abuseConfidenceScore", 0)
            return score >= confidence_threshold
        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB report for {ip_address}: {e}")
            return False
