import os
import requests
import logging
from typing import Set

logger = logging.getLogger("ThreatIntel")

def fetch_abuseipdb_blacklist(limit: int = 10000, confidence_minimum: int = 90) -> Set[str]:
    """
    Fetches the list of most abusive IP addresses from AbuseIPDB.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("AbuseIPDB API Key not found. Skipping AbuseIPDB blacklist fetch.")
        return set()

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit
    }

    iocs = set()
    try:
        logger.info(f"Fetching AbuseIPDB blacklist (Limit: {limit}, Confidence: {confidence_minimum}%)...")
        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            for item in data.get("data", []):
                ip = item.get("ipAddress")
                if ip:
                    iocs.add(ip)
            logger.info(f"Fetched {len(iocs)} IPs from AbuseIPDB.")
        elif response.status_code == 429:
            logger.warning("AbuseIPDB API quota exceeded (429) while fetching blacklist.")
        else:
            logger.error(f"Error fetching AbuseIPDB blacklist: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error(f"Exception fetching AbuseIPDB blacklist: {e}")

    return iocs
