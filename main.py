import os
import logging
import argparse
import sys
from dotenv import load_dotenv
from utils.logger import setup_logger
from utils.file_ops import read_file_lines, write_output_file
from sources.feed_manager import FeedManager
from core.processor import ThreatProcessor
from integrations.virustotal import VirusTotalClient
from integrations.abuseipdb import AbuseIPDBClient
from core.normalizer import normalize_item

# Load environment variables
load_dotenv()

# Constants
OUTPUT_FILE = "bad_motherfuckerz.txt"
WHITELIST_FILE = "whitelist.txt"
ADD_REQUESTS_FILE = "input/add_requests.txt"
REMOVE_REQUESTS_FILE = "input/remove_requests.txt"

def validate_candidates(candidates: set, vt_client: VirusTotalClient, abuse_client: AbuseIPDBClient) -> set:
    """
    Validates a set of candidates against VT and AbuseIPDB.
    Follows a FAIL-OPEN policy: Manual additions are trusted by default.
    Validation is used for enrichment/logging (confirming maliciousness).
    Returns all candidates, logging any confirmed malicious findings.
    """
    logger = logging.getLogger("ThreatIntel")
    validated = set()

    logger.info(f"Starting validation for {len(candidates)} manual candidates...")

    for item in candidates:
        item = normalize_item(item)
        if not item:
            continue

        is_malicious = False

        # Determine if IP or Domain
        # Simple heuristic: if it looks like an IP, use AbuseIPDB, else VT
        # (This is a simplification, VT handles IPs too)

        # Check AbuseIPDB (IPs)
        # We can try AbuseIPDB first if it looks like an IP?
        # For now, let's try VT for everything as it covers both well,
        # and AbuseIPDB only for IPs if we want to save VT quota.

        # Strategy:
        # 1. Try VT.
        # 2. If VT fails/skipped and it's an IP, try AbuseIPDB.

        # Check VirusTotal
        vt_result = vt_client.is_malicious(item)
        if vt_result:
            is_malicious = True
            logger.info(f"[{item}] CONFIRMED Malicious by VirusTotal")
        else:
            # If VT said no or skipped, check AbuseIPDB if it's an IP
            # Basic IP check (digits and dots)
            if all(c.isdigit() or c == '.' for c in item):
                abuse_result = abuse_client.is_malicious(item)
                if abuse_result:
                    is_malicious = True
                    logger.info(f"[{item}] CONFIRMED Malicious by AbuseIPDB")

        # Decision Logic
        # REQUIREMENT UPDATE: Fail-Open Policy + Manual Priority.
        # Even if validation fails or returns clean, we trust the manual addition.

        if is_malicious:
            validated.add(item)
        else:
            logger.info(f"[{item}] Validation negative (or quota exceeded/error). Keeping in manual additions (Fail-Open/Manual Priority).")
            validated.add(item)

    return validated

def main():
    parser = argparse.ArgumentParser(description="ThreatIntel Aggregator")
    parser.add_argument("--conf", action="store_true", help="Launch configuration menu")
    args = parser.parse_args()

    if args.conf:
        from utils.config_menu import run_configuration_wizard
        run_configuration_wizard()
        sys.exit(0)

    logger = setup_logger()
    logger.info("Starting ThreatIntel Aggregator...")

    # 1. Initialize Components
    feed_manager = FeedManager()
    vt_client = VirusTotalClient()
    abuse_client = AbuseIPDBClient()

    # 2. Load Static Files
    whitelist = read_file_lines(WHITELIST_FILE)
    manual_adds = read_file_lines(ADD_REQUESTS_FILE)
    manual_removes = read_file_lines(REMOVE_REQUESTS_FILE)
    existing_list = read_file_lines(OUTPUT_FILE)

    processor = ThreatProcessor(whitelist)

    # 3. Validate Manual Additions
    # Only validate manual adds to save quota and ensure high quality for community contributions
    if manual_adds:
        validated_adds = validate_candidates(manual_adds, vt_client, abuse_client)
        logger.info(f"Manual Adds: {len(manual_adds)} requested -> {len(validated_adds)} validated")
    else:
        validated_adds = set()

    # 4. Fetch Feeds
    feed_data = feed_manager.fetch_all()

    # 5. Process and Consolidate
    final_list = processor.process_data(
        feed_iocs=feed_data,
        manual_adds=validated_adds,
        manual_removes=manual_removes,
        existing_blocklist=existing_list
    )

    # 6. Write Output
    write_output_file(OUTPUT_FILE, final_list)

    # 7. Clear Request Files (if successful)
    if manual_adds:
        write_output_file(ADD_REQUESTS_FILE, [])
        logger.info(f"Cleared {ADD_REQUESTS_FILE} after processing.")

    if manual_removes:
        write_output_file(REMOVE_REQUESTS_FILE, [])
        logger.info(f"Cleared {REMOVE_REQUESTS_FILE} after processing.")

    # 8. Statistics
    added_count = len(set(final_list) - set(existing_list))
    removed_count = len(set(existing_list) - set(final_list))

    logger.info(f"Run Complete. Total domains: {len(final_list)}")
    logger.info(f"Stats: +{added_count} new, -{removed_count} removed")

if __name__ == "__main__":
    main()
