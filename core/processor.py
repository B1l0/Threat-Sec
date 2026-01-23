from typing import Set, List
import logging
from .normalizer import normalize_item, is_valid_domain_or_ip

logger = logging.getLogger("ThreatIntel")

class ThreatProcessor:
    """
    Handles the logic of processing, normalizing, filtering, and merging IOCs.
    """

    def __init__(self, whitelist: Set[str]):
        self.whitelist = {normalize_item(w) for w in whitelist}
        logger.info(f"Initialized Processor with {len(self.whitelist)} whitelisted domains")

    def normalize_and_filter(self, raw_items: Set[str], source_name: str = "unknown") -> Set[str]:
        """
        Normalizes items and filters invalid ones.
        """
        clean_set = set()
        for item in raw_items:
            normalized = normalize_item(item)
            if is_valid_domain_or_ip(normalized):
                clean_set.add(normalized)
            else:
                # excessive logging check
                pass

        logger.info(f"[{source_name}] Normalized {len(raw_items)} -> {len(clean_set)} items")
        return clean_set

    def process_data(self,
                     feed_iocs: Set[str],
                     manual_adds: Set[str],
                     manual_removes: Set[str],
                     existing_blocklist: Set[str]) -> List[str]:
        """
        Consolidates all sources, applies whitelist and removal requests.
        Returns a sorted list of unique domains.
        """

        # 1. Normalize all inputs
        norm_feed = self.normalize_and_filter(feed_iocs, "Feeds")
        norm_adds = self.normalize_and_filter(manual_adds, "ManualAdd")
        norm_removes = self.normalize_and_filter(manual_removes, "ManualRemove")
        norm_existing = self.normalize_and_filter(existing_blocklist, "Existing")

        # 2. Combine candidates (Feeds + Existing + Manual Adds)
        # Note: We prioritize Manual Adds, but here it's a set union
        candidates = norm_feed.union(norm_existing).union(norm_adds)
        logger.info(f"Total candidates before filtering: {len(candidates)}")

        # 3. Apply Removals (Manual Remove)
        candidates = candidates - norm_removes
        logger.info(f"After applying {len(norm_removes)} removals: {len(candidates)}")

        # 4. Apply Whitelist (Golden Rule)
        # Check exact match and also subdomain match?
        # "Si un domaine est dans la whitelist"
        # If google.com is whitelisted, strictly google.com is removed.
        # What about mail.google.com? usually yes.
        # For this implementation, I will do exact match check first.
        # Advanced whitelist (subdomain check) is safer but heavier.
        # Given "google.com" in whitelist, we probably don't want to block "drive.google.com".
        # I'll implement a suffix check for whitelist.

        final_set = set()
        whitelisted_count = 0

        for domain in candidates:
            if self._is_whitelisted(domain):
                whitelisted_count += 1
                continue
            final_set.add(domain)

        logger.info(f"Whitelisted {whitelisted_count} items. Final count: {len(final_set)}")

        return sorted(list(final_set))

    def _is_whitelisted(self, domain: str) -> bool:
        """
        Checks if a domain is in the whitelist or is a subdomain of a whitelisted domain.
        """
        if domain in self.whitelist:
            return True

        # Check subdomains (e.g., sub.google.com matches google.com)
        parts = domain.split('.')
        # iterate over parts to check parent domains
        # e.g. a.b.c.com -> check b.c.com, c.com
        for i in range(1, len(parts) - 1): # ensure at least a TLD + SLD remains usually
             parent = ".".join(parts[i:])
             if parent in self.whitelist:
                 return True

        return False
