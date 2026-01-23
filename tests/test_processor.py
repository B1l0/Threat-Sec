import unittest
from core.processor import ThreatProcessor

class TestThreatProcessor(unittest.TestCase):
    def setUp(self):
        self.whitelist = {"google.com", "microsoft.com"}
        self.processor = ThreatProcessor(self.whitelist)

    def test_normalization_and_deduplication(self):
        feed_data = {"Example.com", "http://example.com/", "example.com", "TEST.com"}
        # "Example.com", "http://example.com/", "example.com" -> "example.com"
        # "TEST.com" -> "test.com"

        result = self.processor.process_data(
            feed_iocs=feed_data,
            manual_adds=set(),
            manual_removes=set(),
            existing_blocklist=set()
        )
        self.assertEqual(result, ["example.com", "test.com"])

    def test_whitelist_filtering(self):
        feed_data = {"malware.com", "google.com", "drive.google.com"}
        # google.com is whitelisted.
        # drive.google.com is subdomain of whitelisted -> should be removed.

        result = self.processor.process_data(
            feed_iocs=feed_data,
            manual_adds=set(),
            manual_removes=set(),
            existing_blocklist=set()
        )
        self.assertEqual(result, ["malware.com"])

    def test_manual_removes(self):
        feed_data = {"bad.com", "worse.com"}
        removes = {"bad.com"}

        result = self.processor.process_data(
            feed_iocs=feed_data,
            manual_adds=set(),
            manual_removes=removes,
            existing_blocklist=set()
        )
        self.assertEqual(result, ["worse.com"])

    def test_manual_adds_priority(self):
        feed_data = {"bad.com"}
        adds = {"new-bad.com"}

        result = self.processor.process_data(
            feed_iocs=feed_data,
            manual_adds=adds,
            manual_removes=set(),
            existing_blocklist=set()
        )
        self.assertEqual(result, ["bad.com", "new-bad.com"])

if __name__ == '__main__':
    unittest.main()
