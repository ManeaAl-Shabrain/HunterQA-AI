
import unittest
from sanitizer_parser import parse_sanitizer_log


class TestSanitizerParser(unittest.TestCase):

    def test_use_after_free(self):
        log = """
ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: AddressSanitizer: heap-use-after-free
/home/kali/uaf_test.c:14:27
"""
        result = parse_sanitizer_log(log)

        self.assertEqual(
            result["category"], "heap-use-after-free"
        )
        self.assertEqual(
            result["cwe_candidate"], "CWE-416"
        )
        self.assertTrue(result["evidence_confirmed"])
        self.assertFalse(result["zero_day_confirmed"])

    def test_intentional_abort(self):
        result = parse_sanitizer_log("")

        self.assertIsNone(result["category"])
        self.assertIsNone(result["cwe_candidate"])
        self.assertFalse(result["evidence_confirmed"])


if __name__ == "__main__":
    unittest.main()
