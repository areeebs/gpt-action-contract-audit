import unittest

from tool import audit


class ContractTests(unittest.TestCase):
    def test_non_https_and_unapproved_write_are_rejected(self):
        report = audit({
            "servers": [{"url": "http://api.example.test"}],
            "paths": {"/records": {"post": {"operationId": "createRecord", "security": [{"oauth": []}]}}},
        }, {"api.example.test"})
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("server_not_https", codes)
        self.assertIn("write_without_approval_contract", codes)
        self.assertFalse(report["pass"])

    def test_approved_https_contract_passes(self):
        report = audit({
            "servers": [{"url": "https://api.example.test/v1"}],
            "security": [{"oauth": ["records:read"]}],
            "paths": {"/records": {"get": {"operationId": "searchRecords"}}},
        }, {"api.example.test"})
        self.assertTrue(report["pass"])

    def test_host_is_exact_not_suffix_matched(self):
        report = audit({"servers": [{"url": "https://api.example.test.evil.invalid"}], "paths": {}},
                       {"api.example.test"})
        self.assertIn("server_host_not_allowlisted", {x["code"] for x in report["findings"]})


if __name__ == "__main__":
    unittest.main()
