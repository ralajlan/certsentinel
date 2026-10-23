import unittest

from certsentinel.core import parse_target


class ParseTargetTests(unittest.TestCase):
    def test_accepts_https_url_and_ignores_path(self):
        self.assertEqual(parse_target("https://example.org:8443/health?x=1"), ("example.org", 8443))

    def test_accepts_hostname_and_port(self):
        self.assertEqual(parse_target("example.org:443"), ("example.org", 443))

    def test_accepts_bracketed_ipv6(self):
        self.assertEqual(parse_target("[::1]:8443"), ("::1", 8443))

    def test_rejects_http_and_credentials(self):
        for target in ("http://example.org", "https://user:pass@example.org"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_target(target)

    def test_rejects_invalid_ports_and_paths_without_scheme(self):
        for target in ("example.org:0", "example.org:65536", "example.org/path", "", "https://example.org:bad"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_target(target)


if __name__ == "__main__":
    unittest.main()
