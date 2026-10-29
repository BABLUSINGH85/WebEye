import unittest

from reconscope import normalize_target


class NormalizeTargetTests(unittest.TestCase):
    def test_domain_defaults_to_https(self):
        origin, host = normalize_target("example.com")
        self.assertEqual(origin, "https://example.com")
        self.assertEqual(host, "example.com")

    def test_url_path_is_removed_from_origin(self):
        origin, host = normalize_target("https://example.com/path?q=1")
        self.assertEqual(origin, "https://example.com")
        self.assertEqual(host, "example.com")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            normalize_target("https://user:secret@example.com")


if __name__ == "__main__":
    unittest.main()
