from __future__ import annotations

import sqlite3
import unittest

from core.load_seeds_to_frontier import load_seed_urls_to_frontier
from core.url_intake import format_skip_summary, normalize_fetchable_url


VALID_ONION = "a" * 56 + ".onion"


class UrlIntakeTests(unittest.TestCase):
    def test_normalizes_https_onion_to_http_and_drops_fragment(self) -> None:
        result = normalize_fetchable_url(f" HTTPS://WWW.{VALID_ONION}/path/#frag ")

        self.assertTrue(result.accepted)
        self.assertEqual(result.network, "tor")
        self.assertEqual(result.normalized_url, f"http://www.{VALID_ONION}/path")

    def test_normalizes_schemeless_clearnet_url(self) -> None:
        result = normalize_fetchable_url("Example.COM/some page/?q=leak hunt#section")

        self.assertTrue(result.accepted)
        self.assertEqual(result.network, "clearnet")
        self.assertEqual(result.normalized_url, "https://example.com/some%20page?q=leak%20hunt")

    def test_normalizes_freenet_key(self) -> None:
        result = normalize_fetchable_url("USK@example-site/index/1")

        self.assertTrue(result.accepted)
        self.assertEqual(result.network, "freenet")
        self.assertEqual(result.normalized_url, "freenet:USK@example-site/index/1")

    def test_rejects_non_web_scheme(self) -> None:
        result = normalize_fetchable_url("mailto:analyst@example.com")

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "non_web_scheme")

    def test_rejects_non_fetchable_network(self) -> None:
        result = normalize_fetchable_url("gnunet://threat-exchange/forums/zero-day")

        self.assertFalse(result.accepted)
        self.assertEqual(result.network, "gnunet")
        self.assertEqual(result.reason, "non_fetchable_network")

    def test_rejects_malformed_onion_placeholder(self) -> None:
        result = normalize_fetchable_url("http://lzogc...u57id.onion")

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "invalid_host")

    def test_rejects_missing_host(self) -> None:
        result = normalize_fetchable_url("http:///just-a-path")

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "missing_host")

    def test_formats_skip_summary(self) -> None:
        summary = format_skip_summary({"non_web_scheme": 2, "malformed_onion": 1})

        self.assertEqual(summary, "non_web_scheme=2, malformed_onion=1")


class SeedFrontierLoadTests(unittest.TestCase):
    def test_load_seeds_to_frontier_normalizes_and_summarizes_skips(self) -> None:
        seeds = [
            f"https://{VALID_ONION}/",
            "mailto:analyst@example.com",
            "gnunet://threat-exchange/forums/zero-day",
        ]
        with sqlite3.connect(":memory:") as conn:
            conn.execute(
                """
                CREATE TABLE frontier (
                    url TEXT UNIQUE,
                    source TEXT,
                    depth INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    network TEXT DEFAULT 'unknown'
                )
                """
            )
            conn.commit()

            stats = load_seed_urls_to_frontier(seeds, conn)
            row = conn.execute("SELECT url, network FROM frontier").fetchone()

        self.assertEqual(stats["read"], 3)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["inserted"], 1)
        self.assertEqual(stats["skipped"], {"non_web_scheme": 1, "non_fetchable_network": 1})
        self.assertEqual(row, (f"http://{VALID_ONION}/", "tor"))


if __name__ == "__main__":
    unittest.main()
