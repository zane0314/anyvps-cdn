import unittest
from urllib.parse import parse_qs, urlparse

import app


class SubStoreRefreshTest(unittest.TestCase):
    def test_no_cache_and_real_substore_url(self):
        url = app.add_no_cache_param("https://example.test/download/example-%E4%B8%9C%E4%BA%AC-cdn?target=Clash")
        self.assertEqual(parse_qs(urlparse(url).query), {"target": ["Clash"], "noCache": ["true"]})
        row = {
            "substore_base64_url": "https://substore.test/download/item",
            "substore_cdn_base64_url": "https://substore.test/download/cdn",
            "substore_combo_base64_url": "",
            "substore_xui_base64_url": "",
        }
        self.assertEqual(app.substore_verify_url(row), row["substore_base64_url"])


if __name__ == "__main__":
    unittest.main()
