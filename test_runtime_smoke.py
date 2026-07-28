import subprocess
import unittest
from pathlib import Path

import config
import embedded


class RuntimeSmokeTest(unittest.TestCase):
    def test_install_script_uses_configured_public_url_and_is_valid_bash(self):
        self.assertIn(config.PUBLIC_URL, embedded.INSTALL_SCRIPT)
        self.assertNotIn("__MANAGER_URL__", embedded.INSTALL_SCRIPT)
        subprocess.run(
            ["bash", "-n"],
            input=embedded.INSTALL_SCRIPT,
            text=True,
            check=True,
        )

    def test_static_entrypoints_exist(self):
        root = Path(__file__).resolve().parent
        self.assertTrue((root / "static/index.html").is_file())
        self.assertTrue((root / "static/login.html").is_file())


if __name__ == "__main__":
    unittest.main()
