"""Tests for release layout. Requires Python stdlib only."""
import importlib.util
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def test_all_main_modules_compile(self):
        for name in ("server.py", "remote_dev_tools.py", "ubuntu_mcp_local_oauth.py",
                     "dev_access.py", "approval_store.py", "approve.py"):
            with self.subTest(name=name):
                compile((ROOT / name).read_text(encoding="utf-8"), name, "exec")

    def test_config_example_contains_no_real_hostname(self):
        values = json.loads((ROOT / "config.example.json").read_text())
        self.assertIn("your-tailnet.ts.net", values["public_host"])
        self.assertEqual(values["port"], 8766)
        self.assertEqual(values["project_root"], "~/Development")

    def test_secret_files_absent(self):
        for name in ("config.json", "oauth_config.json", ".mcp_private", "oauth_login.txt"):
            self.assertFalse((ROOT / name).exists(), name)

if __name__ == "__main__":
    unittest.main()
