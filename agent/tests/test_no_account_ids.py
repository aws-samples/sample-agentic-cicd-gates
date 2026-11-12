"""No real AWS account ID ships in this repository.

Only AWS documentation's example account IDs (and runs of one digit) may
appear. When release-manifest.yaml is present (the internal source repository),
only the files it publishes are scanned; in a published copy there is no
manifest, so every tracked file is scanned.
"""
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PLACEHOLDERS = {"111111111111", "111122223333", "123456789012", "444455556666",
                "777788889999", "210987654321"}
TWELVE = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])")


def account_ids(text: str) -> list[str]:
    """12-digit numbers that are not a documented placeholder or one repeated digit."""
    return sorted({n for n in TWELVE.findall(text) if n not in PLACEHOLDERS and len(set(n)) > 1})


def _manifest_lists(text: str) -> dict[str, list[str]]:
    """The top-level lists of the simple release manifest (no YAML dependency)."""
    lists, key = {}, None
    for line in text.splitlines():
        line = line.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            key = line[:-1]
            lists[key] = []
        elif not line.startswith(" ") and ":" in line:
            key = None
        elif key and line.lstrip().startswith("- "):
            lists[key].append(line.lstrip()[2:].strip().strip("\"'"))
    return lists


def shipped_files(root: pathlib.Path) -> list[str]:
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                             check=True).stdout.decode().split("\0")
    tracked = [f for f in tracked if f]
    manifest = root / "release-manifest.yaml"
    if not manifest.exists():
        return tracked
    lists = _manifest_lists(manifest.read_text(encoding="utf-8"))
    modules, paths = set(lists.get("public", [])), lists.get("public_paths", [])
    return [f for f in tracked
            if ("/" in f and f.split("/", 1)[0] in modules)
            or any(f == p or f.startswith(p.rstrip("/") + "/") for p in paths)]


class AccountIdTests(unittest.TestCase):
    def test_the_scan_flags_a_real_looking_id_and_passes_placeholders(self):
        planted = "2718" + "28182845"   # built at run time, so this file stays clean
        self.assertEqual(account_ids(f"arn:aws:iam::{planted}:role/deploy"), [planted])
        self.assertEqual(account_ids("arn:aws:iam::123456789012:root 555555555555"), [])
        self.assertEqual(account_ids("sha a" + planted + "b and 1" + planted), [])

    def test_the_manifest_lists_are_read_without_yaml(self):
        lists = _manifest_lists("public:\n  - src   # app\npreview: []\npublic_paths:\n"
                                "  - README.md\nospo_managed:\n  - LICENSE\n")
        self.assertEqual(lists["public"], ["src"])
        self.assertEqual(lists["public_paths"], ["README.md"])

    def test_no_shipped_file_holds_a_real_account_id(self):
        try:
            files = shipped_files(ROOT)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        found = {}
        for rel in files:
            data = (ROOT / rel).read_bytes() if (ROOT / rel).is_file() else b""
            if b"\0" in data:
                continue                     # binary: images and archives
            ids = account_ids(data.decode("utf-8", "replace"))
            if ids:
                found[rel] = [i[:2] + "*" * 8 + i[-2:] for i in ids]
        self.assertEqual(found, {}, "real-looking AWS account IDs; use 111122223333 or a "
                                    "deploy-time value instead")


if __name__ == "__main__":
    unittest.main()
