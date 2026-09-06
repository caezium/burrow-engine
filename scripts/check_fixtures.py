#!/usr/bin/env python3
"""Check the public fixture inventory and independently defined contract invariants."""

import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def check():
    manifest = read("fixtures-manifest.json")
    assert manifest["format"] == 1, "unsupported fixture manifest"
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src").rglob("*.golden.json")
    }
    assert actual == set(manifest["sha256"]), "fixture inventory changed"
    for name, expected in manifest["sha256"].items():
        # Checkout line endings are not contract data (Windows may use CRLF).
        data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(data).hexdigest() == expected, f"unreviewed fixture change: {name}"
        json.loads(data)

    protection = read("src/clean/protection.golden.json")
    assert protection["count"] == len(protection["paths"]) == 1968
    assert sum(row["protected"] for row in protection["paths"]) == protection["protected"] == 1120
    assert sum(row["default_whitelisted"] for row in protection["paths"]) == protection["default_whitelisted"] == 99
    deletion = read("src/clean/deletion_rails.golden.json")
    assert deletion["count"] == len(deletion["paths"]) == 2414
    assert deletion["validate_refused"] == 1479
    assert deletion["mode_differs"] == 1137
    assert deletion["protect_mode_differs"] == 1160
    whitelist = read("src/clean/whitelist_match.golden.json")
    assert whitelist["glob_count"] == len(whitelist["globs"]) == 9376
    assert whitelist["whitelist_count"] == len(whitelist["whitelist"]) == 825
    assert whitelist["glob_matches"] == 1065
    assert whitelist["whitelisted"] == 421

    status = read("src/status/status.golden.json")
    timestamp = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[+-]\d\d:\d\d"
    assert re.fullmatch(timestamp, status["collected_at"]), "fractional timestamp and UTC offset required"
    memory = status["memory"]
    assert memory["used"] + memory["available"] == memory["total"]
    assert memory["used_percent"] == memory["used"] * 100 / memory["total"]
    assert status["cpu"]["usage"] == sum(status["cpu"]["per_core"]) / len(status["cpu"]["per_core"])
    for row in status["disks"]:
        assert row["used_percent"] == row["used"] * 100 / row["total"]
    for direction in ("rx", "tx"):
        assert status["network_history"][direction + "_history"] == [sum(row[direction + "_rate_mbs"] for row in status["network"])]
    network = read("src/net/net.golden.json")
    assert network["count"] == len(network["by_total_bytes"]) == 15
    assert all(row["total"] == row["bytes_in"] + row["bytes_out"] for row in network["by_total_bytes"])
    assert [row["total"] for row in network["by_total_bytes"]] == sorted((row["total"] for row in network["by_total_bytes"]), reverse=True)

    apps = read("src/uninstall/uninstall-list.golden.json")
    assert len(apps) == 7
    assert sum(row["source"] == "App" for row in apps) == 3
    assert sum(row["source"] == "Homebrew" for row in apps) == 4
    assert all(set(row) == {"bundle_id", "name", "path", "size", "source", "uninstall_name"} for row in apps)
    assert all(all(isinstance(value, str) for value in row.values()) for row in apps)
    assert any(row["path"] != f'/Applications/{row["name"]}.app' for row in apps)
    for row in apps:
        expected = row["name"].lower() if row["source"] == "Homebrew" else row["name"]
        assert row["uninstall_name"] == expected
    assert read("src/analyze.golden.json") == read("src/analyze/analyze.golden.json")
    print(f"Verified {len(actual)} public fixtures and their preserved contract invariants.")


if __name__ == "__main__":
    check()
