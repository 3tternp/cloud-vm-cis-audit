"""Headless tests for GUI helper logic. Run: python tests/test_gui_model.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cloud_audit.models import make  # noqa: E402
from cloud_audit import gui_model as gm  # noqa: E402


def sample():
    return [make("A", "AWS VM", "No public IP", "web (r)", "WARN", "public"),
            make("B", "AWS VM", "SSH closed", "web (r)", "FAIL", "22"),
            make("C", "AWS VM", "Encrypted", "web (r)", "PASS", True),
            make("D", "Azure VM", "OS support", "db (w)", "PASS", "ok", category="EOL"),
            make("E", "Azure VM", "Patches", "db (w)", "INFO", "n/a", category="PATCH")]


def test_filter_and_sort():
    res = sample()
    assert [r.check_id for r in gm.filter_results(res)] == ["B", "A", "E", "D", "C"]
    assert [r.check_id for r in gm.filter_results(res, status="PASS")] == ["D", "C"]
    assert [r.check_id for r in gm.filter_results(res, category="EOL")] == ["D"]
    assert [r.check_id for r in gm.filter_results(res, text="ssh")] == ["B"]


def test_by_vm_and_summary():
    rows = gm.by_vm(sample())
    assert rows[0]["vm"] == "web (r)" and rows[0]["fail"] == 1 and rows[0]["warn"] == 1 and rows[0]["provider"] == "AWS"
    assert rows[1]["other"] == 1
    c, score, vms = gm.summary(sample())
    assert vms == 2 and c["FAIL"] == 1 and score == 50   # 2 pass / (2 pass + 1 fail + 1 warn)
    assert gm.summary([])[1] == 0


if __name__ == "__main__":
    test_filter_and_sort()
    test_by_vm_and_summary()
    print("OK - gui model tests passed")
