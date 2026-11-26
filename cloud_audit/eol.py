"""Guest-OS lifecycle rules: bundled table + optional refresh from endoflife.date.

A refreshed copy is cached in ~/.cloud_audit/os_eol.json and takes precedence over the
bundled table. The refresh is opt-in (--update-eol); nothing is fetched during a normal scan.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

BUNDLED = Path(__file__).resolve().parent / "data" / "os_eol.json"
USER_FILE = Path(os.path.expanduser("~")) / ".cloud_audit" / "os_eol.json"
STALE_DAYS = 180


def _read(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_rules():
    """Cached online rules first (first match wins), then the bundled rules."""
    rules = list(_read(USER_FILE).get("rules", []))
    return rules + list(_read(BUNDLED).get("rules", []))


def data_age_days(today=None):
    """Age of the freshest data source (cache refresh date, else bundled 'verified' date)."""
    today = today or dt.date.today()
    for p in (USER_FILE, BUNDLED):
        v = _read(p).get("verified")
        if v:
            try:
                return (today - dt.date.fromisoformat(v)).days
            except ValueError:
                pass
    return None


def _num(c):  # "22.04" -> regex matching 22.04 or 2204
    return re.escape(c) + (r"|" + c.replace(".", "") if "." in c else "")


def _rule(slug, cycle, eol):
    c = str(cycle).lower()
    if slug == "ubuntu":
        return "Ubuntu " + c, rf"ubuntu.*({_num(c)})"
    if slug == "windows-server":
        r2 = c.endswith("-r2")
        base = c.replace("-r2", "")
        return f"Windows Server {base}{' R2' if r2 else ''}", rf"windows.*{base}" + (r"\s*r2" if r2 else "")
    if slug == "rhel":
        return f"RHEL {c}", rf"(rhel|red\s*hat).*\b{re.escape(c)}\b"
    if slug == "centos":
        return f"CentOS {c}", rf"centos.*\b{re.escape(c)}\b"
    if slug == "debian":
        return f"Debian {c}", rf"debian.*\b{re.escape(c)}\b"
    if slug == "amazon-linux":
        return f"Amazon Linux {c}", rf"amazon.*linux.*(\b{re.escape(c)}\b|amzn{re.escape(c)}|al{re.escape(c)})"
    if slug == "almalinux":
        return f"AlmaLinux {c}", rf"alma.*\b{re.escape(c)}\b"
    if slug == "rocky-linux":
        return f"Rocky Linux {c}", rf"rocky.*\b{re.escape(c)}\b"
    return None


SLUGS = ("windows-server", "ubuntu", "rhel", "centos", "debian", "amazon-linux", "almalinux", "rocky-linux")


def refresh_online(log=lambda m: None, timeout=15):
    """Rebuild the rule cache from endoflife.date. Returns number of rules written."""
    import requests
    rules = []
    for slug in SLUGS:
        try:
            r = requests.get(f"https://endoflife.date/api/{slug}.json", timeout=timeout,
                             headers={"User-Agent": "cloud-vm-cis-audit"})
            r.raise_for_status()
            rows = r.json()
        except Exception as e:
            log(f"endoflife.date/{slug}: {type(e).__name__} - keeping bundled rules for it")
            continue
        # R2 cycles must precede their plain counterpart (first match wins)
        rows.sort(key=lambda x: (0 if str(x.get("cycle", "")).endswith("-r2") else 1))
        for item in rows:
            eol = item.get("eol")
            built = _rule(slug, item.get("cycle", ""), eol)
            if built and isinstance(eol, str):
                rules.append({"name": built[0], "match": built[1], "eol": eol})
        log(f"{slug}: {len([x for x in rules if x['name']])} rules so far")
    if not rules:
        raise RuntimeError("no EOL data could be fetched (offline?)")
    USER_FILE.parent.mkdir(exist_ok=True)
    USER_FILE.write_text(json.dumps({"verified": dt.date.today().isoformat(), "source": "endoflife.date", "rules": rules}, indent=1),
                         encoding="utf-8")
    return len(rules)
