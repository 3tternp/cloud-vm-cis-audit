"""GUI-independent helpers (filtering, per-VM roll-up, summary) so they can be unit-tested headless."""
from __future__ import annotations

from collections import Counter, OrderedDict

from .models import STATUSES, PASS, FAIL, WARN

ORDER = {s: i for i, s in enumerate(STATUSES)}


def sort_results(results):
    return sorted(results, key=lambda r: (ORDER.get(r.status, 9), r.target, r.check_id))


def filter_results(results, status="ALL", category="ALL", text=""):
    q = (text or "").strip().lower()
    out = []
    for r in sort_results(results):
        if status != "ALL" and r.status != status:
            continue
        if category != "ALL" and r.category != category:
            continue
        if q and q not in f"{r.title} {r.target} {r.actual} {r.check_id} {r.area} {r.remediation}".lower():
            continue
        out.append(r)
    return out


def by_vm(results):
    """One row per VM (result target), worst offenders first. Guest-OS results fold into their VM."""
    rows = OrderedDict()
    for r in results:
        row = rows.setdefault(r.target, {"vm": r.target, "provider": r.area.split()[0], "counts": Counter()})
        row["counts"][r.status] += 1
    out = []
    for row in rows.values():
        c = row["counts"]
        out.append({"vm": row["vm"], "provider": row["provider"], "fail": c[FAIL], "warn": c[WARN], "pass": c[PASS],
                    "other": sum(c.values()) - c[FAIL] - c[WARN] - c[PASS]})
    return sorted(out, key=lambda x: (-x["fail"], -x["warn"], x["vm"]))


def summary(results):
    """(counts, score%, vm_count). Score = PASS / (PASS + FAIL + WARN)."""
    c = Counter(r.status for r in results)
    scored = c[PASS] + c[FAIL] + c[WARN]
    score = round(100 * c[PASS] / scored) if scored else 0
    return c, score, len(by_vm(results))
