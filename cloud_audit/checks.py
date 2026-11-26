"""Provider-neutral CIS-style checks for cloud VMs.

Collectors (aws.py / azure.py / gcp.py) normalise each instance into a plain dict,
so every check here is testable without any cloud SDK or credentials.

Normalised VM dict keys:
  provider, id, name, region, state, os (free text), public_ip (bool),
  open_mgmt_ports (list[str] reachable from the internet, e.g. ["22"]),
  disk_encrypted (bool|None)       - at-rest encryption on (provider default counts)
  disk_cmk (bool|None)             - customer-managed key / encryption at host
  imdsv2_required (bool|None)      - AWS only
  secure_boot, vtpm, integrity (bool|None) - shielded VM / trusted launch
  block_project_ssh_keys, os_login, serial_port_enabled, default_sa_full_access (bool|None) - GCP
  missing_critical, missing_other (int|None) - None means patch state unknown
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

from .models import PASS, FAIL, WARN, INFO, make

from . import eol as _eol

WARN_DAYS = 180


def _os_rules():
    return _eol.load_rules()


def os_eol(os_text: str, today=None):
    """Return (product, eol_date) for the first matching rule or None."""
    today = today or dt.date.today()
    for rule in _os_rules():
        if re.search(rule["match"], os_text or "", re.I):
            return rule["name"], dt.date.fromisoformat(rule["eol"])
    return None


def check_vm(vm: dict, today=None):
    today = today or dt.date.today()
    area = f"{vm['provider']} VM"
    tgt = f"{vm['name']} ({vm.get('region', '')})"
    p = vm["provider"]
    out = []

    def add(cid, title, status, actual, expected, fix="", level="L1", cat="CIS"):
        out.append(make(cid, area, title, tgt, status, actual, expected, "" if status == PASS else fix, level, category=cat))

    # ---- exposure
    add("CLD-001", "No public IP address attached", WARN if vm.get("public_ip") else PASS,
        "public IP" if vm.get("public_ip") else "private only", "private only unless required",
        "Remove the public IP; use a bastion, VPN, SSM Session Manager, Azure Bastion or IAP.")
    ports = vm.get("open_mgmt_ports") or []
    add("CLD-002", "SSH/RDP not open to the internet (0.0.0.0/0)", FAIL if ports else PASS,
        ", ".join(ports) or "none open", "none",
        "Restrict security group / NSG / firewall rules for 22 and 3389 to trusted source ranges.")

    if vm.get("no_nsg"):
        add("CLD-005", "Public IP protected by a network security group", WARN, "public IP with no NIC or subnet NSG",
            "NSG on NIC or subnet", "Attach an NSG that restricts inbound traffic.")

    # ---- encryption
    enc = vm.get("disk_encrypted")
    if enc is not None:
        add("CLD-003", "Attached disks encrypted at rest", PASS if enc else FAIL, enc, True,
            "Enable EBS encryption (and default encryption per region) or re-create the volumes encrypted.")
    cmk = vm.get("disk_cmk")
    if cmk is not None:
        add("CLD-004", "Customer-managed keys / encryption at host", PASS if cmk else WARN, cmk, True,
            "Use CMK (KMS / Key Vault disk encryption set / Cloud KMS) where policy requires key control.", "L2")

    # ---- provider specific
    if p == "AWS":
        v2 = vm.get("imdsv2_required")
        if v2 is not None:
            add("CLD-010", "Instance metadata service requires IMDSv2", PASS if v2 else FAIL, v2, True,
                "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled")
    if p in ("Azure", "GCP"):
        for key, label in (("secure_boot", "Secure Boot"), ("vtpm", "vTPM"), ("integrity", "Integrity monitoring")):
            val = vm.get(key)
            if val is not None:
                add(f"CLD-02{('secure_boot', 'vtpm', 'integrity').index(key)}", f"{label} enabled (Shielded VM / Trusted launch)",
                    PASS if val else WARN, val, True,
                    "Enable Trusted launch (Azure) / Shielded VM options (GCP); may require a supported image.", "L2")
    if p == "GCP":
        for key, cid, title, want, fix in (
            ("block_project_ssh_keys", "CLD-030", "Project-wide SSH keys blocked", True, "Set metadata block-project-ssh-keys=TRUE."),
            ("os_login", "CLD-031", "OS Login enabled", True, "Set metadata enable-oslogin=TRUE."),
            ("serial_port_enabled", "CLD-032", "Interactive serial console disabled", False, "Set metadata serial-port-enable=FALSE."),
            ("default_sa_full_access", "CLD-033", "No default service account with full API access", False,
             "Use a dedicated least-privilege service account instead of cloud-platform scope."),
        ):
            val = vm.get(key)
            if val is not None:
                add(cid, title, PASS if val == want else FAIL, val, want, fix)

    # ---- EOL of the guest OS
    hit = os_eol(vm.get("os", ""), today)
    if hit:
        name, eol = hit
        days = (eol - today).days
        if days < 0:
            add("CLD-EOL", f"Guest OS support: {name}", FAIL, f"{name} reached end of support {eol} ({-days} days ago)",
                "supported OS", "Migrate to a supported OS release (or buy extended security updates).", cat="EOL")
        elif days <= WARN_DAYS:
            add("CLD-EOL", f"Guest OS support: {name}", WARN, f"{name} support ends {eol} (in {days} days)", "supported OS",
                "Plan an OS upgrade.", cat="EOL")
        else:
            add("CLD-EOL", f"Guest OS support: {name}", PASS, f"{name}, supported until {eol}", "supported OS", cat="EOL")
    else:
        add("CLD-EOL", "Guest OS support lifecycle", INFO, vm.get("os") or "OS not reported",
            "known OS", "OS not recognised in os_eol.json; verify the lifecycle manually.", cat="EOL")

    # ---- patches
    mc, mo = vm.get("missing_critical"), vm.get("missing_other")
    if mc is None and mo is None:
        hint = {"AWS": "Install/enable the SSM Agent with an instance profile (AmazonSSMManagedInstanceCore) for Patch Manager, "
                       "or enable Amazon Inspector for agentless package scanning.",
                "Azure": "Enable Azure Update Manager periodic assessment.",
                "GCP": "Enable VM Manager (OS Config agent) on the instance/project."}.get(p, "")
        why = ("not managed by SSM and no Inspector data" if (p == "AWS" and vm.get("ssm_managed") is False)
               else "patch state unavailable")
        add("CLD-PATCH", "Missing OS patches", WARN, why, "assessment enabled", hint, cat="PATCH")
    else:
        mc, mo = mc or 0, mo or 0
        status = FAIL if mc else (WARN if mo else PASS)
        src = f" [{vm['patch_source']}]" if vm.get("patch_source") else ""
        add("CLD-PATCH", "Missing OS patches", status, f"{mc} critical/security, {mo} other{src}", "0 missing",
            "Apply the pending patches (Patch Manager / Update Manager / VM Manager patch job).", cat="PATCH")
    return out


def check_all(vms, today=None):
    res = []
    for v in vms:
        res.extend(check_vm(v, today))
    return res
