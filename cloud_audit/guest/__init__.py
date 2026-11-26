"""Opt-in, read-only in-guest audit executed through the cloud provider's agent channel.

AWS   : SSM Run Command (needs the SSM agent + ssm:SendCommand)
Azure : VM Run Command   (needs the VM agent + Microsoft.Compute/virtualMachines/runCommand/action)
GCP   : no agentless execution channel is used; run the bundled scripts via your own tooling.

The scripts in this folder are plain text, make no changes, and print one 'CIS|id|STATUS|detail' line per check.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..models import make, ERROR, WARN, INFO, PASS, FAIL

HERE = Path(__file__).resolve().parent
VALID = {PASS, FAIL, WARN, INFO}


def script_for(family: str) -> str:
    name = "windows_audit.ps1" if family == "windows" else "linux_audit.sh"
    return (HERE / name).read_text(encoding="utf-8")


def parse_output(text: str, vm: dict, title_map=None):
    """Turn script output into Result objects (unknown lines are ignored)."""
    area = f"{vm['provider']} guest OS"
    tgt = f"{vm['name']} ({vm.get('region', '')})"
    res = []
    for line in (text or "").splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) != 4 or parts[0] != "CIS" or parts[2] not in VALID:
            continue
        _, cid, status, detail = parts
        res.append(make(f"GUEST-{cid}", area, TITLES.get(cid, cid), tgt, status, detail, "", "" if status == PASS else FIX.get(cid, "Review against the CIS benchmark for this OS."),
                        "L1"))
    return res


TITLES = {
    "LIN-001": "SSH root login restricted", "LIN-002": "SSH password authentication disabled", "LIN-003": "SSH empty passwords denied",
    "LIN-004": "SSH X11 forwarding disabled", "LIN-010": "No accounts with empty passwords", "LIN-011": "Only root has UID 0",
    "LIN-012": "Password maximum age set", "LIN-020": "Host firewall active", "LIN-021": "Audit daemon (auditd) active",
    "LIN-022": "Time synchronisation active", "LIN-023": "ASLR enabled", "LIN-024": "Mandatory access control enforcing",
    "LIN-025": "SUID core dumps restricted", "LIN-026": "No telnet listener", "LIN-030": "No pending reboot",
    "LIN-031": "Security updates applied", "LIN-032": "Automatic security updates configured",
    "WIN-001": "Windows Firewall enabled (all profiles)", "WIN-002": "SMBv1 server disabled", "WIN-003": "Defender real-time protection",
    "WIN-004": "RDP requires NLA", "WIN-005": "UAC enabled", "WIN-006": "Guest account disabled",
    "WIN-007": "Minimum password length >= 14", "WIN-008": "Account lockout threshold 1-5",
    "WIN-010": "No pending reboot", "WIN-011": "Recent Windows updates installed",
}
FIX = {
    "LIN-001": "Set 'PermitRootLogin no' (or prohibit-password) in sshd_config and reload sshd.",
    "LIN-002": "Set 'PasswordAuthentication no' after key-based access is verified.",
    "LIN-031": "Apply security updates (apt upgrade / dnf update --security) and reboot if required.",
    "LIN-023": "sysctl -w kernel.randomize_va_space=2 and persist in /etc/sysctl.d/.",
    "WIN-002": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
    "WIN-004": "Require Network Level Authentication for Remote Desktop.",
}


def run_aws(session, region, vm, timeout=180):
    ssm = session.client("ssm", region_name=region)
    doc = "AWS-RunPowerShellScript" if vm.get("os_family") == "windows" else "AWS-RunShellScript"
    cmd = ssm.send_command(InstanceIds=[vm["id"]], DocumentName=doc,
                           Parameters={"commands": script_for(vm.get("os_family", "linux")).splitlines()},
                           Comment="cloud-vm-cis-audit read-only guest audit")["Command"]["CommandId"]
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(3)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=vm["id"])
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            return inv.get("StandardOutputContent", ""), inv["Status"]
    return "", "Timeout"


def run_azure(compute, vm, timeout=300):
    cmd = "RunPowerShellScript" if vm.get("os_family") == "windows" else "RunShellScript"
    poller = compute.virtual_machines.begin_run_command(
        vm["_rg"], vm["name"], {"command_id": cmd, "script": script_for(vm.get("os_family", "linux")).splitlines()})
    out = poller.result(timeout=timeout)
    return "\n".join((v.message or "") for v in (out.value or [])), "Success"


def run_guest_audit(provider, vms, params, log=lambda m: None):
    """Run the read-only scripts on eligible VMs and return Results."""
    results = []
    session = compute = None
    if provider == "aws":
        import boto3
        session = boto3.Session(profile_name=params.get("profile") or None)
    elif provider == "azure":
        from ..azure import _clients
        compute, _ = _clients(params["subscription_id"])
    else:
        log("Guest audit is not supported for GCP (no agentless execution channel).")
        return results
    for vm in vms:
        tgt = f"{vm['name']} ({vm.get('region', '')})"
        if provider == "aws" and not (vm.get("state") == "running" and vm.get("ssm_managed")):
            results.append(make("GUEST-SKIP", "AWS guest OS", "Guest audit skipped", tgt, INFO,
                                "not running or not managed by SSM", "", "Attach AmazonSSMManagedInstanceCore and install the SSM Agent."))
            continue
        log(f"Guest audit: {vm['name']}")
        try:
            text, status = run_aws(session, vm["region"], vm) if provider == "aws" else run_azure(compute, vm)
            parsed = parse_output(text, vm)
            if not parsed:
                results.append(make("GUEST-NODATA", f"{vm['provider']} guest OS", "Guest audit returned no results", tgt, WARN,
                                    f"command status {status}", "", "Check agent health and run-command permissions."))
            results.extend(parsed)
        except Exception as e:
            log(f"  failed: {type(e).__name__}: {e}")
            results.append(make("GUEST-ERR", f"{vm['provider']} guest OS", "Guest audit could not run", tgt, ERROR,
                                f"{type(e).__name__}: {str(e)[:120]}", "", "Check permissions, agent state and that the VM is running."))
    return results
