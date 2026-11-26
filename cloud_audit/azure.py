"""Azure VM collector (read-only). Uses DefaultAzureCredential (az login, env, managed identity).

Role: Reader on the subscription is sufficient.
Limitation: only NSGs attached to the NIC are evaluated; subnet-level NSGs are not.
"""
from __future__ import annotations

MGMT = (22, 3389)
INTERNET_SRC = {"*", "internet", "0.0.0.0/0", "any"}


def _port_hit(rng, port):
    rng = str(rng).strip()
    if rng == "*":
        return True
    if "-" in rng:
        lo, hi = rng.split("-", 1)
        return int(lo) <= port <= int(hi)
    return rng.isdigit() and int(rng) == port


def nsg_open_ports(rules):
    """rules: iterable of dicts {direction, access, source[list], ports[list]}"""
    ports = set()
    for r in sorted(rules, key=lambda x: x.get("priority", 65000)):
        if r["direction"].lower() != "inbound" or r["access"].lower() != "allow":
            continue
        if not any(s.lower() in INTERNET_SRC for s in r["source"]):
            continue
        for mp in MGMT:
            if any(_port_hit(p, mp) for p in r["ports"]):
                ports.add(str(mp))
    return sorted(ports)


def _rules(nsg):
    out = []
    for r in list(nsg.security_rules or []):
        out.append({"direction": str(r.direction), "access": str(r.access), "priority": r.priority,
                    "source": [r.source_address_prefix] if r.source_address_prefix else list(r.source_address_prefixes or []),
                    "ports": [r.destination_port_range] if r.destination_port_range else list(r.destination_port_ranges or [])})
    return out


def normalize(vm, iv, public_ip, open_ports):
    sec = getattr(vm, "security_profile", None)
    uefi = getattr(sec, "uefi_settings", None) if sec else None
    osd = vm.storage_profile.os_disk
    des = getattr(getattr(osd, "managed_disk", None), "disk_encryption_set", None)
    ref = vm.storage_profile.image_reference
    os_text = " ".join(filter(None, [getattr(iv, "os_name", None), getattr(iv, "os_version", None)])) or \
        " ".join(filter(None, [getattr(ref, "offer", None), getattr(ref, "sku", None)]))
    ps = getattr(iv, "patch_status", None)
    summ = getattr(ps, "available_patch_summary", None) if ps else None
    return {
        "provider": "Azure", "id": vm.id, "name": vm.name, "region": vm.location,
        "state": None, "os": os_text, "public_ip": public_ip, "open_mgmt_ports": open_ports,
        "disk_encrypted": True,  # managed disks always have platform-managed SSE
        "disk_cmk": bool(des) or bool(getattr(sec, "encryption_at_host", False)),
        "secure_boot": bool(getattr(uefi, "secure_boot_enabled", False)) if sec else False,
        "vtpm": bool(getattr(uefi, "v_tpm_enabled", False)) if sec else False,
        "missing_critical": getattr(summ, "critical_and_security_patch_count", None) if summ else None,
        "missing_other": getattr(summ, "other_patch_count", None) if summ else None,
    }


def collect(subscription_id, log=lambda m: None):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except ImportError as e:
        raise RuntimeError("Azure SDK is required: pip install -r requirements-cloud.txt") from e
    cred = DefaultAzureCredential()
    compute, net = ComputeManagementClient(cred, subscription_id), NetworkManagementClient(cred, subscription_id)
    vms = []
    for vm in compute.virtual_machines.list_all():
        rg = vm.id.split("/")[4]
        log(f"Azure: {vm.name}")
        try:
            iv = compute.virtual_machines.instance_view(rg, vm.name)
        except Exception:
            iv = None
        public, rules = False, []
        for ref in (vm.network_profile.network_interfaces or []):
            try:
                nic = net.network_interfaces.get(ref.id.split("/")[4], ref.id.split("/")[-1])
                public = public or any(c.public_ip_address for c in (nic.ip_configurations or []))
                if nic.network_security_group:
                    nsg_id = nic.network_security_group.id
                    nsg = net.network_security_groups.get(nsg_id.split("/")[4], nsg_id.split("/")[-1])
                    rules += _rules(nsg)
            except Exception as e:
                log(f"Azure {vm.name}: NIC/NSG lookup failed ({type(e).__name__})")
        vms.append(normalize(vm, iv, public, nsg_open_ports(rules)))
    return vms
