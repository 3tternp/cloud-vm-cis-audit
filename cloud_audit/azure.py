"""Azure VM collector (read-only). Uses DefaultAzureCredential (az login, env, managed identity).

Role: Reader on the subscription is sufficient for configuration checks.
Network exposure is evaluated like Azure does: rules are processed by priority (first match wins, so a
higher-priority Deny closes a port) and traffic must pass BOTH the subnet NSG and the NIC NSG.
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
    """Management ports an NSG lets in from the internet.
    rules: iterable of {direction, access, priority, source[list], ports[list]}."""
    ordered = sorted(rules, key=lambda x: x.get("priority", 65000))
    ports = set()
    for mp in MGMT:
        for r in ordered:
            if str(r["direction"]).lower() != "inbound":
                continue
            if not any(str(s).lower() in INTERNET_SRC for s in r["source"]):
                continue
            if not any(_port_hit(p, mp) for p in r["ports"]):
                continue
            if str(r["access"]).lower() == "allow":
                ports.add(str(mp))
            break  # first matching rule decides (Allow or Deny)
    return sorted(ports)


def effective_open_ports(nic_rules, subnet_rules):
    """Intersect NIC-level and subnet-level NSGs. A level with no NSG is passed as None.
    Returns None when neither level has an NSG (nothing filters the traffic)."""
    sets = [set(nsg_open_ports(r)) for r in (nic_rules, subnet_rules) if r is not None]
    if not sets:
        return None
    return sorted(set.intersection(*sets))


def _rules(nsg):
    out = []
    for r in list(nsg.security_rules or []):
        out.append({"direction": str(r.direction), "access": str(r.access), "priority": r.priority,
                    "source": [r.source_address_prefix] if r.source_address_prefix else list(r.source_address_prefixes or []),
                    "ports": [r.destination_port_range] if r.destination_port_range else list(r.destination_port_ranges or [])})
    return out


def normalize(vm, iv, public_ip, open_ports, no_nsg=False):
    sec = getattr(vm, "security_profile", None)
    uefi = getattr(sec, "uefi_settings", None) if sec else None
    osd = vm.storage_profile.os_disk
    des = getattr(getattr(osd, "managed_disk", None), "disk_encryption_set", None)
    ref = vm.storage_profile.image_reference
    os_text = " ".join(filter(None, [getattr(iv, "os_name", None), getattr(iv, "os_version", None)])) or \
        " ".join(filter(None, [getattr(ref, "offer", None), getattr(ref, "sku", None)]))
    ps = getattr(iv, "patch_status", None)
    summ = getattr(ps, "available_patch_summary", None) if ps else None
    os_type = str(getattr(osd, "os_type", "") or "").lower()
    return {
        "provider": "Azure", "id": vm.id, "name": vm.name, "region": vm.location,
        "state": None, "os": os_text, "os_family": "windows" if "windows" in os_type else "linux",
        "public_ip": public_ip, "open_mgmt_ports": open_ports, "no_nsg": no_nsg,
        "disk_encrypted": True,  # managed disks always have platform-managed SSE
        "disk_cmk": bool(des) or bool(getattr(sec, "encryption_at_host", False)),
        "secure_boot": bool(getattr(uefi, "secure_boot_enabled", False)) if sec else False,
        "vtpm": bool(getattr(uefi, "v_tpm_enabled", False)) if sec else False,
        "missing_critical": getattr(summ, "critical_and_security_patch_count", None) if summ else None,
        "missing_other": getattr(summ, "other_patch_count", None) if summ else None,
        "patch_source": "Azure Update Manager" if summ else None,
        "_rg": vm.id.split("/")[4],
    }


def _clients(subscription_id):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except ImportError as e:
        raise RuntimeError("Azure SDK is required: pip install -r requirements.txt") from e
    cred = DefaultAzureCredential()
    return ComputeManagementClient(cred, subscription_id), NetworkManagementClient(cred, subscription_id)


def _nic_exposure(net, nic_ref_id, log, vmname):
    """Returns (has_public_ip, open_ports or None)."""
    try:
        parts = nic_ref_id.split("/")
        nic = net.network_interfaces.get(parts[4], parts[-1])
        public = any(c.public_ip_address for c in (nic.ip_configurations or []))
        nic_rules = None
        if nic.network_security_group:
            i = nic.network_security_group.id.split("/")
            nic_rules = _rules(net.network_security_groups.get(i[4], i[-1]))
        subnet_rules = None
        sn = next((c.subnet for c in (nic.ip_configurations or []) if c.subnet), None)
        if sn:
            s = sn.id.split("/")  # .../resourceGroups/rg/.../virtualNetworks/vnet/subnets/name
            subnet = net.subnets.get(s[4], s[8], s[10])
            if subnet.network_security_group:
                i = subnet.network_security_group.id.split("/")
                subnet_rules = _rules(net.network_security_groups.get(i[4], i[-1]))
        return public, effective_open_ports(nic_rules, subnet_rules)
    except Exception as e:
        log(f"Azure {vmname}: NIC/NSG lookup failed ({type(e).__name__})")
        return False, []


def collect(subscription_id, log=lambda m: None):
    compute, net = _clients(subscription_id)
    vms = []
    for vm in compute.virtual_machines.list_all():
        rg = vm.id.split("/")[4]
        log(f"Azure: {vm.name}")
        try:
            iv = compute.virtual_machines.instance_view(rg, vm.name)
        except Exception:
            iv = None
        public, ports, unfiltered = False, set(), False
        for ref in (vm.network_profile.network_interfaces or []):
            pub, op = _nic_exposure(net, ref.id, log, vm.name)
            public = public or pub
            if op is None:
                unfiltered = unfiltered or pub
            else:
                ports |= set(op)
        vms.append(normalize(vm, iv, public, sorted(ports), no_nsg=unfiltered))
    return vms
