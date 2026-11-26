"""GCP Compute Engine collector (read-only). Uses Application Default Credentials
(gcloud auth application-default login, workload identity, service account).

Role: roles/compute.viewer is sufficient. Patch state comes from VM Manager (roles/osconfig.inventoryViewer + vulnerabilityReportViewer);
without it patch state is reported as unknown.
"""
from __future__ import annotations

MGMT = (22, 3389)


def _meta(inst):
    return {i.key: (i.value or "") for i in (inst.metadata.items if inst.metadata else [])}


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def firewall_open_ports(inst, firewalls):
    """Management ports reachable from the internet. VPC firewall rules are evaluated by priority
    (lowest number first; a matching deny closes the port). Hierarchical policies are not evaluated."""
    net = inst.network_interfaces[0].network.split("/")[-1] if inst.network_interfaces else "default"
    tags = set(inst.tags.items) if inst.tags and inst.tags.items else set()
    rules = [f for f in firewalls if not f.get("disabled") and f["direction"] == "INGRESS" and f["network"] == net
             and ("0.0.0.0/0" in f["source_ranges"] or "::/0" in f["source_ranges"])
             and (not f["target_tags"] or set(f["target_tags"]) & tags)]
    rules.sort(key=lambda f: (f.get("priority", 1000), 0 if f.get("action") == "deny" else 1))  # deny wins ties
    ports = set()
    for mp in MGMT:
        for f in rules:
            if any(proto in ("all", "tcp") and (proto == "all" or not prts or any(_hit(p, mp) for p in prts))
                   for proto, prts in f["rules"]):
                if f.get("action", "allow") == "allow":
                    ports.add(str(mp))
                break
    return sorted(ports)


def _hit(rng, port):
    if "-" in rng:
        lo, hi = rng.split("-", 1)
        return int(lo) <= port <= int(hi)
    return rng.isdigit() and int(rng) == port


def normalize(inst, zone, firewalls, patch=None):
    md = _meta(inst)
    sh = inst.shielded_instance_config
    sas = inst.service_accounts or []
    default_full = any(sa.email.endswith("-compute@developer.gserviceaccount.com") and
                       any(s.endswith("/auth/cloud-platform") for s in sa.scopes) for sa in sas)
    licenses = " ".join(l.split("/")[-1] for d in inst.disks for l in (d.licenses or []))
    cmk = [bool(d.disk_encryption_key and (d.disk_encryption_key.kms_key_name or d.disk_encryption_key.sha256))
           for d in inst.disks]
    return {
        "provider": "GCP", "id": str(inst.id), "name": inst.name, "region": zone, "state": inst.status,
        "os": licenses, "public_ip": any(ac for ni in inst.network_interfaces for ac in (ni.access_configs or [])),
        "open_mgmt_ports": firewall_open_ports(inst, firewalls),
        "disk_encrypted": True,  # Google encrypts all disks at rest by default
        "disk_cmk": all(cmk) if cmk else None,
        "secure_boot": bool(sh.enable_secure_boot) if sh else False,
        "vtpm": bool(sh.enable_vtpm) if sh else False,
        "integrity": bool(sh.enable_integrity_monitoring) if sh else False,
        "block_project_ssh_keys": _truthy(md.get("block-project-ssh-keys")),
        "os_login": _truthy(md.get("enable-oslogin")),
        "serial_port_enabled": _truthy(md.get("serial-port-enable")),
        "default_sa_full_access": default_full,
        "missing_critical": patch[0] if patch else None, "missing_other": patch[1] if patch else None,
        "patch_source": "VM Manager (OS Config)" if patch else None,
        "os_family": "windows" if "windows" in licenses.lower() else "linux",
    }


def osconfig_patch(client, osconfig_v1, project, zone, instance_id):
    """(critical/high vulnerabilities, other available updates) from VM Manager, or None if unavailable
    (VM Manager not enabled / agent not reporting / permission missing)."""
    base = f"projects/{project}/locations/{zone}/instances/{instance_id}"
    try:
        inv = client.get_inventory(request={"name": base + "/inventory", "view": osconfig_v1.InventoryView.FULL})
    except Exception:
        return None
    updates = sum(1 for it in inv.items.values()
                  if "AVAILABLE" in str(getattr(it, "type_", getattr(it, "type", ""))).upper())
    crit = 0
    try:
        rep = client.get_vulnerability_report(request={"name": base + "/vulnerabilityReport"})
        crit = sum(1 for v in rep.vulnerabilities
                   if str(getattr(getattr(v, "details", None), "severity", "")).upper() in ("CRITICAL", "HIGH"))
    except Exception:
        pass
    return crit, max(updates - crit, 0)


def collect(project, log=lambda m: None):
    try:
        from google.cloud import compute_v1
    except ImportError as e:
        raise RuntimeError("google-cloud-compute is required: pip install -r requirements-cloud.txt") from e
    fws = []
    for f in compute_v1.FirewallsClient().list(project=project):
        deny = bool(f.denied)
        fws.append({"disabled": f.disabled, "direction": f.direction, "network": f.network.split("/")[-1],
                    "source_ranges": list(f.source_ranges), "target_tags": list(f.target_tags),
                    "priority": f.priority, "action": "deny" if deny else "allow",
                    "rules": [(a.I_p_protocol, list(a.ports)) for a in (f.denied if deny else f.allowed)]})
    osc = osv = None
    try:
        from google.cloud import osconfig_v1 as osv
        osc = osv.OsConfigZonalServiceClient()
    except ImportError:
        log("GCP: google-cloud-os-config not installed; patch state will be reported as unknown")
    vms = []
    for zone_path, scoped in compute_v1.InstancesClient().aggregated_list(project=project):
        for inst in scoped.instances:
            log(f"GCP: {inst.name}")
            zone = zone_path.split("/")[-1]
            patch = osconfig_patch(osc, osv, project, zone, inst.id) if osc and inst.status == "RUNNING" else None
            vms.append(normalize(inst, zone, fws, patch))
    return vms
