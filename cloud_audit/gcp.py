"""GCP Compute Engine collector (read-only). Uses Application Default Credentials
(gcloud auth application-default login, workload identity, service account).

Role: roles/compute.viewer is sufficient. Patch state needs VM Manager and is reported as unknown here.
"""
from __future__ import annotations

MGMT = (22, 3389)


def _meta(inst):
    return {i.key: (i.value or "") for i in (inst.metadata.items if inst.metadata else [])}


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def firewall_open_ports(inst, firewalls):
    net = inst.network_interfaces[0].network.split("/")[-1] if inst.network_interfaces else "default"
    tags = set(inst.tags.items) if inst.tags and inst.tags.items else set()
    ports = set()
    for fw in firewalls:
        if fw.get("disabled") or fw["direction"] != "INGRESS" or fw["network"] != net:
            continue
        if "0.0.0.0/0" not in fw["source_ranges"] and "::/0" not in fw["source_ranges"]:
            continue
        if fw["target_tags"] and not (set(fw["target_tags"]) & tags):
            continue
        for proto, prts in fw["allowed"]:
            if proto not in ("tcp", "all"):
                continue
            for mp in MGMT:
                if proto == "all" or not prts or any(_hit(p, mp) for p in prts):
                    ports.add(str(mp))
    return sorted(ports)


def _hit(rng, port):
    if "-" in rng:
        lo, hi = rng.split("-", 1)
        return int(lo) <= port <= int(hi)
    return rng.isdigit() and int(rng) == port


def normalize(inst, zone, firewalls):
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
        "missing_critical": None, "missing_other": None,
    }


def collect(project, log=lambda m: None):
    try:
        from google.cloud import compute_v1
    except ImportError as e:
        raise RuntimeError("google-cloud-compute is required: pip install -r requirements-cloud.txt") from e
    fws = []
    for f in compute_v1.FirewallsClient().list(project=project):
        fws.append({"disabled": f.disabled, "direction": f.direction, "network": f.network.split("/")[-1],
                    "source_ranges": list(f.source_ranges), "target_tags": list(f.target_tags),
                    "allowed": [(a.I_p_protocol, list(a.ports)) for a in f.allowed]})
    vms = []
    for zone_path, scoped in compute_v1.InstancesClient().aggregated_list(project=project):
        for inst in scoped.instances:
            log(f"GCP: {inst.name}")
            vms.append(normalize(inst, zone_path.split("/")[-1], fws))
    return vms
