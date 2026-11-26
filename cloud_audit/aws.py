"""AWS EC2 collector (read-only). Credentials come from the standard boto3 chain
(env vars, ~/.aws, SSO, instance role); nothing is entered into or stored by this tool.

Needs: ec2:DescribeInstances/Volumes/SecurityGroups/Images, ssm:DescribeInstanceInformation,
ssm:DescribeInstancePatchStates, and optionally inspector2:ListFindings
(agentless patch fallback when the SSM agent is absent). All read-only.
"""
from __future__ import annotations

MGMT_PORTS = (22, 3389)


def _open_ports(sg_list):
    ports = set()
    for sg in sg_list:
        for perm in sg.get("IpPermissions", []):
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
            if not any(c in ("0.0.0.0/0", "::/0") for c in cidrs):
                continue
            proto = perm.get("IpProtocol")
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            for mp in MGMT_PORTS:
                if proto == "-1" or (proto in ("tcp", "6") and lo <= mp <= hi):
                    ports.add(str(mp))
    return sorted(ports)


def normalize(inst, sgs, vols, ssm_info, ssm_patch, image_name, region, inspector=None):
    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
    own_sgs = [sgs[g["GroupId"]] for g in inst.get("SecurityGroups", []) if g["GroupId"] in sgs]
    attached = [vols[b["Ebs"]["VolumeId"]] for b in inst.get("BlockDeviceMappings", [])
                if "Ebs" in b and b["Ebs"]["VolumeId"] in vols]
    os_text = " ".join(filter(None, [ssm_info.get("PlatformName"), ssm_info.get("PlatformVersion")])) \
        or " ".join(filter(None, [image_name, inst.get("PlatformDetails")]))
    mo = inst.get("MetadataOptions", {})
    pat = ssm_patch
    if pat is not None:
        crit = pat.get("SecurityNonCompliantCount", 0) + pat.get("CriticalNonCompliantCount", 0)
        other, src = pat.get("OtherNonCompliantCount", 0), "SSM Patch Manager"
    elif inspector is not None:
        (crit, other), src = inspector, "Amazon Inspector (vulnerable packages)"
    else:
        crit = other = src = None
    windows = (ssm_info.get("PlatformType") == "Windows") or inst.get("Platform") == "windows"
    return {
        "provider": "AWS", "id": inst["InstanceId"], "name": name, "region": region,
        "state": inst.get("State", {}).get("Name"), "os": os_text,
        "public_ip": bool(inst.get("PublicIpAddress")),
        "open_mgmt_ports": _open_ports(own_sgs),
        "disk_encrypted": all(v.get("Encrypted") for v in attached) if attached else None,
        "disk_cmk": None,
        "imdsv2_required": (mo.get("HttpTokens") == "required") if mo else None,
        "missing_critical": crit, "missing_other": other, "patch_source": src,
        "ssm_managed": bool(ssm_info), "os_family": "windows" if windows else "linux",
    }


def _inspector_counts(insp, instance_id):
    """(critical+high, other) active package-vulnerability findings, or None if Inspector is unavailable."""
    crit = other = 0
    try:
        flt = {"resourceId": [{"comparison": "EQUALS", "value": instance_id}],
               "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
               "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]}
        for page in insp.get_paginator("list_findings").paginate(filterCriteria=flt):
            for f in page.get("findings", []):
                if f.get("severity") in ("CRITICAL", "HIGH"):
                    crit += 1
                else:
                    other += 1
        return crit, other
    except Exception:
        return None


def collect(regions=None, profile=None, log=lambda m: None):
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError("boto3 is required: pip install -r requirements-cloud.txt") from e
    session = boto3.Session(profile_name=profile or None)
    regions = regions or [session.region_name or "us-east-1"]
    vms = []
    for region in regions:
        log(f"AWS: scanning {region} ...")
        ec2, ssm = session.client("ec2", region_name=region), session.client("ssm", region_name=region)
        insts = [i for r in ec2.get_paginator("describe_instances").paginate().build_full_result()["Reservations"]
                 for i in r["Instances"] if i["State"]["Name"] not in ("terminated", "shutting-down")]
        if not insts:
            continue
        sgs = {g["GroupId"]: g for p in ec2.get_paginator("describe_security_groups").paginate() for g in p["SecurityGroups"]}
        vols = {v["VolumeId"]: v for p in ec2.get_paginator("describe_volumes").paginate() for v in p["Volumes"]}
        info, patch = {}, {}
        try:
            for p in ssm.get_paginator("describe_instance_information").paginate():
                info.update({i["InstanceId"]: i for i in p["InstanceInformationList"]})
            ids = [i["InstanceId"] for i in insts if i["InstanceId"] in info]
            for k in range(0, len(ids), 50):
                for s in ssm.describe_instance_patch_states(InstanceIds=ids[k:k + 50])["InstancePatchStates"]:
                    patch[s["InstanceId"]] = s
        except Exception as e:
            log(f"AWS {region}: SSM patch data unavailable ({type(e).__name__})")
        img_ids = list({i["ImageId"] for i in insts if i["InstanceId"] not in info})
        images = {}
        if img_ids:
            try:
                images = {im["ImageId"]: f"{im.get('Name', '')} {im.get('Description', '')}"
                          for im in ec2.describe_images(ImageIds=img_ids)["Images"]}
            except Exception:
                pass
        insp = None
        if any(i["InstanceId"] not in patch for i in insts):
            try:  # agentless fallback when SSM patch data is missing
                insp = session.client("inspector2", region_name=region)
            except Exception:
                insp = None
        for i in insts:
            iid = i["InstanceId"]
            fallback = (_inspector_counts(insp, iid)
                        if (insp is not None and iid not in patch and i["State"]["Name"] == "running") else None)
            vms.append(normalize(i, sgs, vols, info.get(iid, {}), patch.get(iid),
                                 images.get(i["ImageId"], ""), region, fallback))
    return vms
