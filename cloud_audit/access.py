"""Pre-flight access check: tries each read-only API the audit needs and reports what is allowed.

Run this first against a real account (`--check-access`) so permission gaps show up as a clear
list instead of silently missing findings.
"""
from __future__ import annotations


def _probe(name, fn):
    try:
        fn()
        return name, True, "ok"
    except Exception as e:  # report everything, never raise
        return name, False, f"{type(e).__name__}: {str(e)[:110]}"


def check_aws(regions=None, profile=None):
    import boto3
    s = boto3.Session(profile_name=profile or None)
    region = (regions or [s.region_name or "us-east-1"])[0]
    ec2, ssm = s.client("ec2", region_name=region), s.client("ssm", region_name=region)
    out = [_probe("sts:GetCallerIdentity", lambda: s.client("sts").get_caller_identity()),
           _probe("ec2:DescribeInstances", lambda: ec2.describe_instances(MaxResults=5)),
           _probe("ec2:DescribeSecurityGroups", lambda: ec2.describe_security_groups(MaxResults=5)),
           _probe("ec2:DescribeVolumes", lambda: ec2.describe_volumes(MaxResults=5)),
           _probe("ec2:DescribeImages (optional)", lambda: ec2.describe_images(Owners=["self"], MaxResults=5)),
           _probe("ssm:DescribeInstanceInformation (patch data)", lambda: ssm.describe_instance_information(MaxResults=5)),
           _probe("inspector2:ListFindings (optional fallback)",
                  lambda: s.client("inspector2", region_name=region).list_findings(maxResults=1))]
    return out


def check_azure(subscription_id):
    from . import azure
    compute, net = azure._clients(subscription_id)
    first = lambda it: next(iter(it), None)
    return [_probe("compute: list virtual machines", lambda: first(compute.virtual_machines.list_all())),
            _probe("network: list NSGs", lambda: first(net.network_security_groups.list_all())),
            _probe("network: list network interfaces", lambda: first(net.network_interfaces.list_all()))]


def check_gcp(project):
    from google.cloud import compute_v1
    first = lambda it: next(iter(it), None)
    out = [_probe("compute.instances.list", lambda: first(compute_v1.InstancesClient().aggregated_list(project=project))),
           _probe("compute.firewalls.list", lambda: first(compute_v1.FirewallsClient().list(project=project)))]
    try:
        from google.cloud import osconfig_v1
        out.append(_probe("osconfig client (VM Manager, optional)", lambda: osconfig_v1.OsConfigZonalServiceClient()))
    except ImportError:
        out.append(("osconfig client (VM Manager, optional)", False, "google-cloud-os-config not installed"))
    return out


def run_access_check(provider, params):
    if provider == "aws":
        regions = [r.strip() for r in str(params.get("regions") or "").split(",") if r.strip()] or None
        return check_aws(regions, params.get("profile"))
    if provider == "azure":
        return check_azure(params["subscription_id"])
    return check_gcp(params["project"])
