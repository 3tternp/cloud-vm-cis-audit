"""Cloud VM auditing (AWS, Azure, GCP). SDKs are optional and imported lazily."""
from __future__ import annotations

from . import checks


def run_cloud_scan(provider, params, log=lambda m: None):
    """provider: 'aws' | 'azure' | 'gcp'. params: dict (regions/profile | subscription_id | project)."""
    provider = provider.lower()
    if provider == "aws":
        from . import aws
        regions = [r.strip() for r in str(params.get("regions", "")).split(",") if r.strip()] or None
        vms = aws.collect(regions, params.get("profile"), log)
        target = ",".join(regions or ["default region"])
    elif provider == "azure":
        from . import azure
        if not params.get("subscription_id"):
            raise ValueError("Azure subscription id is required")
        vms = azure.collect(params["subscription_id"], log)
        target = params["subscription_id"]
    elif provider == "gcp":
        from . import gcp
        if not params.get("project"):
            raise ValueError("GCP project id is required")
        vms = gcp.collect(params["project"], log)
        target = params["project"]
    else:
        raise ValueError(f"unknown provider {provider}")
    results = checks.check_all(vms)
    log(f"{len(vms)} VMs audited, {len(results)} checks")
    meta = {"target": target, "type": f"{provider.upper()} cloud VMs", "product": f"{len(vms)} VMs", "build": "n/a"}
    return results, meta
