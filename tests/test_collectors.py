"""Exercise each collector's control flow against stub SDKs (no network, no credentials).

These tests prove the API-call sequencing and parsing logic; they cannot prove that the real
cloud APIs return exactly these shapes. Use `--check-access` and a lab account for that.

Run:  python tests/test_collectors.py
"""
import os
import sys
import types
from contextlib import contextmanager
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cloud_audit import aws, azure, gcp, checks  # noqa: E402


@contextmanager
def stub_modules(mods):
    saved = {k: sys.modules.get(k, "__missing__") for k in mods}
    sys.modules.update(mods)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v == "__missing__":
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# ------------------------------------------------------------------ AWS
class Pages:
    def __init__(self, pages): self.pages = pages
    def __iter__(self): return iter(self.pages)
    def build_full_result(self):
        merged = {}
        for p in self.pages:
            for k, v in p.items():
                merged.setdefault(k, []).extend(v)
        return merged


class FakeClient:
    def __init__(self, svc, region): self.svc, self.region = svc, region

    def get_paginator(self, op):
        data = {
            "describe_instances": [{"Reservations": [{"Instances": [
                {"InstanceId": "i-managed", "State": {"Name": "running"}, "ImageId": "ami-1", "PublicIpAddress": "5.5.5.5",
                 "Tags": [{"Key": "Name", "Value": "managed"}], "SecurityGroups": [{"GroupId": "sg-1"}],
                 "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}], "MetadataOptions": {"HttpTokens": "required"}},
                {"InstanceId": "i-bare", "State": {"Name": "running"}, "ImageId": "ami-2", "SecurityGroups": [],
                 "BlockDeviceMappings": []},
                {"InstanceId": "i-gone", "State": {"Name": "terminated"}, "ImageId": "ami-2"}]}]}],
            "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}],
            "describe_volumes": [{"Volumes": [{"VolumeId": "vol-1", "Encrypted": True}]}],
            "describe_instance_information": [{"InstanceInformationList": [
                {"InstanceId": "i-managed", "PlatformName": "Ubuntu", "PlatformVersion": "24.04", "PlatformType": "Linux"}]}],
            "list_findings": [{"findings": [{"severity": "CRITICAL"}, {"severity": "LOW"}]}],
        }[op]
        return NS(paginate=lambda **kw: Pages(data))

    def describe_instance_patch_states(self, InstanceIds):
        return {"InstancePatchStates": [{"InstanceId": "i-managed", "SecurityNonCompliantCount": 0,
                                         "CriticalNonCompliantCount": 0, "OtherNonCompliantCount": 0}]}

    def describe_images(self, ImageIds):
        return {"Images": [{"ImageId": "ami-2", "Name": "ubuntu/images/ubuntu-focal-20.04-amd64", "Description": ""}]}


def test_aws_collect():
    fake = NS(Session=lambda profile_name=None: NS(region_name="eu-west-1", client=lambda svc, region_name=None: FakeClient(svc, region_name)))
    with stub_modules({"boto3": fake}):
        vms = {v["name"]: v for v in aws.collect(["eu-west-1"])}
    assert set(vms) == {"managed", "i-bare"}                      # terminated instance skipped
    m, b = vms["managed"], vms["i-bare"]
    assert m["ssm_managed"] and m["patch_source"] == "SSM Patch Manager" and m["missing_critical"] == 0
    assert m["open_mgmt_ports"] == [] and m["disk_encrypted"] is True and m["imdsv2_required"] is True
    assert not b["ssm_managed"] and "Inspector" in b["patch_source"] and b["missing_critical"] == 1 and b["missing_other"] == 1
    assert "20.04" in b["os"]
    assert checks.os_eol(b["os"]) is not None


# ---------------------------------------------------------------- Azure
def _rule(prio, access, port, src="*"):
    return NS(direction="Inbound", access=access, priority=prio, source_address_prefix=src, source_address_prefixes=None,
              destination_port_range=port, destination_port_ranges=None)


def _azure_stubs(subnet_nsg):
    base = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/"
    nsgs = {"nicnsg": NS(security_rules=[_rule(100, "Allow", "22")]),
            "subnsg": NS(security_rules=[_rule(100, "Deny", "22")])}
    nic = NS(ip_configurations=[NS(public_ip_address=NS(), subnet=NS(id=base + "virtualNetworks/vn/subnets/sn"))],
             network_security_group=NS(id=base + "networkSecurityGroups/nicnsg"))
    subnet = NS(network_security_group=NS(id=base + "networkSecurityGroups/subnsg") if subnet_nsg else None)
    net = NS(network_interfaces=NS(get=lambda rg, n: nic), subnets=NS(get=lambda rg, v, s: subnet),
             network_security_groups=NS(get=lambda rg, n: nsgs[n]))
    vm = NS(id="/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/v1", name="v1", location="westeurope",
            network_profile=NS(network_interfaces=[NS(id=base + "networkInterfaces/nic1")]),
            storage_profile=NS(os_disk=NS(os_type="Linux", managed_disk=None), image_reference=NS(offer="UbuntuServer", sku="18.04-LTS")),
            security_profile=None)
    iv = NS(os_name="Ubuntu", os_version="18.04", patch_status=NS(available_patch_summary=NS(
        critical_and_security_patch_count=2, other_patch_count=7)))
    compute = NS(virtual_machines=NS(list_all=lambda: [vm], instance_view=lambda rg, n: iv))
    az = types.ModuleType("azure")
    return {"azure": az,
            "azure.identity": NS(DefaultAzureCredential=lambda: object()),
            "azure.mgmt": types.ModuleType("azure.mgmt"),
            "azure.mgmt.compute": NS(ComputeManagementClient=lambda c, s: compute),
            "azure.mgmt.network": NS(NetworkManagementClient=lambda c, s: net)}


def test_azure_collect_subnet_nsg():
    with stub_modules(_azure_stubs(subnet_nsg=True)):
        v = azure.collect("s")[0]
    assert v["public_ip"] and v["open_mgmt_ports"] == [] and not v["no_nsg"]      # subnet NSG denies what NIC NSG allows
    assert v["missing_critical"] == 2 and v["patch_source"] == "Azure Update Manager"
    with stub_modules(_azure_stubs(subnet_nsg=False)):
        v = azure.collect("s")[0]
    assert v["open_mgmt_ports"] == ["22"]                                           # only the permissive NIC NSG applies


# ------------------------------------------------------------------ GCP
def test_gcp_collect():
    fw = NS(disabled=False, direction="INGRESS", network="x/default", source_ranges=["0.0.0.0/0"], target_tags=[],
            priority=1000, denied=[], allowed=[NS(I_p_protocol="tcp", ports=["22"])])
    inst = NS(id=42, name="g1", status="RUNNING", tags=NS(items=[]), metadata=NS(items=[]),
              network_interfaces=[NS(network="x/default", access_configs=[])],
              shielded_instance_config=NS(enable_secure_boot=True, enable_vtpm=True, enable_integrity_monitoring=True),
              service_accounts=[], disks=[NS(licenses=["x/licenses/debian-12-bookworm"], disk_encryption_key=None)])
    cv1 = NS(FirewallsClient=lambda: NS(list=lambda project: [fw]),
             InstancesClient=lambda: NS(aggregated_list=lambda project: [("zones/us-central1-a", NS(instances=[inst]))]))
    cloud = types.ModuleType("google.cloud")
    cloud.compute_v1 = cv1
    with stub_modules({"google": NS(cloud=cloud), "google.cloud": cloud}):
        vms = gcp.collect("proj")
    v = vms[0]
    assert v["open_mgmt_ports"] == ["22"] and v["region"] == "us-central1-a" and not v["public_ip"]
    assert v["missing_critical"] is None            # VM Manager client unavailable -> unknown, not "0 missing"
    assert checks.os_eol(v["os"]) is not None


if __name__ == "__main__":
    from cloud_audit import eol
    eol.USER_FILE = eol.USER_FILE.with_name("does_not_exist.json")
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("OK - collector tests passed")
