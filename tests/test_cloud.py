"""Offline tests for cloud VM checks (no SDKs or credentials needed).

Run:  python tests/test_cloud.py
"""
import os
import sys
from datetime import date
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cloud_audit import checks, aws, azure, gcp  # noqa: E402

TODAY = date(2026, 11, 26)


def by_id(res):
    return {r.check_id: r for r in res}


def test_aws():
    inst = {"InstanceId": "i-1", "Tags": [{"Key": "Name", "Value": "web"}], "PublicIpAddress": "1.2.3.4",
            "State": {"Name": "running"}, "ImageId": "ami-1", "PlatformDetails": "Linux/UNIX",
            "SecurityGroups": [{"GroupId": "sg-1"}], "MetadataOptions": {"HttpTokens": "optional"},
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}]}
    sgs = {"sg-1": {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 20, "ToPort": 30, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}}
    vols = {"vol-1": {"Encrypted": False}}
    vm = aws.normalize(inst, sgs, vols, {"PlatformName": "Ubuntu", "PlatformVersion": "18.04"},
                       {"SecurityNonCompliantCount": 3, "CriticalNonCompliantCount": 1, "OtherNonCompliantCount": 2}, "", "eu-west-1")
    r = by_id(checks.check_vm(vm, TODAY))
    assert vm["open_mgmt_ports"] == ["22"]
    assert r["CLD-001"].status == "WARN" and r["CLD-002"].status == "FAIL"
    assert r["CLD-003"].status == "FAIL" and r["CLD-010"].status == "FAIL"
    assert r["CLD-EOL"].status == "FAIL" and r["CLD-PATCH"].status == "FAIL"
    assert "4 critical" in r["CLD-PATCH"].actual


def test_aws_clean():
    inst = {"InstanceId": "i-2", "State": {"Name": "running"}, "ImageId": "a", "SecurityGroups": [],
            "MetadataOptions": {"HttpTokens": "required"}, "BlockDeviceMappings": [{"Ebs": {"VolumeId": "v"}}]}
    vm = aws.normalize(inst, {}, {"v": {"Encrypted": True}}, {"PlatformName": "Ubuntu", "PlatformVersion": "24.04"},
                       {"SecurityNonCompliantCount": 0, "CriticalNonCompliantCount": 0, "OtherNonCompliantCount": 0}, "", "r")
    r = by_id(checks.check_vm(vm, TODAY))
    assert all(r[k].status == "PASS" for k in ("CLD-001", "CLD-002", "CLD-003", "CLD-010", "CLD-EOL", "CLD-PATCH")), \
        {k: v.status for k, v in r.items()}


def test_azure_nsg():
    rules = [{"direction": "Inbound", "access": "Allow", "priority": 100, "source": ["*"], "ports": ["3389"]},
             {"direction": "Inbound", "access": "Allow", "priority": 110, "source": ["10.0.0.0/8"], "ports": ["22"]},
             {"direction": "Outbound", "access": "Allow", "priority": 120, "source": ["*"], "ports": ["22"]}]
    assert azure.nsg_open_ports(rules) == ["3389"]
    assert azure.nsg_open_ports([{"direction": "Inbound", "access": "Allow", "source": ["Internet"], "ports": ["1-100"]}]) == ["22"]


def test_gcp():
    inst = NS(id=1, name="vm1", status="RUNNING", tags=NS(items=["web"]),
              metadata=NS(items=[NS(key="serial-port-enable", value="true"), NS(key="enable-oslogin", value="TRUE")]),
              network_interfaces=[NS(network="projects/p/global/networks/default", access_configs=[NS()])],
              shielded_instance_config=NS(enable_secure_boot=False, enable_vtpm=True, enable_integrity_monitoring=True),
              service_accounts=[NS(email="123-compute@developer.gserviceaccount.com", scopes=["https://www.googleapis.com/auth/cloud-platform"])],
              disks=[NS(licenses=["projects/ubuntu-os-cloud/global/licenses/ubuntu-2004-lts"], disk_encryption_key=None)])
    fws = [{"disabled": False, "direction": "INGRESS", "network": "default", "source_ranges": ["0.0.0.0/0"],
            "target_tags": ["web"], "allowed": [("tcp", ["22"])]}]
    vm = gcp.normalize(inst, "us-central1-a", fws)
    r = by_id(checks.check_vm(vm, TODAY))
    assert r["CLD-002"].status == "FAIL" and r["CLD-020"].status == "WARN" and r["CLD-021"].status == "PASS"
    assert r["CLD-030"].status == "FAIL" and r["CLD-031"].status == "PASS" and r["CLD-032"].status == "FAIL"
    assert r["CLD-033"].status == "FAIL"
    assert r["CLD-EOL"].status == "FAIL"           # Ubuntu 20.04 standard support ended 2025-05-31
    assert r["CLD-PATCH"].status == "WARN"         # unknown patch state


def test_unknown_os():
    r = by_id(checks.check_vm({"provider": "Azure", "name": "x", "os": "FreeBSD 14"}, TODAY))
    assert r["CLD-EOL"].status == "INFO"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("OK - cloud tests passed")
