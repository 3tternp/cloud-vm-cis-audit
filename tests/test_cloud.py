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

from cloud_audit import eol  # noqa: E402
eol.USER_FILE = eol.USER_FILE.with_name("does_not_exist.json")  # tests use bundled data only


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
    assert "4 critical" in r["CLD-PATCH"].actual and "SSM Patch Manager" in r["CLD-PATCH"].actual


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
            "target_tags": ["web"], "priority": 1000, "action": "allow", "rules": [("tcp", ["22"])]}]
    vm = gcp.normalize(inst, "us-central1-a", fws)
    r = by_id(checks.check_vm(vm, TODAY))
    assert r["CLD-002"].status == "FAIL" and r["CLD-020"].status == "WARN" and r["CLD-021"].status == "PASS"
    assert r["CLD-030"].status == "FAIL" and r["CLD-031"].status == "PASS" and r["CLD-032"].status == "FAIL"
    assert r["CLD-033"].status == "FAIL"
    assert r["CLD-EOL"].status == "FAIL"           # Ubuntu 20.04 standard support ended 2025-05-31
    assert r["CLD-PATCH"].status == "WARN"         # unknown patch state


def test_azure_priority_and_subnet():
    allow = {"direction": "Inbound", "access": "Allow", "priority": 200, "source": ["*"], "ports": ["22"]}
    deny = {"direction": "Inbound", "access": "Deny", "priority": 100, "source": ["Internet"], "ports": ["22"]}
    assert azure.nsg_open_ports([allow]) == ["22"]
    assert azure.nsg_open_ports([allow, deny]) == []                 # higher-priority deny wins
    assert azure.effective_open_ports([allow], [deny]) == []         # subnet NSG blocks what NIC NSG allows
    assert azure.effective_open_ports([allow], None) == ["22"]       # no subnet NSG -> NIC NSG decides
    assert azure.effective_open_ports(None, None) is None            # nothing filters traffic


def test_gcp_priority_deny():
    inst = NS(network_interfaces=[NS(network="x/default")], tags=NS(items=[]))
    base = {"disabled": False, "direction": "INGRESS", "network": "default", "source_ranges": ["0.0.0.0/0"], "target_tags": []}
    allow = dict(base, priority=1000, action="allow", rules=[("tcp", ["22"])])
    deny = dict(base, priority=500, action="deny", rules=[("tcp", ["22"])])
    assert gcp.firewall_open_ports(inst, [allow]) == ["22"]
    assert gcp.firewall_open_ports(inst, [allow, deny]) == []


def test_patch_fallbacks():
    inst = {"InstanceId": "i-3", "State": {"Name": "running"}, "ImageId": "a", "SecurityGroups": [], "BlockDeviceMappings": []}
    vm = aws.normalize(inst, {}, {}, {}, None, "Ubuntu 22.04 AMI", "r", inspector=(2, 5))
    assert vm["missing_critical"] == 2 and "Inspector" in vm["patch_source"]
    vm2 = aws.normalize(inst, {}, {}, {}, None, "Ubuntu 22.04 AMI", "r")
    r = by_id(checks.check_vm(vm2, TODAY))
    assert r["CLD-PATCH"].status == "WARN" and "not managed by SSM" in r["CLD-PATCH"].actual
    vm3 = {"provider": "Azure", "name": "v", "os": "x", "public_ip": True, "no_nsg": True, "open_mgmt_ports": []}
    assert by_id(checks.check_vm(vm3, TODAY))["CLD-005"].status == "WARN"


def test_gcp_osconfig():
    inv = NS(items={"a": NS(type_="AVAILABLE_PACKAGE"), "b": NS(type_="INSTALLED_PACKAGE"), "c": NS(type_="AVAILABLE_PACKAGE")})
    rep = NS(vulnerabilities=[NS(details=NS(severity="CRITICAL"))])

    class C:
        def get_inventory(self, request): return inv
        def get_vulnerability_report(self, request): return rep

    osv = NS(InventoryView=NS(FULL=2))
    assert gcp.osconfig_patch(C(), osv, "p", "z", 1) == (1, 1)

    class Broken(C):
        def get_inventory(self, request): raise RuntimeError("403")
    assert gcp.osconfig_patch(Broken(), osv, "p", "z", 1) is None


def test_guest_parser_and_scripts():
    from cloud_audit import guest
    vm = {"provider": "AWS", "name": "web", "region": "r"}
    out = "\n".join(["noise", "CIS|LIN-001|FAIL|PermitRootLogin=yes", "CIS|LIN-023|PASS|ASLR=2", "CIS|BAD|MAYBE|x", "CIS|WIN-002|WARN|a|b"])
    r = by_id(guest.parse_output(out, vm))
    assert set(r) == {"GUEST-LIN-001", "GUEST-LIN-023", "GUEST-WIN-002"}
    assert r["GUEST-LIN-001"].status == "FAIL" and r["GUEST-LIN-001"].remediation
    assert r["GUEST-WIN-002"].actual == "a|b"
    # scripts are read-only: no obvious mutating commands
    for fam in ("linux", "windows"):
        text = guest.script_for(fam).lower()
        for bad in ("rm -", "set-itemproperty", "remove-item", "sysctl -w", "systemctl restart", "systemctl stop", "apt-get install", "yum install", "set-netfirewall"):
            assert bad not in text, (fam, bad)


def test_eol_rule_builder():
    from cloud_audit import eol
    name, rx = eol._rule("windows-server", "2012-r2", "2023-10-10")
    import re
    assert name == "Windows Server 2012 R2" and re.search(rx, "Windows Server 2012 R2 Datacenter", re.I)
    name, rx = eol._rule("ubuntu", "22.04", "2027-04-01")
    assert re.search(rx, "Ubuntu 22.04 LTS", re.I) and re.search(rx, "ubuntu-2204-lts", re.I)
    name, rx = eol._rule("amazon-linux", "2", "2026-06-30")
    assert re.search(rx, "Amazon Linux 2", re.I) and not re.search(rx, "Amazon Linux 2023", re.I)


def test_unknown_os():
    r = by_id(checks.check_vm({"provider": "Azure", "name": "x", "os": "FreeBSD 14"}, TODAY))
    assert r["CLD-EOL"].status == "INFO"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("OK - cloud tests passed")
