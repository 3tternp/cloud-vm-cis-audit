# Cloud VM CIS, EOL & Patch Auditor

[![tests](https://github.com/3tternp/cloud-vm-cis-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/3tternp/cloud-vm-cis-audit/actions/workflows/tests.yml) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![access: read-only](https://img.shields.io/badge/access-read--only-informational)

Read-only audit of **AWS EC2, Azure VMs and GCP Compute Engine** instances: CIS-style configuration checks, guest-OS end of support, and missing patches. It uses your existing cloud login; no keys are entered or stored. Companion to [vmware-vcenter-esxi-cis-audit](https://github.com/3tternp/vmware-vcenter-esxi-cis-audit).

## Install and run
```powershell
pip install -r requirements.txt
python cloud_audit_cli.py --cloud aws --regions us-east-1,eu-west-1 [--profile myprofile]
python cloud_audit_cli.py --cloud azure --subscription <subscription-id>     # after: az login
python cloud_audit_cli.py --cloud gcp --project <project-id>                  # after: gcloud auth application-default login
```
Writes `cloud_audit.html`, `.csv` and `.json` (use `--out` to change the prefix). Requires Python 3.10+. Minimum access: AWS read-only EC2 + SSM Describe*, Azure Reader, GCP `roles/compute.viewer`.

## Checks
| ID | Check | Providers |
|---|---|---|
| CLD-001 | No public IP attached | all |
| CLD-002 | SSH/RDP not open to the internet | all |
| CLD-003/004 | Disks encrypted; customer-managed keys / encryption at host (L2) | all |
| CLD-010 | IMDSv2 required | AWS |
| CLD-020..022 | Secure Boot, vTPM, integrity monitoring (L2) | Azure, GCP |
| CLD-030..033 | Block project SSH keys, OS Login, serial console off, no default SA with full API access | GCP |
| CLD-EOL | Guest OS end of support (`cloud_audit/data/os_eol.json`) | all |
| CLD-PATCH | Missing OS patches (SSM Patch Manager, Azure Update Manager; GCP unknown) | all |

## Scheduling
[docs/examples/cloud-audit-aws.yml](docs/examples/cloud-audit-aws.yml) is a GitHub Actions example (OIDC, no stored keys). Copy it to `.github/workflows/` to enable it.

## Limits
- OS EOL dates are best-effort; verify them against vendor lifecycle pages and edit the JSON.
- Azure checks NIC-level NSGs only (not subnet NSGs). EC2 patch data requires the SSM agent. GCP patch state is not collected.
- VM configuration level only, not an in-guest CIS OS scan.
- Not yet run against real cloud accounts; covered by offline tests (`python tests/test_cloud.py`).

## License
[MIT](LICENSE)
