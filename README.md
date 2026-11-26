<p align="center">
  <img src="assets/icon.png" width="110" alt="Cloud VM Auditor icon">
</p>

<h1 align="center">☁️ Cloud VM CIS, EOL & Patch Auditor</h1>

<p align="center">
  Audit <b>AWS EC2</b>, <b>Azure VMs</b> and <b>GCP Compute Engine</b> instances for CIS-style misconfigurations, end-of-support operating systems and missing patches, from a modern desktop GUI or the command line.
</p>

<p align="center">
  <a href="https://github.com/3tternp/cloud-vm-cis-audit/actions/workflows/tests.yml"><img src="https://github.com/3tternp/cloud-vm-cis-audit/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
  <a href="https://github.com/3tternp/cloud-vm-cis-audit/releases"><img src="https://img.shields.io/github/v/release/3tternp/cloud-vm-cis-audit?label=release" alt="release"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platforms">
  <img src="https://img.shields.io/badge/access-read--only%20by%20default-informational" alt="read-only by default">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/AWS-EC2-FF9900?logo=amazonwebservices&logoColor=white" alt="AWS">
  <img src="https://img.shields.io/badge/Azure-VMs-0078D4?logo=microsoftazure&logoColor=white" alt="Azure">
  <img src="https://img.shields.io/badge/Google%20Cloud-Compute%20Engine-4285F4?logo=googlecloud&logoColor=white" alt="GCP">
</p>

<p align="center">
  <img src="docs/screenshot_dark.png" width="49%" alt="Dark theme"> <img src="docs/screenshot_light.png" width="49%" alt="Light theme">
</p>
<p align="center"><sub>Screenshots use <b>made-up demo data</b> (<code>tools/make_screenshot.py</code>), not a real environment.</sub></p>

## ✨ Features

| | |
|---|---|
| 🛡️ **CIS-style checks** | Public IPs, SSH/RDP open to the internet, disk encryption, IMDSv2, Shielded VM / Trusted launch, OS Login, and more |
| ⏳ **End-of-support detection** | Guest OS lifecycle vs. a bundled table, refreshable from endoflife.date |
| 🩹 **Missing patches** | SSM Patch Manager / Amazon Inspector, Azure Update Manager, GCP VM Manager, with the data source shown |
| 🔬 **In-guest scan (opt-in)** | Read-only Linux and Windows hardening scripts run through SSM / Run Command |
| 🖥️ **Modern GUI** | Dark / light themes, summary cards, filters, search, per-VM roll-up and a "how to fix" panel |
| 📦 **Reports** | HTML, CSV and JSON export |
| 🔐 **No stored secrets** | Uses your existing cloud login (AWS profile / SSO, `az login`, `gcloud`); read-only API calls by default |

## 🚀 Quick start

```powershell
pip install -r requirements.txt
python cloud_audit_gui.py
```

1. Pick **AWS**, **Azure** or **GCP** and fill in the one or two fields (AWS profile and regions, Azure subscription ID, GCP project ID).
2. Click **Check access** once to see which read-only APIs your credentials can call, then **Run audit**.
3. Read the result cards. **Findings** has filters, search and a fix panel; **By VM** ranks machines by failures (double-click to drill in); **Log** shows progress.
4. Export HTML, CSV or JSON. **Update EOL data** refreshes guest-OS lifecycle dates.

### 🪟 Windows executable
No Python needed: download `CloudVMAuditor.exe` from the [Releases](https://github.com/3tternp/cloud-vm-cis-audit/releases) page and verify it against the published `.sha256`. It is the same GUI with the AWS, Azure and GCP SDKs bundled. You still need your own cloud login on that machine.

Build it yourself (isolated `.venv-build`, your global Python is untouched):
```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1     # -> dist\CloudVMAuditor.exe
```
The exe is unsigned, so Windows SmartScreen may warn on first run ("More info" > "Run anyway"). It is GUI-only; use the Python CLI for headless runs. Pushing a tag like `v0.1.0` makes the `build-exe` workflow build the exe and attach it to a GitHub release.

### ⌨️ Command line
```powershell
python cloud_audit_cli.py --cloud aws --check-access --regions us-east-1     # 1) see which APIs your credentials can call
python cloud_audit_cli.py --cloud aws --regions us-east-1,eu-west-1 [--profile myprofile]
python cloud_audit_cli.py --cloud azure --subscription <subscription-id>     # after: az login
python cloud_audit_cli.py --cloud gcp --project <project-id>                  # after: gcloud auth application-default login
python cloud_audit_cli.py --update-eol                                        # refresh guest-OS EOL dates from endoflife.date
```
Writes `cloud_audit.html`, `.csv` and `.json` (`--out` changes the prefix). Requires Python 3.10+; the GUI needs Tkinter (bundled with the standard Windows/macOS installers; on Debian/Ubuntu `sudo apt install python3-tk`).

## ✅ Checks

| ID | Check | Providers |
|---|---|---|
| CLD-001 | 🌐 No public IP attached | all |
| CLD-002 | 🚪 SSH/RDP not open to the internet (rules evaluated by priority, deny honoured) | all |
| CLD-005 | 🧱 Public IP protected by an NSG | Azure |
| CLD-003/004 | 🔒 Disks encrypted; customer-managed keys / encryption at host (L2) | all |
| CLD-010 | 🧾 IMDSv2 required | AWS |
| CLD-020..022 | 🛡️ Secure Boot, vTPM, integrity monitoring (L2) | Azure, GCP |
| CLD-030..033 | 🔑 Block project SSH keys, OS Login, serial console off, no default SA with full API access | GCP |
| CLD-EOL | ⏳ Guest OS end of support | all |
| CLD-PATCH | 🩹 Missing OS patches, with the data source shown | all |
| GUEST-* | 🔬 In-guest hardening (opt-in): SSH, accounts, firewall, auditd, time sync, ASLR, SELinux/AppArmor, pending security updates; Windows firewall, SMBv1, Defender, NLA, UAC, password policy, hotfix age | AWS, Azure |

### 🩹 How patch data is obtained
| Provider | Source | Without it |
|---|---|---|
| AWS | SSM Patch Manager; **fallback: Amazon Inspector** package findings (agentless); instances in neither are listed as "not managed by SSM" with the fix | WARN with remediation |
| Azure | Azure Update Manager assessment | WARN |
| GCP | VM Manager inventory + vulnerability report (needs `google-cloud-os-config`) | WARN (unknown, never "0 missing") |

### 🌐 Network exposure
Azure traffic must pass both the subnet NSG and the NIC NSG (intersection), first matching rule by priority wins. GCP VPC firewall rules are ordered by priority with deny honoured. AWS security groups are allow-only. Hierarchical GCP firewall policies and AWS network ACLs are not evaluated.

### ⏳ OS end-of-support data
`cloud_audit/data/os_eol.json` ships with dates compiled on its `verified` date. `--update-eol` (or **Update EOL data** in the GUI) rebuilds the rules from endoflife.date into `~/.cloud_audit/os_eol.json` (takes precedence; falls back per product if offline). The CLI warns when the data is older than 180 days. Unrecognised OS strings are reported as INFO, never silently passed.

## 🔬 In-guest scan (opt-in)
Runs the bundled scripts in [`cloud_audit/guest/`](cloud_audit/guest) inside running VMs through the provider agent: **AWS SSM Run Command** and **Azure Run Command**. The scripts are short, read-only (a test asserts they contain no mutating commands) and print `CIS|id|STATUS|detail` lines. The CLI (`--guest-scan`) and the GUI both ask for confirmation first. Review the scripts before enabling.

Needs more than read-only access: AWS `ssm:SendCommand` + `ssm:GetCommandInvocation`, Azure `Microsoft.Compute/virtualMachines/runCommand/action` (e.g. Virtual Machine Contributor). GCP has no agentless execution channel here, so GCP VMs are skipped. This is a focused CIS-aligned subset, not a full CIS-CAT scan.

## 🔐 Minimum read-only access
- **AWS:** `ec2:Describe{Instances,SecurityGroups,Volumes,Images}`, `ssm:DescribeInstanceInformation`, `ssm:DescribeInstancePatchStates`, optional `inspector2:ListFindings`
- **Azure:** Reader
- **GCP:** `roles/compute.viewer` (+ `roles/osconfig.inventoryViewer`, `roles/osconfig.vulnerabilityReportViewer` for patch data)

## 🗓️ Scheduling
[docs/examples/cloud-audit-aws.yml](docs/examples/cloud-audit-aws.yml) is a GitHub Actions example (OIDC, no stored keys). Copy it to `.github/workflows/` to enable it.

## 🧪 Testing and what is not proven
```powershell
python tests/test_cloud.py        # checks, network rules, patch logic, guest parser, EOL rule builder
python tests/test_collectors.py   # each collector against stub SDKs
python tests/test_gui_model.py    # GUI filtering / per-VM roll-up logic (headless)
```
All of these run in CI without any cloud SDK or credentials. They prove the logic and call sequencing, **not** that the live APIs return exactly these shapes; this tool has not yet run against real AWS, Azure or GCP accounts. Run **Check access** and a first scan in a non-production account, and report anything that differs.

Remaining limits: Azure patch data requires an Update Manager assessment; AWS network ACLs and GCP hierarchical policies are not evaluated; the in-guest scan is a subset of CIS controls.

## 📄 License
[MIT](LICENSE)
