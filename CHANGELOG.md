# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-26

### Changed
- README rewritten with a logo, badges, section icons and a features table.
- Removed the reference to the companion VMware audit project from the README.

No functional changes; the Windows executable is rebuilt from the same code.

## [0.1.0] - 2026-11-26

First release.

### Added
- **Cloud VM audits** for AWS EC2, Azure VMs and GCP Compute Engine using your existing cloud login (no keys entered or stored), read-only by default.
- **CIS-style checks:** public IP, SSH/RDP exposure (rules evaluated by priority with deny honoured; Azure subnet and NIC NSGs combined), disk encryption and customer-managed keys, IMDSv2 (AWS), Secure Boot / vTPM / integrity monitoring (Azure, GCP), GCP project SSH keys, OS Login, serial console and default service account scope.
- **Guest OS end-of-support** detection from a bundled table, refreshable from endoflife.date (`--update-eol` / GUI button) with a staleness warning.
- **Missing-patch reporting** from AWS SSM Patch Manager (with an Amazon Inspector fallback), Azure Update Manager and GCP VM Manager; unknown patch state is reported, never as "0 missing".
- **Opt-in in-guest scan** (`--guest-scan`) running bundled read-only Linux and Windows scripts through AWS SSM Run Command and Azure Run Command, with confirmation prompts.
- **Access pre-check** (`--check-access` / GUI button) to list which read-only APIs the current credentials can call.
- **Desktop GUI** (CustomTkinter) with dark, light and system themes, summary cards, filterable findings with remediation text, per-VM roll-up and a log; **CLI** with the same scans.
- **HTML, CSV and JSON reports.**
- **Windows executable** (`CloudVMAuditor.exe`, PyInstaller, unsigned) with SHA-256 checksum, built by the `build-exe` GitHub Actions workflow.
- Offline test suites (checks, collectors against stub SDKs, GUI logic) run in CI on Python 3.10, 3.12 and 3.13.

### Known limitations
- Not yet validated against live AWS, Azure or GCP accounts; tests use fake and stub data only.
- OS end-of-support dates are best-effort and should be verified.
- AWS network ACLs and GCP hierarchical firewall policies are not evaluated; Azure patch data needs an Update Manager assessment; the in-guest scan is a CIS-aligned subset and does not cover GCP.

[Unreleased]: https://github.com/3tternp/cloud-vm-cis-audit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/3tternp/cloud-vm-cis-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/3tternp/cloud-vm-cis-audit/releases/tag/v0.1.0
