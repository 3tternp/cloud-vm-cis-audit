# Security Policy

## Supported versions

This is an early-stage project. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| Latest release (see [Releases](https://github.com/3tternp/cloud-vm-cis-audit/releases)) | Yes |
| Older releases | No |

## Reporting a vulnerability

Please **do not** open a public issue with details of a vulnerability.

1. **Preferred:** open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting), if that button is available.
2. **Otherwise:** open a public issue titled "Security contact request" that contains **no technical details**, and the maintainer will arrange a private channel.

Please include, when you report privately: the affected version, what you observed, steps to reproduce, and the impact you expect. Remove cloud account IDs, VM names, IP addresses and any credentials from logs and screenshots.

This is a volunteer-maintained project, so there is no guaranteed response time, but reports are taken seriously and will be acknowledged as soon as possible. Please allow time for a fix before disclosing publicly.

## What is in scope

Issues in this tool's own code and release artifacts, for example:

- anything that could **expose or store credentials, tokens or account data** (logs, reports, the GUI, cached files such as `~/.cloud_audit/`);
- the opt-in in-guest scan **running commands it should not**, or a way to make it run attacker-controlled input;
- report generation flaws (for example HTML injection from cloud data into exported reports);
- a tampered or malicious Windows executable or build workflow.

Out of scope: vulnerabilities in the cloud providers or their SDKs (report those upstream), findings the tool *reports* about your own cloud estate, and the tool's results being incomplete or inaccurate (open a normal issue instead).

## Design principles that protect you

- **Read-only by default.** The audit makes read-only API calls. The in-guest scan is opt-in, asks for confirmation, and runs short scripts in `cloud_audit/guest/` that a test checks for obviously mutating commands. Review them before enabling it.
- **No secrets handled.** The tool uses your existing cloud login (AWS profile/SSO, `az login`, Application Default Credentials) and has no field for keys or passwords.
- **Least privilege.** Minimum permissions are listed in the [README](README.md#-minimum-read-only-access). Use a dedicated read-only role for audits.
- **Reports can contain sensitive data** (VM names, IPs, configuration weaknesses). Treat exported HTML/CSV/JSON files as confidential.

## Verifying downloads

The Windows executable is **unsigned**. Each release publishes a SHA-256 checksum next to `CloudVMAuditor.exe`:

```powershell
Get-FileHash .\CloudVMAuditor.exe -Algorithm SHA256
```

Compare the result with the `.sha256` file from the same release page, and download only from this repository's Releases. You can also build the exe yourself from source with `build_exe.ps1`.

## Known limitation

The tool has not yet been validated against live cloud accounts. Do not rely on it as your only security control, and test it in a non-production account first.
