# Contributing

Thanks for helping improve Cloud VM CIS, EOL & Patch Auditor. Bug reports, real-account test feedback, new checks and doc fixes are all welcome.

## The most useful contribution right now

The tool has only been tested with fake and stub data. If you can run it against a **non-production** AWS, Azure or GCP account, please:

1. Run **Check access** (GUI) or `--check-access` (CLI) and note any denied calls.
2. Run a scan and compare the findings with what the cloud console shows.
3. Open an issue with what differed (API errors, wrong values, missing VMs). Remove account IDs, VM names and IP addresses first.

## Development setup

Requires Python 3.10+ (the GUI also needs Tkinter).

```powershell
git clone https://github.com/3tternp/cloud-vm-cis-audit.git
cd cloud-vm-cis-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the tests (no cloud credentials or network needed):

```powershell
python tests/test_cloud.py
python tests/test_collectors.py
python tests/test_gui_model.py
```

CI runs the same tests plus a syntax check on Python 3.10, 3.12 and 3.13. Please make sure they pass before opening a pull request.

## Project layout

| Path | Purpose |
|---|---|
| `cloud_audit/checks.py` | Provider-neutral checks over a normalised VM dict |
| `cloud_audit/aws.py`, `azure.py`, `gcp.py` | Collectors: call the cloud APIs and normalise results |
| `cloud_audit/eol.py`, `data/os_eol.json` | Guest-OS end-of-support rules |
| `cloud_audit/guest/` | Opt-in in-guest scripts and output parser |
| `cloud_audit/access.py` | `--check-access` probes |
| `cloud_audit/gui.py`, `gui_model.py` | CustomTkinter GUI and its headless logic |
| `cloud_audit/report.py` | HTML / CSV / JSON export |
| `tests/` | Offline tests |

## Guidelines

### Keep it read-only
By default the tool must only make read-only API calls. Anything that runs code inside a VM (the in-guest scan) stays **opt-in**, behind an explicit confirmation, and must be documented with the extra permissions it needs. Never add code that changes cloud resources.

### Never handle secrets
Use the standard credential chains (AWS profile/SSO, `az login`, Application Default Credentials). Do not add fields that accept keys or passwords, and do not log credentials, account IDs or tokens.

### Be honest about uncertainty
If a value cannot be determined (no agent, no permission, API absent), report it as unknown/WARN with the fix, never as a pass. A "0 missing patches" result must mean it was actually measured.

## Adding or changing a check

1. If you need a new fact about the VM, add it to the collector for each provider and put it in the normalised VM dict (document the key in the docstring at the top of `checks.py`).
2. Add the check in `check_vm` in `cloud_audit/checks.py` with a stable ID (`CLD-0xx`), a clear title, the actual and expected values, and a remediation that tells the reader what to do.
3. Add tests: logic in `tests/test_cloud.py`, and API call sequencing against fake SDK objects in `tests/test_collectors.py`.
4. Update the checks table in `README.md` and add a line under **Unreleased** in `CHANGELOG.md`.

## Adding in-guest checks

Scripts live in `cloud_audit/guest/` and must stay **read-only** (a test rejects obvious mutating commands such as `rm -`, `sysctl -w`, `Set-ItemProperty`). Each script prints one `CIS|<id>|<PASS|FAIL|WARN|INFO>|<detail>` line per check. Add the ID's title and fix text to `TITLES` / `FIX` in `cloud_audit/guest/__init__.py`, and extend the parser test.

## Updating OS end-of-support data

Edit `cloud_audit/data/os_eol.json`: patterns are regular expressions matched in order (specific before general), dates are ISO `YYYY-MM-DD`, and the top-level `verified` date should be updated. Cite the vendor lifecycle page in your pull request. Users can also refresh the data themselves with `--update-eol`.

## GUI changes

Put filtering, sorting and aggregation logic in `gui_model.py` so it can be unit tested without a display. After visible changes, regenerate the demo screenshots (they use made-up data, never real environments):

```powershell
pip install pillow
python tools/make_screenshot.py
```

## Windows executable

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1     # -> dist\CloudVMAuditor.exe
```

If you add a dependency that is imported lazily (like the cloud SDKs), add it to `cloud_audit.spec` so PyInstaller bundles it. Releases are built by the `build-exe` workflow when a `v*` tag is pushed.

## Pull requests

- Keep each pull request focused on one change.
- Describe what changed and how you tested it. Say clearly if it has not run against a real cloud account.
- Update `README.md` and `CHANGELOG.md` when behaviour changes.
- Follow the existing code style: type hints where practical, short docstrings explaining *why*, no unused code.

## Reporting security issues

Please do **not** open a public issue for a vulnerability in this tool (for example, something that could expose credentials or run unintended commands in a VM). Use GitHub's private reporting on the repository's **Security** tab if it is enabled, or contact the maintainer directly.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
