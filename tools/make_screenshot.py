"""Render the GUI with DEMO data (made-up VMs, not a real environment) -> docs/screenshot*.png.
Requires Pillow and a desktop session (it grabs the real window)."""
import ctypes
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

from PIL import ImageGrab  # noqa: E402
from cloud_audit import checks, eol, guest  # noqa: E402
from cloud_audit.gui import App  # noqa: E402

eol.USER_FILE = eol.USER_FILE.with_name("does_not_exist.json")  # bundled data only, reproducible
VMS = [
    {"provider": "AWS", "id": "i-01", "name": "web-prod-01", "region": "eu-west-1", "os": "Ubuntu 18.04", "public_ip": True,
     "open_mgmt_ports": ["22"], "disk_encrypted": False, "imdsv2_required": False, "missing_critical": 4, "missing_other": 11,
     "patch_source": "SSM Patch Manager", "ssm_managed": True},
    {"provider": "AWS", "id": "i-02", "name": "db-prod-01", "region": "eu-west-1", "os": "Amazon Linux 2023", "public_ip": False,
     "open_mgmt_ports": [], "disk_encrypted": True, "imdsv2_required": True, "missing_critical": 0, "missing_other": 0,
     "patch_source": "SSM Patch Manager", "ssm_managed": True},
    {"provider": "AWS", "id": "i-03", "name": "batch-worker", "region": "us-east-1", "os": "Windows Server 2012 R2", "public_ip": False,
     "open_mgmt_ports": [], "disk_encrypted": True, "imdsv2_required": True, "ssm_managed": False},
    {"provider": "Azure", "id": "a1", "name": "app-win-01", "region": "westeurope", "os": "Windows Server 2019", "public_ip": True,
     "open_mgmt_ports": ["3389"], "no_nsg": False, "disk_encrypted": True, "disk_cmk": False, "secure_boot": True, "vtpm": False,
     "missing_critical": 1, "missing_other": 3, "patch_source": "Azure Update Manager"},
    {"provider": "GCP", "id": "g1", "name": "api-gateway", "region": "us-central1-a", "os": "debian-12-bookworm", "public_ip": True,
     "open_mgmt_ports": [], "disk_encrypted": True, "disk_cmk": True, "secure_boot": True, "vtpm": True, "integrity": True,
     "block_project_ssh_keys": True, "os_login": True, "serial_port_enabled": False, "default_sa_full_access": True},
]
results = checks.check_all(VMS, today=date(2026, 11, 26))
results += guest.parse_output("CIS|LIN-001|FAIL|PermitRootLogin=yes\nCIS|LIN-023|PASS|ASLR=2\nCIS|LIN-031|FAIL|6 pending security updates",
                              VMS[0])
meta = {"target": "demo (made-up data)", "type": "Demo cloud audit"}

app = App()
app.geometry("1380x860+30+30")
app.load_results(results, meta)
first = app.tree.get_children()[0]
app.tree.selection_set(first)
app._detail()
app.update()
app.after(900, app.quit)
app.mainloop()
x, y, w, h = app.winfo_rootx(), app.winfo_rooty(), app.winfo_width(), app.winfo_height()
out = ROOT / "docs"
out.mkdir(exist_ok=True)
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_dark.png")
app.mode_menu.set("Light")
app._set_mode("Light")
app.update()
app.after(900, app.quit)
app.mainloop()
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_light.png")
print("saved", sorted(p.name for p in out.glob("screenshot*")))
