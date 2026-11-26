# PyInstaller spec: python -m PyInstaller cloud_audit.spec --noconfirm
# Produces dist/CloudVMAuditor.exe (single file, windowed). The cloud SDKs are imported lazily by the app,
# so they are collected explicitly below.
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

datas = [
    ("cloud_audit/data", "cloud_audit/data"),
    ("cloud_audit/guest/linux_audit.sh", "cloud_audit/guest"),
    ("cloud_audit/guest/windows_audit.ps1", "cloud_audit/guest"),
    ("assets", "assets"),
]
binaries, hiddenimports = [], []
datas += collect_data_files("customtkinter")

for pkg in ("boto3", "botocore", "azure.identity", "azure.mgmt.compute", "azure.mgmt.network", "azure.core",
            "google.cloud.compute_v1", "google.cloud.osconfig_v1", "google.api_core", "google.auth"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as e:  # SDK missing at build time -> that provider will report a clear error at runtime
        print(f"WARNING: could not collect {pkg}: {e}")

hiddenimports += collect_submodules("cloud_audit")

a = Analysis(
    ["cloud_audit_gui.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["pyVmomi", "pyVim", "matplotlib", "numpy", "pandas", "scipy", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="CloudVMAuditor",
    icon="assets/icon.ico",
    console=False,
    upx=False,
    disable_windowed_traceback=False,
)
