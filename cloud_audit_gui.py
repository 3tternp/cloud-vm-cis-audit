"""Launcher for the desktop GUI:  python cloud_audit_gui.py"""
import os
import sys

# A windowed (no console) PyInstaller build has no stdout/stderr; libraries that print would crash.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

from cloud_audit.gui import main  # noqa: E402

if __name__ == "__main__":
    main()
