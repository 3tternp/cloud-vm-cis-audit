"""Modern desktop GUI (CustomTkinter) for the cloud VM auditor.

Layout: left control panel (provider, credentials source, options, actions) and a main area with
summary cards, a findings table with filters + remediation detail, a per-VM roll-up and a live log.
Credentials are never entered here: the tool uses your existing AWS / Azure / GCP login.
"""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from . import eol, gui_model as gm, report
from .models import STATUSES

ASSETS = Path(__file__).resolve().parent.parent / "assets"

STATUS_COLOR = {"FAIL": "#e5484d", "WARN": "#f5a524", "PASS": "#30a46c", "INFO": "#3e8ed0", "ERROR": "#8e4ec6", "MANUAL": "#8b8d98"}
ROW_DARK = {"FAIL": "#4a2326", "WARN": "#4a3a1b", "PASS": "#1d3a2b", "INFO": "#1c3550", "ERROR": "#3a2750", "MANUAL": "#33363b"}
ROW_LIGHT = {"FAIL": "#fde3e4", "WARN": "#fff0d4", "PASS": "#e0f4e9", "INFO": "#ddeafa", "ERROR": "#eddff9", "MANUAL": "#eceef1"}

PROVIDERS = {
    "AWS": [("profile", "AWS profile (optional)", "default"), ("regions", "Regions (comma separated)", "us-east-1,eu-west-1")],
    "Azure": [("subscription_id", "Subscription ID", "00000000-0000-0000-0000-000000000000")],
    "GCP": [("project", "Project ID", "my-project-id")],
}
LOGIN_HINT = {
    "AWS": "Uses your AWS profile / SSO / environment credentials.",
    "Azure": "Uses 'az login' (or environment / managed identity).",
    "GCP": "Uses 'gcloud auth application-default login'.",
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("Cloud VM Auditor - CIS, EOL & Patch")
        self.geometry("1380x860")
        self.minsize(1100, 700)
        self.q = queue.Queue()
        self.results, self.meta, self.worker = [], {}, None
        self._rows = {}
        self.fields = {}
        self._build_sidebar()
        self._build_main()
        self._style_tree()
        self._on_provider("AWS")
        self.after(150, self._set_icon)
        self.after(100, self._pump)

    # ------------------------------------------------------------------ chrome
    def _set_icon(self):
        try:
            if sys.platform == "win32":
                self.iconbitmap(str(ASSETS / "icon.ico"))
            else:
                self.iconphoto(True, tk.PhotoImage(file=str(ASSETS / "icon_64.png")))
        except Exception:
            pass

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=310, corner_radius=0)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)
        ctk.CTkLabel(sb, text="Cloud VM Auditor", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", padx=20, pady=(22, 0))
        ctk.CTkLabel(sb, text="CIS hardening · EOL · missing patches", text_color=("gray40", "gray65")).pack(anchor="w", padx=20, pady=(0, 18))

        ctk.CTkLabel(sb, text="PROVIDER", font=ctk.CTkFont(size=11, weight="bold"), text_color=("gray40", "gray65")).pack(anchor="w", padx=20)
        self.provider = ctk.CTkSegmentedButton(sb, values=list(PROVIDERS), command=self._on_provider)
        self.provider.pack(fill="x", padx=20, pady=(4, 12))
        self.provider.set("AWS")

        self.form = ctk.CTkFrame(sb, fg_color="transparent")
        self.form.pack(fill="x", padx=20)
        for prov, fields in PROVIDERS.items():
            for key, label, hint in fields:
                lab = ctk.CTkLabel(self.form, text=label, anchor="w")
                ent = ctk.CTkEntry(self.form, placeholder_text=hint)
                self.fields[(prov, key)] = (lab, ent)
        self.hint = ctk.CTkLabel(sb, text="", wraplength=260, justify="left", text_color=("gray40", "gray65"), font=ctk.CTkFont(size=12))
        self.hint.pack(anchor="w", padx=20, pady=(8, 10))

        ctk.CTkLabel(sb, text="OPTIONS", font=ctk.CTkFont(size=11, weight="bold"), text_color=("gray40", "gray65")).pack(anchor="w", padx=20, pady=(6, 2))
        self.guest = ctk.CTkCheckBox(sb, text="In-guest scan (opt-in)", command=self._guest_warn)
        self.guest.pack(anchor="w", padx=20, pady=4)
        ctk.CTkLabel(sb, text="Runs read-only scripts inside running VMs via SSM / Run Command. Needs more than read-only permissions.",
                     justify="left", anchor="w", wraplength=235, font=ctk.CTkFont(size=11),
                     text_color=("gray40", "gray65")).pack(anchor="w", padx=(46, 12))

        self.btn_run = ctk.CTkButton(sb, text="Run audit", height=40, font=ctk.CTkFont(size=15, weight="bold"), command=self.start)
        self.btn_run.pack(fill="x", padx=20, pady=(22, 8))
        self.btn_access = ctk.CTkButton(sb, text="Check access", height=34, fg_color="transparent", border_width=1,
                                        text_color=("gray10", "gray90"), command=self.check_access)
        self.btn_access.pack(fill="x", padx=20, pady=4)
        self.btn_eol = ctk.CTkButton(sb, text="Update EOL data", height=34, fg_color="transparent", border_width=1,
                                     text_color=("gray10", "gray90"), command=self.update_eol)
        self.btn_eol.pack(fill="x", padx=20, pady=4)

        bottom = ctk.CTkFrame(sb, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=16)
        ctk.CTkLabel(bottom, text="Appearance").pack(side="left")
        self.mode_menu = ctk.CTkOptionMenu(bottom, values=["Dark", "Light", "System"], width=110, command=self._set_mode)
        self.mode_menu.pack(side="right")

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(side="left", fill="both", expand=True, padx=(16, 16), pady=14)

        head = ctk.CTkFrame(main, fg_color="transparent")
        head.pack(fill="x")
        self.title_lbl = ctk.CTkLabel(head, text="No audit yet", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_lbl.pack(side="left")
        for kind in ("JSON", "CSV", "HTML"):
            ctk.CTkButton(head, text=f"Export {kind}", width=96, height=30, fg_color="transparent", border_width=1,
                          text_color=("gray10", "gray90"), command=lambda k=kind.lower(): self.export(k)).pack(side="right", padx=(6, 0))

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.pack(fill="x", pady=12)
        self.card = {}
        for i, (key, label, color) in enumerate((("vms", "VMs audited", None), ("FAIL", "Failed", STATUS_COLOR["FAIL"]),
                                                 ("WARN", "Warnings", STATUS_COLOR["WARN"]), ("PASS", "Passed", STATUS_COLOR["PASS"]),
                                                 ("score", "Compliance score", None))):
            f = ctk.CTkFrame(cards, corner_radius=12)
            f.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="nsew")
            cards.grid_columnconfigure(i, weight=1, uniform="c")
            v = ctk.CTkLabel(f, text="-", font=ctk.CTkFont(size=30, weight="bold"), text_color=color or ("gray10", "gray95"))
            v.pack(anchor="w", padx=16, pady=(12, 0))
            ctk.CTkLabel(f, text=label, text_color=("gray40", "gray65")).pack(anchor="w", padx=16, pady=(0, 12))
            self.card[key] = v
        self.score_bar = ctk.CTkProgressBar(main, height=8)
        self.score_bar.set(0)
        self.score_bar.pack(fill="x", pady=(0, 10))

        self.tabs = ctk.CTkTabview(main, anchor="w")
        self.tabs.pack(fill="both", expand=True)
        t_find, t_vm, t_log = (self.tabs.add(n) for n in ("Findings", "By VM", "Log"))

        # ---- findings
        bar = ctk.CTkFrame(t_find, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 8))
        self.f_status = ctk.CTkOptionMenu(bar, values=["ALL", *STATUSES], width=110, command=lambda _: self._refresh())
        self.f_status.pack(side="left")
        self.f_cat = ctk.CTkOptionMenu(bar, values=["ALL", "CIS", "EOL", "PATCH"], width=110, command=lambda _: self._refresh())
        self.f_cat.pack(side="left", padx=8)
        self.f_entry = ctk.CTkEntry(bar, placeholder_text="Search VM, check, value...", width=320)
        self.f_entry.pack(side="left")
        self.f_entry.bind("<KeyRelease>", lambda _e: self._refresh())
        self.count_lbl = ctk.CTkLabel(bar, text="", text_color=("gray40", "gray65"))
        self.count_lbl.pack(side="right")

        pane = ctk.CTkFrame(t_find, fg_color="transparent")
        pane.pack(fill="both", expand=True)
        self.tree = self._make_tree(pane, ("status", "type", "check", "target", "actual"),
                                    (80, 70, 330, 270, 330), ("Status", "Type", "Check", "VM", "Actual"))
        self.tree.bind("<<TreeviewSelect>>", self._detail)
        self.detail = ctk.CTkTextbox(t_find, height=130, wrap="word", font=ctk.CTkFont(size=13))
        self.detail.pack(fill="x", pady=(8, 0))
        self.detail.configure(state="disabled")

        # ---- by VM
        self.vm_tree = self._make_tree(t_vm, ("vm", "prov", "fail", "warn", "pass", "other"), (330, 80, 70, 70, 70, 70),
                                       ("VM", "Cloud", "Fail", "Warn", "Pass", "Other"))
        self.vm_tree.bind("<Double-1>", self._vm_drill)
        ctk.CTkLabel(t_vm, text="Double-click a VM to see only its findings.", text_color=("gray40", "gray65")).pack(anchor="w", pady=(6, 0))

        # ---- log
        self.log_box = ctk.CTkTextbox(t_log, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

        self.status = ctk.CTkLabel(main, text="Ready. No credentials are stored; your existing cloud login is used.", anchor="w",
                                   text_color=("gray40", "gray65"))
        self.status.pack(fill="x", pady=(8, 0))
        self.busy = ctk.CTkProgressBar(main, mode="indeterminate", height=4)

    def _make_tree(self, parent, cols, widths, heads):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse", style="Cloud.Treeview")
        for c, w, h in zip(cols, widths, heads):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w", stretch=(c in ("actual", "check", "vm")))
        sb = ctk.CTkScrollbar(wrap, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tree

    # ------------------------------------------------------------------ theming
    def _style_tree(self):
        dark = ctk.get_appearance_mode() == "Dark"
        bg, fg, head = ("#242424", "#e6e6e6", "#2f2f2f") if dark else ("#ffffff", "#1a1a1a", "#eceef1")
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("Cloud.Treeview", background=bg, fieldbackground=bg, foreground=fg, rowheight=30, borderwidth=0, font=("Segoe UI", 10))
        st.configure("Cloud.Treeview.Heading", background=head, foreground=fg, relief="flat", font=("Segoe UI", 10, "bold"))
        st.map("Cloud.Treeview", background=[("selected", "#1f6aa5")], foreground=[("selected", "#ffffff")])
        st.map("Cloud.Treeview.Heading", background=[("active", head)])
        rows = ROW_DARK if dark else ROW_LIGHT
        for s, col in rows.items():
            self.tree.tag_configure(s, background=col)

    def _set_mode(self, mode):
        ctk.set_appearance_mode(mode)
        self.after(80, self._style_tree)

    # ------------------------------------------------------------------ provider form
    def _on_provider(self, prov):
        for w in self.form.winfo_children():
            w.pack_forget()
        for (p, _key), (lab, ent) in self.fields.items():
            if p == prov:
                lab.pack(anchor="w", pady=(8, 0))
                ent.pack(fill="x", pady=(2, 0))
        self.hint.configure(text=LOGIN_HINT[prov])

    def _params(self):
        prov = self.provider.get()
        p = {k: ent.get().strip() for (pp, k), (_, ent) in self.fields.items() if pp == prov}
        p["guest_scan"] = bool(self.guest.get())
        return prov.lower(), p

    def _guest_warn(self):
        if self.guest.get() and not messagebox.askyesno(
                "In-guest scan",
                "This runs the read-only scripts in cloud_audit/guest/ INSIDE your running VMs through the provider agent "
                "(AWS SSM Run Command / Azure Run Command). GCP VMs are skipped.\n\nIt needs permissions beyond read-only "
                "and should be reviewed first.\n\nEnable it?"):
            self.guest.deselect()

    # ------------------------------------------------------------------ actions
    def log(self, msg):
        self.q.put(("log", msg))

    def _set_busy(self, on, text=""):
        for b in (self.btn_run, self.btn_access, self.btn_eol):
            b.configure(state="disabled" if on else "normal")
        if on:
            self.busy.pack(fill="x", pady=(4, 0))
            self.busy.start()
        else:
            self.busy.stop()
            self.busy.pack_forget()
        if text:
            self.status.configure(text=text)

    def _run_bg(self, label, fn, on_done):
        if self.worker and self.worker.is_alive():
            return
        self._set_busy(True, label)

        def work():
            try:
                self.q.put(("done", (on_done, fn())))
            except Exception as e:
                self.q.put(("error", f"{type(e).__name__}: {e}"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def start(self):
        prov, params = self._params()
        required = {"azure": "subscription_id", "gcp": "project"}.get(prov)
        if required and not params.get(required):
            messagebox.showwarning("Missing input", "Please fill in the " + ("Subscription ID" if prov == "azure" else "Project ID") + ".")
            return
        from . import run_cloud_scan
        self.log(f"--- {prov.upper()} audit started ---")
        self._run_bg(f"Auditing {prov.upper()} VMs ...", lambda: run_cloud_scan(prov, params, self.log), self._finish_scan)

    def check_access(self):
        prov, params = self._params()
        from .access import run_access_check

        def done(rows):
            lines = [f"{'OK     ' if ok else 'DENIED '} {name}" + ("" if ok else f"  -> {detail}") for name, ok, detail in rows]
            for ln in lines:
                self.log(ln)
            bad = sum(1 for _, ok, _ in rows if not ok)
            messagebox.showinfo("Access check", ("All required APIs are reachable.\n\n" if not bad else
                                                 f"{bad} API call(s) failed (optional ones may be fine).\n\n") + "\n".join(lines))
            self.status.configure(text="Access check complete.")
        self._run_bg("Checking API access ...", lambda: run_access_check(prov, params), done)

    def update_eol(self):
        def done(n):
            self.status.configure(text=f"OS EOL data refreshed ({n} rules).")
            messagebox.showinfo("EOL data", f"{n} rules saved to {eol.USER_FILE}")
        self._run_bg("Fetching EOL data from endoflife.date ...", lambda: eol.refresh_online(self.log), done)

    def _finish_scan(self, res):
        self.load_results(*res)
        self.status.configure(text=f"Audit complete: {len(self.results)} checks.")

    def load_results(self, results, meta):
        self.results, self.meta = results, meta
        c, score, vms = gm.summary(results)
        self.title_lbl.configure(text=f"{meta.get('type', 'Audit')}  ·  {meta.get('target', '')}")
        self.card["vms"].configure(text=str(vms))
        for k in ("FAIL", "WARN", "PASS"):
            self.card[k].configure(text=str(c.get(k, 0)))
        self.card["score"].configure(text=f"{score}%", text_color=STATUS_COLOR["PASS"] if score >= 80 else
                                     STATUS_COLOR["WARN"] if score >= 50 else STATUS_COLOR["FAIL"])
        self.score_bar.set(score / 100)
        self._refresh()
        self.vm_tree.delete(*self.vm_tree.get_children())
        for r in gm.by_vm(results):
            self.vm_tree.insert("", "end", values=(r["vm"], r["provider"], r["fail"], r["warn"], r["pass"], r["other"]))

    # ------------------------------------------------------------------ tables
    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        rows = gm.filter_results(self.results, self.f_status.get(), self.f_cat.get(), self.f_entry.get())
        for r in rows:
            iid = self.tree.insert("", "end", values=(r.status, r.category, r.title, r.target, str(r.actual)[:160]), tags=(r.status,))
            self._rows[iid] = r
        self.count_lbl.configure(text=f"{len(rows)} of {len(self.results)} findings")
        self._style_tree()

    def _detail(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self._rows[sel[0]]
        txt = (f"[{r.status}] {r.title}\nVM: {r.target}    Check: {r.check_id}    Profile: {r.level or '-'}\n"
               f"Actual:   {r.actual}\nExpected: {r.expected}\n\nHow to fix:\n{r.remediation or 'Nothing to fix.'}")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", txt)
        self.detail.configure(state="disabled")

    def _vm_drill(self, _evt=None):
        sel = self.vm_tree.selection()
        if sel:
            self.f_entry.delete(0, "end")
            self.f_entry.insert(0, self.vm_tree.item(sel[0], "values")[0])
            self.f_status.set("ALL")
            self.tabs.set("Findings")
            self._refresh()

    # ------------------------------------------------------------------ export / queue
    def export(self, kind):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run an audit first.")
            return
        p = filedialog.asksaveasfilename(defaultextension="." + kind, initialfile=f"cloud_audit.{kind}", filetypes=[(kind.upper(), "*." + kind)])
        if not p:
            return
        {"html": lambda: report.to_html(self.results, self.meta, p), "csv": lambda: report.to_csv(self.results, p),
         "json": lambda: report.to_json(self.results, self.meta, p)}[kind]()
        self.status.configure(text=f"Exported {p}")

    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log_box.configure(state="normal")
                    self.log_box.insert("end", payload + "\n")
                    self.log_box.see("end")
                    self.log_box.configure(state="disabled")
                elif kind == "done":
                    self._set_busy(False)
                    cb, value = payload
                    cb(value)
                elif kind == "error":
                    self._set_busy(False, "Failed - see Log tab.")
                    self.log(payload)
                    messagebox.showerror("Operation failed", payload)
        except queue.Empty:
            pass
        self.after(100, self._pump)


def main():
    App().mainloop()
