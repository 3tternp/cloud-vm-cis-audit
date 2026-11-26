"""Cloud VM audit CLI:  python cloud_audit_cli.py --cloud aws|azure|gcp ..."""
import argparse
import sys

from cloud_audit import run_cloud_scan, report, eol


def main():
    ap = argparse.ArgumentParser(description="Read-only CIS-style audit of cloud VMs (config, guest OS EOL, patches)")
    ap.add_argument("--cloud", choices=["aws", "azure", "gcp"])
    ap.add_argument("--regions", help="AWS: comma separated regions")
    ap.add_argument("--profile", help="AWS: named profile")
    ap.add_argument("--subscription", help="Azure subscription id")
    ap.add_argument("--project", help="GCP project id")
    ap.add_argument("--out", default="cloud_audit", help="output file prefix (writes .html/.csv/.json)")
    ap.add_argument("--update-eol", action="store_true", help="refresh guest-OS EOL dates from endoflife.date and exit")
    ap.add_argument("--check-access", action="store_true", help="test which read-only APIs the current credentials can call, then exit")
    ap.add_argument("--guest-scan", action="store_true",
                    help="ALSO run bundled read-only scripts inside VMs (AWS SSM / Azure Run Command); asks for confirmation")
    ap.add_argument("--yes", action="store_true", help="skip the --guest-scan confirmation prompt")
    a = ap.parse_args()
    params = {"regions": a.regions, "profile": a.profile, "subscription_id": a.subscription, "project": a.project}

    if a.update_eol:
        n = eol.refresh_online(print)
        print(f"{n} rules written to {eol.USER_FILE}")
        return 0
    if not a.cloud:
        ap.error("--cloud is required")
    if a.check_access:
        from cloud_audit.access import run_access_check
        rows = run_access_check(a.cloud, params)
        for name, ok, detail in rows:
            print(f"[{'OK ' if ok else 'DENIED'}] {name}: {detail}")
        return 0 if all(ok for _, ok, _ in rows) else 1
    if a.guest_scan:
        print("--guest-scan will execute the read-only scripts in cloud_audit/guest/ inside your running VMs "
              "via the provider agent (AWS SSM Run Command / Azure Run Command). Review them first.")
        if not a.yes and input("Type 'yes' to continue: ").strip().lower() != "yes":
            print("Aborted.")
            return 1
        params["guest_scan"] = True
    age = eol.data_age_days()
    if age is not None and age > eol.STALE_DAYS:
        print(f"Note: OS EOL data is {age} days old; run with --update-eol to refresh it.")
    res, meta = run_cloud_scan(a.cloud, params, print)
    report.to_html(res, meta, a.out + ".html")
    report.to_csv(res, a.out + ".csv")
    report.to_json(res, meta, a.out + ".json")
    c, score = report.summarize(res)
    print(dict(c), f"score={score}%", "-> reports written to", a.out + ".*")
    return 0


if __name__ == "__main__":
    sys.exit(main())
