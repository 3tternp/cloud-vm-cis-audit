"""Cloud VM audit CLI:  python cloud_audit_cli.py --cloud aws|azure|gcp ..."""
import argparse

from cloud_audit import run_cloud_scan, report


def main():
    ap = argparse.ArgumentParser(description="Read-only CIS-style audit of cloud VMs (config, guest OS EOL, patches)")
    ap.add_argument("--cloud", required=True, choices=["aws", "azure", "gcp"])
    ap.add_argument("--regions", help="AWS: comma separated regions")
    ap.add_argument("--profile", help="AWS: named profile")
    ap.add_argument("--subscription", help="Azure subscription id")
    ap.add_argument("--project", help="GCP project id")
    ap.add_argument("--out", default="cloud_audit", help="output file prefix (writes .html/.csv/.json)")
    a = ap.parse_args()
    res, meta = run_cloud_scan(a.cloud, {"regions": a.regions, "profile": a.profile,
                                         "subscription_id": a.subscription, "project": a.project}, print)
    report.to_html(res, meta, a.out + ".html")
    report.to_csv(res, a.out + ".csv")
    report.to_json(res, meta, a.out + ".json")
    c, score = report.summarize(res)
    print(dict(c), f"score={score}%", "-> reports written to", a.out + ".*")


if __name__ == "__main__":
    main()
