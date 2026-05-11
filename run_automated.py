#!/usr/bin/env python3
"""
Automated scan runner for GitHub Actions.
Discovers targets → scans → tests → reports to Sheets → emails alerts.
"""
import argparse
import json
import logging
import sys
from datetime import datetime

from config.settings import settings
from scanners.discovery import TargetDiscovery
from orchestrator import ScanOrchestrator
from utils.email_alerter import EmailAlerter
from utils.scan_history import ScanHistory
from utils.logger import setup_logging

log = logging.getLogger(__name__)


def run_automated_scan(
    max_repos_per_method: int = 50,
    save_to_sheets: bool = True,
    send_email: bool = True,
) -> dict:
    setup_logging(verbose=True)

    if not settings.GITHUB_TOKEN:
        log.error("GITHUB_TOKEN is required. Set it in .env or as environment variable.")
        sys.exit(1)

    log.info("=" * 60)
    log.info("AUTOMATED API KEY SCANNER - Starting")
    log.info(f"Time: {datetime.now().isoformat()}")
    log.info("=" * 60)

    history = ScanHistory()
    log.info(f"Scan history: {history.get_stats()}")

    discovery = TargetDiscovery(scan_history=history)

    orgs = []
    if settings.DISCOVERY_ORGS:
        orgs = [o.strip() for o in settings.DISCOVERY_ORGS.split(",") if o.strip()]

    targets = discovery.discover_all(
        max_repos_per_method=max_repos_per_method,
        orgs=orgs if orgs else None,
    )

    log.info(f"Discovered {targets['total_repos']} repos and {targets['total_users']} users")

    if targets["total_repos"] == 0 and targets["total_users"] == 0:
        log.warning("No targets discovered. Exiting.")
        return {"total_findings": 0, "active_keys": 0, "inactive_keys": 0, "findings": []}

    orchestrator = ScanOrchestrator(
        include_low_confidence=False,
        test_keys=True,
        save_to_sheets=save_to_sheets,
    )

    all_findings = []
    all_active = 0
    all_inactive = 0
    sheet_url = ""

    if targets["repos"]:
        log.info(f"Scanning {len(targets['repos'])} discovered repos...")
        repo_urls = [f"https://github.com/{repo}" for repo in targets["repos"]]

        batch_size = 10
        for i in range(0, len(repo_urls), batch_size):
            batch = repo_urls[i:i + batch_size]
            batch_names = targets["repos"][i:i + batch_size]
            log.info(f"Batch {i // batch_size + 1}: scanning {len(batch)} repos...")
            try:
                result = orchestrator.scan_urls(batch)
                batch_findings = result.get("findings", [])
                all_findings.extend(batch_findings)
                all_active += result.get("active_keys", 0)
                all_inactive += result.get("inactive_keys", 0)
                for repo_name in batch_names:
                    findings_for_repo = sum(1 for f in batch_findings if repo_name in f.get("repo_name", ""))
                    history.record_repo_scan(repo_name, findings_for_repo)
            except Exception as e:
                log.error(f"Batch scan failed: {e}")
            finally:
                orchestrator.scanner.clear_findings()

    if targets["users"]:
        log.info(f"Scanning repos for {len(targets['users'])} discovered users...")
        for username in targets["users"]:
            try:
                result = orchestrator.scan_user(username, max_repos=20)
                user_findings = result.get("findings", [])
                all_findings.extend(user_findings)
                all_active += result.get("active_keys", 0)
                all_inactive += result.get("inactive_keys", 0)
                history.record_user_scan(username, len(user_findings))
            except Exception as e:
                log.error(f"User scan failed for {username}: {e}")
            finally:
                orchestrator.scanner.clear_findings()

    history.save()

    if all_findings and save_to_sheets:
        sheet_url = orchestrator.save_all_to_sheets(all_findings, scan_label=f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    combined_results = {
        "total_findings": len(all_findings),
        "active_keys": all_active,
        "inactive_keys": all_inactive,
        "sheet_url": sheet_url,
        "findings": all_findings,
        "discovery_info": targets,
        "scan_time": datetime.now().isoformat(),
    }

    results_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    serializable = {**combined_results, "findings": combined_results["findings"][:500]}
    with open(results_file, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    log.info(f"Results saved to {results_file}")

    if send_email:
        alerter = EmailAlerter()
        if all_active > 0:
            alerter.send_alert(combined_results)
        else:
            alerter.send_summary(combined_results)

    log.info("=" * 60)
    log.info(f"SCAN COMPLETE: {len(all_findings)} keys found, {all_active} ACTIVE")
    log.info("=" * 60)

    return combined_results


def main():
    parser = argparse.ArgumentParser(description="Run automated API key discovery and scanning")
    parser.add_argument("--max-repos-per-method", type=int, default=50)
    parser.add_argument("--no-sheets", action="store_true")
    parser.add_argument("--no-email", action="store_true")
    args = parser.parse_args()

    run_automated_scan(
        max_repos_per_method=args.max_repos_per_method,
        save_to_sheets=not args.no_sheets,
        send_email=not args.no_email,
    )


if __name__ == "__main__":
    main()
