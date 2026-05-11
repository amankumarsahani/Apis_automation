#!/usr/bin/env python3
import argparse
import sys
import json
import logging

from config.settings import settings
from orchestrator import ScanOrchestrator
from utils.logger import setup_logging

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyscanner",
        description="Scan GitHub repos for leaked API keys, test them, and save results to Google Sheets.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Scan mode")

    user_parser = subparsers.add_parser("scan-user", help="Scan all repos of a GitHub user/org")
    user_parser.add_argument("username", help="GitHub username or organization")
    user_parser.add_argument("--max-repos", type=int, default=0, help="Max repos to scan (0 = all)")

    repo_parser = subparsers.add_parser("scan-repo", help="Scan a specific GitHub repo")
    repo_parser.add_argument("url", help="GitHub repo URL")

    repos_parser = subparsers.add_parser("scan-repos", help="Scan multiple GitHub repos from a file")
    repos_parser.add_argument("file", help="Text file with one repo URL per line")

    discover_parser = subparsers.add_parser("scan-discover", help="Auto-discover and scan targets (full automation)")
    discover_parser.add_argument("--max-per-method", type=int, default=50, help="Max repos per discovery method")
    discover_parser.add_argument("--orgs", type=str, default="", help="Comma-separated org names to scan members")
    discover_parser.add_argument("--no-email", action="store_true", help="Skip email alerts")

    for sub in [user_parser, repo_parser, repos_parser, discover_parser]:
        sub.add_argument("--no-test", action="store_true", help="Skip key validation testing")
        sub.add_argument("--no-sheets", action="store_true", help="Skip saving to Google Sheets (print only)")
        sub.add_argument("--include-low", action="store_true", help="Include low-confidence pattern matches")
        sub.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
        sub.add_argument("--json", action="store_true", dest="json_output", help="Output results as JSON")

    return parser


def print_results_table(results: dict):
    from tabulate import tabulate
    from colorama import Fore, Style

    findings = results.get("findings", [])
    if not findings:
        print(f"\n{Fore.GREEN}No API keys found.{Style.RESET_ALL}")
        return

    print(f"\n{'=' * 80}")
    print(f"  SCAN RESULTS")
    print(f"{'=' * 80}")
    print(f"  Total keys found:  {results['total_findings']}")
    print(f"  {Fore.RED}Active (WORKING):  {results['active_keys']}{Style.RESET_ALL}")
    print(f"  Inactive:          {results['inactive_keys']}")
    if results.get("sheet_url"):
        print(f"  Google Sheet:      {results['sheet_url']}")
    print(f"{'=' * 80}\n")

    table_data = []
    for f in findings:
        key_masked = f["key_value"][:6] + "..." + f["key_value"][-4:] if len(f["key_value"]) > 14 else f["key_value"]
        status_color = Fore.RED if f["is_active"] else Fore.GREEN
        active_label = f"{status_color}ACTIVE{Style.RESET_ALL}" if f["is_active"] else f"{status_color}INACTIVE{Style.RESET_ALL}"

        table_data.append([
            f["service"],
            f["key_type"],
            key_masked,
            active_label,
            f["confidence"],
            f["repo_name"],
            f"{f['file_path']}:{f['line_number']}",
        ])

    headers = ["Service", "Type", "Key (Masked)", "Status", "Confidence", "Repo", "Location"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    active_findings = [f for f in findings if f["is_active"]]
    if active_findings:
        print(f"\n{Fore.RED}{'!' * 60}")
        print(f"  WARNING: {len(active_findings)} ACTIVE keys found!")
        print(f"  These keys are currently working and should be ROTATED IMMEDIATELY.")
        print(f"{'!' * 60}{Style.RESET_ALL}\n")
        for af in active_findings:
            print(f"  {Fore.RED}[{af['service']}]{Style.RESET_ALL} {af['key_type']}")
            print(f"    Repo: {af['repo_name']}")
            print(f"    File: {af['file_path']}:{af['line_number']}")
            print(f"    Status: {af['status_detail']}")
            if af.get("additional_info"):
                for k, v in af["additional_info"].items():
                    print(f"    {k}: {v}")
            print()


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    setup_logging(verbose=getattr(args, "verbose", False))

    errors = settings.validate()
    skip_sheets = getattr(args, "no_sheets", False)
    if errors:
        for err in errors:
            if "Google credentials" in err and skip_sheets:
                continue
            log.error(err)
        if any("GITHUB_TOKEN" in e for e in errors):
            sys.exit(1)

    orchestrator = ScanOrchestrator(
        include_low_confidence=getattr(args, "include_low", False),
        test_keys=not getattr(args, "no_test", False),
        save_to_sheets=not skip_sheets,
    )

    if args.command == "scan-user":
        results = orchestrator.scan_user(args.username, getattr(args, "max_repos", 0))
        if not skip_sheets and results.get("findings"):
            results["sheet_url"] = orchestrator.save_all_to_sheets(results["findings"], f"User_{args.username}")
    elif args.command == "scan-repo":
        results = orchestrator.scan_single_url(args.url)
        if not skip_sheets and results.get("findings"):
            repo_name = args.url.rstrip("/").split("/")[-1]
            results["sheet_url"] = orchestrator.save_all_to_sheets(results["findings"], f"Repo_{repo_name}")
    elif args.command == "scan-repos":
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = orchestrator.scan_urls(urls)
        if not skip_sheets and results.get("findings"):
            results["sheet_url"] = orchestrator.save_all_to_sheets(results["findings"], "URL_Scan")
    elif args.command == "scan-discover":
        from run_automated import run_automated_scan
        results = run_automated_scan(
            max_repos_per_method=getattr(args, "max_per_method", 50),
            save_to_sheets=not skip_sheets,
            send_email=not getattr(args, "no_email", False),
        )
    else:
        parser.print_help()
        sys.exit(1)

    if getattr(args, "json_output", False):
        safe_results = {k: v for k, v in results.items() if k != "findings"}
        safe_results["findings"] = [
            {k: v for k, v in f.items() if k != "key_value"} for f in results.get("findings", [])
        ]
        print(json.dumps(safe_results, indent=2, default=str))
    else:
        print_results_table(results)


if __name__ == "__main__":
    main()
