import logging
from datetime import datetime

from scanners.github_scanner import GitHubScanner, KeyFinding
from testers.key_tester import KeyTester, TestResult
from utils.sheets_reporter import SheetsReporter
from tqdm import tqdm

log = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, include_low_confidence: bool = False, test_keys: bool = True, save_to_sheets: bool = True):
        self.scanner = GitHubScanner(include_low_confidence=include_low_confidence)
        self.tester = KeyTester() if test_keys else None
        self.reporter = SheetsReporter() if save_to_sheets else None
        self.test_keys = test_keys
        self.save_to_sheets = save_to_sheets

    def scan_user(self, username: str, max_repos: int = 0) -> dict:
        log.info(f"Starting scan for GitHub user: {username}")
        findings = self.scanner.scan_user(username, max_repos)
        return self._process_findings(findings, scan_label=f"User_{username}")

    def scan_urls(self, urls: list[str]) -> dict:
        log.info(f"Starting scan for {len(urls)} repo URLs")
        findings = self.scanner.scan_repo_urls(urls)
        return self._process_findings(findings, scan_label="URL_Scan")

    def scan_single_url(self, url: str) -> dict:
        log.info(f"Starting scan for repo: {url}")
        findings = self.scanner.scan_repo_url(url)
        repo_name = url.rstrip("/").split("/")[-1]
        return self._process_findings(findings, scan_label=f"Repo_{repo_name}")

    def _process_findings(self, findings: list[KeyFinding], scan_label: str) -> dict:
        log.info(f"Scan complete. Found {len(findings)} potential keys.")

        findings = self._deduplicate_findings(findings)
        results = []

        if findings and self.test_keys:
            log.info("Testing discovered keys...")
            for finding in tqdm(findings, desc="Testing keys", unit="key"):
                test_result = self.tester.test_key(
                    finding.key_value, finding.service, finding.key_type
                )
                results.append(self._merge_finding_and_result(finding, test_result))
        else:
            for finding in findings:
                results.append(self._finding_to_dict(finding))

        active_count = sum(1 for r in results if r.get("is_active"))
        inactive_count = sum(1 for r in results if not r.get("is_active"))

        log.info(f"Results: {len(results)} keys found | {active_count} ACTIVE | {inactive_count} inactive")

        if active_count > 0:
            log.warning(f"ALERT: {active_count} ACTIVE API keys found! These should be rotated immediately.")

        return {
            "total_findings": len(results),
            "active_keys": active_count,
            "inactive_keys": inactive_count,
            "sheet_url": "",
            "findings": results,
        }

    def save_all_to_sheets(self, all_results: list[dict], scan_label: str = "") -> str:
        if not self.reporter or not all_results:
            return ""
        try:
            label = scan_label or f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            sheet_url = self.reporter.save_results(all_results, label)
            log.info(f"All results saved to Google Sheets: {sheet_url}")
            return sheet_url
        except Exception as e:
            log.error(f"Failed to save to Google Sheets: {e}")
            return ""

    def _merge_finding_and_result(self, finding: KeyFinding, test_result: TestResult) -> dict:
        return {
            "scan_date": finding.found_at,
            "service": finding.service,
            "key_type": finding.key_type,
            "key_value": finding.key_value,
            "confidence": finding.confidence,
            "description": finding.description,
            "repo_name": finding.repo_name,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "commit_sha": finding.commit_sha,
            "commit_date": finding.commit_date,
            "commit_author": finding.commit_author,
            "is_active": test_result.is_active,
            "status_detail": test_result.status_detail,
            "additional_info": test_result.additional_info,
        }

    def _finding_to_dict(self, finding: KeyFinding) -> dict:
        return {
            "scan_date": finding.found_at,
            "service": finding.service,
            "key_type": finding.key_type,
            "key_value": finding.key_value,
            "confidence": finding.confidence,
            "description": finding.description,
            "repo_name": finding.repo_name,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "commit_sha": finding.commit_sha,
            "commit_date": finding.commit_date,
            "commit_author": finding.commit_author,
            "is_active": False,
            "status_detail": "Not tested",
            "additional_info": {},
        }

    def _deduplicate_findings(self, findings: list[KeyFinding]) -> list[KeyFinding]:
        seen: dict[str, KeyFinding] = {}
        for finding in findings:
            key = finding.key_value
            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                if self._confidence_rank(finding.confidence) > self._confidence_rank(existing.confidence):
                    seen[key] = finding
                elif finding.service != "Unknown" and existing.service == "Unknown":
                    seen[key] = finding

        deduped = list(seen.values())
        removed = len(findings) - len(deduped)
        if removed > 0:
            log.info(f"Deduplication removed {removed} duplicate findings")
        return deduped

    @staticmethod
    def _confidence_rank(confidence: str) -> int:
        return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)
