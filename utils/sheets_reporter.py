import json
import logging
from datetime import datetime
from pathlib import Path

import gspread
from google.oauth2.service_account import Credentials

from config.settings import settings

log = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

HEADER_ROW = [
    "Scan Date",
    "Service",
    "Key Type",
    "API Key (Masked)",
    "API Key (Full)",
    "Status",
    "Active?",
    "Confidence",
    "Repo",
    "File Path",
    "Line #",
    "Commit SHA",
    "Commit Date",
    "Commit Author",
    "Additional Info",
]


class SheetsReporter:
    def __init__(self):
        self.client = None
        self.spreadsheet = None
        self.worksheet = None

    def connect(self):
        creds_path = Path(settings.GOOGLE_CREDENTIALS_PATH)
        if not creds_path.exists():
            raise FileNotFoundError(
                f"Google credentials not found at {creds_path}. "
                "Download service account JSON from Google Cloud Console."
            )

        creds = Credentials.from_service_account_file(str(creds_path), scopes=SCOPES)
        self.client = gspread.authorize(creds)
        log.info("Connected to Google Sheets API")

    def _get_or_create_spreadsheet(self) -> gspread.Spreadsheet:
        sheet_name = settings.GOOGLE_SHEET_NAME
        try:
            self.spreadsheet = self.client.open(sheet_name)
            log.info(f"Opened existing spreadsheet: {sheet_name}")
        except gspread.SpreadsheetNotFound:
            self.spreadsheet = self.client.create(sheet_name)
            log.info(f"Created new spreadsheet: {sheet_name}")

            if settings.SHARE_WITH_EMAIL:
                self.spreadsheet.share(
                    settings.SHARE_WITH_EMAIL,
                    perm_type="user",
                    role="writer",
                )
                log.info(f"Shared spreadsheet with {settings.SHARE_WITH_EMAIL}")

        return self.spreadsheet

    def _setup_worksheet(self, scan_label: str = "") -> gspread.Worksheet:
        spreadsheet = self._get_or_create_spreadsheet()
        worksheet_title = scan_label or f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        try:
            self.worksheet = spreadsheet.add_worksheet(
                title=worksheet_title, rows=1000, cols=len(HEADER_ROW)
            )
        except gspread.exceptions.APIError:
            self.worksheet = spreadsheet.sheet1
            self.worksheet.update_title(worksheet_title)

        self.worksheet.update([HEADER_ROW], value_input_option="RAW")
        self._format_header()
        return self.worksheet

    def _format_header(self):
        self.worksheet.format("A1:O1", {
            "backgroundColor": {"red": 0.2, "green": 0.2, "blue": 0.2},
            "textFormat": {"foregroundColor": {"red": 1, "green": 1, "blue": 1}, "bold": True, "fontSize": 11},
            "horizontalAlignment": "CENTER",
        })
        self.worksheet.freeze(rows=1)

    def _mask_key(self, key: str) -> str:
        if len(key) <= 10:
            return key[:3] + "*" * (len(key) - 3)
        return key[:6] + "*" * (len(key) - 10) + key[-4:]

    def save_results(self, findings: list[dict], scan_label: str = ""):
        if not self.client:
            self.connect()

        self._setup_worksheet(scan_label)

        rows = []
        for f in findings:
            additional = f.get("additional_info", {})
            additional_str = json.dumps(additional) if additional else ""

            rows.append([
                f.get("scan_date", datetime.now().isoformat()),
                f.get("service", ""),
                f.get("key_type", ""),
                self._mask_key(f.get("key_value", "")),
                f.get("key_value", ""),
                f.get("status_detail", "Not tested"),
                "YES" if f.get("is_active") else "NO",
                f.get("confidence", ""),
                f.get("repo_name", ""),
                f.get("file_path", ""),
                f.get("line_number", ""),
                f.get("commit_sha", ""),
                f.get("commit_date", ""),
                f.get("commit_author", ""),
                additional_str,
            ])

        if rows:
            self.worksheet.append_rows(rows, value_input_option="RAW")
            self._apply_conditional_formatting()
            log.info(f"Saved {len(rows)} findings to Google Sheets")

        self._add_summary_sheet(findings)

        sheet_url = f"https://docs.google.com/spreadsheets/d/{self.spreadsheet.id}"
        log.info(f"Results saved: {sheet_url}")
        return sheet_url

    def _apply_conditional_formatting(self):
        try:
            all_data = self.worksheet.get_all_values()
            for row_idx, row in enumerate(all_data[1:], start=2):
                is_active = row[6] if len(row) > 6 else ""
                if is_active == "YES":
                    self.worksheet.format(f"G{row_idx}", {
                        "backgroundColor": {"red": 1, "green": 0.8, "blue": 0.8},
                        "textFormat": {"bold": True, "foregroundColor": {"red": 0.8, "green": 0, "blue": 0}},
                    })
                elif is_active == "NO":
                    self.worksheet.format(f"G{row_idx}", {
                        "backgroundColor": {"red": 0.85, "green": 0.95, "blue": 0.85},
                        "textFormat": {"foregroundColor": {"red": 0, "green": 0.5, "blue": 0}},
                    })
        except Exception as e:
            log.warning(f"Could not apply formatting: {e}")

    def _add_summary_sheet(self, findings: list[dict]):
        try:
            summary_ws = self.spreadsheet.add_worksheet(title="Summary", rows=50, cols=5)
        except gspread.exceptions.APIError:
            try:
                summary_ws = self.spreadsheet.worksheet("Summary")
                summary_ws.clear()
            except gspread.exceptions.WorksheetNotFound:
                return

        total = len(findings)
        active = sum(1 for f in findings if f.get("is_active"))
        inactive = sum(1 for f in findings if not f.get("is_active"))

        services = {}
        for f in findings:
            svc = f.get("service", "Unknown")
            services[svc] = services.get(svc, 0) + 1

        high_conf = sum(1 for f in findings if f.get("confidence") == "high")
        med_conf = sum(1 for f in findings if f.get("confidence") == "medium")

        summary_data = [
            ["SCAN SUMMARY", "", "", ""],
            ["", "", "", ""],
            ["Total Keys Found", str(total), "", ""],
            ["Active (WORKING) Keys", str(active), "", "CRITICAL - Rotate immediately!"],
            ["Inactive Keys", str(inactive), "", ""],
            ["High Confidence Matches", str(high_conf), "", ""],
            ["Medium Confidence Matches", str(med_conf), "", ""],
            ["", "", "", ""],
            ["BREAKDOWN BY SERVICE", "", "", ""],
        ]

        for svc, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
            active_for_svc = sum(1 for f in findings if f.get("service") == svc and f.get("is_active"))
            summary_data.append([svc, str(count), f"Active: {active_for_svc}", ""])

        summary_ws.update(summary_data, value_input_option="RAW")

        summary_ws.format("A1", {
            "textFormat": {"bold": True, "fontSize": 14},
        })
        summary_ws.format("A4", {
            "backgroundColor": {"red": 1, "green": 0.8, "blue": 0.8},
            "textFormat": {"bold": True},
        })
