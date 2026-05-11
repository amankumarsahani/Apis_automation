import json
import logging
import time
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

WRITE_BATCH_SIZE = 500
RATE_LIMIT_PAUSE = 5


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
            log.warning(f"Spreadsheet '{sheet_name}' not found. Attempting to create...")
            try:
                self.spreadsheet = self.client.create(sheet_name)
                log.info(f"Created new spreadsheet: {sheet_name}")
                if settings.SHARE_WITH_EMAIL:
                    self.spreadsheet.share(
                        settings.SHARE_WITH_EMAIL,
                        perm_type="user",
                        role="writer",
                    )
                    log.info(f"Shared spreadsheet with {settings.SHARE_WITH_EMAIL}")
            except gspread.exceptions.APIError as e:
                log.error(f"Cannot create spreadsheet: {e}")
                log.error(
                    "Fix: Manually create a Google Sheet named "
                    f"'{sheet_name}' and share it with the service account email as Editor."
                )
                raise

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
            self._batch_append_rows(rows)
            self._apply_conditional_formatting_rules()
            log.info(f"Saved {len(rows)} findings to Google Sheets")

        time.sleep(RATE_LIMIT_PAUSE)
        self._add_summary_sheet(findings)

        sheet_url = f"https://docs.google.com/spreadsheets/d/{self.spreadsheet.id}"
        log.info(f"Results saved: {sheet_url}")
        return sheet_url

    def _batch_append_rows(self, rows: list):
        for i in range(0, len(rows), WRITE_BATCH_SIZE):
            batch = rows[i:i + WRITE_BATCH_SIZE]
            self.worksheet.append_rows(batch, value_input_option="RAW")
            if i + WRITE_BATCH_SIZE < len(rows):
                log.info(f"  Wrote {i + len(batch)}/{len(rows)} rows, pausing for rate limit...")
                time.sleep(RATE_LIMIT_PAUSE)

    def _apply_conditional_formatting_rules(self):
        """Use a single batch_update with conditional formatting rules instead of per-row API calls."""
        try:
            sheet_id = self.worksheet.id
            requests = [
                {
                    "addConditionalFormatRule": {
                        "rule": {
                            "ranges": [{"sheetId": sheet_id, "startRowIndex": 1, "startColumnIndex": 6, "endColumnIndex": 7}],
                            "booleanRule": {
                                "condition": {"type": "TEXT_EQ", "values": [{"userEnteredValue": "YES"}]},
                                "format": {
                                    "backgroundColor": {"red": 1, "green": 0.8, "blue": 0.8},
                                    "textFormat": {"bold": True, "foregroundColor": {"red": 0.8, "green": 0, "blue": 0}},
                                },
                            },
                        },
                        "index": 0,
                    }
                },
                {
                    "addConditionalFormatRule": {
                        "rule": {
                            "ranges": [{"sheetId": sheet_id, "startRowIndex": 1, "startColumnIndex": 6, "endColumnIndex": 7}],
                            "booleanRule": {
                                "condition": {"type": "TEXT_EQ", "values": [{"userEnteredValue": "NO"}]},
                                "format": {
                                    "backgroundColor": {"red": 0.85, "green": 0.95, "blue": 0.85},
                                    "textFormat": {"foregroundColor": {"red": 0, "green": 0.5, "blue": 0}},
                                },
                            },
                        },
                        "index": 1,
                    }
                },
            ]
            self.spreadsheet.batch_update({"requests": requests})
        except Exception as e:
            log.warning(f"Could not apply formatting rules: {e}")

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

        try:
            summary_ws.format("A1", {
                "textFormat": {"bold": True, "fontSize": 14},
            })
            summary_ws.format("A4", {
                "backgroundColor": {"red": 1, "green": 0.8, "blue": 0.8},
                "textFormat": {"bold": True},
            })
        except Exception as e:
            log.warning(f"Could not format summary: {e}")
