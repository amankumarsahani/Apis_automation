"""
Email alerter for notifying when active API keys are found.
Uses Gmail SMTP with app password authentication.
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


class EmailAlerter:
    """Send email alerts when active API keys are discovered."""

    def __init__(
        self,
        smtp_host: str = "",
        smtp_port: int = 0,
        sender_email: str = "",
        sender_password: str = "",
        recipient_email: str = "",
    ):
        self.smtp_host = smtp_host or settings.SMTP_HOST
        self.smtp_port = smtp_port or settings.SMTP_PORT
        self.sender_email = sender_email or settings.SMTP_EMAIL
        self.sender_password = sender_password or settings.SMTP_PASSWORD
        self.recipient_email = recipient_email or settings.ALERT_EMAIL

    def send_alert(self, scan_results: dict) -> bool:
        """Send email alert with scan results summary.

        Args:
            scan_results: Dict with keys: total_findings, active_keys, inactive_keys, findings, sheet_url

        Returns:
            True if email sent successfully, False otherwise.
        """
        active_keys = scan_results.get("active_keys", 0)

        if active_keys == 0:
            log.info("No active keys found. Skipping email alert.")
            return False

        if not self._validate_config():
            log.warning("Email configuration incomplete. Cannot send alert.")
            return False

        subject = f"🚨 ALERT: {active_keys} Active API Keys Found - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        html_body = self._build_html_body(scan_results)

        return self._send_email(subject, html_body)

    def send_summary(self, scan_results: dict) -> bool:
        """Send daily summary even if no active keys found."""
        if not self._validate_config():
            log.warning("Email configuration incomplete. Cannot send summary.")
            return False

        total = scan_results.get("total_findings", 0)
        active = scan_results.get("active_keys", 0)

        subject = f"📊 Daily Scan Summary: {total} keys found, {active} active - {datetime.now().strftime('%Y-%m-%d')}"
        html_body = self._build_summary_html(scan_results)

        return self._send_email(subject, html_body)

    def _validate_config(self) -> bool:
        """Check all required SMTP settings are present."""
        required = [self.smtp_host, self.smtp_port, self.sender_email, self.sender_password, self.recipient_email]
        return all(required)

    def _send_email(self, subject: str, html_body: str) -> bool:
        """Send an HTML email via Gmail SMTP."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender_email
            msg["To"] = self.recipient_email

            html_part = MIMEText(html_body, "html")
            msg.attach(html_part)

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.recipient_email, msg.as_string())

            log.info(f"Alert email sent to {self.recipient_email}")
            return True

        except smtplib.SMTPAuthenticationError:
            log.error(
                "SMTP authentication failed. For Gmail, use an App Password: "
                "https://myaccount.google.com/apppasswords"
            )
            return False
        except Exception as e:
            log.error(f"Failed to send email: {e}")
            return False

    def _build_html_body(self, scan_results: dict) -> str:
        """Build HTML email body with active key details."""
        active_keys = scan_results.get("active_keys", 0)
        total = scan_results.get("total_findings", 0)
        findings = scan_results.get("findings", [])
        sheet_url = scan_results.get("sheet_url", "")

        active_findings = [f for f in findings if f.get("is_active")]

        rows_html = ""
        for f in active_findings[:50]:  # Limit to 50 in email
            key_masked = f["key_value"][:6] + "****" + f["key_value"][-4:] if len(f["key_value"]) > 14 else "****"
            rows_html += f"""
            <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 8px;">{f.get('service', 'Unknown')}</td>
                <td style="padding: 8px;">{f.get('key_type', 'Unknown')}</td>
                <td style="padding: 8px; font-family: monospace; font-size: 12px;">{key_masked}</td>
                <td style="padding: 8px;">{f.get('repo_name', 'N/A')}</td>
                <td style="padding: 8px; font-size: 11px;">{f.get('file_path', 'N/A')}</td>
                <td style="padding: 8px;">{f.get('confidence', 'N/A')}</td>
            </tr>
            """

        sheet_link = ""
        if sheet_url:
            sheet_link = f'<p><a href="{sheet_url}" style="color: #1a73e8;">📄 View Full Results in Google Sheets</a></p>'

        html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
            <div style="background: #d32f2f; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 22px;">🚨 Active API Keys Detected</h1>
                <p style="margin: 5px 0 0; opacity: 0.9;">Automated scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>

            <div style="background: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 0 0 8px 8px;">
                <div style="display: flex; gap: 20px; margin-bottom: 20px;">
                    <div style="background: #ffebee; padding: 15px; border-radius: 8px; flex: 1;">
                        <div style="font-size: 28px; font-weight: bold; color: #d32f2f;">{active_keys}</div>
                        <div style="font-size: 12px; color: #666;">ACTIVE KEYS</div>
                    </div>
                    <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; flex: 1;">
                        <div style="font-size: 28px; font-weight: bold; color: #333;">{total}</div>
                        <div style="font-size: 12px; color: #666;">TOTAL FOUND</div>
                    </div>
                </div>

                <h2 style="font-size: 16px; border-bottom: 2px solid #d32f2f; padding-bottom: 8px;">Active Keys Details</h2>

                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="background: #f5f5f5;">
                            <th style="padding: 8px; text-align: left;">Service</th>
                            <th style="padding: 8px; text-align: left;">Type</th>
                            <th style="padding: 8px; text-align: left;">Key (Masked)</th>
                            <th style="padding: 8px; text-align: left;">Repo</th>
                            <th style="padding: 8px; text-align: left;">File</th>
                            <th style="padding: 8px; text-align: left;">Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>

                {sheet_link}

                <p style="font-size: 11px; color: #999; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px;">
                    This is an automated alert from API Key Scanner. Keys shown are masked for security.
                    Full details are available in the Google Sheet.
                </p>
            </div>
        </body>
        </html>
        """
        return html

    def _build_summary_html(self, scan_results: dict) -> str:
        """Build HTML email for daily summary (no active keys)."""
        total = scan_results.get("total_findings", 0)
        active = scan_results.get("active_keys", 0)
        inactive = scan_results.get("inactive_keys", 0)
        sheet_url = scan_results.get("sheet_url", "")
        discovery_info = scan_results.get("discovery_info", {})

        methods_used = discovery_info.get("methods_used", [])
        repos_scanned = discovery_info.get("total_repos", 0)
        users_scanned = discovery_info.get("total_users", 0)

        sheet_link = ""
        if sheet_url:
            sheet_link = f'<p><a href="{sheet_url}" style="color: #1a73e8;">📄 View Full Results</a></p>'

        status_color = "#4caf50" if active == 0 else "#d32f2f"
        status_text = "All Clear" if active == 0 else f"{active} Active Keys Found!"

        html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: {status_color}; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 20px;">📊 Daily Scan Summary</h1>
                <p style="margin: 5px 0 0; opacity: 0.9;">{status_text} — {datetime.now().strftime('%Y-%m-%d')}</p>
            </div>

            <div style="background: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 0 0 8px 8px;">
                <h3 style="margin-top: 0;">Scan Statistics</h3>
                <table style="width: 100%; font-size: 14px;">
                    <tr><td style="padding: 4px 0; color: #666;">Repos scanned:</td><td style="font-weight: bold;">{repos_scanned}</td></tr>
                    <tr><td style="padding: 4px 0; color: #666;">Users scanned:</td><td style="font-weight: bold;">{users_scanned}</td></tr>
                    <tr><td style="padding: 4px 0; color: #666;">Total keys found:</td><td style="font-weight: bold;">{total}</td></tr>
                    <tr><td style="padding: 4px 0; color: #666;">Active keys:</td><td style="font-weight: bold; color: {status_color};">{active}</td></tr>
                    <tr><td style="padding: 4px 0; color: #666;">Inactive keys:</td><td style="font-weight: bold;">{inactive}</td></tr>
                    <tr><td style="padding: 4px 0; color: #666;">Discovery methods:</td><td>{', '.join(methods_used)}</td></tr>
                </table>

                {sheet_link}

                <p style="font-size: 11px; color: #999; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px;">
                    Automated daily report from API Key Scanner.
                </p>
            </div>
        </body>
        </html>
        """
        return html
