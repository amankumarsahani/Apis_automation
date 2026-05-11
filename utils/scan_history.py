"""
Scan history tracker — prevents re-scanning the same repos on subsequent runs.

Stores a JSON file mapping repo full_names to their last scan timestamp.
Repos are only re-scanned after RESCAN_AFTER_DAYS have elapsed.
"""
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


class ScanHistory:
    """Tracks which repos have been scanned and when."""

    def __init__(self, history_path: Optional[str] = None, rescan_after_days: Optional[int] = None):
        self.history_path = Path(history_path or settings.SCAN_HISTORY_PATH)
        self.rescan_after_days = rescan_after_days if rescan_after_days is not None else settings.RESCAN_AFTER_DAYS
        self._history: dict = self._load()

    def _load(self) -> dict:
        """Load scan history from JSON file."""
        if self.history_path.exists():
            try:
                with open(self.history_path, "r") as f:
                    data = json.load(f)
                log.info(f"Loaded scan history: {len(data.get('repos', {}))} repos tracked")
                return data
            except (json.JSONDecodeError, IOError) as e:
                log.warning(f"Failed to load scan history: {e}. Starting fresh.")
        return {"repos": {}, "users": {}, "metadata": {"created": datetime.now().isoformat()}}

    def save(self) -> None:
        """Persist scan history to disk."""
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self._history["metadata"]["last_updated"] = datetime.now().isoformat()
        self._history["metadata"]["total_repos"] = len(self._history["repos"])
        self._history["metadata"]["total_users"] = len(self._history["users"])
        with open(self.history_path, "w") as f:
            json.dump(self._history, f, indent=2, default=str)
        log.info(f"Scan history saved: {len(self._history['repos'])} repos, {len(self._history['users'])} users")

    def was_recently_scanned(self, repo_full_name: str) -> bool:
        """Check if a repo was scanned within the rescan window."""
        entry = self._history["repos"].get(repo_full_name)
        if not entry:
            return False
        last_scanned = datetime.fromisoformat(entry["last_scanned"])
        cutoff = datetime.now() - timedelta(days=self.rescan_after_days)
        return last_scanned > cutoff

    def was_user_recently_scanned(self, username: str) -> bool:
        """Check if a user was scanned within the rescan window."""
        entry = self._history["users"].get(username)
        if not entry:
            return False
        last_scanned = datetime.fromisoformat(entry["last_scanned"])
        cutoff = datetime.now() - timedelta(days=self.rescan_after_days)
        return last_scanned > cutoff

    def record_repo_scan(self, repo_full_name: str, findings_count: int = 0) -> None:
        """Record that a repo was scanned."""
        now = datetime.now().isoformat()
        existing = self._history["repos"].get(repo_full_name, {})
        self._history["repos"][repo_full_name] = {
            "last_scanned": now,
            "scan_count": existing.get("scan_count", 0) + 1,
            "last_findings": findings_count,
            "first_scanned": existing.get("first_scanned", now),
        }

    def record_user_scan(self, username: str, findings_count: int = 0) -> None:
        """Record that a user was scanned."""
        now = datetime.now().isoformat()
        existing = self._history["users"].get(username, {})
        self._history["users"][username] = {
            "last_scanned": now,
            "scan_count": existing.get("scan_count", 0) + 1,
            "last_findings": findings_count,
            "first_scanned": existing.get("first_scanned", now),
        }

    def filter_new_repos(self, repos: list) -> list:
        """Filter out repos that were recently scanned. Returns only new/stale repos."""
        new_repos = [r for r in repos if not self.was_recently_scanned(r)]
        skipped = len(repos) - len(new_repos)
        if skipped > 0:
            log.info(f"Scan history: skipping {skipped} already-scanned repos ({len(new_repos)} new)")
        return new_repos

    def filter_new_users(self, users: list) -> list:
        """Filter out users that were recently scanned."""
        new_users = [u for u in users if not self.was_user_recently_scanned(u)]
        skipped = len(users) - len(new_users)
        if skipped > 0:
            log.info(f"Scan history: skipping {skipped} already-scanned users ({len(new_users)} new)")
        return new_users

    def get_stats(self) -> dict:
        """Return history statistics."""
        return {
            "total_repos_tracked": len(self._history["repos"]),
            "total_users_tracked": len(self._history["users"]),
            "history_file": str(self.history_path),
            "rescan_after_days": self.rescan_after_days,
        }

    def clear(self) -> None:
        """Reset all scan history."""
        self._history = {"repos": {}, "users": {}, "metadata": {"created": datetime.now().isoformat()}}
        self.save()
        log.info("Scan history cleared")
