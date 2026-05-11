"""
Configuration settings loaded from environment variables.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Central configuration for the API key scanner."""

    # GitHub
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    # Google Sheets
    GOOGLE_CREDENTIALS_PATH: str = os.getenv("GOOGLE_CREDENTIALS_PATH", "./config/google_credentials.json")
    GOOGLE_SHEET_NAME: str = os.getenv("GOOGLE_SHEET_NAME", "API_Keys_Scan_Results")
    SHARE_WITH_EMAIL: str = os.getenv("SHARE_WITH_EMAIL", "")

    # Email / SMTP (Gmail)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_EMAIL: str = os.getenv("SMTP_EMAIL", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL: str = os.getenv("ALERT_EMAIL", "")

    # Discovery settings
    DISCOVERY_MAX_REPOS: int = int(os.getenv("DISCOVERY_MAX_REPOS", "50"))
    DISCOVERY_ORGS: str = os.getenv("DISCOVERY_ORGS", "")

    # Scan settings
    MAX_REPOS: int = int(os.getenv("MAX_REPOS", "100"))
    SCAN_COMMIT_HISTORY: bool = os.getenv("SCAN_COMMIT_HISTORY", "true").lower() == "true"
    MAX_COMMITS_PER_REPO: int = int(os.getenv("MAX_COMMITS_PER_REPO", "500"))
    CLONE_DEPTH: int = int(os.getenv("CLONE_DEPTH", "50"))

    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    TEMP_REPOS_DIR: Path = BASE_DIR / "temp_repos"

    @classmethod
    def validate(cls) -> list[str]:
        """Return list of configuration errors."""
        errors = []
        if not cls.GITHUB_TOKEN:
            errors.append("GITHUB_TOKEN is required. Set it in .env file.")
        if not Path(cls.GOOGLE_CREDENTIALS_PATH).exists():
            errors.append(
                f"Google credentials not found at {cls.GOOGLE_CREDENTIALS_PATH}. "
                "Download service account JSON from Google Cloud Console."
            )
        return errors


settings = Settings()
