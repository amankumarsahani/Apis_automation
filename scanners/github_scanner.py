import os
import shutil
import tempfile
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from github import Github, GithubException
from git import Repo as GitRepo, InvalidGitRepositoryError

from config.settings import settings
from scanners.patterns import get_patterns, SKIP_EXTENSIONS, SKIP_DIRS, SKIP_PATH_PATTERNS, KeyPattern
from scanners.entropy_scanner import scan_content_entropy

log = logging.getLogger(__name__)


@dataclass
class KeyFinding:
    key_value: str
    service: str
    key_type: str
    confidence: str
    description: str
    repo_name: str
    file_path: str
    line_number: int
    commit_sha: str = ""
    commit_date: str = ""
    commit_author: str = ""
    branch: str = ""
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())


class GitHubScanner:
    def __init__(self, token: str = "", include_low_confidence: bool = False):
        self.token = token or settings.GITHUB_TOKEN
        self.github = Github(self.token) if self.token else Github()
        self.patterns = get_patterns(include_low_confidence)
        self.temp_dir = settings.TEMP_REPOS_DIR
        self.findings: list[KeyFinding] = []
        self._seen_keys: set[str] = set()
        self._seen_per_repo: dict[str, set[str]] = {}

    def scan_user(self, username: str, max_repos: int = 0) -> list[KeyFinding]:
        max_repos = max_repos or settings.MAX_REPOS
        log.info(f"Scanning repos for user: {username}")

        try:
            user = self.github.get_user(username)
            repos = list(user.get_repos())[:max_repos]
        except GithubException as e:
            log.error(f"Failed to fetch repos for {username}: {e}")
            return []

        log.info(f"Found {len(repos)} repos for {username}")
        for repo in repos:
            if repo.fork:
                log.info(f"Skipping fork: {repo.full_name}")
                continue
            self._scan_repo(repo.full_name, repo.clone_url)

        return self.findings

    def scan_repo_url(self, repo_url: str) -> list[KeyFinding]:
        repo_url = repo_url.rstrip("/")

        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        parts = repo_url.replace("https://github.com/", "").replace("http://github.com/", "")
        repo_name = parts.strip("/")

        clone_url = f"https://github.com/{repo_name}.git"
        if self.token:
            clone_url = f"https://{self.token}@github.com/{repo_name}.git"

        self._scan_repo(repo_name, clone_url)
        return self.findings

    def scan_repo_urls(self, urls: list[str]) -> list[KeyFinding]:
        for url in urls:
            self.scan_repo_url(url)
        return self.findings

    def _scan_repo(self, repo_name: str, clone_url: str):
        log.info(f"Scanning: {repo_name}")
        clone_path = None

        try:
            clone_path = self._clone_repo(repo_name, clone_url)
            if not clone_path:
                return

            self._scan_current_files(repo_name, clone_path)

            if settings.SCAN_COMMIT_HISTORY:
                self._scan_commit_history(repo_name, clone_path)

        except Exception as e:
            log.error(f"Error scanning {repo_name}: {e}")
        finally:
            if clone_path and clone_path.exists():
                shutil.rmtree(clone_path, ignore_errors=True)

    def _clone_repo(self, repo_name: str, clone_url: str) -> Optional[Path]:
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        safe_name = repo_name.replace("/", "_")
        clone_path = self.temp_dir / safe_name

        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)

        try:
            if self.token and "@" not in clone_url:
                clone_url = clone_url.replace("https://", f"https://{self.token}@")

            GitRepo.clone_from(
                clone_url,
                str(clone_path),
                depth=settings.CLONE_DEPTH,
                no_single_branch=True,
            )
            return clone_path
        except Exception as e:
            log.error(f"Clone failed for {repo_name}: {e}")
            return None

    def _scan_current_files(self, repo_name: str, clone_path: Path):
        for file_path in clone_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative = file_path.relative_to(clone_path)
            if self._should_skip(relative):
                continue

            try:
                content = file_path.read_text(errors="ignore")
                self._scan_content(
                    content=content,
                    repo_name=repo_name,
                    file_path=str(relative),
                    source="current_files",
                )
            except Exception:
                continue

    def _scan_commit_history(self, repo_name: str, clone_path: Path):
        try:
            git_repo = GitRepo(str(clone_path))
        except InvalidGitRepositoryError:
            return

        commits_scanned = 0

        try:
            for commit in git_repo.iter_commits(max_count=settings.MAX_COMMITS_PER_REPO):
                commits_scanned += 1
                try:
                    diffs = commit.diff(commit.parents[0] if commit.parents else None, create_patch=True)
                except Exception:
                    continue

                for diff in diffs:
                    if not diff.diff:
                        continue
                    try:
                        diff_text = diff.diff.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    self._scan_content(
                        content=diff_text,
                        repo_name=repo_name,
                        file_path=diff.b_path or diff.a_path or "unknown",
                        source="commit_history",
                        commit_sha=commit.hexsha[:8],
                        commit_date=datetime.fromtimestamp(commit.committed_date).isoformat(),
                        commit_author=str(commit.author),
                    )

        except Exception as e:
            log.warning(f"Error scanning commits for {repo_name}: {e}")

        log.info(f"Scanned {commits_scanned} commits in {repo_name}")

    def _scan_content(
        self,
        content: str,
        repo_name: str,
        file_path: str,
        source: str,
        commit_sha: str = "",
        commit_date: str = "",
        commit_author: str = "",
    ) -> list[KeyFinding]:
        new_findings = []
        seen_in_this_scan: set[str] = set()
        lines = content.split("\n")

        for pattern_def in self.patterns:
            for line_num, line in enumerate(lines, 1):
                matches = pattern_def.pattern.findall(line)
                for match in matches:
                    key_value = match if isinstance(match, str) else match[0] if match else ""
                    if not key_value or len(key_value) < 10:
                        continue

                    if key_value in seen_in_this_scan:
                        continue

                    if self._is_duplicate(key_value, repo_name):
                        continue

                    if self._is_false_positive(key_value, line, pattern_def):
                        continue

                    seen_in_this_scan.add(key_value)
                    self._mark_seen(key_value, repo_name)
                    finding = KeyFinding(
                        key_value=key_value,
                        service=pattern_def.service,
                        key_type=pattern_def.key_type,
                        confidence=pattern_def.confidence,
                        description=pattern_def.description,
                        repo_name=repo_name,
                        file_path=file_path,
                        line_number=line_num,
                        commit_sha=commit_sha,
                        commit_date=commit_date,
                        commit_author=commit_author,
                    )
                    self.findings.append(finding)
                    new_findings.append(finding)
                    log.info(
                        f"  FOUND [{pattern_def.service}] {pattern_def.key_type} "
                        f"in {file_path}:{line_num} (confidence: {pattern_def.confidence})"
                    )

        entropy_findings = scan_content_entropy(content)
        for ef in entropy_findings:
            if ef.value in seen_in_this_scan:
                continue
            if self._is_duplicate(ef.value, repo_name):
                continue

            seen_in_this_scan.add(ef.value)
            self._mark_seen(ef.value, repo_name)
            finding = KeyFinding(
                key_value=ef.value,
                service="Unknown",
                key_type=f"Secret ({ef.context_key})",
                confidence=ef.confidence,
                description=f"Entropy-detected secret (Shannon: {ef.entropy:.2f}) via context: {ef.context_key}",
                repo_name=repo_name,
                file_path=file_path,
                line_number=ef.line_number,
                commit_sha=commit_sha,
                commit_date=commit_date,
                commit_author=commit_author,
            )
            self.findings.append(finding)
            new_findings.append(finding)
            log.info(
                f"  FOUND [Entropy] secret via {ef.context_key} "
                f"in {file_path}:{ef.line_number} (entropy: {ef.entropy:.2f}, confidence: {ef.confidence})"
            )

        return new_findings

    def _is_duplicate(self, key_value: str, repo_name: str) -> bool:
        repo_seen = self._seen_per_repo.get(repo_name)
        if repo_seen and key_value in repo_seen:
            return True
        return False

    def _mark_seen(self, key_value: str, repo_name: str):
        self._seen_keys.add(key_value)
        if repo_name not in self._seen_per_repo:
            self._seen_per_repo[repo_name] = set()
        self._seen_per_repo[repo_name].add(key_value)

    def _is_false_positive(self, key_value: str, line: str, pattern: KeyPattern) -> bool:
        placeholder_indicators = [
            "example", "placeholder", "your_", "xxx", "yyy", "zzz",
            "insert", "replace", "dummy", "fake", "test_key", "sample",
            "todo", "fixme", "changeme", "<your", "${", "{{",
            "000000", "111111", "abcdef", "123456",
        ]
        key_lower = key_value.lower()
        line_lower = line.lower()

        for indicator in placeholder_indicators:
            if indicator in key_lower or indicator in line_lower:
                return True

        if all(c == key_value[0] for c in key_value):
            return True

        if pattern.service == "Generic" and pattern.key_type == "Password":
            if len(key_value) < 8:
                return True

        framework_config_indicators = [
            "config.", "devise", "secret_key_base", "pepper",
            "secret_token", "encryption_key", "master.key",
            "rails.application", "application.config",
            "initializer", "doorkeeper", "omniauth",
            "warden", "bcrypt", "argon2",
        ]
        for indicator in framework_config_indicators:
            if indicator in line_lower:
                return True

        if key_value.startswith("ENV[") or key_value.startswith("ENV.fetch"):
            return True
        if key_value.startswith("Rails.") or key_value.startswith("config."):
            return True

        return False

    def _should_skip(self, relative_path: Path) -> bool:
        for part in relative_path.parts:
            if part in SKIP_DIRS:
                return True

        if relative_path.suffix.lower() in SKIP_EXTENSIONS:
            return True

        path_str = str(relative_path).lower()
        if any(skip in path_str for skip in SKIP_PATH_PATTERNS):
            return True

        return False

    def get_findings(self) -> list[KeyFinding]:
        return self.findings

    def clear_findings(self):
        self.findings.clear()
        self._seen_keys.clear()
        self._seen_per_repo.clear()
