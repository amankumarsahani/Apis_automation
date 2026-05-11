"""
Auto-discovery module for finding GitHub targets likely to have leaked API keys.

Discovery methods:
1. Recently pushed repos (last 24h)
2. Trending repos/developers
3. Organization members
4. GitHub code search for exposed config files
"""
import logging
import time
from datetime import datetime, timedelta
from typing import Optional

from github import Github, GithubException, RateLimitExceededException

from config.settings import settings

log = logging.getLogger(__name__)


class TargetDiscovery:
    """Discovers GitHub repos/users likely to have leaked secrets."""

    def __init__(self, token: str = ""):
        self.token = token or settings.GITHUB_TOKEN
        self.github = Github(self.token) if self.token else Github()
        self._discovered_repos: set[str] = set()
        self._discovered_users: set[str] = set()

    def discover_all(
        self,
        max_repos_per_method: int = 50,
        orgs: Optional[list[str]] = None,
    ) -> dict:
        """Run all discovery methods and return combined targets."""
        log.info("Starting auto-discovery of targets...")

        results = {
            "repos": [],
            "users": [],
            "total_repos": 0,
            "total_users": 0,
            "methods_used": [],
        }

        # Method 1: Recently pushed repos
        try:
            recent = self.discover_recently_pushed(max_repos_per_method)
            results["repos"].extend(recent)
            results["methods_used"].append("recently_pushed")
            log.info(f"Recently pushed: found {len(recent)} repos")
        except Exception as e:
            log.warning(f"Recently pushed discovery failed: {e}")

        # Method 2: Trending repos/developers
        try:
            trending = self.discover_trending(max_repos_per_method)
            results["repos"].extend(trending)
            results["methods_used"].append("trending")
            log.info(f"Trending: found {len(trending)} repos")
        except Exception as e:
            log.warning(f"Trending discovery failed: {e}")

        # Method 3: Organization members
        if orgs:
            try:
                org_repos = self.discover_org_members(orgs, max_repos_per_method)
                results["users"].extend(org_repos)
                results["methods_used"].append("org_members")
                log.info(f"Org members: found {len(org_repos)} users")
            except Exception as e:
                log.warning(f"Org member discovery failed: {e}")

        # Method 4: Search for exposed config files
        try:
            exposed = self.discover_exposed_configs(max_repos_per_method)
            results["repos"].extend(exposed)
            results["methods_used"].append("exposed_configs")
            log.info(f"Exposed configs: found {len(exposed)} repos")
        except Exception as e:
            log.warning(f"Exposed config discovery failed: {e}")

        # Deduplicate
        results["repos"] = list(set(results["repos"]))
        results["users"] = list(set(results["users"]))
        results["total_repos"] = len(results["repos"])
        results["total_users"] = len(results["users"])

        log.info(
            f"Discovery complete: {results['total_repos']} repos, "
            f"{results['total_users']} users from {len(results['methods_used'])} methods"
        )
        return results

    def discover_recently_pushed(self, max_results: int = 50) -> list[str]:
        """Find repos pushed to in the last 24 hours that are likely to contain secrets."""
        repos = []
        since = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%d")

        # Search for repos with recent pushes containing common secret file patterns
        queries = [
            f"pushed:>{since} .env in:path",
            f"pushed:>{since} config in:path extension:json",
            f"pushed:>{since} credentials in:path",
            f"pushed:>{since} secrets in:path",
        ]

        for query in queries:
            if len(repos) >= max_results:
                break
            try:
                results = self.github.search_repositories(
                    query=query, sort="updated", order="desc"
                )
                for repo in results[:max_results // len(queries)]:
                    full_name = repo.full_name
                    if full_name not in self._discovered_repos:
                        self._discovered_repos.add(full_name)
                        repos.append(full_name)
                    if len(repos) >= max_results:
                        break
                self._rate_limit_pause()
            except RateLimitExceededException:
                log.warning("Rate limit hit during recently pushed discovery")
                self._wait_for_rate_limit()
            except GithubException as e:
                log.warning(f"Search query failed: {query} - {e}")

        return repos

    def discover_trending(self, max_results: int = 50) -> list[str]:
        """Find trending repos (high star velocity in last week) — often have quick-n-dirty code."""
        repos = []
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

        # Repos created recently with stars (often hobby/demo projects with secrets)
        queries = [
            f"created:>{since} stars:1..50 language:python",
            f"created:>{since} stars:1..50 language:javascript",
            f"created:>{since} stars:1..50 language:typescript",
            f"created:>{since} stars:0..10 language:python pushed:>{since}",
        ]

        for query in queries:
            if len(repos) >= max_results:
                break
            try:
                results = self.github.search_repositories(
                    query=query, sort="stars", order="desc"
                )
                for repo in results[:max_results // len(queries)]:
                    full_name = repo.full_name
                    if full_name not in self._discovered_repos:
                        self._discovered_repos.add(full_name)
                        repos.append(full_name)
                    if len(repos) >= max_results:
                        break
                self._rate_limit_pause()
            except RateLimitExceededException:
                log.warning("Rate limit hit during trending discovery")
                self._wait_for_rate_limit()
            except GithubException as e:
                log.warning(f"Trending search failed: {query} - {e}")

        return repos

    def discover_org_members(self, org_names: list[str], max_per_org: int = 50) -> list[str]:
        """Find all members of specified organizations."""
        users = []

        for org_name in org_names:
            try:
                org = self.github.get_organization(org_name)
                members = org.get_members()
                count = 0
                for member in members:
                    if count >= max_per_org:
                        break
                    login = member.login
                    if login not in self._discovered_users:
                        self._discovered_users.add(login)
                        users.append(login)
                        count += 1
                self._rate_limit_pause()
            except GithubException as e:
                log.warning(f"Failed to get members of org {org_name}: {e}")

        return users

    def discover_exposed_configs(self, max_results: int = 50) -> list[str]:
        """Search GitHub for repos that likely have exposed secrets via code search."""
        repos = []

        # These searches target common patterns where developers accidentally push secrets
        code_queries = [
            'filename:.env "API_KEY="',
            'filename:.env "SECRET_KEY="',
            'filename:.env "OPENAI_API_KEY="',
            'filename:config.json "api_key"',
            'filename:credentials.json "private_key"',
            '"sk-" filename:.env',
            '"AKIA" filename:.env',
            'filename:.env "STRIPE_SECRET"',
            'filename:application.properties "password="',
            'filename:.env "DATABASE_URL=postgres"',
        ]

        for query in code_queries:
            if len(repos) >= max_results:
                break
            try:
                results = self.github.search_code(query=query)
                for code_result in results[:max_results // len(code_queries)]:
                    full_name = code_result.repository.full_name
                    if full_name not in self._discovered_repos:
                        self._discovered_repos.add(full_name)
                        repos.append(full_name)
                    if len(repos) >= max_results:
                        break
                self._rate_limit_pause()
            except RateLimitExceededException:
                log.warning("Rate limit hit during code search")
                self._wait_for_rate_limit()
            except GithubException as e:
                log.warning(f"Code search failed: {query} - {e}")

        return repos

    def _rate_limit_pause(self):
        """Brief pause to avoid hitting rate limits between requests."""
        time.sleep(2)

    def _wait_for_rate_limit(self):
        """Wait for rate limit to reset."""
        try:
            rate_limit = self.github.get_rate_limit()
            reset_time = rate_limit.search.reset
            wait_seconds = (reset_time - datetime.utcnow()).total_seconds() + 5
            if wait_seconds > 0:
                log.info(f"Rate limited. Waiting {int(wait_seconds)}s for reset...")
                time.sleep(min(wait_seconds, 120))  # Cap at 2 minutes
        except Exception:
            log.info("Rate limited. Waiting 60s...")
            time.sleep(60)

    def clear(self):
        """Reset discovery state."""
        self._discovered_repos.clear()
        self._discovered_users.clear()
