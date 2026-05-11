import logging
from dataclasses import dataclass
import requests

log = logging.getLogger(__name__)

TIMEOUT = 10


@dataclass
class TestResult:
    key_value: str
    service: str
    key_type: str
    is_active: bool
    status_detail: str
    additional_info: dict


class KeyTester:
    def test_key(self, key_value: str, service: str, key_type: str) -> TestResult:
        tester_map = {
            "OpenAI": self._test_openai,
            "Anthropic": self._test_anthropic,
            "Groq": self._test_groq,
            "Hugging Face": self._test_huggingface,
            "Cohere": self._test_cohere,
            "Replicate": self._test_replicate,
            "Mistral": self._test_mistral,
            "Perplexity": self._test_perplexity,
            "Together AI": self._test_together,
            "DeepSeek": self._test_deepseek,
            "AI21": self._test_ai21,
            "Stability AI": self._test_stability,
            "ElevenLabs": self._test_elevenlabs,
            "GitHub": self._test_github,
            "Stripe": self._test_stripe,
            "SendGrid": self._test_sendgrid,
            "Twilio": self._test_twilio,
            "Slack": self._test_slack,
            "Telegram": self._test_telegram,
            "Mailgun": self._test_mailgun,
            "Mailchimp": self._test_mailchimp,
            "Google": self._test_google_api_key,
            "YouTube": self._test_google_api_key,
            "DigitalOcean": self._test_digitalocean,
            "Shopify": self._test_shopify,
            "Discord": self._test_discord_webhook,
            "npm": self._test_npm,
            "Docker Hub": self._test_dockerhub,
            "HashiCorp Vault": self._test_vault,
            "AWS": self._test_aws,
            "Notion": self._test_notion,
            "Mapbox": self._test_mapbox,
            "Razorpay": self._test_razorpay,
            "Twitter/X": self._test_twitter,
            "Sentry": self._test_sentry,
            "Linear": self._test_linear,
            "Vercel": self._test_vercel,
            "Resend": self._test_resend,
            "OpenWeatherMap": self._test_openweathermap,
            "Airtable": self._test_airtable,
            "Clerk": self._test_clerk,
        }

        tester = tester_map.get(service)
        if not tester:
            if service == "Unknown":
                return TestResult(
                    key_value=key_value,
                    service=service,
                    key_type=key_type,
                    is_active=True,
                    status_detail="Entropy-detected secret — unable to validate (no known endpoint). Treat as potentially active.",
                    additional_info={"detection_method": "entropy + context"},
                )
            return TestResult(
                key_value=key_value,
                service=service,
                key_type=key_type,
                is_active=False,
                status_detail="No tester available for this service",
                additional_info={},
            )

        try:
            return tester(key_value, key_type)
        except Exception as e:
            log.error(f"Error testing {service} key: {e}")
            return TestResult(
                key_value=key_value,
                service=service,
                key_type=key_type,
                is_active=False,
                status_detail=f"Test error: {str(e)[:200]}",
                additional_info={},
            )

    def _test_openai(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["models_count"] = len(data.get("data", []))
            info["org"] = resp.headers.get("openai-organization", "unknown")
        return TestResult(
            key_value=key, service="OpenAI", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_anthropic(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            },
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="Anthropic", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_github(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["username"] = data.get("login", "")
            info["name"] = data.get("name", "")
            info["email"] = data.get("email", "")
            info["public_repos"] = data.get("public_repos", 0)

            scopes = resp.headers.get("X-OAuth-Scopes", "")
            info["scopes"] = scopes
            info["rate_limit_remaining"] = resp.headers.get("X-RateLimit-Remaining", "")
        return TestResult(
            key_value=key, service="GitHub", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (f" - User: {info.get('username', '')}" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_stripe(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.stripe.com/v1/balance",
            auth=(key, ""),
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            available = data.get("available", [])
            if available:
                info["currency"] = available[0].get("currency", "")
                info["balance"] = available[0].get("amount", 0) / 100
            info["livemode"] = data.get("livemode", False)
        return TestResult(
            key_value=key, service="Stripe", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_sendgrid(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["username"] = data.get("username", "")
            info["email"] = data.get("email", "")
        return TestResult(
            key_value=key, service="SendGrid", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_twilio(self, key: str, key_type: str) -> TestResult:
        if not key.startswith("AC"):
            return TestResult(
                key_value=key, service="Twilio", key_type=key_type,
                is_active=False,
                status_detail="Twilio Account SID required for testing (starts with AC)",
                additional_info={},
            )
        resp = requests.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{key}.json",
            auth=(key, "dummy"),
            timeout=TIMEOUT,
        )
        is_active = resp.status_code != 401
        return TestResult(
            key_value=key, service="Twilio", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - SID exists" if is_active else " - Invalid SID"),
            additional_info={},
        )

    def _test_slack(self, key: str, key_type: str) -> TestResult:
        if key.startswith("https://hooks.slack.com"):
            return self._test_slack_webhook(key, key_type)

        resp = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        data = resp.json()
        is_active = data.get("ok", False)
        info = {}
        if is_active:
            info["team"] = data.get("team", "")
            info["user"] = data.get("user", "")
            info["team_id"] = data.get("team_id", "")
        return TestResult(
            key_value=key, service="Slack", key_type=key_type,
            is_active=is_active,
            status_detail="Valid token" if is_active else f"Invalid: {data.get('error', 'unknown')}",
            additional_info=info,
        )

    def _test_slack_webhook(self, url: str, key_type: str) -> TestResult:
        resp = requests.post(
            url,
            json={"text": ""},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code != 404 and "invalid" not in resp.text.lower()
        return TestResult(
            key_value=url, service="Slack", key_type="Webhook URL",
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code} - {'Webhook active' if is_active else 'Webhook invalid'}",
            additional_info={},
        )

    def _test_telegram(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            f"https://api.telegram.org/bot{key}/getMe",
            timeout=TIMEOUT,
        )
        data = resp.json()
        is_active = data.get("ok", False)
        info = {}
        if is_active:
            result = data.get("result", {})
            info["bot_name"] = result.get("first_name", "")
            info["bot_username"] = result.get("username", "")
            info["can_join_groups"] = result.get("can_join_groups", False)
        return TestResult(
            key_value=key, service="Telegram", key_type=key_type,
            is_active=is_active,
            status_detail="Valid bot token" if is_active else "Invalid bot token",
            additional_info=info,
        )

    def _test_mailgun(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.mailgun.net/v3/domains",
            auth=("api", key),
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            domains = data.get("items", [])
            info["domains_count"] = len(domains)
            if domains:
                info["first_domain"] = domains[0].get("name", "")
        return TestResult(
            key_value=key, service="Mailgun", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_mailchimp(self, key: str, key_type: str) -> TestResult:
        dc = key.split("-")[-1] if "-" in key else "us1"
        resp = requests.get(
            f"https://{dc}.api.mailchimp.com/3.0/",
            auth=("anystring", key),
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["account_name"] = data.get("account_name", "")
            info["email"] = data.get("email", "")
        return TestResult(
            key_value=key, service="Mailchimp", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_google_api_key(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={key}",
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return TestResult(
                key_value=key, service="Google", key_type=key_type,
                is_active=True,
                status_detail="Valid Google API key",
                additional_info=resp.json(),
            )

        # Fallback: test as Maps key
        resp2 = requests.get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}",
            timeout=TIMEOUT,
        )
        is_active = resp2.status_code == 200 and resp2.json().get("status") != "REQUEST_DENIED"
        return TestResult(
            key_value=key, service="Google", key_type=key_type,
            is_active=is_active,
            status_detail="Valid Google Maps key" if is_active else "Invalid or restricted key",
            additional_info={},
        )

    def _test_digitalocean(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.digitalocean.com/v2/account",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json().get("account", {})
            info["email"] = data.get("email", "")
            info["droplet_limit"] = data.get("droplet_limit", 0)
            info["status"] = data.get("status", "")
        return TestResult(
            key_value=key, service="DigitalOcean", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_shopify(self, key: str, key_type: str) -> TestResult:
        return TestResult(
            key_value=key, service="Shopify", key_type=key_type,
            is_active=False,
            status_detail="Shopify testing requires store URL — skipped",
            additional_info={},
        )

    def _test_discord_webhook(self, key: str, key_type: str) -> TestResult:
        if not key.startswith("https://discord"):
            return TestResult(
                key_value=key, service="Discord", key_type=key_type,
                is_active=False,
                status_detail="Discord bot token testing requires bot application context — skipped",
                additional_info={},
            )

        resp = requests.get(key, timeout=TIMEOUT)
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["webhook_name"] = data.get("name", "")
            info["channel_id"] = data.get("channel_id", "")
            info["guild_id"] = data.get("guild_id", "")
        return TestResult(
            key_value=key, service="Discord", key_type="Webhook URL",
            is_active=is_active,
            status_detail="Active webhook" if is_active else "Invalid webhook",
            additional_info=info,
        )

    def _test_npm(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://registry.npmjs.org/-/whoami",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            info["username"] = resp.json().get("username", "")
        return TestResult(
            key_value=key, service="npm", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (f" - User: {info.get('username', '')}" if is_active else " - Invalid token"),
            additional_info=info,
        )

    def _test_dockerhub(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://hub.docker.com/v2/user/",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["username"] = data.get("username", "")
        return TestResult(
            key_value=key, service="Docker Hub", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid token"),
            additional_info=info,
        )

    def _test_vault(self, key: str, key_type: str) -> TestResult:
        return TestResult(
            key_value=key, service="HashiCorp Vault", key_type=key_type,
            is_active=False,
            status_detail="Vault testing requires server URL — skipped",
            additional_info={},
        )

    def _test_aws(self, key: str, key_type: str) -> TestResult:
        if not key.startswith("AKIA"):
            return TestResult(
                key_value=key, service="AWS", key_type=key_type,
                is_active=False,
                status_detail="AWS Secret Key testing requires both Access Key ID + Secret — skipped",
                additional_info={"note": "Pair with AKIA* Access Key ID for full validation"},
            )

        resp = requests.get(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            timeout=TIMEOUT,
        )
        return TestResult(
            key_value=key, service="AWS", key_type=key_type,
            is_active=False,
            status_detail="AWS Access Key ID found — requires Secret Key for STS validation",
            additional_info={"access_key_id": key},
        )

    def _test_groq(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["models_count"] = len(data.get("data", []))
        return TestResult(
            key_value=key, service="Groq", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_huggingface(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://huggingface.co/api/whoami-v2",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["username"] = data.get("name", "")
            info["email"] = data.get("email", "")
            info["orgs"] = [o.get("name", "") for o in data.get("orgs", [])]
        return TestResult(
            key_value=key, service="Hugging Face", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (f" - User: {info.get('username', '')}" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_cohere(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.cohere.ai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["models_count"] = len(data.get("models", []))
        return TestResult(
            key_value=key, service="Cohere", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_replicate(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.replicate.com/v1/account",
            headers={"Authorization": f"Token {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["username"] = data.get("username", "")
            info["github_url"] = data.get("github_url", "")
        return TestResult(
            key_value=key, service="Replicate", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (f" - User: {info.get('username', '')}" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_mistral(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.mistral.ai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["models_count"] = len(data.get("data", []))
        return TestResult(
            key_value=key, service="Mistral", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_perplexity(self, key: str, key_type: str) -> TestResult:
        resp = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": "sonar", "messages": [{"role": "user", "content": "test"}], "max_tokens": 1},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code in (200, 400)
        if resp.status_code == 401 or resp.status_code == 403:
            is_active = False
        return TestResult(
            key_value=key, service="Perplexity", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_together(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.together.xyz/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            if isinstance(data, list):
                info["models_count"] = len(data)
        return TestResult(
            key_value=key, service="Together AI", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_deepseek(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.deepseek.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["models_count"] = len(data.get("data", []))
        return TestResult(
            key_value=key, service="DeepSeek", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_ai21(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.ai21.com/studio/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="AI21", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_stability(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.stability.ai/v1/user/account",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["email"] = data.get("email", "")
            info["credits"] = data.get("credits", 0)
        return TestResult(
            key_value=key, service="Stability AI", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_elevenlabs(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.elevenlabs.io/v1/user",
            headers={"xi-api-key": key},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            sub = data.get("subscription", {})
            info["tier"] = sub.get("tier", "")
            info["character_limit"] = sub.get("character_limit", 0)
            info["characters_used"] = sub.get("character_count", 0)
        return TestResult(
            key_value=key, service="ElevenLabs", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_notion(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.notion.com/v1/users/me",
            headers={"Authorization": f"Bearer {key}", "Notion-Version": "2022-06-28"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["name"] = data.get("name", "")
            info["type"] = data.get("type", "")
        return TestResult(
            key_value=key, service="Notion", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_mapbox(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            f"https://api.mapbox.com/tokens/v2?access_token={key}",
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="Mapbox", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_razorpay(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.razorpay.com/v1/payments?count=1",
            auth=(key, ""),
            timeout=TIMEOUT,
        )
        is_active = resp.status_code != 401
        return TestResult(
            key_value=key, service="Razorpay", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_twitter(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.twitter.com/2/users/me",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json().get("data", {})
            info["username"] = data.get("username", "")
            info["name"] = data.get("name", "")
        return TestResult(
            key_value=key, service="Twitter/X", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_sentry(self, key: str, key_type: str) -> TestResult:
        return TestResult(
            key_value=key, service="Sentry", key_type=key_type,
            is_active=True,
            status_detail="Sentry DSN found — likely active (DSNs don't expire)",
            additional_info={"note": "DSNs are project-specific and usually remain valid"},
        )

    def _test_linear(self, key: str, key_type: str) -> TestResult:
        resp = requests.post(
            "https://api.linear.app/graphql",
            headers={"Authorization": key, "Content-Type": "application/json"},
            json={"query": "{ viewer { id name email } }"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200 and "errors" not in resp.json()
        info = {}
        if is_active:
            viewer = resp.json().get("data", {}).get("viewer", {})
            info["name"] = viewer.get("name", "")
            info["email"] = viewer.get("email", "")
        return TestResult(
            key_value=key, service="Linear", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_vercel(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.vercel.com/v2/user",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json().get("user", {})
            info["username"] = data.get("username", "")
            info["email"] = data.get("email", "")
        return TestResult(
            key_value=key, service="Vercel", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid token" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_resend(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.resend.com/domains",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="Resend", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_openweathermap(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            f"https://api.openweathermap.org/data/2.5/weather?q=London&appid={key}",
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="OpenWeatherMap", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )

    def _test_airtable(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.airtable.com/v0/meta/whoami",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        info = {}
        if is_active:
            data = resp.json()
            info["user_id"] = data.get("id", "")
        return TestResult(
            key_value=key, service="Airtable", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info=info,
        )

    def _test_clerk(self, key: str, key_type: str) -> TestResult:
        resp = requests.get(
            "https://api.clerk.com/v1/users?limit=1",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        is_active = resp.status_code == 200
        return TestResult(
            key_value=key, service="Clerk", key_type=key_type,
            is_active=is_active,
            status_detail=f"HTTP {resp.status_code}" + (" - Valid key" if is_active else " - Invalid/expired"),
            additional_info={},
        )
