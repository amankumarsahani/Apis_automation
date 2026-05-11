"""
Comprehensive regex patterns for detecting API keys, tokens, and secrets.
Each pattern includes: regex, service name, key type, description, and confidence level.
"""
import re
from dataclasses import dataclass


@dataclass
class KeyPattern:
    """Defines a pattern for detecting a specific type of API key."""
    service: str
    key_type: str
    pattern: re.Pattern
    description: str
    confidence: str  # "high", "medium", "low"
    test_endpoint: str = ""  # URL or method used to validate


# All patterns compiled once at module load
PATTERNS: list[KeyPattern] = [
    # ── AWS ──────────────────────────────────────────────────
    KeyPattern(
        service="AWS",
        key_type="Access Key ID",
        pattern=re.compile(r'(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])'),
        description="AWS Access Key ID (starts with AKIA)",
        confidence="high",
    ),
    KeyPattern(
        service="AWS",
        key_type="Secret Access Key",
        pattern=re.compile(r'(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])'),
        description="AWS Secret Access Key (40 char base64)",
        confidence="low",  # high false positive rate without AKIA context
    ),

    # ── OpenAI ───────────────────────────────────────────────
    KeyPattern(
        service="OpenAI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9\-])'),
        description="OpenAI API key (legacy sk- format)",
        confidence="high",
    ),
    KeyPattern(
        service="OpenAI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-proj-[A-Za-z0-9\-_]{80,200})(?![A-Za-z0-9\-_])'),
        description="OpenAI project API key (sk-proj- format)",
        confidence="high",
    ),
    KeyPattern(
        service="OpenAI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-svcacct-[A-Za-z0-9\-_]{80,200})(?![A-Za-z0-9\-_])'),
        description="OpenAI service account key (sk-svcacct- format)",
        confidence="high",
    ),

    # ── Anthropic ────────────────────────────────────────────
    KeyPattern(
        service="Anthropic",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-ant-api03-[A-Za-z0-9\-_]{80,120})(?![A-Za-z0-9\-_])'),
        description="Anthropic Claude API key",
        confidence="high",
    ),

    # ── Groq ─────────────────────────────────────────────────
    KeyPattern(
        service="Groq",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-_])(gsk_[A-Za-z0-9]{48,60})(?![A-Za-z0-9\-_])'),
        description="Groq API key",
        confidence="high",
    ),

    # ── Hugging Face ─────────────────────────────────────────
    KeyPattern(
        service="Hugging Face",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,40})(?![A-Za-z0-9_])'),
        description="Hugging Face access token",
        confidence="high",
    ),

    # ── Cohere ───────────────────────────────────────────────
    KeyPattern(
        service="Cohere",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(co:[A-Za-z0-9\-_]{20,60})(?![A-Za-z0-9\-_])'),
        description="Cohere API key (co: prefix)",
        confidence="high",
    ),

    # ── Replicate ────────────────────────────────────────────
    KeyPattern(
        service="Replicate",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(r8_[A-Za-z0-9]{36,42})(?![A-Za-z0-9_])'),
        description="Replicate API token",
        confidence="high",
    ),

    # ── Mistral AI ───────────────────────────────────────────
    KeyPattern(
        service="Mistral",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(mistral-[A-Za-z0-9]{32,48})(?![A-Za-z0-9\-])'),
        description="Mistral AI API key",
        confidence="medium",
    ),

    # ── Perplexity ───────────────────────────────────────────
    KeyPattern(
        service="Perplexity",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(pplx-[A-Za-z0-9]{48,64})(?![A-Za-z0-9\-])'),
        description="Perplexity API key",
        confidence="high",
    ),

    # ── Together AI ──────────────────────────────────────────
    KeyPattern(
        service="Together AI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(tog-[A-Za-z0-9\-_]{40,64})(?![A-Za-z0-9\-_])'),
        description="Together AI API key",
        confidence="high",
    ),

    # ── DeepSeek ─────────────────────────────────────────────
    KeyPattern(
        service="DeepSeek",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-[a-f0-9]{48,64})(?![A-Za-z0-9\-])'),
        description="DeepSeek API key (sk- with hex chars)",
        confidence="medium",
    ),

    # ── AI21 Labs ────────────────────────────────────────────
    KeyPattern(
        service="AI21",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-_])(ai21-[A-Za-z0-9\-_]{40,60})(?![A-Za-z0-9\-_])'),
        description="AI21 Labs API key",
        confidence="high",
    ),

    # ── Stability AI ─────────────────────────────────────────
    KeyPattern(
        service="Stability AI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sk-[A-Za-z0-9]{40,60})(?![A-Za-z0-9\-])'),
        description="Stability AI API key",
        confidence="medium",
    ),

    # ── Voyage AI ────────────────────────────────────────────
    KeyPattern(
        service="Voyage AI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(pa-[A-Za-z0-9\-_]{40,60})(?![A-Za-z0-9\-_])'),
        description="Voyage AI API key",
        confidence="medium",
    ),

    # ── Pinecone (vector DB for LLM apps) ────────────────────
    KeyPattern(
        service="Pinecone",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?![A-Za-z0-9\-])'),
        description="Pinecone API key (UUID format)",
        confidence="low",
    ),

    # ── Eleven Labs (AI voice) ───────────────────────────────
    KeyPattern(
        service="ElevenLabs",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])(el-[A-Za-z0-9]{32,48})(?![A-Za-z0-9])'),
        description="ElevenLabs API key",
        confidence="high",
    ),

    # ── RunPod ───────────────────────────────────────────────
    KeyPattern(
        service="RunPod",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-_])(rp_[A-Za-z0-9]{24,36})(?![A-Za-z0-9\-_])'),
        description="RunPod API key",
        confidence="high",
    ),

    # ── Google ───────────────────────────────────────────────
    KeyPattern(
        service="Google",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9\-_])'),
        description="Google API key (starts with AIza)",
        confidence="high",
    ),
    KeyPattern(
        service="Google Cloud",
        key_type="Service Account Key",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        description="Google Cloud service account JSON key file",
        confidence="high",
    ),
    KeyPattern(
        service="Google",
        key_type="OAuth Client Secret",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(GOCSPX-[A-Za-z0-9\-_]{28})(?![A-Za-z0-9\-_])'),
        description="Google OAuth2 client secret",
        confidence="high",
    ),

    # ── GitHub ───────────────────────────────────────────────
    KeyPattern(
        service="GitHub",
        key_type="Personal Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,40})(?![A-Za-z0-9_])'),
        description="GitHub Personal Access Token",
        confidence="high",
    ),
    KeyPattern(
        service="GitHub",
        key_type="Fine-Grained Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{60,90})(?![A-Za-z0-9_])'),
        description="GitHub Fine-Grained Personal Access Token",
        confidence="high",
    ),
    KeyPattern(
        service="GitHub",
        key_type="OAuth Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(gho_[A-Za-z0-9]{36,40})(?![A-Za-z0-9_])'),
        description="GitHub OAuth Access Token",
        confidence="high",
    ),
    KeyPattern(
        service="GitHub",
        key_type="App Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(ghu_[A-Za-z0-9]{36,40})(?![A-Za-z0-9_])'),
        description="GitHub App User-to-Server Token",
        confidence="high",
    ),
    KeyPattern(
        service="GitHub",
        key_type="App Installation Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(ghs_[A-Za-z0-9]{36,40})(?![A-Za-z0-9_])'),
        description="GitHub App Server-to-Server Token",
        confidence="high",
    ),

    # ── Stripe ───────────────────────────────────────────────
    KeyPattern(
        service="Stripe",
        key_type="Secret Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,99})(?![A-Za-z0-9_])'),
        description="Stripe live secret key",
        confidence="high",
    ),
    KeyPattern(
        service="Stripe",
        key_type="Publishable Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(pk_live_[A-Za-z0-9]{24,99})(?![A-Za-z0-9_])'),
        description="Stripe live publishable key",
        confidence="high",
    ),
    KeyPattern(
        service="Stripe",
        key_type="Restricted Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(rk_live_[A-Za-z0-9]{24,99})(?![A-Za-z0-9_])'),
        description="Stripe live restricted key",
        confidence="high",
    ),
    KeyPattern(
        service="Stripe",
        key_type="Test Secret Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(sk_test_[A-Za-z0-9]{24,99})(?![A-Za-z0-9_])'),
        description="Stripe test secret key",
        confidence="medium",
    ),

    # ── Slack ────────────────────────────────────────────────
    KeyPattern(
        service="Slack",
        key_type="Bot Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24})(?![A-Za-z0-9\-])'),
        description="Slack Bot User OAuth Token",
        confidence="high",
    ),
    KeyPattern(
        service="Slack",
        key_type="User Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Fa-f0-9]{32})(?![A-Za-z0-9\-])'),
        description="Slack User OAuth Token",
        confidence="high",
    ),
    KeyPattern(
        service="Slack",
        key_type="Webhook URL",
        pattern=re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})'),
        description="Slack Incoming Webhook URL",
        confidence="high",
    ),

    # ── Twilio ───────────────────────────────────────────────
    KeyPattern(
        service="Twilio",
        key_type="Account SID",
        pattern=re.compile(r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])'),
        description="Twilio Account SID",
        confidence="high",
    ),
    KeyPattern(
        service="Twilio",
        key_type="Auth Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])([a-f0-9]{32})(?![A-Za-z0-9])'),
        description="Twilio Auth Token (32 hex chars)",
        confidence="low",  # very generic pattern
    ),

    # ── SendGrid ─────────────────────────────────────────────
    KeyPattern(
        service="SendGrid",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})(?![A-Za-z0-9\-_])'),
        description="SendGrid API key",
        confidence="high",
    ),

    # ── Mailgun ──────────────────────────────────────────────
    KeyPattern(
        service="Mailgun",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(key-[A-Za-z0-9]{32})(?![A-Za-z0-9\-])'),
        description="Mailgun API key",
        confidence="high",
    ),

    # ── Firebase ─────────────────────────────────────────────
    KeyPattern(
        service="Firebase",
        key_type="Cloud Messaging Key",
        pattern=re.compile(r'(?<![A-Za-z0-9=])(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})(?![A-Za-z0-9=])'),
        description="Firebase Cloud Messaging server key",
        confidence="high",
    ),

    # ── Heroku ───────────────────────────────────────────────
    KeyPattern(
        service="Heroku",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?![A-Fa-f0-9])'),
        description="Heroku API key (UUID format)",
        confidence="low",  # UUIDs are common
    ),

    # ── DigitalOcean ─────────────────────────────────────────
    KeyPattern(
        service="DigitalOcean",
        key_type="Personal Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(dop_v1_[a-f0-9]{64})(?![A-Za-z0-9_])'),
        description="DigitalOcean Personal Access Token",
        confidence="high",
    ),
    KeyPattern(
        service="DigitalOcean",
        key_type="OAuth Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(doo_v1_[a-f0-9]{64})(?![A-Za-z0-9_])'),
        description="DigitalOcean OAuth Token",
        confidence="high",
    ),

    # ── Azure ────────────────────────────────────────────────
    KeyPattern(
        service="Azure",
        key_type="Subscription Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])'),
        description="Azure Subscription Key (32 hex)",
        confidence="low",
    ),

    # ── PayPal ───────────────────────────────────────────────
    KeyPattern(
        service="PayPal",
        key_type="Client ID",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(A[A-Za-z0-9\-_]{60,80})(?![A-Za-z0-9\-_])'),
        description="PayPal Client ID",
        confidence="low",
    ),

    # ── Shopify ──────────────────────────────────────────────
    KeyPattern(
        service="Shopify",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])(shpat_[A-Fa-f0-9]{32})(?![A-Za-z0-9])'),
        description="Shopify Admin API access token",
        confidence="high",
    ),
    KeyPattern(
        service="Shopify",
        key_type="Private App Password",
        pattern=re.compile(r'(?<![A-Za-z0-9])(shppa_[A-Fa-f0-9]{32})(?![A-Za-z0-9])'),
        description="Shopify Private App password",
        confidence="high",
    ),

    # ── Square ───────────────────────────────────────────────
    KeyPattern(
        service="Square",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sq0atp-[A-Za-z0-9\-_]{22})(?![A-Za-z0-9\-_])'),
        description="Square Access Token",
        confidence="high",
    ),
    KeyPattern(
        service="Square",
        key_type="OAuth Secret",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(sq0csp-[A-Za-z0-9\-_]{43})(?![A-Za-z0-9\-_])'),
        description="Square OAuth Secret",
        confidence="high",
    ),

    # ── Telegram ─────────────────────────────────────────────
    KeyPattern(
        service="Telegram",
        key_type="Bot Token",
        pattern=re.compile(r'(?<![0-9])([0-9]{8,10}:[A-Za-z0-9_-]{30,40})(?![A-Za-z0-9_-])'),
        description="Telegram Bot Token",
        confidence="high",
    ),

    # ── Discord ──────────────────────────────────────────────
    KeyPattern(
        service="Discord",
        key_type="Bot Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])((?:MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})(?![A-Za-z0-9\._-])'),
        description="Discord Bot Token",
        confidence="high",
    ),
    KeyPattern(
        service="Discord",
        key_type="Webhook URL",
        pattern=re.compile(r'(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,68})'),
        description="Discord Webhook URL",
        confidence="high",
    ),

    # ── Mailchimp ────────────────────────────────────────────
    KeyPattern(
        service="Mailchimp",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9\-])([A-Fa-f0-9]{32}-us[0-9]{1,2})(?![A-Za-z0-9\-])'),
        description="Mailchimp API key",
        confidence="high",
    ),

    # ── npm ──────────────────────────────────────────────────
    KeyPattern(
        service="npm",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])'),
        description="npm access token",
        confidence="high",
    ),

    # ── PyPI ─────────────────────────────────────────────────
    KeyPattern(
        service="PyPI",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(pypi-[A-Za-z0-9\-_]{50,200})(?![A-Za-z0-9\-_])'),
        description="PyPI API token",
        confidence="high",
    ),

    # ── Docker Hub ───────────────────────────────────────────
    KeyPattern(
        service="Docker Hub",
        key_type="Personal Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(dckr_pat_[A-Za-z0-9\-_]{27})(?![A-Za-z0-9\-_])'),
        description="Docker Hub Personal Access Token",
        confidence="high",
    ),

    # ── Supabase ─────────────────────────────────────────────
    KeyPattern(
        service="Supabase",
        key_type="Service Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,300}\.[A-Za-z0-9_-]{30,60})(?![A-Za-z0-9\._-])'),
        description="Supabase/JWT token (HS256 signed)",
        confidence="medium",
    ),

    # ── Cloudflare ───────────────────────────────────────────
    KeyPattern(
        service="Cloudflare",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-_])([A-Za-z0-9_-]{40})(?![A-Za-z0-9\-_])'),
        description="Cloudflare API token",
        confidence="low",
    ),

    # ── Datadog ──────────────────────────────────────────────
    KeyPattern(
        service="Datadog",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])'),
        description="Datadog API key (32 hex chars)",
        confidence="low",
    ),

    # ── Vault / Generic ─────────────────────────────────────
    KeyPattern(
        service="HashiCorp Vault",
        key_type="Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(hvs\.[A-Za-z0-9_-]{24,})(?![A-Za-z0-9\._-])'),
        description="HashiCorp Vault service token",
        confidence="high",
    ),

    # ── Twitter/X ────────────────────────────────────────────
    KeyPattern(
        service="Twitter/X",
        key_type="Bearer Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])(AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%\-_]{30,80})(?![A-Za-z0-9%\-_])'),
        description="Twitter/X API Bearer Token",
        confidence="high",
    ),
    KeyPattern(
        service="Twitter/X",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{25})(?![A-Za-z0-9])'),
        description="Twitter/X API Key (25 alphanumeric chars)",
        confidence="low",
    ),

    # ── Facebook/Meta ────────────────────────────────────────
    KeyPattern(
        service="Facebook",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])(EAA[A-Za-z0-9]{100,300})(?![A-Za-z0-9])'),
        description="Facebook/Meta Graph API access token",
        confidence="high",
    ),
    KeyPattern(
        service="Facebook",
        key_type="App Secret",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])'),
        description="Facebook App Secret (32 hex chars)",
        confidence="low",
    ),

    # ── Reddit ───────────────────────────────────────────────
    KeyPattern(
        service="Reddit",
        key_type="API Secret",
        pattern=re.compile(r'(?<![A-Za-z0-9\-_])([A-Za-z0-9\-_]{27})(?![A-Za-z0-9\-_])'),
        description="Reddit API secret (27 chars)",
        confidence="low",
    ),

    # ── YouTube/Google ───────────────────────────────────────
    KeyPattern(
        service="YouTube",
        key_type="Data API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9\-_])'),
        description="YouTube Data API key (same as Google API key format)",
        confidence="high",
    ),

    # ── NewsAPI ──────────────────────────────────────────────
    KeyPattern(
        service="NewsAPI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])'),
        description="NewsAPI key (32 hex chars)",
        confidence="low",
    ),

    # ── New York Times ───────────────────────────────────────
    KeyPattern(
        service="NYT",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{32})(?![A-Za-z0-9])'),
        description="New York Times API key (32 alphanumeric)",
        confidence="low",
    ),

    # ── Guardian ─────────────────────────────────────────────
    KeyPattern(
        service="Guardian",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?![A-Za-z0-9\-])'),
        description="The Guardian API key (UUID format)",
        confidence="low",
    ),

    # ── Notion ───────────────────────────────────────────────
    KeyPattern(
        service="Notion",
        key_type="Integration Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(secret_[A-Za-z0-9]{43})(?![A-Za-z0-9_])'),
        description="Notion internal integration token",
        confidence="high",
    ),
    KeyPattern(
        service="Notion",
        key_type="OAuth Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(ntn_[A-Za-z0-9]{40,60})(?![A-Za-z0-9_])'),
        description="Notion OAuth token",
        confidence="high",
    ),

    # ── Airtable ─────────────────────────────────────────────
    KeyPattern(
        service="Airtable",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])(key[A-Za-z0-9]{14})(?![A-Za-z0-9])'),
        description="Airtable API key (legacy format)",
        confidence="medium",
    ),
    KeyPattern(
        service="Airtable",
        key_type="Personal Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})(?![A-Za-z0-9\.])'),
        description="Airtable Personal Access Token",
        confidence="high",
    ),

    # ── Jira/Atlassian ───────────────────────────────────────
    KeyPattern(
        service="Atlassian",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{24})(?![A-Za-z0-9])'),
        description="Atlassian/Jira API token (24 chars)",
        confidence="low",
    ),

    # ── Zapier ───────────────────────────────────────────────
    KeyPattern(
        service="Zapier",
        key_type="Webhook URL",
        pattern=re.compile(r'(https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/)'),
        description="Zapier webhook URL",
        confidence="high",
    ),

    # ── Vonage/Nexmo ─────────────────────────────────────────
    KeyPattern(
        service="Vonage",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{8})(?![A-Fa-f0-9])'),
        description="Vonage/Nexmo API key (8 hex chars)",
        confidence="low",
    ),
    KeyPattern(
        service="Vonage",
        key_type="API Secret",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{16})(?![A-Za-z0-9])'),
        description="Vonage/Nexmo API secret (16 chars)",
        confidence="low",
    ),

    # ── Plivo ────────────────────────────────────────────────
    KeyPattern(
        service="Plivo",
        key_type="Auth ID",
        pattern=re.compile(r'(?<![A-Z0-9])([A-Z]{2}[A-Z0-9]{16}[A-Z]{2}[A-Z0-9]{2})(?![A-Z0-9])'),
        description="Plivo Auth ID",
        confidence="medium",
    ),

    # ── Razorpay ─────────────────────────────────────────────
    KeyPattern(
        service="Razorpay",
        key_type="Key ID",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(rzp_live_[A-Za-z0-9]{14})(?![A-Za-z0-9_])'),
        description="Razorpay live key ID",
        confidence="high",
    ),
    KeyPattern(
        service="Razorpay",
        key_type="Key Secret",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{20})(?![A-Za-z0-9])'),
        description="Razorpay key secret (20 chars)",
        confidence="low",
    ),
    KeyPattern(
        service="Razorpay",
        key_type="Test Key ID",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(rzp_test_[A-Za-z0-9]{14})(?![A-Za-z0-9_])'),
        description="Razorpay test key ID",
        confidence="medium",
    ),

    # ── Coinbase ─────────────────────────────────────────────
    KeyPattern(
        service="Coinbase",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])([A-Za-z0-9]{16})(?![A-Za-z0-9\-])'),
        description="Coinbase API key (16 chars)",
        confidence="low",
    ),

    # ── Binance ──────────────────────────────────────────────
    KeyPattern(
        service="Binance",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{64})(?![A-Za-z0-9])'),
        description="Binance API key (64 chars)",
        confidence="low",
    ),

    # ── OpenWeatherMap ───────────────────────────────────────
    KeyPattern(
        service="OpenWeatherMap",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([a-f0-9]{32})(?![A-Fa-f0-9])'),
        description="OpenWeatherMap API key (32 hex)",
        confidence="low",
    ),

    # ── Mapbox ───────────────────────────────────────────────
    KeyPattern(
        service="Mapbox",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(pk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9\.])'),
        description="Mapbox public access token",
        confidence="high",
    ),
    KeyPattern(
        service="Mapbox",
        key_type="Secret Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(sk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9\.])'),
        description="Mapbox secret access token",
        confidence="high",
    ),

    # ── Algolia ──────────────────────────────────────────────
    KeyPattern(
        service="Algolia",
        key_type="Admin API Key",
        pattern=re.compile(r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])'),
        description="Algolia Admin API key (32 hex)",
        confidence="low",
    ),

    # ── Yelp ─────────────────────────────────────────────────
    KeyPattern(
        service="Yelp",
        key_type="API Key",
        pattern=re.compile(r'(?i)(?:yelp|fusion)[_\-\s]*(?:api)?[_\-\s]*(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{80,200})["\']?'),
        description="Yelp Fusion API key (via context)",
        confidence="medium",
    ),

    # ── Wolfram Alpha ────────────────────────────────────────
    KeyPattern(
        service="Wolfram Alpha",
        key_type="App ID",
        pattern=re.compile(r'(?<![A-Z0-9\-])([A-Z0-9]{6}-[A-Z0-9]{10})(?![A-Z0-9\-])'),
        description="Wolfram Alpha App ID",
        confidence="medium",
    ),

    # ── RapidAPI ─────────────────────────────────────────────
    KeyPattern(
        service="RapidAPI",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])([a-f0-9]{50})(?![A-Za-z0-9])'),
        description="RapidAPI key (50 hex chars)",
        confidence="medium",
    ),

    # ── Sentry ───────────────────────────────────────────────
    KeyPattern(
        service="Sentry",
        key_type="DSN",
        pattern=re.compile(r'(https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+)'),
        description="Sentry DSN with embedded auth key",
        confidence="high",
    ),

    # ── Linear ───────────────────────────────────────────────
    KeyPattern(
        service="Linear",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(lin_api_[A-Za-z0-9]{40,50})(?![A-Za-z0-9_])'),
        description="Linear API key",
        confidence="high",
    ),

    # ── Vercel ───────────────────────────────────────────────
    KeyPattern(
        service="Vercel",
        key_type="API Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(vercel_[A-Za-z0-9_-]{24,})(?![A-Za-z0-9_-])'),
        description="Vercel API token",
        confidence="high",
    ),

    # ── Supabase ─────────────────────────────────────────────
    KeyPattern(
        service="Supabase",
        key_type="Service Role Key",
        pattern=re.compile(r'(?<![A-Za-z0-9\.])(sbp_[A-Fa-f0-9]{40})(?![A-Za-z0-9\.])'),
        description="Supabase service role / project API key",
        confidence="high",
    ),

    # ── Planetscale ──────────────────────────────────────────
    KeyPattern(
        service="PlanetScale",
        key_type="Password",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(pscale_pw_[A-Za-z0-9_-]{30,60})(?![A-Za-z0-9_-])'),
        description="PlanetScale database password",
        confidence="high",
    ),
    KeyPattern(
        service="PlanetScale",
        key_type="OAuth Token",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(pscale_tkn_[A-Za-z0-9_-]{30,60})(?![A-Za-z0-9_-])'),
        description="PlanetScale OAuth token",
        confidence="high",
    ),

    # ── Livekit ──────────────────────────────────────────────
    KeyPattern(
        service="LiveKit",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9])(API[A-Za-z0-9]{9,12})(?![A-Za-z0-9])'),
        description="LiveKit API key",
        confidence="medium",
    ),

    # ── Clerk ────────────────────────────────────────────────
    KeyPattern(
        service="Clerk",
        key_type="Secret Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,60})(?![A-Za-z0-9_])'),
        description="Clerk secret key",
        confidence="high",
    ),
    KeyPattern(
        service="Clerk",
        key_type="Publishable Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(pk_live_[A-Za-z0-9]{24,60})(?![A-Za-z0-9_])'),
        description="Clerk publishable key",
        confidence="high",
    ),

    # ── Resend ───────────────────────────────────────────────
    KeyPattern(
        service="Resend",
        key_type="API Key",
        pattern=re.compile(r'(?<![A-Za-z0-9_])(re_[A-Za-z0-9_]{30,50})(?![A-Za-z0-9_])'),
        description="Resend email API key",
        confidence="high",
    ),

    # ── Postmark ─────────────────────────────────────────────
    KeyPattern(
        service="Postmark",
        key_type="Server Token",
        pattern=re.compile(r'(?<![A-Za-z0-9\-])([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?![A-Za-z0-9\-])'),
        description="Postmark server API token (UUID format)",
        confidence="low",
    ),

    # ── WhatsApp Business ────────────────────────────────────
    KeyPattern(
        service="WhatsApp",
        key_type="Access Token",
        pattern=re.compile(r'(?<![A-Za-z0-9])(EAA[A-Za-z0-9]{100,300})(?![A-Za-z0-9])'),
        description="WhatsApp Business API token (same as Meta Graph token)",
        confidence="high",
    ),

    # ── Private Keys ─────────────────────────────────────────
    KeyPattern(
        service="SSH/TLS",
        key_type="Private Key",
        pattern=re.compile(r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)'),
        description="PEM-encoded private key",
        confidence="high",
    ),

    # ── Generic high-entropy secrets with context ────────────
    KeyPattern(
        service="Generic",
        key_type="API Key (context-based)",
        pattern=re.compile(
            r'(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)'
            r'[\s]*[=:]\s*["\']?([A-Za-z0-9\-_\.]{20,100})["\']?'
        ),
        description="Generic secret found via variable name context (api_key=, secret=, token=, etc.)",
        confidence="medium",
    ),
    KeyPattern(
        service="Generic",
        key_type="Password",
        pattern=re.compile(
            r'(?i)(?:password|passwd|pwd|db_password|database_password|mysql_password|postgres_password)'
            r'[\s]*[=:]\s*["\']([^"\']{8,100})["\']'
        ),
        description="Password found via variable name context",
        confidence="medium",
    ),
    KeyPattern(
        service="Generic",
        key_type="Connection String",
        pattern=re.compile(
            r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s"\'<>]{10,200}'
        ),
        description="Database/service connection string with credentials",
        confidence="high",
    ),
]


# Filter out low-confidence patterns unless explicitly requested
def get_patterns(include_low_confidence: bool = False) -> list[KeyPattern]:
    """Return patterns filtered by confidence level."""
    if include_low_confidence:
        return PATTERNS
    return [p for p in PATTERNS if p.confidence != "low"]


# Binary file extensions to skip during scanning
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".sqlite", ".db", ".sqlite3",
    ".DS_Store", ".lock",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".next", ".nuxt",
    ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".coverage", "htmlcov",
}

SKIP_PATH_PATTERNS = [
    "locales/",
    "locale/",
    "i18n/",
    "translations/",
    "config/initializers/devise",
    "config/initializers/doorkeeper",
    "config/initializers/omniauth",
    "config/initializers/warden",
    "config/initializers/sorcery",
    "devise/passwords",
    "devise/sessions",
    "devise/registrations",
    "devise/confirmations",
    "devise/unlocks",
    "test/fixtures",
    "spec/fixtures",
    "test/factories",
    "spec/factories",
    "mock/",
    "mocks/",
    "fixture/",
    "fixtures/",
    "__tests__/",
    "__snapshots__/",
    "testdata/",
    "test_data/",
    ".github/workflows/",
    ".buildkite/",
    ".circleci/",
    ".travis.yml",
    "jenkinsfile",
    "docker-compose",
]
