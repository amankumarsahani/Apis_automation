# GitHub API Key Scanner

Scans GitHub repositories for accidentally leaked API keys, tests if they're still active, and saves results to Google Sheets.

## Supported Key Types (30+)

AWS, OpenAI, Anthropic, Google (API/OAuth/Service Account), GitHub (PAT/Fine-Grained/OAuth/App), Stripe, Slack, Twilio, SendGrid, Mailgun, Firebase, Heroku, DigitalOcean, Azure, PayPal, Shopify, Square, Telegram, Discord, Mailchimp, npm, PyPI, Docker Hub, Supabase/JWT, Cloudflare, Datadog, HashiCorp Vault, SSH/TLS Private Keys, Generic secrets (passwords, connection strings, API keys by context).

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

### 3. GitHub Token

Create a GitHub Personal Access Token at https://github.com/settings/tokens with `repo` scope (for private repos) or no scopes (public only).

### 4. Google Sheets (Service Account)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → Enable "Google Sheets API" and "Google Drive API"
3. Create a Service Account → Download JSON key
4. Save as `config/google_credentials.json`
5. Set `SHARE_WITH_EMAIL` in `.env` to your email (so you can access the sheet)

## Usage

### Scan all repos of a user/org

```bash
python main.py scan-user <username>
python main.py scan-user microsoft --max-repos 50
```

### Scan a specific repo

```bash
python main.py scan-repo https://github.com/user/repo
```

### Scan multiple repos from a file

```bash
python main.py scan-repos repos.txt
```

Where `repos.txt` contains one URL per line.

### Options

| Flag | Description |
|------|-------------|
| `--no-test` | Skip API key validation (faster scan) |
| `--no-sheets` | Skip Google Sheets saving (print to terminal only) |
| `--include-low` | Include low-confidence matches (more false positives) |
| `--verbose` / `-v` | Debug logging |
| `--json` | Output results as JSON |

## Examples

```bash
# Quick scan, no sheets
python main.py scan-user johndoe --no-sheets

# Full scan with testing and sheet export
python main.py scan-user mycompany --max-repos 200

# Scan specific repo, output JSON
python main.py scan-repo https://github.com/user/repo --json

# Include all patterns (high false-positive rate)
python main.py scan-user target --include-low --no-test
```

## Google Sheets Output

Results are saved with:
- **Masked + full API keys**
- **Active/Inactive status** (color-coded)
- **Service identification** (which API the key belongs to)
- **Source location** (repo, file, line number, commit)
- **Additional metadata** (account info for active keys)
- **Summary sheet** with totals and breakdown

## Architecture

```
main.py                  → CLI entry point
orchestrator.py          → Pipeline: scan → detect → test → report
scanners/
  patterns.py            → 30+ regex patterns for key detection
  github_scanner.py      → GitHub repo cloning & scanning
testers/
  key_tester.py          → API validation for 18+ services
utils/
  sheets_reporter.py     → Google Sheets output with formatting
  logger.py              → Colored terminal logging
config/
  settings.py            → Environment configuration
```

## Security Notes

- **Only scan your own repos** or repos you have permission to scan
- Active keys found should be **rotated immediately**
- The tool does not store raw keys locally (only in the Google Sheet you control)
- The `.gitignore` prevents accidental commit of credentials
