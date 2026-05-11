import math
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class EntropyFinding:
    value: str
    entropy: float
    context_key: str
    line_number: int
    confidence: str


# Shannon entropy calculation
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"

ENTROPY_THRESHOLD_BASE64 = 4.5
ENTROPY_THRESHOLD_HEX = 3.5
MIN_SECRET_LENGTH = 16
MAX_SECRET_LENGTH = 500

# Variable names that indicate secrets
SECRET_VARIABLE_PATTERNS = re.compile(
    r'(?i)(?:'
    r'api[_\-]?key|api[_\-]?secret|api[_\-]?token|'
    r'access[_\-]?key|access[_\-]?token|access[_\-]?secret|'
    r'secret[_\-]?key|secret[_\-]?token|'
    r'private[_\-]?key|private[_\-]?token|'
    r'auth[_\-]?key|auth[_\-]?token|auth[_\-]?secret|'
    r'client[_\-]?secret|client[_\-]?id|'
    r'consumer[_\-]?key|consumer[_\-]?secret|'
    r'signing[_\-]?key|signing[_\-]?secret|'
    r'encryption[_\-]?key|'
    r'bearer[_\-]?token|refresh[_\-]?token|'
    r'session[_\-]?key|session[_\-]?secret|'
    r'webhook[_\-]?secret|webhook[_\-]?key|'
    r'app[_\-]?key|app[_\-]?secret|'
    r'service[_\-]?key|service[_\-]?account|'
    r'master[_\-]?key|'
    r'publishable[_\-]?key|'
    r'account[_\-]?key|account[_\-]?secret|account[_\-]?sid|'
    r'database[_\-]?url|database[_\-]?password|'
    r'db[_\-]?password|db[_\-]?pass|'
    r'password|passwd|pwd|'
    r'token|apikey|appkey|'
    r'credentials|'
    r'smtp[_\-]?password|'
    r'aws[_\-]?secret|'
    r'heroku[_\-]?api|'
    r'(?:[a-z_]+)_(?:key|token|secret|password|credential|auth)'
    r')'
)

# Assignment operators — how keys are assigned in code and config
ASSIGNMENT_PATTERNS = re.compile(
    r'(?:'
    r'[\s]*[=:]\s*'       # = or : with optional spaces
    r'|[\s]*=>[\s]*'      # => (JS arrow in objects)
    r'|[\s]*:=[\s]*'      # := (Go short declaration)
    r')'
)

# URL parameter patterns with secrets
URL_SECRET_PARAMS = re.compile(
    r'(?i)[?&](?:key|api_key|apikey|token|access_token|secret|auth|authorization|password|passwd)'
    r'=([A-Za-z0-9\-_%.+/]{16,200})'
)

# HTTP header patterns
HEADER_PATTERNS = re.compile(
    r'(?i)(?:'
    r'(?:Authorization|X-API-Key|X-Auth-Token|X-Access-Token|X-Secret-Key|'
    r'X-Api-Secret|Bearer|Token|Api-Key|Api-Token|X-Token)'
    r'[\s]*[:\s]+[\s]*'
    r')(["\']?)([A-Za-z0-9\-_./+=%]{20,300})\1'
)

# Config file value extraction (YAML, JSON, TOML, .properties)
CONFIG_SECRET_PATTERNS = re.compile(
    r'(?i)(?:api[_\-]?key|secret|token|password|credential|auth|private[_\-]?key|access[_\-]?key)'
    r'["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_./+=]{16,300})["\']'
)

# Environment variable exports
ENV_SECRET_PATTERNS = re.compile(
    r'(?:export\s+|set\s+)?'
    r'([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|API)[A-Z0-9_]*)'
    r'\s*=\s*["\']?([A-Za-z0-9\-_./+=]{16,300})["\']?'
)

# Known non-secret patterns to exclude
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'^[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+$'),  # Java-style package names
    re.compile(r'^(?:true|false|null|none|undefined|nil)$', re.I),
    re.compile(r'^[0-9]+(?:\.[0-9]+)*$'),  # Version numbers
    re.compile(r'^https?://(?!.*[?&](?:key|token|secret|password|auth)=)'),  # Normal URLs without secrets
    re.compile(r'^/[a-z0-9/_-]+$', re.I),  # File paths
    re.compile(r'^\$\{.*\}$'),  # Template variables
    re.compile(r'^\{\{.*\}\}$'),  # Mustache/Jinja templates
    re.compile(r'^%\(.*\)s$'),  # Python string formatting
    re.compile(r'^<.*>$'),  # XML/HTML-like placeholders
]

COMMON_NON_SECRETS = {
    "application/json", "application/xml", "text/html", "text/plain",
    "utf-8", "utf8", "ascii", "latin-1", "iso-8859-1",
    "localhost", "127.0.0.1", "0.0.0.0",
    "production", "development", "staging", "testing",
    "master", "main", "develop",
}


def _shannon_entropy(data: str, charset: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        if c in charset:
            freq[c] = freq.get(c, 0) + 1

    length = sum(freq.values())
    if length == 0:
        return 0.0

    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def _is_high_entropy(value: str) -> bool:
    base64_entropy = _shannon_entropy(value, BASE64_CHARS)
    hex_entropy = _shannon_entropy(value, HEX_CHARS)

    if all(c in HEX_CHARS for c in value) and len(value) >= 32:
        return hex_entropy >= ENTROPY_THRESHOLD_HEX

    return base64_entropy >= ENTROPY_THRESHOLD_BASE64


def _is_false_positive(value: str) -> bool:
    if len(value) < MIN_SECRET_LENGTH or len(value) > MAX_SECRET_LENGTH:
        return True

    if value.lower() in COMMON_NON_SECRETS:
        return True

    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.match(value):
            return True

    # All same character
    if len(set(value)) < 4:
        return True

    # Mostly repeated pattern (like "abcabcabc")
    if len(value) >= 20:
        chunk = value[:4]
        if value == chunk * (len(value) // len(chunk)) + chunk[:len(value) % len(chunk)]:
            return True

    # Common placeholder keywords
    placeholders = [
        "example", "placeholder", "your_", "xxx", "yyy", "zzz",
        "insert_", "replace_", "dummy", "fake", "sample", "test",
        "todo", "fixme", "changeme", "update_this",
    ]
    val_lower = value.lower()
    if any(p in val_lower for p in placeholders):
        return True

    return False


def _extract_value_after_assignment(line: str, match_end: int) -> Optional[str]:
    rest = line[match_end:]
    assignment = ASSIGNMENT_PATTERNS.match(rest)
    if not assignment:
        return None

    after_op = rest[assignment.end():]

    # Strip quotes
    if after_op and after_op[0] in ('"', "'", '`'):
        quote = after_op[0]
        end_idx = after_op.find(quote, 1)
        if end_idx > 0:
            return after_op[1:end_idx]
    else:
        # No quotes — grab until whitespace/comma/semicolon/comment
        m = re.match(r'([A-Za-z0-9\-_./+=:%]+)', after_op)
        if m:
            return m.group(1)

    return None


def scan_line_entropy(line: str, line_number: int) -> list[EntropyFinding]:
    findings = []

    # 1. Variable assignment context — highest signal
    for m in SECRET_VARIABLE_PATTERNS.finditer(line):
        value = _extract_value_after_assignment(line, m.end())
        if value and not _is_false_positive(value) and _is_high_entropy(value):
            findings.append(EntropyFinding(
                value=value,
                entropy=_shannon_entropy(value, BASE64_CHARS),
                context_key=m.group(0),
                line_number=line_number,
                confidence="high",
            ))

    # 2. URL parameters with secret names
    for m in URL_SECRET_PARAMS.finditer(line):
        value = m.group(1)
        if not _is_false_positive(value) and _is_high_entropy(value):
            findings.append(EntropyFinding(
                value=value,
                entropy=_shannon_entropy(value, BASE64_CHARS),
                context_key="url_param",
                line_number=line_number,
                confidence="high",
            ))

    # 3. HTTP headers with tokens
    for m in HEADER_PATTERNS.finditer(line):
        value = m.group(2)
        if not _is_false_positive(value) and _is_high_entropy(value):
            findings.append(EntropyFinding(
                value=value,
                entropy=_shannon_entropy(value, BASE64_CHARS),
                context_key="http_header",
                line_number=line_number,
                confidence="high",
            ))

    # 4. Environment variable exports
    for m in ENV_SECRET_PATTERNS.finditer(line):
        var_name = m.group(1)
        value = m.group(2)
        if not _is_false_positive(value) and _is_high_entropy(value):
            findings.append(EntropyFinding(
                value=value,
                entropy=_shannon_entropy(value, BASE64_CHARS),
                context_key=var_name,
                line_number=line_number,
                confidence="high",
            ))

    # 5. Config file patterns
    for m in CONFIG_SECRET_PATTERNS.finditer(line):
        value = m.group(1)
        if not _is_false_positive(value) and _is_high_entropy(value):
            findings.append(EntropyFinding(
                value=value,
                entropy=_shannon_entropy(value, BASE64_CHARS),
                context_key="config_value",
                line_number=line_number,
                confidence="medium",
            ))

    return findings


def scan_content_entropy(content: str) -> list[EntropyFinding]:
    findings = []
    seen_values: set[str] = set()

    for line_num, line in enumerate(content.split("\n"), 1):
        if not line.strip() or line.strip().startswith("#") and "=" not in line:
            continue

        for finding in scan_line_entropy(line, line_num):
            if finding.value not in seen_values:
                seen_values.add(finding.value)
                findings.append(finding)

    return findings
