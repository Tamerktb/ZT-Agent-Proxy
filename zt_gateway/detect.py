"""
Detection engine — categorized rules with rule IDs (FireClaw/ClawShield-style).

Categories: injection, pii, secret, vuln.
Each finding carries a stable rule_id used in audit records, forensic JSONL,
and the /check endpoint. Action resolution (block/warn/log) happens in policy.py.
"""
import re

# (rule_id, category, name, severity, regex, luhn)
RULES = [
    # ── Prompt injection ──
    ("INJ-001", "injection", "ignore previous instructions", "high",
     r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)", False),
    ("INJ-002", "injection", "forget previous instructions", "high",
     r"forget\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)", False),
    ("INJ-003", "injection", "role override", "high",
     r"you\s+are\s+(now|not\s+bound|free)", False),
    ("INJ-004", "injection", "instruction override", "high",
     r"override\s+(your\s+)?(instructions|programming|directives)", False),
    ("INJ-005", "injection", "system prompt access", "high",
     r"system\s+(prompt|instruction|message)", False),
    ("INJ-006", "injection", "disregard rules", "high",
     r"disregard\s+(all\s+)?(rules|policies|safety)", False),
    ("INJ-007", "injection", "persona swap", "medium",
     r"simulate\s+(a\s+)?(different|new)\s+(persona|role|character)", False),
    ("INJ-008", "injection", "DAN jailbreak", "high", r"\bDAN\b", False),
    ("INJ-009", "injection", "sudo mode", "high", r"sudo\s+mode", False),
    ("INJ-010", "injection", "developer mode", "high", r"developer\s+mode", False),
    ("INJ-011", "injection", "pretend persona", "medium",
     r"pretend\s+(you\s+are|to\s+be)", False),
    ("INJ-012", "injection", "reveal system prompt", "high",
     r"reveal\s+(your\s+)?(system|prompt|instructions)", False),
    ("INJ-013", "injection", "output system prompt", "high",
     r"output\s+your\s+(prompt|instructions|system\s+message)", False),
    ("INJ-014", "injection", "secret leak request", "high",
     r"leak\s+(the\s+)?(prompt|api[-\s]?key|secret|token|password)", False),
    ("INJ-015", "injection", "jailbreak keyword", "high", r"\bjailbreak\b", False),
    ("INJ-016", "injection", "no restrictions claim", "medium",
     r"you\s+(have|are)\s+no\s+(restrictions|filters|limits)", False),

    # ── PII / data exfiltration ──
    ("PII-001", "pii", "credit card number (Luhn)", "high",
     r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b", True),
    ("PII-002", "pii", "US SSN", "high", r"\b\d{3}-\d{2}-\d{4}\b", False),
    ("PII-003", "pii", "email address", "medium",
     r"\b[\w.\-]+@[\w.\-]+\.\w{2,}\b", False),
    ("PII-004", "pii", "sensitive data keyword", "high",
     r"(credit\s*card|social\s*security|passport\s*number)", False),

    # ── Secrets ──
    ("SEC-001", "secret", "AWS access key", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", False),
    ("SEC-002", "secret", "GitHub token", "high", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", False),
    ("SEC-003", "secret", "sk- API key (OpenAI/Anthropic style)", "high",
     r"\bsk-[A-Za-z0-9_\-]{20,}\b", False),
    ("SEC-004", "secret", "JWT", "medium",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", False),
    ("SEC-005", "secret", "private key block", "high",
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----", False),
    ("SEC-006", "secret", "credential assignment", "high",
     r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token)\s*[:=]\s*[\"']?\S{6,}", False),

    # ── Vulnerabilities (probe/exploit payloads in agent traffic) ──
    ("VUL-001", "vuln", "SQL injection", "high",
     r"(?i)(union[\s/*]+select|'\s*or\s*'?\d+'?\s*=\s*'?|sleep\s*\(\s*\d|benchmark\s*\()", False),
    ("VUL-002", "vuln", "XSS payload", "high",
     r"(?i)(<script[\s>]|javascript:alert|onerror\s*=)", False),
    ("VUL-003", "vuln", "command injection", "high",
     r"(?i)(;\s*(?:cat|curl|wget|nc|bash)\s+/|\$\((?:id|whoami|uname)\)|`(?:id|whoami)`)", False),
]

_COMPILED = [(rid, cat, name, sev, re.compile(rx, re.IGNORECASE), luhn)
             for rid, cat, name, sev, rx, luhn in RULES]

MAX_MATCHES = 10


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(match: str, category: str) -> str:
    if category in ("pii", "secret") and len(match) > 6:
        return match[:4] + "*" * (len(match) - 6) + match[-2:]
    if len(match) > 48:
        return match[:48] + "..."
    return match


def inspect_text(text: str) -> list:
    """Return findings: [{rule_id, category, name, severity, match}]."""
    findings = []
    for rid, cat, name, sev, rx, luhn in _COMPILED:
        m = rx.search(text)
        if not m:
            continue
        matched = m.group(0)
        if luhn and not luhn_valid(matched):
            continue  # not a real card number — avoid false positives
        findings.append({
            "rule_id": rid, "category": cat, "name": name,
            "severity": sev, "match": redact(matched, cat),
        })
        if len(findings) >= MAX_MATCHES:
            break
    return findings


def describe() -> list:
    """Rule catalog for the management API."""
    return [{"rule_id": rid, "category": cat, "name": name, "severity": sev}
            for rid, cat, name, sev, _rx, _luhn in RULES]
