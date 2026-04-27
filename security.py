"""
security.py — Security utilities: input validation, URL allowlist, command allowlist,
output sanitization, and prompt injection detection.
"""

import re
import html
import ipaddress
import socket
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────
# 1a. Input Validation
# ─────────────────────────────────────────────────────────────

MAX_MESSAGE_LENGTH = 1000   # characters
MAX_HISTORY_TURNS = 20      # conversation turns kept


def validate_user_message(message: str) -> tuple[bool, str]:
    """Returns (is_valid, reason_if_invalid)."""
    if not message or not message.strip():
        return False, "Empty message"
    if len(message) > MAX_MESSAGE_LENGTH:
        return False, f"Message exceeds {MAX_MESSAGE_LENGTH} character limit"
    return True, ""


# ─────────────────────────────────────────────────────────────
# 1b. URL Allowlist Validator (SSRF defense)
# ─────────────────────────────────────────────────────────────

# Only these specific domains are allowed for MCP/HTTP tool calls
ALLOWED_DOMAINS = {
    "api.company.com",
    "httpbin.org",                      # for testing — remove in prod
    "jsonplaceholder.typicode.com",     # for testing — remove in prod
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/GCP/Azure IMDS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 private (ULA)
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("::/128"),            # IPv6 unspecified
]


def _ip_is_blocked(ip_str: str) -> bool:
    """Returns True if the IP address falls within any blocked network."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable — block it
    for network in BLOCKED_IP_NETWORKS:
        try:
            if ip in network:
                return True
        except TypeError:
            # Mixed IPv4/IPv6 comparison — skip
            continue
    return False


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validates a URL against allowlist + blocks private/internal IPs.
    Returns (is_valid, reason_if_invalid).

    Defends against:
    - SSRF to internal services (private IP ranges)
    - SSRF to cloud metadata endpoints (169.254.x.x)
    - Non-HTTPS schemes (file://, gopher://, dict://, ftp://, http://)
    - DNS rebinding (resolve then check)
    - Direct IP addresses in URL
    - Domains not on the approved allowlist
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    # Reject URLs that are suspiciously long
    if len(url) > 2048:
        return False, "URL exceeds maximum length"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"

    # Scheme must be HTTPS only — blocks file://, http://, gopher://, dict://, ftp://
    if parsed.scheme != "https":
        return False, "Only HTTPS URLs are permitted"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    # Block if hostname is a raw IP address (before DNS resolution)
    try:
        ipaddress.ip_address(hostname)
        return False, "Direct IP addresses are not permitted"
    except ValueError:
        pass  # it's a hostname — continue

    # Check domain allowlist BEFORE resolving (fast rejection)
    hostname_lower = hostname.lower()
    on_allowlist = (
        hostname_lower in ALLOWED_DOMAINS
        or any(hostname_lower.endswith("." + d) for d in ALLOWED_DOMAINS)
    )
    if not on_allowlist:
        return False, f"Domain '{hostname}' is not on the approved allowlist"

    # Resolve hostname to IP and check against blocked ranges (DNS rebinding defense)
    try:
        # getaddrinfo returns all addresses (IPv4 + IPv6)
        results = socket.getaddrinfo(hostname, None)
        if not results:
            return False, "Could not resolve hostname"
        for result in results:
            ip_str = result[4][0]
            if _ip_is_blocked(ip_str):
                return False, "Access to internal/private IP ranges is not permitted"
    except socket.gaierror:
        return False, "Could not resolve hostname"

    return True, ""


# ─────────────────────────────────────────────────────────────
# 1c. Command Allowlist (RCE defense)
# ─────────────────────────────────────────────────────────────

# ONLY these named operations are permitted. The LLM picks from this enum.
# It never constructs a shell string. Ever.
ALLOWED_OPERATIONS: dict[str, tuple[list[str], str]] = {
    "disk_usage": (
        ["powershell", "-NoProfile", "-Command",
         "Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}},@{N='Free(GB)';E={[math]::Round($_.Free/1GB,2)}} | Format-Table -AutoSize | Out-String"],
        "Disk usage",
    ),
    "memory_usage": (
        ["powershell", "-NoProfile", "-Command",
         "$os = Get-CimInstance Win32_OperatingSystem; "
         "[PSCustomObject]@{"
         "  'Total(MB)' = [math]::Round($os.TotalVisibleMemorySize/1KB, 0);"
         "  'Free(MB)'  = [math]::Round($os.FreePhysicalMemory/1KB, 0);"
         "  'Used(MB)'  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)/1KB, 0)"
         "} | Format-List | Out-String"],
        "Memory usage",
    ),
    "uptime": (
        ["powershell", "-NoProfile", "-Command",
         "$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "
         "\"Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m\""],
        "System uptime",
    ),
    "cpu_load": (
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Processor | Select-Object Name,LoadPercentage | Format-List | Out-String"],
        "CPU load",
    ),
    "process_count": (
        ["powershell", "-NoProfile", "-Command",
         "\"Running processes: $((Get-Process).Count)\""],
        "Process count",
    ),
}


def get_allowed_operations_list() -> list[str]:
    return list(ALLOWED_OPERATIONS.keys())


# ─────────────────────────────────────────────────────────────
# 1d. Output Sanitizer (XSS + sensitive data defense)
# ─────────────────────────────────────────────────────────────

# Patterns that indicate sensitive data leaking in LLM output
SENSITIVE_PATTERNS = [
    r'(?i)(password|passwd|secret|api[_\-]?key|token|credential|auth[_\-]?key)\s*[:=]\s*\S+',
    r'(?i)aws[_\-]?(secret|access)[_\-]?key\s*[:=]\s*\S+',
    r'(?i)sk-[a-zA-Z0-9]{20,}',         # Anthropic/OpenAI API key patterns
    r'(?i)-----BEGIN [A-Z ]+PRIVATE KEY-----',
    r'(?i)(Authorization|Bearer)\s+[A-Za-z0-9\-._~+/]+=*',
    r'(?i)(database[_\-]?url|db[_\-]?password)\s*[:=]\s*\S+',
]


def redact_llm_output(text: str) -> str:
    """Redact accidentally leaked secrets from LLM output. Safe to store in history."""
    for pattern in SENSITIVE_PATTERNS:
        text = re.sub(pattern, '[REDACTED]', text)
    return text


def sanitize_llm_output(text: str) -> str:
    """
    Full sanitization for frontend delivery: redact secrets + HTML-escape.
    Do NOT store the result of this in conversation history — use redact_llm_output for that.
    """
    text = redact_llm_output(text)
    return html.escape(text)


# ─────────────────────────────────────────────────────────────
# 1e. Prompt Injection Screen
# ─────────────────────────────────────────────────────────────

INJECTION_INDICATORS = [
    r'(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions',
    r'(?i)disregard\s+(your|all|previous|prior)',
    r'(?i)forget\s+(everything|all|your|previous)',
    r'(?i)you\s+are\s+now\s+(a|an|in)',
    r'(?i)new\s+(role|persona|identity|instructions|task|directive)',
    r'(?i)system\s+(override|prompt|mode|bypass|reset)',
    r'(?i)act\s+as\s+(if|a|an)',
    r'(?i)pretend\s+(you\s+are|to\s+be)',
    r'(?i)jailbreak',
    r'(?i)\bDAN\b',
    r'(?i)maintenance\s+mode',
    r'(?i)developer\s+mode',
    r'(?i)unrestricted\s+mode',
    r'(?i)override\s+(your|all|safety|security|previous)',
    r'(?i)bypass\s+(your|all|safety|security|restrictions)',
    r'(?i)reveal\s+(your|the)\s+(system\s+)?prompt',
    r'(?i)print\s+(your|the)\s+(system\s+)?prompt',
    r'(?i)show\s+(me\s+)?(your|the)\s+(system\s+)?prompt',
    r'(?i)what\s+(are\s+your|is\s+your)\s+(system\s+)?instructions',
    r'(?i)repeat\s+(everything|all)\s+(above|before)',
    r'(?i)sudo\s+',
    r'(?i)\[SYSTEM\]',
    r'(?i)\[INST\]',
    r'(?i)<\|system\|>',
    r'(?i)###\s*system',
    r'(?i)###\s*instruction',
]


def screen_for_injection(text: str) -> tuple[bool, str]:
    """
    Checks text (user input OR tool result content) for prompt injection patterns.
    Returns (injection_detected, matched_pattern).
    """
    if not text or not isinstance(text, str):
        return False, ""
    for pattern in INJECTION_INDICATORS:
        if re.search(pattern, text):
            return True, pattern
    return False, ""
