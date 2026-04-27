"""
audit.py — Append-only security audit logger.
Every security-relevant event is recorded permanently.
"""

import json
import os
import time
import logging
from pathlib import Path

# Ensure logs directory exists
LOG_DIR = Path(os.environ.get("LOG_DIR", "./logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "security.log"

# Separate security logger — writes to security.log, never to stdout
security_logger = logging.getLogger("security_audit")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False  # don't leak to root logger / stdout

_handler = logging.FileHandler(str(LOG_PATH), mode='a', encoding='utf-8')
_handler.setFormatter(logging.Formatter('%(message)s'))
security_logger.addHandler(_handler)


def _log(event_type: str, data: dict) -> None:
    """Core logging function — all audit events pass through here."""
    entry = {
        "timestamp": time.time(),
        "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event_type,
        **data
    }
    try:
        security_logger.info(json.dumps(entry, default=str))
    except Exception:
        # Logging must never crash the app
        pass


# ─────────────────────────────────────────────────────────────
# Public audit functions
# ─────────────────────────────────────────────────────────────

def log_injection_attempt(user_id: str, content: str, source: str, pattern: str) -> None:
    """Log a detected prompt injection attempt."""
    _log("INJECTION_ATTEMPT", {
        "user_id": user_id,
        "source": source,
        "matched_pattern": pattern,
        "content_preview": content[:200],
        "severity": "HIGH",
    })


def log_blocked_action(tool: str, input_val: str, reason: str) -> None:
    """Log a blocked tool call or action."""
    _log("BLOCKED_TOOL_CALL", {
        "tool": tool,
        "input_preview": input_val[:200],
        "reason": reason,
        "severity": "MEDIUM",
    })


def log_auth_failure(ip: str, username: str) -> None:
    """Log a failed authentication attempt."""
    _log("AUTH_FAILURE", {
        "ip": ip,
        "username": username,
        "severity": "HIGH",
    })


def log_auth_success(ip: str, user_id: str) -> None:
    """Log a successful authentication."""
    _log("AUTH_SUCCESS", {
        "ip": ip,
        "user_id": user_id,
        "severity": "INFO",
    })


def log_tool_call(user_id: str, tool: str, inputs: dict, output_preview: str) -> None:
    """Log every tool call for forensic trail."""
    _log("TOOL_CALL", {
        "user_id": user_id,
        "tool": tool,
        "inputs": inputs,
        "output_preview": output_preview[:200],
        "severity": "INFO",
    })


def log_rate_limit(user_id: str, endpoint: str, ip: str = "") -> None:
    """Log a rate limit hit."""
    _log("RATE_LIMIT_HIT", {
        "user_id": user_id,
        "endpoint": endpoint,
        "ip": ip,
        "severity": "MEDIUM",
    })


def log_internal_error(error: str, error_type: str, context: str = "") -> None:
    """Log an internal error without exposing it to the user."""
    _log("INTERNAL_ERROR", {
        "error": error[:500],
        "type": error_type,
        "context": context[:200],
        "severity": "HIGH",
    })


def log_suspicious_history(user_id: str, turn_index: int, pattern: str) -> None:
    """Log when injection is found in conversation history."""
    _log("SUSPICIOUS_HISTORY", {
        "user_id": user_id,
        "turn_index": turn_index,
        "matched_pattern": pattern,
        "severity": "HIGH",
    })


def log_tool_limit_exceeded(user_id: str, count: int, limit: int) -> None:
    """Log when tool call limit is exceeded in a single turn."""
    _log("TOOL_LIMIT_EXCEEDED", {
        "user_id": user_id,
        "tool_call_count": count,
        "limit": limit,
        "severity": "MEDIUM",
    })
