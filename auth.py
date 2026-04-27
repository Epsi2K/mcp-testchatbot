"""
auth.py — JWT authentication + session management.
- JWT stored server-side only (client keeps Bearer token in memory, not localStorage)
- Short expiry (1 hour)
- bcrypt password verification
- Rate-limited login endpoint
- No default credentials — all users from env
"""

import os
import secrets
import time
from functools import wraps

import bcrypt
import jwt
from flask import request, jsonify

import audit

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_SECONDS = 3600   # 1 hour


def _get_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET", "")
    if not secret or len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set or is too short. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(64))\""
        )
    return secret


def _load_users() -> dict[str, bytes]:
    """
    Load users from USERS env var.
    Format: USERS=alice:$2b$12$...,bob:$2b$12$...
    Returns dict of {username: bcrypt_hash_bytes}
    """
    users_str = os.environ.get("USERS", "")
    if not users_str:
        return {}

    users: dict[str, bytes] = {}
    for pair in users_str.split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        username, hashed = pair.split(":", 1)
        username = username.strip().lower()
        hashed = hashed.strip()
        if username and hashed:
            users[username] = hashed.encode("utf-8")
    return users


# ─────────────────────────────────────────────────────────────
# Token management
# ─────────────────────────────────────────────────────────────

def generate_token(user_id: str) -> str:
    """Generate a signed JWT for the given user."""
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "jti": secrets.token_hex(16),   # unique token ID — enables future revocation
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Verify a JWT and return its payload.
    Returns None if invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            _get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat", "jti"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ─────────────────────────────────────────────────────────────
# Login verification
# ─────────────────────────────────────────────────────────────

def verify_credentials(username: str, password: str) -> bool:
    """
    Verify username + password against bcrypt hashes from env.
    Constant-time comparison to prevent timing attacks.
    """
    users = _load_users()
    username_lower = username.strip().lower()

    stored_hash = users.get(username_lower)
    if stored_hash is None:
        # Run a dummy bcrypt check to prevent username enumeration via timing
        bcrypt.checkpw(b"dummy_password", b"$2b$12$abcdefghijklmnopqrstuvuTHoVmGEq.dummy")
        return False

    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Flask auth decorator
# ─────────────────────────────────────────────────────────────

def require_auth(f):
    """Decorator for Flask routes that require a valid JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header[7:]
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        payload = verify_token(token)
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Attach user_id to request context
        request.user_id = str(payload["sub"])
        return f(*args, **kwargs)

    return decorated
