"""
app.py — Flask application with defense-in-depth security middleware.

Security layers:
  - Security headers on every response (CSP, HSTS, X-Frame-Options, etc.)
  - Rate limiting (flask-limiter)
  - JWT authentication on protected endpoints
  - Input validation before touching the agent
  - History sanitization
  - Generic error responses (no internal details leaked)
  - No debug mode, no admin endpoints, no version disclosure
"""

import os
import sys
import logging

from dotenv import load_dotenv

# Load .env FIRST — before importing anything that reads env vars
load_dotenv()

# Validate required env vars at startup — fail loudly
_required_vars = ["GROQ_API_KEY", "JWT_SECRET"]
_missing = [v for v in _required_vars if not os.environ.get(v)]
if _missing:
    print(f"[FATAL] Missing required environment variables: {', '.join(_missing)}", file=sys.stderr)
    print("[FATAL] Copy .env.example to .env and fill in the required values.", file=sys.stderr)
    sys.exit(1)

from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import db
import security
import agent
import audit
import mcp_client
from auth import require_auth, verify_credentials, generate_token

# ─────────────────────────────────────────────────────────────
# App initialization
# ─────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates")
app.config["DEBUG"] = False
app.config["TESTING"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False

# CORS — restrict to same origin only
CORS(app, resources={r"/*": {"origins": []}})

# Rate limiter — keyed by remote IP
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Suppress Flask's default server header
logging.getLogger("werkzeug").setLevel(logging.ERROR)


# ─────────────────────────────────────────────────────────────
# Security headers middleware
# ─────────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """Apply security headers to every response."""
    # Content Security Policy — blocks XSS, inline scripts, external resources
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    # Remove server fingerprint
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)

    return response


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Serve the single-page application."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    """
    Public health check — returns only status.
    No version info, no debug data, no environment info.
    """
    return jsonify({"status": "ok"}), 200


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """
    Authenticate user and return JWT.
    Rate-limited to 5 attempts per minute per IP.
    """
    ip = request.remote_addr or "unknown"

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    # Basic input validation
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid credentials"}), 401
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) > 100 or len(password) > 256:
        audit.log_auth_failure(ip, username[:50])
        return jsonify({"error": "Invalid credentials"}), 401

    if not verify_credentials(username, password):
        audit.log_auth_failure(ip, username[:50])
        # Generic error — no hint about which field is wrong
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(username.strip().lower())
    audit.log_auth_success(ip, username.strip().lower())

    return jsonify({"token": token}), 200


@app.route("/chat", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def chat():
    """
    Main chat endpoint. Requires valid JWT.
    Rate-limited to 10 requests per minute per IP.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    message = data.get("message", "")
    history = data.get("history", [])

    # Validate message
    if not isinstance(message, str):
        return jsonify({"error": "Message must be a string"}), 400

    is_valid, reason = security.validate_user_message(message)
    if not is_valid:
        return jsonify({"error": reason}), 400

    # Validate + truncate history
    if not isinstance(history, list):
        return jsonify({"error": "Invalid history format"}), 400

    # Truncate to prevent context stuffing
    history = history[-(security.MAX_HISTORY_TURNS * 2):]

    # Validate history structure — each item must be a dict with role + content
    clean_history = []
    for turn in history:
        if (
            isinstance(turn, dict)
            and turn.get("role") in ("user", "assistant")
            and isinstance(turn.get("content"), str)
        ):
            clean_history.append({
                "role": turn["role"],
                "content": turn["content"],
            })

    try:
        response_text, updated_history = agent.run_agent(
            user_message=message,
            conversation_history=clean_history,
            user_id=request.user_id,
        )

        return jsonify({
            "response": response_text,
            "history": updated_history,
        }), 200

    except Exception as e:
        audit.log_internal_error(str(e), type(e).__name__, "chat_endpoint")
        return jsonify({"error": "An internal error occurred"}), 500


@app.route("/reset", methods=["POST"])
@limiter.limit("20 per minute")
@require_auth
def reset():
    """Reset conversation history for the current user."""
    return jsonify({"status": "ok", "history": []}), 200


# ─────────────────────────────────────────────────────────────
# Error handlers — generic messages, no internal details
# ─────────────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Authentication required"}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(429)
def ratelimit_handler(e):
    user_id = getattr(request, "user_id", "anonymous")
    audit.log_rate_limit(user_id, request.path, request.remote_addr or "")
    return jsonify({"error": "Too many requests. Please slow down."}), 429


@app.errorhandler(500)
def internal_error(e):
    audit.log_internal_error(str(e), type(e).__name__, "flask_error_handler")
    return jsonify({"error": "An internal error occurred"}), 500


# ─────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────

def startup():
    """Initialize database and MCP servers."""
    db.initialize_database()
    print("[INFO] Database initialized.")

    docs_dir = os.environ.get("DOCS_DIR", "./docs")
    db_path = os.environ.get("DB_PATH", "./data/company.db")
    mcp_client.init_mcp_servers(docs_dir=docs_dir, db_path=db_path)

    print("[INFO] Employee Connect Agent started. debug=False")
    print(f"[INFO] Listening on http://127.0.0.1:{os.environ.get('PORT', 5000)}")


if __name__ == "__main__":
    startup()
    port = int(os.environ.get("PORT", 5000))
    # debug=False is critical for production — never expose debug mode
    app.run(host="127.0.0.1", port=port, debug=False)
