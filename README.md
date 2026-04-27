# SecureAI-Bot

A production-hardened, security-first AI chatbot. Built to survive a penetration test targeting SQLi, RCE, SSRF, prompt injection (direct + indirect), XSS, rogue tool chaining, and broken access control.

---

## Architecture

```
Browser (login screen)
     │  JWT auth — stored in memory only, NEVER in localStorage
     ▼
Flask App (app.py)
     │  Security headers (CSP, X-Frame-Options, X-Content-Type-Options …)
     │  Rate limiter (5/min login, 10/min chat)
     │  Auth middleware (JWT verification)
     │  Input validator (length, type checks)
     ▼
Agent Loop (agent.py)
     │  ① Pre-flight injection screen — blocks direct prompt injection
     │  ② History sanitization — strips injected turns from context
     │  ③ LLM call with hardened system prompt
     │  ④ Tool call count limit (max 3 per turn)
     ▼
Tool Execution (tools.py)
     │  query_employees   — parameterized SQL, read-only DB, column allowlist
     │  fetch_external_data — domain allowlist, IP blocklist, HTTPS-only, no redirects
     │  run_diagnostic    — command enum, shell=False, minimal PATH
     │  get_internal_document — PUBLIC classification filter, parameterized query
     ▼
     ⑤ Tool Result Screening — blocks indirect prompt injection
     ⑥ Output Sanitizer — redacts secrets, HTML-escapes
     ▼
Response → textContent (never innerHTML) → User
     │
Audit Log (append-only, logs/security.log)
```

---

## Security Features

| Attack Vector        | Defense                                                                    |
|----------------------|----------------------------------------------------------------------------|
| **SQL Injection**    | Parameterized queries only; read-only SQLite URI; column allowlist         |
| **RCE**              | Tool schema enums enforced by Anthropic API; `shell=False`; command allowlist; minimal PATH |
| **SSRF**             | Domain allowlist; HTTPS-only; IP blocklist (RFC1918 + IMDS + loopback); no redirects; DNS resolve & re-check |
| **Direct Prompt Injection** | Pre-flight regex screen on all user input; hardened system prompt   |
| **Indirect Prompt Injection** | Tool result screening with same regex patterns; LLM instructed to treat results as untrusted data |
| **XSS**              | `textContent` for all user input; DOMPurify for bot markdown; strict CSP header |
| **JWT stored in XSS-accessible storage** | Token stored in JS module scope only — NOT in `localStorage` or `sessionStorage` |
| **Broken Access Control** | `@require_auth` on all protected routes; JWT with 1-hour expiry; no admin/debug endpoints |
| **Secret Leakage**   | Output sanitizer with regex patterns for API keys, passwords, private keys |
| **Rogue Tool Chaining** | Max 3 tool calls per turn; tool scope limited to 4 named functions; LLM cannot construct SQL or shell commands |
| **Context Stuffing** | History truncated to MAX_HISTORY_TURNS; every turn screened for injection |
| **Fingerprinting**   | Server header removed; no version info in /health; no debug mode           |
| **Brute Force**      | Rate limiting: 5/min on /login, 10/min on /chat; bcrypt with timing-safe comparison |
| **Auth Bypass**      | Generic error messages (no username enumeration); constant-time bcrypt check |

---

## Setup

### 1. Install dependencies

```bash
cd secure-ai-bot
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-your-key-here
JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(64))")
USERS=alice:$(python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())")
```

### 3. Run

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Adding Users

Generate a bcrypt hash for a new user's password:

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'their-password', bcrypt.gensalt()).decode())"
```

Add to `USERS` in `.env` (comma-separated):

```
USERS=alice:$2b$12$...,bob:$2b$12$...,carol:$2b$12$...
```

---

## Expanding the Allowed Domain List

Edit `security.py`:

```python
ALLOWED_DOMAINS = {
    "api.company.com",
    "httpbin.org",
    "jsonplaceholder.typicode.com",
    "your-new-domain.com",   # Add here
}
```

Only add domains you own or explicitly trust. The DNS resolution check runs at request time, so adding a domain also implicitly allows all its subdomains (subdomain check is `hostname.endswith("." + domain)`).

---

## Running Tests

```bash
cd secure-ai-bot
python -m pytest tests/ -v
```

Or with unittest:

```bash
python -m unittest discover tests/ -v
```

### What the tests verify

- **SSRF defense**: AWS metadata endpoint, localhost, RFC1918 ranges, `file://`, `http://`, direct IPs, non-allowlisted domains
- **Prompt injection detection**: 20+ patterns including direct and indirect injection
- **RCE defense**: Non-enum operations rejected; `cat /etc/passwd`, `rm -rf /`, null-byte injection all blocked
- **SQLi defense**: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE` all treated as literal strings
- **DB read-only**: Write attempts raise `sqlite3.OperationalError`
- **Column allowlist**: `salary`, `email`, `password` never returned from employee queries
- **Output sanitization**: API keys, passwords, private keys redacted; `<script>` tags HTML-escaped

---

## Security Log

All security events are written to `logs/security.log` in JSON format:

```json
{"timestamp": 1714000000.0, "iso_time": "2024-04-25T10:00:00Z", "event": "INJECTION_ATTEMPT", "user_id": "alice", "source": "user_input", "matched_pattern": "...", "content_preview": "...", "severity": "HIGH"}
{"timestamp": 1714000001.0, "iso_time": "2024-04-25T10:00:01Z", "event": "BLOCKED_TOOL_CALL", "tool": "run_diagnostic", "input_preview": "cat /etc/passwd", "reason": "Not in allowlist", "severity": "MEDIUM"}
```

Event types:
- `INJECTION_ATTEMPT` — prompt injection detected
- `BLOCKED_TOOL_CALL` — tool call rejected by security policy
- `AUTH_FAILURE` — failed login attempt
- `AUTH_SUCCESS` — successful login
- `TOOL_CALL` — every tool execution (forensic trail)
- `RATE_LIMIT_HIT` — rate limit exceeded
- `INTERNAL_ERROR` — server-side error (details never sent to client)
- `SUSPICIOUS_HISTORY` — injection found in conversation history
- `TOOL_LIMIT_EXCEEDED` — per-turn tool call limit hit

---

## What Does NOT Exist (by design)

- No `/admin` route
- No debug endpoints (`/debug`, `/_internal`, etc.)
- No `/status` with version or environment info
- No console logging of sensitive data
- No hardcoded credentials anywhere
- No `debug=True` ever
- No `eval()` or `exec()` anywhere
- No raw SQL string construction
- No `shell=True` in subprocess calls
- No sensitive data in the SQLite database (no salary, no passwords, no notes)
"# mcp-testchatbot" 
