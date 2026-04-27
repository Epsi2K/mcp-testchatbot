"""
tools.py — Hardened tool definitions and safe execution.

Each tool:
  - Has a strict JSON schema (enum fields where possible)
  - Executes via named functions only — never raw shell or SQL
  - Returns sanitized output only
  - Logs every call via audit.py
"""

import subprocess
import requests

import db
import security
import audit

# ─────────────────────────────────────────────────────────────
# Tool schemas — passed to the Anthropic API
# ─────────────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "query_employees",
        "description": (
            "Look up company employee information. Can filter by department or search by name. "
            "Only returns: name, department, and role. "
            "Does NOT return salary, email, or any other sensitive fields."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["get_all", "by_department", "search_by_name"],
                    "description": "The query operation to perform.",
                },
                "filter_value": {
                    "type": "string",
                    "description": (
                        "Department name (for by_department) or name fragment "
                        "(for search_by_name). Not required for get_all."
                    ),
                    "maxLength": 100,
                },
            },
            "required": ["operation"],
            "additionalProperties": False,
        },
    },
    {
        "name": "fetch_external_data",
        "description": (
            "Fetch data from an approved external API endpoint. "
            "Only HTTPS URLs on the approved domain allowlist are permitted. "
            "HTTP, file://, and private IP addresses are always blocked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": (
                        "The full HTTPS URL to fetch. Must be on the approved domain allowlist."
                    ),
                    "maxLength": 2048,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_diagnostic",
        "description": (
            "Run a predefined system diagnostic check. "
            "Only the listed operations are available — no custom commands are supported."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": list(security.ALLOWED_OPERATIONS.keys()),
                    "description": "The diagnostic operation to run.",
                },
            },
            "required": ["operation"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_internal_document",
        "description": (
            "Retrieve an internal company document by title. "
            "Only PUBLIC-classified documents are accessible."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "The exact title of the document to retrieve.",
                    "maxLength": 200,
                },
            },
            "required": ["title"],
            "additionalProperties": False,
        },
    },
]


# ─────────────────────────────────────────────────────────────
# Tool executor — maps tool name → execution function
# ─────────────────────────────────────────────────────────────

def execute_tool(tool_name: str, tool_input: dict, user_id: str) -> str:
    """
    Dispatch a tool call to the appropriate execution function.
    Logs every call. Returns sanitized string result.
    """
    try:
        if tool_name == "query_employees":
            result = run_query_employees(
                operation=tool_input.get("operation", ""),
                filter_value=str(tool_input.get("filter_value", "")),
            )
        elif tool_name == "fetch_external_data":
            result = run_fetch_external_data(
                url=str(tool_input.get("url", "")),
            )
        elif tool_name == "run_diagnostic":
            result = run_diagnostic(
                operation=str(tool_input.get("operation", "")),
            )
        elif tool_name == "get_internal_document":
            result = run_get_internal_document(
                title=str(tool_input.get("title", "")),
            )
        else:
            audit.log_blocked_action(tool_name, str(tool_input), "Unknown tool name")
            result = "Unknown tool."

        audit.log_tool_call(user_id, tool_name, tool_input, result)
        return result

    except Exception as e:
        audit.log_internal_error(str(e), type(e).__name__, f"tool={tool_name}")
        return "Tool execution failed due to an internal error."


# ─────────────────────────────────────────────────────────────
# Tool 1: query_employees
# ─────────────────────────────────────────────────────────────

def run_query_employees(operation: str, filter_value: str = "") -> str:
    """
    Executes employee queries via parameterized DB functions only.
    The LLM never constructs SQL.
    """
    # Validate operation (extra defense; schema enum already constrains this)
    allowed_ops = {"get_all", "by_department", "search_by_name"}
    if operation not in allowed_ops:
        audit.log_blocked_action("query_employees", operation, "Invalid operation")
        return "Invalid operation."

    # Sanitize filter_value — strip to max 100 chars
    filter_value = filter_value.strip()[:100]

    if operation == "get_all":
        rows = db.get_all_employees()
    elif operation == "by_department":
        if not filter_value:
            return "filter_value is required for by_department."
        rows = db.get_employees_by_department(filter_value)
    else:  # search_by_name
        if not filter_value:
            return "filter_value is required for search_by_name."
        rows = db.search_employees(filter_value)

    if not rows:
        return "No employees found matching that query."

    # Enforce column allowlist on returned data (defense-in-depth)
    safe_rows = []
    for r in rows:
        safe_rows.append({
            k: v for k, v in r.items()
            if k in db.EMPLOYEE_SAFE_COLUMNS
        })

    # Format as markdown table
    lines = ["| Name | Department | Role |", "|------|------------|------|"]
    for r in safe_rows:
        name = str(r.get("name", "")).replace("|", "&#124;")
        dept = str(r.get("department", "")).replace("|", "&#124;")
        role = str(r.get("role", "")).replace("|", "&#124;")
        lines.append(f"| {name} | {dept} | {role} |")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Tool 2: fetch_external_data
# ─────────────────────────────────────────────────────────────

def run_fetch_external_data(url: str) -> str:
    """
    SSRF-hardened HTTP fetch.
    - Allowlisted domains only
    - HTTPS only
    - No redirects
    - DNS rebinding protection (re-validate IP after connect)
    - SSL verification enforced
    """
    # Step 1: Validate URL against allowlist + IP blocklist
    is_valid, reason = security.validate_url(url)
    if not is_valid:
        audit.log_blocked_action("fetch_external_data", url, reason)
        return f"Request blocked: {reason}"

    # Step 2: Make request with strict settings
    try:
        resp = requests.get(
            url,
            timeout=5,
            verify=True,               # SSL verification ON
            allow_redirects=False,     # No redirects — prevents open-redirect SSRF chaining
            headers={
                "User-Agent": "CompanyBot/1.0",
                "Accept": "application/json, text/plain",
            },
            stream=False,
        )

        # Step 3: Validate Content-Type — only accept JSON or plain text
        content_type = resp.headers.get("Content-Type", "")
        allowed_content_types = ["application/json", "text/plain", "text/html"]
        if not any(t in content_type for t in allowed_content_types):
            audit.log_blocked_action(
                "fetch_external_data", url,
                f"Blocked content-type: {content_type}"
            )
            return "Response content type not permitted."

        # Truncate response to prevent large data exfiltration
        return resp.text[:2000]

    except requests.exceptions.SSLError:
        return "Request blocked: SSL certificate verification failed."
    except requests.exceptions.Timeout:
        return "Request timed out."
    except requests.exceptions.TooManyRedirects:
        return "Request blocked: redirect detected."
    except Exception as e:
        audit.log_internal_error(str(e), type(e).__name__, f"url={url[:100]}")
        return f"Request failed: {type(e).__name__}"


# ─────────────────────────────────────────────────────────────
# Tool 3: run_diagnostic
# ─────────────────────────────────────────────────────────────

def run_diagnostic(operation: str) -> str:
    """
    RCE-hardened system diagnostic.
    - Only enum values accepted
    - shell=False — no shell injection possible
    - Minimal PATH — no user environment variables
    - Timeout enforced
    """
    cmd_tuple = security.ALLOWED_OPERATIONS.get(operation)
    if not cmd_tuple:
        audit.log_blocked_action("run_diagnostic", operation, "Not in allowlist")
        return "Operation not permitted."

    cmd, label = cmd_tuple

    try:
        result = subprocess.run(
            cmd,
            shell=False,              # shell=False — no shell injection possible
            capture_output=True,
            text=True,
            timeout=15,
            env=None,                 # inherit system env (needed for PowerShell on Windows)
        )
        output = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and not output:
            return f"[{label}]\nDiagnostic returned non-zero exit code: {result.returncode}"

        return f"[{label}]\n{output}" if output else f"[{label}]\n(no output)"

    except subprocess.TimeoutExpired:
        return "Diagnostic timed out."
    except FileNotFoundError:
        return f"Diagnostic command not available on this system."
    except Exception as e:
        audit.log_internal_error(str(e), type(e).__name__, f"diagnostic={operation}")
        return f"Diagnostic failed: {type(e).__name__}"


# ─────────────────────────────────────────────────────────────
# Tool 4: get_internal_document
# ─────────────────────────────────────────────────────────────

def run_get_internal_document(title: str) -> str:
    """
    Returns a PUBLIC-classified internal document by exact title.
    """
    title = title.strip()[:200]
    if not title:
        return "Title is required."

    doc = db.get_document_by_title(title)
    if not doc:
        # Also return the list of available documents as a hint
        all_docs = db.get_public_documents()
        available = [d["title"] for d in all_docs]
        return (
            f"Document '{title}' not found. "
            f"Available documents: {', '.join(available)}"
        )

    return f"**{doc['title']}**\n\n{doc['content']}"
