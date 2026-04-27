# Employee Connect Agent — Full Capabilities Reference

## Overview

Employee Connect Agent is a secure internal AI assistant powered by **Groq (llama-3.3-70b-versatile)**.
It operates with a hardened agentic loop that enforces strict security controls on every
request, tool call, and response. All actions are logged to `logs/security.log`.

---

## 1. Employee Lookup (Built-in Tool: `query_employees`)

Query the internal employee database. Returns **name, department, and role only** —
salary, email, and other sensitive fields are never exposed.

### Supported operations

| Operation | Description | Example prompt |
|---|---|---|
| `get_all` | Return all employees | "List all employees" |
| `by_department` | Filter by department name | "Who works in Engineering?" |
| `search_by_name` | Search by name fragment | "Find employees named Alice" |

### Available departments
Engineering, HR, Finance, Operations, Product, Sales, Marketing, Legal, Customer Support

### Example prompts
- "Show me all employees in Sales"
- "Who is in the Legal department?"
- "Find employees named Kim"
- "How many people work here?"

---

## 2. System Diagnostics (Built-in Tool: `run_diagnostic`)

Runs pre-approved, read-only Windows system commands. The model picks from a fixed
enum — it never constructs or executes arbitrary shell commands.

### Available operations

| Operation | What it runs | Example prompt |
|---|---|---|
| `disk_usage` | PowerShell `Get-PSDrive` | "Show disk usage" |
| `memory_usage` | `Get-CimInstance Win32_OperatingSystem` | "How much memory is free?" |
| `uptime` | System last boot time delta | "How long has the server been running?" |
| `cpu_load` | `Get-CimInstance Win32_Processor` | "Show CPU load" |
| `process_count` | `(Get-Process).Count` | "How many processes are running?" |

### Security controls
- `shell=False` — no shell injection possible
- Enum-only input — LLM cannot pass arbitrary commands
- 15-second timeout enforced
- Inherits system PATH only

### Example prompts
- "Check disk usage"
- "What is the current memory usage?"
- "Show CPU load"
- "What is the system uptime?"
- "How many processes are running?"

---

## 3. External Data Fetch (Built-in Tool: `fetch_external_data`)

Fetches data from approved external HTTPS endpoints. Heavily hardened against SSRF.

### Approved domains
- `api.company.com`
- `httpbin.org` *(testing only)*
- `jsonplaceholder.typicode.com` *(testing only)*

### Security controls
- HTTPS only — `http://`, `file://`, `ftp://` are blocked
- Domain allowlist enforced before DNS resolution
- Private IP ranges blocked (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)
- DNS rebinding protection — IP re-validated after resolution
- No redirects allowed
- Response truncated to 2,000 characters
- Only `application/json` and `text/plain` content types accepted

### Example prompts
- "Fetch data from https://jsonplaceholder.typicode.com/users/1"
- "Get https://httpbin.org/get"

---

## 4. Internal Documents (Built-in Tool: `get_internal_document`)

Retrieves company documents stored in the SQLite database. Only `PUBLIC`-classified
documents are accessible — confidential documents are never returned.

### Available documents
- Remote Work Policy
- Engineering Onboarding Guide
- Office Hours & Locations
- Benefits Overview

### Example prompts
- "Show me the Remote Work Policy"
- "What are the office hours?"
- "What benefits do employees get?"

---

## 5. MCP Filesystem Server (`mcp_fs__*`)

**Protocol:** Model Context Protocol (MCP) over stdio
**Server:** `@modelcontextprotocol/server-filesystem` (Node.js via npx)
**Root directory:** `./docs/` (read-only access, restricted to this path)

### Available tools

| Tool (prefixed) | Description | Example prompt |
|---|---|---|
| `mcp_fs__list_directory` | List files in the docs folder | "What documents are available?" |
| `mcp_fs__read_file` | Read a document file | "Read the onboarding guide" |
| `mcp_fs__search_files` | Search for files by name pattern | "Search for policy documents" |
| `mcp_fs__directory_tree` | Show full folder tree | "Show the document folder structure" |
| `mcp_fs__get_file_info` | File metadata (size, dates) | "When was the handbook last modified?" |
| `mcp_fs__list_allowed_directories` | Show permitted paths | "What directories can you access?" |

### Documents available in `./docs/`
- `employee-handbook.md` — Working hours, leave policy, benefits, IT policy
- `onboarding-guide.md` — Week 1 & 2 plan, key contacts, tools
- `remote-work-policy.md` — Eligibility, requirements, security rules
- `bot-capabilities.md` — This document

### Security controls
- Scoped strictly to `./docs/` — cannot traverse outside
- Write tools (`write_file`, `create_directory`, `move_file`) are not exposed
- Tool allowlist enforced in `mcp_client.py`

### Example prompts
- "What company documents are available?"
- "Show me the employee handbook"
- "What does the onboarding guide say about week 1?"
- "Search for documents about remote work"

---

## 6. MCP SQLite Server (`mcp_db__*`)

**Protocol:** Model Context Protocol (MCP) over stdio
**Server:** `mcp-server-sqlite` (Python via uvx)
**Database:** `./data/company.db`

### Available tools

| Tool (prefixed) | Description | Example prompt |
|---|---|---|
| `mcp_db__list_tables` | List all tables in the database | "What tables are in the database?" |
| `mcp_db__describe_table` | Show schema for a table | "What columns does the employees table have?" |
| `mcp_db__read_query` | Run a SELECT query | "How many employees are in each department?" |

### Database schema

**`employees` table**
| Column | Type | Notes |
|---|---|---|
| id | INTEGER | Primary key |
| name | TEXT | Employee full name |
| department | TEXT | Department name |
| role | TEXT | Job title |

**`internal_docs` table**
| Column | Type | Notes |
|---|---|---|
| id | INTEGER | Primary key |
| title | TEXT | Document title |
| content | TEXT | Document body |
| classification | TEXT | PUBLIC or CONFIDENTIAL |

### Security controls
- Write operations (`write_query`) are not exposed
- Only `read_query`, `list_tables`, `describe_table` are in the allowlist
- Tool allowlist enforced in `mcp_client.py`

### Example prompts
- "What tables are in the database?"
- "Show the schema of the employees table"
- "How many employees are in each department?"
- "Count all employees"
- "Show me all employees in Marketing"

---

## 7. Security Architecture

### Request pipeline (6 layers)
1. **Prompt injection screen** — regex patterns block jailbreak attempts on user input
2. **History sanitization** — injected turns stripped from conversation history
3. **Hardened system prompt** — strict scope, tool use rules, security rules
4. **Tool call limit** — max 3 tool calls per turn (parallel calls disabled)
5. **Tool result injection screen** — tool output scanned before being fed back to LLM
6. **Output sanitization** — secrets redacted, HTML escaped before sending to frontend

### Authentication
- JWT-based — token required for `/chat` and `/reset` endpoints
- Login rate-limited to 5 attempts/minute per IP
- Passwords stored as bcrypt hashes

### Rate limiting
- `/login` — 5 requests/minute
- `/chat` — 10 requests/minute
- `/reset` — 20 requests/minute

### Audit logging
Every tool call, auth event, injection attempt, and error is logged to `logs/security.log`
in structured JSON format with ISO timestamps.
