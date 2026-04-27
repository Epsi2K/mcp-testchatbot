"""
mcp_client.py — MCP server manager for filesystem and SQLite servers.

Runs a persistent background asyncio event loop so Flask (sync) can
call MCP tools without spawning a new process on every request.

Servers started:
  - @modelcontextprotocol/server-filesystem  -> tools prefixed mcp_fs__
  - @modelcontextprotocol/server-sqlite      -> tools prefixed mcp_db__
"""

import asyncio
import threading
import os
import sys
from typing import Optional

# ── MCP SDK ───────────────────────────────────────────────────
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import audit

# ─────────────────────────────────────────────────────────────
# Background event loop (shared by all MCP clients)
# ─────────────────────────────────────────────────────────────

_loop = asyncio.new_event_loop()
_loop_thread = threading.Thread(target=_loop.run_forever, daemon=True)
_loop_thread.start()


def _run_async(coro, timeout: int = 30):
    """Submit a coroutine to the background loop and block until done."""
    return asyncio.run_coroutine_threadsafe(coro, _loop).result(timeout=timeout)


# ─────────────────────────────────────────────────────────────
# Tool allowlists — only expose safe, read-oriented tools
# ─────────────────────────────────────────────────────────────

_FS_ALLOWED_TOOLS = {
    "read_file",
    "list_directory",
    "search_files",
    "get_file_info",
    "directory_tree",
    "list_allowed_directories",
}

_DB_ALLOWED_TOOLS = {
    "read_query",
    "list_tables",
    "describe_table",
}


# ─────────────────────────────────────────────────────────────
# MCP server client
# ─────────────────────────────────────────────────────────────

class MCPServerClient:
    """
    Wraps a single MCP server (stdio transport) with a persistent
    async worker loop. Exposes synchronous call_tool() for Flask.
    """

    def __init__(self, name: str, prefix: str, command: str, args: list,
                 allowed_tools: set):
        self.name = name
        self.prefix = prefix          # e.g. "mcp_fs__"
        self._command = command
        self._args = args
        self._allowed_tools = allowed_tools
        self._queue: Optional[asyncio.Queue] = None
        self._tools: list = []
        self._ready = threading.Event()
        self._start_error: Optional[Exception] = None

    def start(self):
        """Start the MCP server subprocess and wait for it to be ready."""
        asyncio.run_coroutine_threadsafe(self._worker(), _loop)
        if not self._ready.wait(timeout=60):
            raise RuntimeError(
                f"MCP server '{self.name}' did not become ready in time. "
                f"Error: {self._start_error}"
            )
        if self._start_error:
            raise RuntimeError(
                f"MCP server '{self.name}' failed to start: {self._start_error}"
            )

    async def _worker(self):
        """Persistent async worker: holds the MCP session open."""
        try:
            params = StdioServerParameters(
                command=self._command,
                args=self._args,
                env={**os.environ},
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    # Discover and filter tools
                    result = await session.list_tools()
                    self._tools = [
                        t for t in result.tools
                        if t.name in self._allowed_tools
                    ]

                    # Signal ready
                    self._queue = asyncio.Queue()
                    self._ready.set()

                    # Process tool call requests
                    while True:
                        item = await self._queue.get()
                        if item is None:
                            break
                        tool_name, tool_args, fut = item
                        try:
                            res = await session.call_tool(tool_name, tool_args)
                            fut.set_result(res)
                        except Exception as exc:
                            fut.set_exception(exc)

        except Exception as exc:
            self._start_error = exc
            self._ready.set()

    def get_tools(self) -> list:
        return self._tools

    def call_tool(self, tool_name: str, tool_args: dict, timeout: int = 15):
        """Synchronously call an MCP tool and return its result object."""
        if self._queue is None:
            raise RuntimeError(f"MCP server '{self.name}' is not ready.")

        async def _enqueue():
            fut = asyncio.get_running_loop().create_future()
            await self._queue.put((tool_name, tool_args, fut))
            return await fut

        return asyncio.run_coroutine_threadsafe(_enqueue(), _loop).result(timeout=timeout)


# ─────────────────────────────────────────────────────────────
# Server instances
# ─────────────────────────────────────────────────────────────

_fs_client: Optional[MCPServerClient] = None
_db_client: Optional[MCPServerClient] = None


def init_mcp_servers(docs_dir: str, db_path: str):
    """
    Start both MCP servers. Call once at app startup.
    docs_dir — absolute path to the documents directory.
    db_path  — absolute path to the SQLite database file.
    """
    global _fs_client, _db_client

    docs_dir = os.path.abspath(docs_dir)
    db_path = os.path.abspath(db_path)

    print(f"[MCP] Starting filesystem server -> {docs_dir}")
    _fs_client = MCPServerClient(
        name="filesystem",
        prefix="mcp_fs__",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", docs_dir],
        allowed_tools=_FS_ALLOWED_TOOLS,
    )
    _fs_client.start()
    print(f"[MCP] Filesystem server ready. Tools: {[t.name for t in _fs_client.get_tools()]}")

    print(f"[MCP] Starting SQLite server -> {db_path}")
    _db_client = MCPServerClient(
        name="sqlite",
        prefix="mcp_db__",
        command="uvx",
        args=["mcp-server-sqlite", "--db-path", db_path],
        allowed_tools=_DB_ALLOWED_TOOLS,
    )
    _db_client.start()
    print(f"[MCP] SQLite server ready. Tools: {[t.name for t in _db_client.get_tools()]}")


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def get_mcp_tools_for_groq() -> list:
    """
    Return all allowed MCP tools formatted as Groq function definitions.
    Tool names are prefixed (mcp_fs__ / mcp_db__) to avoid collisions.
    """
    tools = []
    for client in [_fs_client, _db_client]:
        if client is None:
            continue
        for tool in client.get_tools():
            tools.append({
                "type": "function",
                "function": {
                    "name": f"{client.prefix}{tool.name}",
                    "description": tool.description or "",
                    "parameters": tool.inputSchema or {
                        "type": "object", "properties": {}
                    },
                },
            })
    return tools


def is_mcp_tool(name: str) -> bool:
    return name.startswith("mcp_fs__") or name.startswith("mcp_db__")


def dispatch_mcp_tool(prefixed_name: str, tool_args: dict, user_id: str) -> str:
    """
    Route a prefixed tool call to the correct MCP server and return
    a plain string result.
    """
    if prefixed_name.startswith("mcp_fs__"):
        tool_name = prefixed_name[len("mcp_fs__"):]
        client = _fs_client
    elif prefixed_name.startswith("mcp_db__"):
        tool_name = prefixed_name[len("mcp_db__"):]
        client = _db_client
    else:
        return f"Unknown MCP tool: {prefixed_name}"

    if client is None:
        return "MCP server not initialized."

    try:
        result = client.call_tool(tool_name, tool_args)
        # Extract text from MCP content blocks
        parts = []
        for block in result.content:
            if hasattr(block, "text") and block.text:
                parts.append(block.text)
        return "\n".join(parts) if parts else "(no output)"

    except Exception as exc:
        audit.log_internal_error(str(exc), type(exc).__name__,
                                 f"mcp_tool={prefixed_name},user={user_id}")
        return f"MCP tool error: {type(exc).__name__}"
