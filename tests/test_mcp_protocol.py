#!/usr/bin/env python3
"""MCP protocol-level end-to-end test: starts the mock agent and the actual
server.py over stdio, then drives it with a real MCP client (initialize,
list_tools, call_tool) — the exact path Claude Code uses."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(HERE)
PORT = 9877
URL = f"http://127.0.0.1:{PORT}"


def wait_ping(timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(URL + "/ping", timeout=2) as r:
                return r.status == 200
        except Exception:
            time.sleep(0.2)
    return False


async def main():
    tmp = tempfile.mkdtemp(prefix="remote-mcp-")
    cfg_path = os.path.join(tmp, "hosts.json")
    with open(cfg_path, "w") as f:
        json.dump({"hosts": {"mock": {"url": URL, "token": "test-token", "cwd": tmp, "platform": "win32"}}, "active": "mock"}, f)

    mock = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "mock_agent.py"), str(PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_ping():
            raise RuntimeError("mock agent did not come up")

        params = StdioServerParameters(
            command=sys.executable,
            args=[os.path.join(SERVER_DIR, "server.py"), "--config", cfg_path],
            cwd=SERVER_DIR,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = sorted(t.name for t in tools.tools)
                print("tools via protocol:", len(names))
                assert len(names) == 14, names

                r = await session.call_tool("remote_bash", {"command": "echo mcp-ok", "host": "mock"})
                text = "".join(b.text for b in r.content if b.type == "text")
                print("call_tool remote_bash ->", repr(text))
                assert "mcp-ok" in text and "exit=0" in text, text
                assert not r.isError, r

                r2 = await session.call_tool("remote_bash", {"command": "__mock_fail__", "host": "mock"})
                print("call_tool error path isError =", r2.isError)
                assert r2.isError, "expected isError for failing command"

                r3 = await session.call_tool("remote_env", {"host": "mock"})
                t3 = "".join(b.text for b in r3.content if b.type == "text")
                print("call_tool remote_env ->", repr(t3[:60]))
                assert "mock" in t3

                # shell session persistence across two protocol calls
                await session.call_tool("remote_shell_exec", {"command": "cd " + tmp, "host": "mock"})
                r4 = await session.call_tool("remote_shell_exec", {"command": "pwd", "host": "mock"})
                t4 = "".join(b.text for b in r4.content if b.type == "text")
                print("shell state across calls ->", repr(t4.splitlines()[-1]))
                assert tmp in t4, t4

                print("\nMCP protocol e2e: ALL OK")
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except Exception:
            mock.kill()


if __name__ == "__main__":
    asyncio.run(main())
