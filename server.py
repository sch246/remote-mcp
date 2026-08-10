#!/usr/bin/env python3
"""
remote-mcp — MCP server for executing on remote hosts.

Talks to a standalone, single-file agent.py HTTP daemon (stdlib only) running
on the target machine, and exposes its capabilities as MCP tools: read/write/
edit files, run shell commands, persistent PTY sessions, stream large files
with sha256 verification, and manage background processes. Works on Linux and
Windows; the design exists for machines where SSH / WinRM / SMB are unavailable
(e.g. a passwordless Windows box whose accounts/registry cannot be changed).

Config file format (default ~/.config/remote-agent-mcp/hosts.json):
    { "hosts": { "<alias>": { "url": "http://host:7777", "token": "...", "cwd": "...", "platform": "win32" } }, "active": "<alias>" }

This format is compatible with the pi coding-agent's ~/.pi/remote-hosts.json,
so you can point this server at it with --config ~/.pi/remote-hosts.json and
share host definitions between the two tools.

Design notes:
  * Explicit over implicit — tools are named remote_* so the model knows the
    call goes to a remote host. There are no hidden redirections of local tools.
  * Paths are NOT remapped: they go to the remote verbatim. Call remote_env
    first to learn the remote cwd / platform.
  * Windows remote shells default to cmd.exe, not bash.
  * remote_spawn discards output unless `stdout` names a file.
  * Shell-session cache is in-memory (lost on server restart); agent.py restart
    is recovered by the 404/410 retry in remote_shell_exec.
  * remote_write is capped at 8 MiB (base64-in-JSON). Larger files use
    remote_upload / remote_download.

Run / register with:
    pip install -r requirements.txt
    claude mcp add --scope user remote-mcp -- python <this-file>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

DEFAULT_CONFIG = Path.home() / ".config" / "remote-agent-mcp" / "hosts.json"
MAX_WRITE_BYTES = 8 * 1024 * 1024  # agent.py caps /write (base64-in-JSON)

_CONFIG: Path = DEFAULT_CONFIG

# In-memory per-(host, session) shell cache: (host alias, session name) -> session uuid.
# Lost on server restart; the 404/410 retry path re-opens stale sessions.
_SESSION_CACHE: dict[tuple[str, str], str] = {}

_client: httpx.Client | None = None


def get_client() -> httpx.Client:
    """Lazily-built shared HTTP client. Generous timeouts: exec can run long."""
    global _client
    if _client is None:
        _client = httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=600.0, write=600.0, pool=10.0),
        )
    return _client


mcp = FastMCP(
    "remote-mcp",
    instructions=(
        "Tools for executing on remote hosts via the agent.py HTTP daemon. "
        "Every tool takes an optional `host` parameter (default: the active host). "
        "Start remote work with remote_env to learn the remote platform/shell/tools. "
        "remote_bash is one-shot; use remote_shell_exec when state (cd/env/REPL) must "
        "persist. Long-running processes use remote_spawn with a `stdout` file path. "
        "Paths are remote paths, sent verbatim — there is no local↔remote mapping. "
        "Windows targets default to cmd.exe."
    ),
)


# ---------------------------------------------------------------------------
# Config + host resolution
# ---------------------------------------------------------------------------

def load_config() -> dict:
    path = os.environ.get("REMOTE_AGENT_CONFIG") or str(_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        raise ValueError(f"remote-hosts config not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"bad JSON in {path}: {e}")
    hosts = cfg.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        raise ValueError(f"no hosts configured in {path}")
    return {"hosts": hosts, "active": cfg.get("active")}


def resolve_host(host: str) -> tuple[str, dict]:
    """Return (alias, entry) for a host. Precedence: explicit host= param >
    REMOTE_AGENT_HOST env (--host override) > config 'active'."""
    cfg = load_config()
    alias = host or os.environ.get("REMOTE_AGENT_HOST") or cfg.get("active")
    if not alias:
        raise ValueError(
            "no host selected: pass host=<alias>, or set a host active in the config"
        )
    entry = cfg["hosts"].get(alias)
    if not entry:
        raise ValueError(
            f"unknown host '{alias}' (configured: {', '.join(cfg['hosts'])})"
        )
    return alias, entry


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def rpc(alias: str, entry: dict, method: str, path: str, payload=None):
    """JSON-in JSON-out RPC. Raises ValueError on non-2xx with the agent's message."""
    url = entry["url"].rstrip("/") + path
    headers = {"Authorization": f"Bearer {entry['token']}"}
    kwargs = {}
    if payload is not None:
        kwargs["json"] = payload
    try:
        resp = get_client().request(method, url, headers=headers, **kwargs)
    except httpx.HTTPError as e:
        raise ValueError(f"{alias}: {e}")
    if resp.status_code < 200 or resp.status_code >= 300:
        msg = resp.text
        try:
            msg = json.loads(resp.text).get("error") or msg
        except Exception:
            pass
        raise ValueError(f"{path} {resp.status_code}: {msg}")
    if not resp.content:
        return {}
    try:
        return resp.json()
    except Exception:
        raise ValueError(f"{path}: bad JSON: {resp.text[:200]}")


def exec_ndjson(alias: str, entry: dict, command: str, cwd=None, timeout=None):
    """POST /exec, parse NDJSON stream. Returns (stdout, stderr, exit_code).
    An error frame with exit_code set = timeout (partial output, exit null);
    an error frame without exit_code = genuine failure."""
    payload = {"command": command}
    if cwd:
        payload["cwd"] = cwd
    if timeout is not None:
        payload["timeout"] = timeout
    url = entry["url"].rstrip("/") + "/exec"
    headers = {
        "Authorization": f"Bearer {entry['token']}",
        "Content-Type": "application/json",
    }
    out_parts: list[str] = []
    err_parts: list[str] = []
    exit_code = None
    error_msg = None
    try:
        with get_client().stream("POST", url, json=payload, headers=headers) as resp:
            if resp.status_code != 200:
                body = resp.read().decode("utf-8", "replace")
                raise ValueError(f"/exec {resp.status_code}: {body[:300]}")
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    f = json.loads(line)
                except Exception:
                    continue
                # Real agent.py hand-rolls chunk framing inside the body
                # ("<hex-len>\r\n<frame>\r\n"); tolerate those bare-number lines.
                if not isinstance(f, dict):
                    continue
                t = f.get("t")
                if t in ("out", "err"):
                    (out_parts if t == "out" else err_parts).append(f.get("d") or "")
                elif t == "exit":
                    exit_code = f.get("code")
                elif t == "error":
                    error_msg = f.get("msg")
    except httpx.HTTPError as e:
        raise ValueError(f"{alias}: {e}")
    if error_msg and exit_code is None:
        raise ValueError(error_msg)
    return "".join(out_parts), "".join(err_parts), exit_code


# ---------------------------------------------------------------------------
# Shell session helpers
# ---------------------------------------------------------------------------

def shell_open(alias: str, entry: dict, session: str) -> str:
    """POST /shell/open, cache and return the session uuid."""
    payload = {"shell": "bash", "label": session}
    if entry.get("cwd"):
        payload["cwd"] = entry["cwd"]
    res = rpc(alias, entry, "POST", "/shell/open", payload)
    session_uuid = res.get("id")
    _SESSION_CACHE[(alias, session)] = session_uuid
    return session_uuid


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def remote_hosts() -> str:
    """List configured remote hosts and which one is active (the default for tools called without a `host`)."""
    cfg = load_config()
    lines = ["Remote hosts:"]
    for name, h in cfg["hosts"].items():
        marker = "*" if name == cfg.get("active") else " "
        lines.append(
            f"  {marker} {name}  {h.get('url')}  "
            f"cwd={h.get('cwd', '<auto>')}  platform={h.get('platform', '<?>')}"
        )
    lines.append(f"Active: {cfg.get('active') or '<none>'}")
    return "\n".join(lines)


@mcp.tool()
def remote_read(path: str, host: str = "") -> str:
    """Read a file from a remote host and return its text content. For binary
    files or large payloads use remote_download instead."""
    alias, entry = resolve_host(host)
    res = rpc(alias, entry, "POST", "/read", {"path": path})
    data = base64.b64decode(res.get("data_b64", ""))
    return data.decode("utf-8", errors="replace")


@mcp.tool()
def remote_write(path: str, content: str, host: str = "") -> str:
    """Write a UTF-8 text file to a remote host. Capped at 8 MiB — use
    remote_upload for larger files."""
    data = content.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        raise ValueError("content exceeds 8 MiB — use remote_upload instead")
    alias, entry = resolve_host(host)
    rpc(alias, entry, "POST", "/write", {
        "path": path,
        "data_b64": base64.b64encode(data).decode("ascii"),
    })
    return f"wrote {len(data)} bytes to {path} on '{alias}'"


@mcp.tool()
def remote_edit(path: str, old_text: str, new_text: str, host: str = "") -> str:
    """Apply a targeted text edit to a file on a remote host. old_text must
    occur exactly once in the file, else the edit fails (same semantics as the
    local edit tool)."""
    alias, entry = resolve_host(host)
    res = rpc(alias, entry, "POST", "/read", {"path": path})
    data = base64.b64decode(res.get("data_b64", "")).decode("utf-8", errors="replace")
    n = data.count(old_text)
    if n == 0:
        raise ValueError(f"old_text not found in {path}")
    if n > 1:
        raise ValueError(f"old_text found {n} times in {path} — make it unique")
    new_data = data.replace(old_text, new_text, 1)
    rpc(alias, entry, "POST", "/write", {
        "path": path,
        "data_b64": base64.b64encode(new_data.encode("utf-8")).decode("ascii"),
    })
    return f"edited {path} on '{alias}': replaced 1 occurrence"


@mcp.tool()
def remote_bash(
    command: str,
    cwd: str = "",
    timeout: float | None = None,
    host: str = "",
) -> str:
    """Run a one-off shell command on a remote host and return stdout/stderr/exit
    code. Windows targets default to cmd.exe. For long-running or stateful work
    use remote_spawn / remote_shell_exec."""
    alias, entry = resolve_host(host)
    workdir = cwd or entry.get("cwd") or None
    out, err, code = exec_ndjson(alias, entry, command, cwd=workdir, timeout=timeout)
    parts = [f"$ {command}", f"exit={code if code is not None else 'null'}"]
    if out:
        parts.append(out)
    if err:
        parts.append(err)
    return "\n".join(parts)


@mcp.tool()
def remote_shell_exec(
    command: str,
    session: str = "default",
    timeout_sec: float | None = None,
    host: str = "",
) -> str:
    """Execute a command in a persistent remote shell session. Unlike
    remote_bash (one-shot), state persists across calls: cd, env vars,
    virtualenvs, REPL state. The session is lazily created on first use; a
    404/410 (agent restarted) is recovered by re-opening once. On timeout the
    output captured so far is returned with exit_code=null (not an error)."""
    alias, entry = resolve_host(host)
    session_uuid = _SESSION_CACHE.get((alias, session))
    if not session_uuid:
        session_uuid = shell_open(alias, entry, session)
    last_error: str | None = None
    for attempt in range(2):
        try:
            payload = {"id": session_uuid, "command": command}
            if timeout_sec is not None:
                payload["timeout_sec"] = timeout_sec
            res = rpc(alias, entry, "POST", "/shell/exec", payload)
            exit_code = res.get("exit_code")
            status = res.get("status", "")
            output = res.get("output", "")
            prefix = "[timed out] " if status == "timeout" else ""
            return (
                f"{prefix}{alias}/{session} $ {command}\n"
                f"exit={exit_code if exit_code is not None else 'null (timeout)'}\n"
                f"{output}"
            )
        except ValueError as e:
            last_error = str(e)
            if attempt == 0 and (" 404:" in last_error or " 410:" in last_error):
                # stale session after agent restart: evict and re-open once
                _SESSION_CACHE.pop((alias, session), None)
                try:
                    session_uuid = shell_open(alias, entry, session)
                except ValueError as oe:
                    raise ValueError(
                        f'session "{session}" on \'{alias}\' was lost and re-open failed: {oe}'
                    ) from oe
                continue
            break
    raise ValueError(f"remote_shell_exec failed: {last_error}")


@mcp.tool()
def remote_shell(
    action: str,
    session: str = "default",
    data: str = "",
    lines: int = 50,
    cols: int = 0,
    rows: int = 0,
    label: str = "",
    host: str = "",
) -> str:
    """Manage persistent remote shell sessions. action: list | peek | close |
    input | interrupt | resize | relabel. Unlike remote_shell_exec this does NOT
    auto-create sessions — a session must exist first (list to see open ones)."""
    alias, entry = resolve_host(host)

    if action == "list":
        res = rpc(alias, entry, "GET", "/shell/list", None)
        sessions = res.get("sessions") or []
        if not sessions:
            return f"no open shell sessions on '{alias}'"
        body = "\n".join(
            f"  {s.get('id')}  label={s.get('label') or '<none>'}" for s in sessions
        )
        return f"Shell sessions on '{alias}':\n{body}"

    session_uuid = _SESSION_CACHE.get((alias, session))
    if not session_uuid:
        raise ValueError(
            f'session "{session}" is not open on \'{alias}\' — call '
            "remote_shell_exec first to lazily create it."
        )

    if action == "peek":
        res = rpc(alias, entry, "POST", "/shell/peek", {"id": session_uuid, "lines": lines})
        return f"{alias}/{session} (last {res.get('lines')} lines):\n{res.get('output', '')}"
    if action == "close":
        res = rpc(alias, entry, "POST", "/shell/close", {"id": session_uuid})
        _SESSION_CACHE.pop((alias, session), None)
        return (
            f'session "{session}" on \'{alias}\' '
            f"{'closed' if res.get('closed') else 'was already closed/missing'}"
        )
    if action == "input":
        if not data:
            raise ValueError('action "input" requires "data" (UTF-8 text to write to PTY stdin)')
        res = rpc(alias, entry, "POST", "/shell/input", {"id": session_uuid, "data": data})
        return f"wrote {res.get('written')} bytes to {alias}/{session}"
    if action == "interrupt":
        res = rpc(alias, entry, "POST", "/shell/interrupt", {"id": session_uuid})
        return (
            f"sent SIGINT to {alias}/{session}: "
            f"{'delivered' if res.get('signalled') else 'no foreground process (PID gone)'}"
        )
    if action == "resize":
        if not cols or not rows:
            raise ValueError('action "resize" requires both "cols" and "rows" (positive integers)')
        res = rpc(alias, entry, "POST", "/shell/resize", {"id": session_uuid, "cols": cols, "rows": rows})
        return f"resized {alias}/{session} to {res.get('cols')}x{res.get('rows')}"
    if action == "relabel":
        if not label:
            raise ValueError('action "relabel" requires "label" (string; pass " " to clear)')
        res = rpc(alias, entry, "POST", "/shell/relabel", {"id": session_uuid, "label": label})
        return f"relabeled {alias}/{session} -> {json.dumps(res.get('label'))}"

    raise ValueError(f"unknown action '{action}' (list|peek|close|input|interrupt|resize|relabel)")


@mcp.tool()
def remote_upload(local_path: str, remote_path: str, host: str = "") -> str:
    """Stream a local file to a remote host with end-to-end sha256 verification.
    local_path is an absolute/relative path on THIS machine; remote_path is a
    remote path sent verbatim. Use for large files (over ~8 MiB)."""
    alias, entry = resolve_host(host)
    local = os.path.abspath(local_path)
    if not os.path.isfile(local):
        raise ValueError(f"local file not found: {local}")
    sha = hashlib.sha256()
    size = 0
    with open(local, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
            size += len(chunk)
    digest = sha.hexdigest()
    url = entry["url"].rstrip("/") + "/upload"
    headers = {
        "Authorization": f"Bearer {entry['token']}",
        "Content-Type": "application/octet-stream",
        "X-Path": remote_path,
        "X-Sha256": digest,
    }
    try:
        # httpx sends Content-Length from the file object and streams the body.
        with open(local, "rb") as f:
            resp = get_client().post(url, content=f, headers=headers)
    except httpx.HTTPError as e:
        raise ValueError(f"{alias}: {e}")
    if resp.status_code != 200:
        msg = resp.text
        try:
            msg = json.loads(resp.text).get("error") or msg
        except Exception:
            pass
        raise ValueError(f"/upload {resp.status_code}: {msg}")
    try:
        info = resp.json()
    except Exception:
        info = {}
    return (
        f"uploaded {os.path.basename(local)} -> {remote_path} on '{alias}': "
        f"{info.get('bytes', size)} bytes, sha256={info.get('sha256', digest)}"
    )


@mcp.tool()
def remote_download(remote_path: str, local_path: str, host: str = "") -> str:
    """Stream a remote file to a local path with end-to-end sha256 verification.
    Local parent directories are auto-created. local_path is on THIS machine;
    remote_path is a remote path sent verbatim."""
    alias, entry = resolve_host(host)
    local = os.path.abspath(local_path)
    os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
    url = entry["url"].rstrip("/") + "/download"
    headers = {"Authorization": f"Bearer {entry['token']}"}
    got = ""
    try:
        with get_client().stream("GET", url, params={"path": remote_path}, headers=headers) as resp:
            if resp.status_code != 200:
                body = resp.read().decode("utf-8", "replace")
                raise ValueError(f"/download {resp.status_code}: {body[:300]}")
            expected_sha = (resp.headers.get("x-sha256") or "").lower() or None
            expected_size = int(resp.headers.get("content-length") or 0) or None
            h = hashlib.sha256()
            written = 0
            tmp = local + ".part"
            with open(tmp, "wb") as f:
                for chunk in resp.iter_bytes():
                    f.write(chunk)
                    h.update(chunk)
                    written += len(chunk)
            got = h.hexdigest()
            if expected_sha and got != expected_sha:
                os.remove(tmp)
                raise ValueError(f"sha256 mismatch: got {got}, expected {expected_sha}")
            if expected_size and written != expected_size:
                os.remove(tmp)
                raise ValueError(f"size mismatch: got {written}, expected {expected_size}")
            os.replace(tmp, local)  # atomic on same volume (.part sibling)
    except httpx.HTTPError as e:
        raise ValueError(f"{alias}: {e}")
    return f"downloaded {remote_path} -> {local} on '{alias}': {written} bytes, sha256={got}"


@mcp.tool()
def remote_env(host: str = "") -> str:
    """Describe a remote host: OS, platform, shells, and installed tools with
    versions. Run this once at the start of remote work to know what's there."""
    alias, entry = resolve_host(host)
    env = rpc(alias, entry, "GET", "/env", None)
    os_info = env.get("os") or {}
    py = env.get("python") or {}
    shells = env.get("shells") or {}
    tools = env.get("tools") or {}
    lines = [
        f"Host '{alias}' ({entry.get('url')})",
        f"  agent: v{env.get('agent_version', '?')}",
        f"  platform: {env.get('platform')}  os: {os_info.get('system')} {os_info.get('release')} ({os_info.get('machine')})",
        f"  user: {env.get('user')}  hostname: {env.get('hostname')}",
        f"  home: {env.get('home')}  cwd: {env.get('cwd')}",
        f"  python: {py.get('version')} ({py.get('executable')})",
        "  shells: " + ("  ".join(f"{n}={p}" for n, p in shells.items()) or "<none>"),
        "  tools:",
    ]
    lines.extend(f"    {n.ljust(10)} {v}" for n, v in tools.items())
    if not tools:
        lines.append("    <none>")
    return "\n".join(lines)


@mcp.tool()
def remote_spawn(
    command: str = "",
    argv: list[str] | None = None,
    cwd: str = "",
    stdout: str = "",
    stderr: str = "",
    shell: bool = True,
    env: dict[str, str] | None = None,
    host: str = "",
) -> str:
    """Start a long-running background process on a remote host and return its
    pid immediately. Use `stdout` to name a file for output capture; otherwise
    output is silently discarded. Monitor with remote_proclist, stop with
    remote_kill. The process survives this tool call."""
    alias, entry = resolve_host(host)
    if not command and not argv:
        raise ValueError("provide either command= (shell string) or argv= (list)")
    payload = {
        "cwd": cwd or None,
        "stdout": stdout or None,
        "stderr": stderr or None,
        "shell": shell,
        "env": env,
    }
    if command:
        payload["command"] = command
    if argv:
        payload["argv"] = argv
    res = rpc(alias, entry, "POST", "/spawn", payload)
    cmd = res.get("command")
    cmd_str = cmd if isinstance(cmd, str) else json.dumps(cmd)
    lines = [
        f"spawned pid={res.get('pid')} on '{alias}'",
        f"  command: {cmd_str}",
        f"  cwd:     {res.get('cwd')}",
    ]
    if res.get("stdout"):
        lines.append(f"  stdout:  {res['stdout']}")
    if res.get("stderr"):
        lines.append(f"  stderr:  {res['stderr']}")
    lines.append(f"  Use remote_proclist to monitor or remote_kill(pid={res.get('pid')}) to stop.")
    return "\n".join(lines)


@mcp.tool()
def remote_proclist(host: str = "") -> str:
    """List processes started via remote_spawn on a remote host. Only shows
    processes spawned through THIS agent, not arbitrary OS processes."""
    alias, entry = resolve_host(host)
    res = rpc(alias, entry, "GET", "/list", None)
    procs = res.get("processes") or []
    if not procs:
        return f"no spawned processes on '{alias}'"
    lines = [f"Spawned processes on '{alias}':"]
    for p in procs:
        cmd = p.get("command")
        cmd_str = cmd if isinstance(cmd, str) else json.dumps(cmd)
        lines.append(
            f"  pid={str(p.get('pid', '?')).ljust(6)} {str(p.get('status', '?')).ljust(15)} {cmd_str}"
        )
        if p.get("stdout"):
            lines.append(f"         stdout: {p['stdout']}")
        if p.get("stderr") and p.get("stderr") != p.get("stdout"):
            lines.append(f"         stderr: {p['stderr']}")
    return "\n".join(lines)


@mcp.tool()
def remote_kill(pid: int, signal: str = "TERM", host: str = "") -> str:
    """Stop a process previously started via remote_spawn on a remote host.
    Refuses PIDs the agent doesn't track. signal: TERM (graceful on POSIX) or
    KILL (Windows always force-kills regardless)."""
    alias, entry = resolve_host(host)
    if signal not in ("TERM", "KILL"):
        raise ValueError("signal must be 'TERM' or 'KILL'")
    res = rpc(alias, entry, "POST", "/kill", {"pid": pid, "signal": signal})
    parts = [f"pid={pid} on '{alias}': {res.get('action')}"]
    if res.get("signal"):
        parts.append(f"({res['signal']})")
    if res.get("status"):
        parts.append(f" status={res['status']}")
    return " ".join(parts)


@mcp.tool()
def remote_shutdown(delay: float = 1.0, host: str = "") -> str:
    """Cleanly shut down the agent.py process on the remote host (NOT the OS).
    Designed for hot-reloading a new agent.py. After it runs, the host is
    unreachable until agent.py is restarted. Use with extreme caution."""
    alias, entry = resolve_host(host)
    delay = max(0.1, min(30.0, delay))
    res = rpc(alias, entry, "POST", "/shutdown", {"delay": delay})
    return (
        f"agent on '{alias}' will exit in {res.get('exit_in_seconds')}s\n"
        f"  pid: {res.get('pid')}  version: {res.get('version')}\n"
        "  After it exits, the host is unreachable until agent.py is restarted."
    )


def main() -> None:
    global _CONFIG
    parser = argparse.ArgumentParser(description="remote-mcp server")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="path to hosts.json (default: ~/.config/remote-agent-mcp/hosts.json; "
        "e.g. --config ~/.pi/remote-hosts.json to reuse a pi config)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="default host alias, overrides config 'active'",
    )
    args = parser.parse_args()
    _CONFIG = Path(args.config)
    if args.host:
        os.environ["REMOTE_AGENT_HOST"] = args.host
    mcp.run()


if __name__ == "__main__":
    main()
