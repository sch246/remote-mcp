#!/usr/bin/env python3
"""
Remote agent for LLM coding agents (pi, Claude Code, any MCP client).

Runs on the target machine as a normal user, no admin / no account
changes / no registry edits required.

Clients connect over HTTP with a Bearer token and get:
  - POST /exec     run a command, stream stdout+stderr line by line
  - POST /read     read a small file (binary, base64-encoded in JSON)
  - POST /write    write a small file (binary, base64-encoded in JSON)
  - POST /upload   stream-upload a large file (raw body, sha256-verified)
  - GET  /download stream-download a file (raw body, sha256 in trailer/header)
  - POST /mkdir    mkdir -p
  - POST /stat     stat a path (exists / size / is_dir / mime for images)
  - GET  /ping     liveness + version

Size policy:
  - /read /write keep base64-in-JSON; cap at ~8 MiB to protect memory.
  - /upload /download use raw streaming + sha256; suitable for hundreds of MB.
  - The client picks which one to use based on file size.

Auth: every request must carry  Authorization: Bearer <TOKEN>
TOKEN is read from agent.token next to this file. If the file does not
exist, a random token is generated on first run and printed once.

Bind: by default binds to 0.0.0.0:7777 so it's reachable from the LAN.
Combine with the token + an IP allowlist (see ALLOWED_IPS below) if the
LAN is not fully trusted.

Run:
  python agent.py              # foreground, prints token on first run
  python agent.py --port 7777  # custom port

Auto-start (no admin needed):
  Place a shortcut to `pythonw.exe agent.py` in:
    %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
  Use pythonw.exe (not python.exe) so no console window appears.
"""

import argparse
import base64
import contextlib
import hashlib
import json
import mimetypes
import os
import secrets
import socket
import stat as stat_mod
import subprocess
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VERSION = "0.4.0"
HERE = Path(__file__).resolve().parent
TOKEN_FILE = HERE / "agent.token"

IS_WINDOWS = sys.platform.startswith("win")

# Hard cap for the JSON-based small-file endpoints. Anything bigger should go
# through /upload or /download (raw streaming). Base64 inflates by ~33% and
# the entire payload is held in memory, so 8 MiB is a sane ceiling.
SMALL_FILE_LIMIT = 8 * 1024 * 1024

# Streaming chunk size for /upload and /download.
STREAM_CHUNK = 1 * 1024 * 1024

# In-memory process registry for /spawn /kill /list. Survives only while the
# agent runs; if the agent restarts, spawned children become orphans (on
# POSIX they reparent to init, on Windows they keep running until they exit).
_PROCS: "dict[int, dict]" = {}
_PROCS_LOCK = threading.Lock()

# Empty list = allow any source IP. To restrict, e.g. ["192.168.88.0/24"] —
# but this simple agent only supports exact-IP matches; expand if needed.
ALLOWED_IPS: list[str] = []


def load_or_create_token() -> str:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    tok = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(tok, encoding="utf-8")
    print(f"[agent] generated new token at {TOKEN_FILE}")
    print(f"[agent] token: {tok}")
    return tok


# Env var wins so you can ship a fixed token without writing it to disk.
# pragma: allowlist secret -- runtime-loaded credential, not a hardcoded one.
_AGENT_TOKEN = (
    os.environ.get("REMOTE_AGENT_TOKEN")
    or os.environ.get("PI_REMOTE_AGENT_TOKEN")  # legacy name, kept for compat
    or load_or_create_token()
)


def _check_auth(handler: BaseHTTPRequestHandler) -> bool:
    if ALLOWED_IPS:
        peer = handler.client_address[0]
        if peer not in ALLOWED_IPS:
            return False
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return secrets.compare_digest(auth[7:].strip(), _AGENT_TOKEN)


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


def _send_json(handler: BaseHTTPRequestHandler, status: int, body: dict) -> None:
    data = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _send_error(handler: BaseHTTPRequestHandler, status: int, msg: str) -> None:
    _send_json(handler, status, {"error": msg})


def _image_mime(path: Path) -> str | None:
    """Mirror detectImageMimeType from the original pi remote-execution extension."""
    mime, _ = mimetypes.guess_type(str(path))
    if mime in ("image/jpeg", "image/png", "image/gif", "image/webp"):
        return mime
    return None


# ---------- handlers ----------


def _current_user() -> str | None:
    """Best-effort cross-platform current user name."""
    return (
        os.environ.get("USER")
        or os.environ.get("USERNAME")
        or os.environ.get("LOGNAME")
    )


def handle_ping(handler: BaseHTTPRequestHandler) -> None:
    _send_json(
        handler,
        200,
        {
            "ok": True,
            "version": VERSION,
            "hostname": socket.gethostname(),
            "cwd": str(Path.cwd()),
            "user": _current_user(),
            "platform": sys.platform,
            "is_windows": IS_WINDOWS,
        },
    )


def handle_env(handler: BaseHTTPRequestHandler) -> None:
    """
    Snapshot of the agent's environment for LLM bootstrap.
    Includes platform / shells / common tools (with versions) / safe env vars.
    Does NOT include the full env dict (would leak secrets).
    """
    import platform as _pl
    import shutil

    def version_of(name: str, args: list[str]) -> str | None:
        path = shutil.which(name)
        if not path:
            return None
        try:
            out = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            blob = (out.stdout or out.stderr or "").strip()
            return blob.splitlines()[0] if blob else None
        except Exception:
            return None

    candidate_shells = ["bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd"]
    candidate_tools = [
        ("git", ["--version"]),
        ("node", ["--version"]),
        ("npm", ["--version"]),
        ("python", ["--version"]),
        ("python3", ["--version"]),
        ("go", ["version"]),
        ("rustc", ["--version"]),
        ("cargo", ["--version"]),
        ("docker", ["--version"]),
        ("java", ["-version"]),
        ("curl", ["--version"]),
        ("wget", ["--version"]),
        ("make", ["--version"]),
        ("cmake", ["--version"]),
        ("ffmpeg", ["-version"]),
    ]

    shells = {n: shutil.which(n) for n in candidate_shells if shutil.which(n)}
    tools = {}
    for name, args in candidate_tools:
        ver = version_of(name, args)
        if ver:
            tools[name] = ver

    safe_env_keys = [
        "PATH",
        "HOME",
        "USERPROFILE",
        "USERNAME",
        "USER",
        "LANG",
        "LC_ALL",
        "TZ",
        "SHELL",
        "COMSPEC",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
        "OS",
    ]
    env_snapshot = {k: os.environ[k] for k in safe_env_keys if k in os.environ}
    path_sep = ";" if IS_WINDOWS else ":"
    path_entries = [p for p in os.environ.get("PATH", "").split(path_sep) if p]

    _send_json(
        handler,
        200,
        {
            "agent_version": VERSION,
            "platform": sys.platform,
            "is_windows": IS_WINDOWS,
            "os": {
                "system": _pl.system(),
                "release": _pl.release(),
                "version": _pl.version(),
                "machine": _pl.machine(),
            },
            "python": {"version": sys.version.split()[0], "executable": sys.executable},
            "hostname": socket.gethostname(),
            "user": _current_user(),
            "home": str(Path.home()),
            "cwd": str(Path.cwd()),
            "path_sep": path_sep,
            "path_entries": path_entries,
            "shells": shells,
            "tools": tools,
            "env": env_snapshot,
        },
    )


def handle_spawn(handler: BaseHTTPRequestHandler) -> None:
    """
    Spawn a long-running background process, return its pid immediately.

    Request JSON:
      command : str          (required if shell=True)
      argv    : list[str]    (required if shell=False)
      cwd     : str          (default: agent cwd)
      env     : dict[str,str] extra env merged onto current env
      stdout  : str path to redirect stdout (created if missing)
      stderr  : str path to redirect stderr; defaults to stdout file if set
      shell   : bool (default true)

    On POSIX, the child is detached into a new session so it survives the
    request. On Windows, we just spawn normally; the child outlives the
    agent unless the agent's own session is terminated.
    """
    import time

    body = _read_json(handler)
    command = body.get("command")
    argv = body.get("argv")
    cwd = body.get("cwd") or str(Path.cwd())
    extra_env = body.get("env") or {}
    stdout_path = body.get("stdout")
    stderr_path = body.get("stderr")
    use_shell = bool(body.get("shell", True))

    if use_shell and not command:
        _send_error(handler, 400, "shell=true requires 'command' (str)")
        return
    if not use_shell and not argv:
        _send_error(handler, 400, "shell=false requires 'argv' (list[str])")
        return

    env = os.environ.copy()
    if isinstance(extra_env, dict):
        for k, v in extra_env.items():
            env[str(k)] = str(v)

    out_f = None
    err_f = None
    try:
        if stdout_path:
            Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
            out_f = open(stdout_path, "ab", buffering=0)  # noqa: SIM115
        if stderr_path:
            Path(stderr_path).parent.mkdir(parents=True, exist_ok=True)
            err_f = open(stderr_path, "ab", buffering=0)  # noqa: SIM115
        elif stdout_path:
            err_f = out_f  # default: merge into stdout file

        popen_kwargs: dict = {
            "cwd": cwd,
            "env": env,
            "stdout": out_f if out_f else subprocess.DEVNULL,
            "stderr": err_f if err_f else subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if not IS_WINDOWS:
            popen_kwargs["start_new_session"] = True

        if use_shell:
            assert isinstance(command, str)  # narrowed above
            proc = subprocess.Popen(command, shell=True, **popen_kwargs)
        else:
            assert isinstance(argv, list)  # narrowed above
            proc = subprocess.Popen(argv, shell=False, **popen_kwargs)
    except Exception as e:
        with contextlib.suppress(Exception):
            if out_f and not out_f.closed:
                out_f.close()
            if err_f and err_f is not out_f and not err_f.closed:
                err_f.close()
        _send_error(handler, 500, f"spawn failed: {type(e).__name__}: {e}")
        return

    info = {
        "pid": proc.pid,
        "command": command if use_shell else argv,
        "cwd": cwd,
        "stdout": stdout_path,
        "stderr": stderr_path,
        "started_at": time.time(),
        "shell": use_shell,
    }
    with _PROCS_LOCK:
        _PROCS[proc.pid] = {**info, "_proc": proc, "_out": out_f, "_err": err_f}
    _send_json(handler, 200, info)


def _proc_status(rec: dict) -> str:
    proc: subprocess.Popen = rec["_proc"]
    code = proc.poll()
    return "running" if code is None else f"exited:{code}"


def handle_list(handler: BaseHTTPRequestHandler) -> None:
    """List spawned processes. Reaps finished ones (closes their log files)."""
    with _PROCS_LOCK:
        result = []
        finished = []
        for pid, rec in _PROCS.items():
            status = _proc_status(rec)
            result.append(
                {
                    "pid": pid,
                    "command": rec["command"],
                    "cwd": rec["cwd"],
                    "stdout": rec["stdout"],
                    "stderr": rec["stderr"],
                    "started_at": rec["started_at"],
                    "status": status,
                }
            )
            if status != "running":
                finished.append(pid)
        for pid in finished:
            rec = _PROCS.pop(pid, None)
            if not rec:
                continue
            out_f = rec.get("_out")
            err_f = rec.get("_err")
            for f in {out_f, err_f}:
                if f and not f.closed:
                    with contextlib.suppress(Exception):
                        f.close()
    _send_json(handler, 200, {"processes": result})


def handle_shutdown(handler: BaseHTTPRequestHandler) -> None:
    """
    Shut down THIS agent process. Useful for hot-reloading a new agent.py.

    Request JSON: { delay: float?  }   defaults to 1.0 second.
    Response: { ok: true, pid, exit_in_seconds, version }

    Behavior:
      - We respond 200 *before* exiting, so the caller sees a clean status.
      - A background thread sleeps `delay` seconds, then calls os._exit().
      - os._exit (vs sys.exit) bypasses atexit handlers / running threads,
        which is what we want: the HTTP server is still serving and
        sys.exit would deadlock waiting for it.
      - Spawned children (registered in _PROCS) are NOT killed. On POSIX
        they were started with start_new_session=True so they survive
        re-parenting; on Windows they were spawned without a job object,
        so they keep running until they exit on their own.

    Hot-reload pattern (driven from the client):
      1. upload new agent.py to agent.py.new (then rename to agent.py)
      2. spawn 'pythonw agent.py --port <SAME_PORT>' as a detached child
         (it will bind to the same port AFTER this agent releases it)
      3. call /shutdown  → this agent exits ~1s later, releasing the port
      4. the spawned child grabs the port; you're now on the new version

    The fallback if step 2 was forgotten is unpleasant: agent.py won't
    be running and nothing will auto-restart it (the Startup folder shim
    only runs at login). So always spawn the replacement first.
    """
    import time

    body = _read_json(handler)
    try:
        delay = float(body.get("delay", 1.0))
    except (TypeError, ValueError):
        delay = 1.0
    delay = max(0.1, min(delay, 30.0))  # clamp

    _send_json(
        handler,
        200,
        {
            "ok": True,
            "pid": os.getpid(),
            "exit_in_seconds": delay,
            "version": VERSION,
        },
    )

    def go_die():
        time.sleep(delay)
        # Flush stdio before slamming the door; os._exit doesn't.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(0)  # noqa: SLF001 -- intentional hard exit

    threading.Thread(target=go_die, name="shutdown", daemon=True).start()


def handle_kill(handler: BaseHTTPRequestHandler) -> None:
    """
    Stop a spawned process. Body: { pid: int, signal: 'TERM'|'KILL' }
    Default is TERM on POSIX, kill() on Windows (signal is ignored there).
    Only processes spawned via /spawn can be killed; arbitrary PIDs are
    refused on purpose so a leaked token can't murder unrelated processes.
    """
    import signal as _sig

    body = _read_json(handler)
    pid = body.get("pid")
    sig_name = (body.get("signal") or "TERM").upper()
    if not isinstance(pid, int):
        _send_error(handler, 400, "pid (int) required")
        return

    with _PROCS_LOCK:
        rec = _PROCS.get(pid)
    if not rec:
        _send_error(handler, 404, f"pid {pid} not tracked by this agent")
        return

    proc: subprocess.Popen = rec["_proc"]
    if proc.poll() is not None:
        _send_json(
            handler,
            200,
            {
                "pid": pid,
                "status": _proc_status(rec),
                "action": "already-exited",
            },
        )
        return
    try:
        if IS_WINDOWS or sig_name == "KILL":
            proc.kill()
        else:
            proc.send_signal(_sig.SIGTERM)
    except Exception as e:
        _send_error(handler, 500, f"kill failed: {type(e).__name__}: {e}")
        return
    _send_json(handler, 200, {"pid": pid, "action": "signal-sent", "signal": sig_name})


def handle_read(handler: BaseHTTPRequestHandler) -> None:
    body = _read_json(handler)
    p = Path(body.get("path", ""))
    try:
        size = p.stat().st_size
    except FileNotFoundError:
        _send_error(handler, 404, f"not found: {p}")
        return
    if size > SMALL_FILE_LIMIT:
        _send_error(
            handler,
            413,
            f"file is {size} bytes; /read caps at {SMALL_FILE_LIMIT}. Use GET /download instead.",
        )
        return
    try:
        data = p.read_bytes()
    except PermissionError as e:
        _send_error(handler, 403, str(e))
        return
    _send_json(handler, 200, {"data_b64": base64.b64encode(data).decode("ascii")})


def handle_write(handler: BaseHTTPRequestHandler) -> None:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length > SMALL_FILE_LIMIT * 2:  # base64 inflation factor
        _send_error(
            handler,
            413,
            f"payload is {length} bytes; /write caps at ~{SMALL_FILE_LIMIT}. Use POST /upload instead.",
        )
        return
    body = _read_json(handler)
    p = Path(body.get("path", ""))
    data_b64 = body.get("data_b64", "")
    try:
        data = base64.b64decode(data_b64)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    except Exception as e:
        _send_error(handler, 500, f"{type(e).__name__}: {e}")
        return
    _send_json(handler, 200, {"ok": True, "bytes": len(data)})


def handle_upload(handler: BaseHTTPRequestHandler) -> None:
    """
    Stream upload. Raw binary in the request body; metadata in headers:
      X-Path:   absolute destination path on this machine (required)
      X-Sha256: hex sha256 of the file bytes (optional; verified if provided)
      Content-Length: total bytes (required for non-chunked uploads)

    Writes to <path>.part during transfer, then atomically renames on success.
    If sha256 is provided and does not match, the .part file is deleted and
    400 is returned. Atomic rename means a concurrent reader on <path> never
    sees a half-written file.
    """
    dest_hdr = handler.headers.get("X-Path")
    if not dest_hdr:
        _send_error(handler, 400, "missing X-Path header")
        return
    expected_sha = (handler.headers.get("X-Sha256") or "").lower().strip() or None
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        _send_error(handler, 400, "missing or zero Content-Length")
        return

    dest = Path(dest_hdr)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        _send_error(handler, 500, f"mkdir parent failed: {e}")
        return

    part = dest.with_suffix(dest.suffix + ".part")
    hasher = hashlib.sha256()
    written = 0
    try:
        with part.open("wb") as f:
            remaining = length
            while remaining > 0:
                chunk = handler.rfile.read(min(STREAM_CHUNK, remaining))
                if not chunk:
                    break
                f.write(chunk)
                hasher.update(chunk)
                written += len(chunk)
                remaining -= len(chunk)
    except Exception as e:
        with contextlib.suppress(Exception):
            part.unlink()
        _send_error(handler, 500, f"write failed after {written}/{length} bytes: {e}")
        return

    if written != length:
        with contextlib.suppress(Exception):
            part.unlink()
        _send_error(
            handler,
            400,
            f"short read: got {written} bytes, expected {length}",
        )
        return

    got_sha = hasher.hexdigest()
    if expected_sha and got_sha != expected_sha:
        with contextlib.suppress(Exception):
            part.unlink()
        _send_error(
            handler,
            400,
            f"sha256 mismatch: got {got_sha}, expected {expected_sha}",
        )
        return

    # Atomic replace. On Windows this works as long as dest is on the same
    # volume as part (which it is, since part is dest + .part).
    try:
        os.replace(part, dest)
    except Exception as e:
        with contextlib.suppress(Exception):
            part.unlink()
        _send_error(handler, 500, f"rename {part} -> {dest} failed: {e}")
        return

    _send_json(
        handler,
        200,
        {"ok": True, "bytes": written, "sha256": got_sha, "path": str(dest)},
    )


def handle_download(handler: BaseHTTPRequestHandler) -> None:
    """
    Stream download. Path comes from query string ?path=...
    Returns the raw bytes with:
      Content-Length: <size>
      X-Sha256:       <hex sha256>   (computed up front; OK for hundreds of MB)
      Content-Type:   application/octet-stream

    We compute sha256 in a single pre-pass so the header is available before
    the body. For multi-GB files this would be inefficient; revisit then.
    """
    qs = parse_qs(urlsplit(handler.path).query)
    src_raw = (qs.get("path") or [""])[0]
    if not src_raw:
        _send_error(handler, 400, "missing ?path= query")
        return
    src = Path(src_raw)
    if not src.exists() or not src.is_file():
        _send_error(handler, 404, f"not found or not a file: {src}")
        return

    size = src.stat().st_size
    hasher = hashlib.sha256()
    try:
        with src.open("rb") as f:
            for chunk in iter(lambda: f.read(STREAM_CHUNK), b""):
                hasher.update(chunk)
    except PermissionError as e:
        _send_error(handler, 403, str(e))
        return
    sha = hasher.hexdigest()

    handler.send_response(200)
    handler.send_header("Content-Type", "application/octet-stream")
    handler.send_header("Content-Length", str(size))
    handler.send_header("X-Sha256", sha)
    handler.send_header("X-Path", str(src))
    handler.end_headers()

    try:
        with src.open("rb") as f:
            for chunk in iter(lambda: f.read(STREAM_CHUNK), b""):
                handler.wfile.write(chunk)
    except Exception:
        # Client may have disconnected; nothing useful we can send now.
        traceback.print_exc()


def handle_mkdir(handler: BaseHTTPRequestHandler) -> None:
    body = _read_json(handler)
    p = Path(body.get("path", ""))
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        _send_error(handler, 500, f"{type(e).__name__}: {e}")
        return
    _send_json(handler, 200, {"ok": True})


def handle_stat(handler: BaseHTTPRequestHandler) -> None:
    body = _read_json(handler)
    p = Path(body.get("path", ""))
    if not p.exists():
        _send_json(handler, 200, {"exists": False})
        return
    st = p.stat()
    _send_json(
        handler,
        200,
        {
            "exists": True,
            "size": st.st_size,
            "is_dir": stat_mod.S_ISDIR(st.st_mode),
            "is_file": stat_mod.S_ISREG(st.st_mode),
            "mtime": st.st_mtime,
            "image_mime": _image_mime(p) if p.is_file() else None,
        },
    )


def handle_exec(handler: BaseHTTPRequestHandler) -> None:
    """
    Streamed exec.
    Request JSON: { command: str, cwd: str, timeout: float|null }
    Response: chunked text/plain. The body is a stream of newline-delimited
    JSON frames, one of:
      {"t":"out","d":"<chunk>"}
      {"t":"err","d":"<chunk>"}
      {"t":"exit","code":<int>}      ← always last frame
      {"t":"error","msg":"..."}      ← only on agent-side failure
    Streaming avoids buffering long-running output.
    """
    body = _read_json(handler)
    command = body.get("command", "")
    cwd = body.get("cwd") or str(Path.cwd())
    timeout = body.get("timeout")  # seconds, or None

    handler.send_response(200)
    handler.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Transfer-Encoding", "chunked")
    handler.end_headers()

    def send_frame(obj: dict) -> None:
        line = (json.dumps(obj) + "\n").encode("utf-8")
        # chunked encoding: <hex-len>\r\n<bytes>\r\n
        handler.wfile.write(f"{len(line):X}\r\n".encode("ascii"))
        handler.wfile.write(line)
        handler.wfile.write(b"\r\n")
        handler.wfile.flush()

    # On Windows, cmd.exe defaults to the system code page (e.g. GBK/936).
    # Force UTF-8 so the pump threads' chunk.decode("utf-8") works。
    if IS_WINDOWS:
        command = f"chcp 65001 > nul && {command}"

    try:
        # On Windows, shell=True uses cmd.exe; we want broad compatibility,
        # including built-ins like `dir`. Users can prefix with `powershell -c`
        # or `bash -c` as desired.
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except Exception as e:
        send_frame({"t": "error", "msg": f"{type(e).__name__}: {e}"})
        handler.wfile.write(b"0\r\n\r\n")
        return

    def pump(stream, tag):
        with contextlib.suppress(Exception):
            for chunk in iter(lambda: stream.read(4096), b""):
                if not chunk:
                    break
                try:
                    text = chunk.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001 -- repr fallback is the point
                    text = repr(chunk)
                send_frame({"t": tag, "d": text})

    t_out = threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True)
    t_err = threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)
    t_out.start()
    t_err.start()

    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        # Drain pump threads so partial output reaches the client before we
        # close the stream. The extension sees exit code 124 (standard `timeout`
        # command convention) and returns the partial output instead of an error.
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        send_frame({"t": "exit", "code": 124})
        handler.wfile.write(b"0\r\n\r\n")
        return

    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)
    send_frame({"t": "exit", "code": code})
    # terminate chunked encoding
    handler.wfile.write(b"0\r\n\r\n")


ROUTES = {
    ("GET", "/ping"): handle_ping,
    ("GET", "/env"): handle_env,
    ("POST", "/read"): handle_read,
    ("POST", "/write"): handle_write,
    ("POST", "/mkdir"): handle_mkdir,
    ("POST", "/stat"): handle_stat,
    ("POST", "/exec"): handle_exec,
    ("POST", "/upload"): handle_upload,
    ("GET", "/download"): handle_download,
    ("POST", "/spawn"): handle_spawn,
    ("GET", "/list"): handle_list,
    ("POST", "/kill"): handle_kill,
    ("POST", "/shutdown"): handle_shutdown,
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"remote-agent/{VERSION}"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write(f"[agent] {self.client_address[0]} - {format % args}\n")

    def _dispatch(self, method: str) -> None:
        # Strip query string for route matching (e.g. /download?path=...).
        path_only = self.path.split("?", 1)[0]
        # /ping is exempt from auth so you can sanity-check connectivity.
        is_ping = method == "GET" and path_only == "/ping"
        if not is_ping and not _check_auth(self):
            _send_error(self, 401, "unauthorized")
            return
        fn = ROUTES.get((method, path_only))
        if fn is None:
            _send_error(self, 404, f"no route: {method} {path_only}")
            return
        try:
            fn(self)
        except Exception as e:
            traceback.print_exc()
            with contextlib.suppress(Exception):
                _send_error(self, 500, f"{type(e).__name__}: {e}")

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[agent] remote-agent v{VERSION}")
    print(f"[agent] listening on http://{args.host}:{args.port}")
    print(f"[agent] token file: {TOKEN_FILE}")
    print(f"[agent] cwd: {Path.cwd()}")
    print("[agent] Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[agent] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
