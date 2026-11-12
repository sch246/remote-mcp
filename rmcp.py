#!/usr/bin/env python3
"""
rmcp.py — Unified single-file CLI, Mesh Router, and Remote Node for remote-mcp.

Zero external dependencies (Python 3.10+ stdlib only). Runs identically on
Linux and Windows. One file serves four roles:
  1. One-shot CLI & Interactive REPL for bots & humans:
       python rmcp.py                      # interactive REPL (when run in a TTY)
       python rmcp.py :repl [target]       # explicit interactive shell (persistent hop pipes)
       python rmcp.py <command...>         # one-shot pass-through to active remote node
       python rmcp.py :<mgmt-cmd> ...      # router & node management commands
  2. SSH stdio router hop / persistent loop (invoked automatically over SSH stdin/stdout):
       python rmcp.py --stdio-hop          # single framed envelope
       python rmcp.py --stdio-loop         # persistent multiplexed framed loop
  3. HTTP daemon + Router + Reverse-Tunnel Hub (backward-compatible with agent.py):
       python rmcp.py --listen [--port 7777] [--watchdog]
  4. Outbound Reverse-Tunnel Client (for NAT / firewall-isolated machines):
       python rmcp.py --dial http://hub:7777 --token <TOKEN> [--alias my-box]
"""
from __future__ import annotations

import argparse
import atexit
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import mimetypes
import os
import platform as platform_mod
import queue
import secrets
import shlex
import shutil
import signal
import socket
import stat as stat_mod
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.7.0"
IS_WINDOWS = sys.platform.startswith("win")
HERE = Path(__file__).resolve().parent

SMALL_FILE_LIMIT = 8 * 1024 * 1024
STREAM_CHUNK = 512 * 1024
DEFAULT_TTL = 6
CRYPTO_WINDOW_SEC = 600

FRAME_REQ_PREFIX = "RMCP_ENV:"
FRAME_RES_PREFIX = "RMCP_RES:"


# ---------------------------------------------------------------------------
# State directory & Machine Identity
# ---------------------------------------------------------------------------

def get_state_dir() -> Path:
    override = os.environ.get("REMOTE_MCP_STATE_DIR") or os.environ.get("RMCP_STATE_DIR")
    if override:
        p = Path(override).expanduser().resolve()
    else:
        p = Path.home() / ".config" / "remote-agent-mcp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _raw_machine_fingerprint() -> str:
    if not IS_WINDOWS:
        for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            with contextlib.suppress(Exception):
                val = Path(candidate).read_text(encoding="utf-8").strip()
                if val:
                    return f"linux:{val}"
    else:
        with contextlib.suppress(Exception):
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                if val:
                    return f"win:{val}"
    return f"fallback:{socket.gethostname()}:{uuid.getnode()}"


def compute_default_node_id() -> str:
    # Include state_dir when overridden so multi-node local tests get distinct IDs.
    seed = _raw_machine_fingerprint()
    if os.environ.get("REMOTE_MCP_STATE_DIR") or os.environ.get("RMCP_STATE_DIR"):
        seed += ":" + str(get_state_dir())
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"node-{digest}"


def current_user() -> str:
    return (
        os.environ.get("USER")
        or os.environ.get("USERNAME")
        or os.environ.get("LOGNAME")
        or "unknown"
    )


# ---------------------------------------------------------------------------
# Zero-dependency Authenticated Encryption (BLAKE2b-CTR + HMAC-SHA256)
# ---------------------------------------------------------------------------

def _derive_keys(secret: str) -> tuple[bytes, bytes]:
    raw = secret.encode("utf-8")
    enc_key = hashlib.blake2b(raw, key=b"rmcp-v1-enc", digest_size=32).digest()
    mac_key = hashlib.blake2b(raw, key=b"rmcp-v1-mac", digest_size=32).digest()
    return enc_key, mac_key


def _keystream_xor(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    mv = memoryview(data)
    offset = 0
    counter = 0
    while offset < len(data):
        person = struct.pack("<Q", counter) + b"\x00" * 8
        block = hashlib.blake2b(
            nonce, key=enc_key, person=person, digest_size=64
        ).digest()
        take = min(64, len(data) - offset)
        for i in range(take):
            out[offset + i] = mv[offset + i] ^ block[i]
        offset += take
        counter += 1
    return bytes(out)


def encrypt_obj(obj: dict, secret: str) -> dict:
    plaintext = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    enc_key, mac_key = _derive_keys(secret)
    nonce = secrets.token_bytes(16)
    ts = int(time.time())
    ct = _keystream_xor(plaintext, enc_key, nonce)
    ts_bytes = struct.pack("<q", ts)
    mac = hmac.new(mac_key, nonce + ts_bytes + ct, hashlib.sha256).hexdigest()
    return {
        "alg": "b2b-hmac-v1",
        "ts": ts,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "mac": mac,
    }


def decrypt_obj(box: dict, secret: str, check_ts: bool = True) -> dict:
    if not isinstance(box, dict) or box.get("alg") != "b2b-hmac-v1":
        raise ValueError("unsupported encrypted box format")
    ts = int(box["ts"])
    if check_ts and abs(int(time.time()) - ts) > CRYPTO_WINDOW_SEC:
        raise ValueError("encrypted packet timestamp outside allowed window")
    nonce = base64.b64decode(box["nonce"])
    ct = base64.b64decode(box["ct"])
    enc_key, mac_key = _derive_keys(secret)
    ts_bytes = struct.pack("<q", ts)
    expected_mac = hmac.new(mac_key, nonce + ts_bytes + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, str(box.get("mac", ""))):
        raise ValueError("HMAC verification failed (bad token or tampered packet)")
    pt = _keystream_xor(ct, enc_key, nonce)
    return json.loads(pt.decode("utf-8"))


# ---------------------------------------------------------------------------
# Router Topology, Caller-Origin Session Isolation & Anti-Storm Deduplication
# ---------------------------------------------------------------------------

_STATE_LOCK = threading.Lock()
_MEM_SEEN: dict[str, float] = {}
_SESSION_OVERRIDE: str = ""


@contextlib.contextmanager
def _cross_process_lock(lock_path: Path):
    """Best-effort OS file lock (fcntl on POSIX, msvcrt on Windows) for shared JSON state."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lf:
        locked = False
        if not IS_WINDOWS:
            with contextlib.suppress(Exception):
                import fcntl

                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                locked = True
        else:
            with contextlib.suppress(Exception):
                import msvcrt

                lf.seek(0)
                if lf.tell() == 0:
                    lf.write(b"0")
                    lf.flush()
                lf.seek(0)
                msvcrt.locking(lf.fileno(), msvcrt.LK_LOCK, 1)
                locked = True
        try:
            yield
        finally:
            if locked:
                if not IS_WINDOWS:
                    with contextlib.suppress(Exception):
                        import fcntl

                        fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
                else:
                    with contextlib.suppress(Exception):
                        import msvcrt

                        lf.seek(0)
                        msvcrt.locking(lf.fileno(), msvcrt.LK_UNLCK, 1)


def _atomic_write_json(target: Path, obj: dict) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(f".tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)


def _router_file() -> Path:
    return get_state_dir() / "router.json"


def _sessions_dir() -> Path:
    return get_state_dir() / "sessions"


def _procs_file() -> Path:
    return get_state_dir() / "procs.json"


def _legacy_hosts_file() -> Path:
    env_cfg = os.environ.get("REMOTE_AGENT_CONFIG")
    if env_cfg:
        return Path(env_cfg).expanduser()
    return get_state_dir() / "hosts.json"


def _seen_file() -> Path:
    return get_state_dir() / "seen_pkts.json"


def _normalize_path_key(p: Path) -> str:
    try:
        s = str(p.resolve())
    except Exception:
        s = os.path.abspath(str(p))
    if IS_WINDOWS and len(s) >= 2 and s[1] == ":":
        s = s[0].upper() + s[1:]
    return s


def _find_project_root(start: Path) -> str:
    """Walk upward from `start` to anchor caller identity at repo root (.rmcp-root/.git/.hg)."""
    cur = Path(_normalize_path_key(start))
    for candidate in (cur, *cur.parents):
        for marker in (".rmcp-root", ".git", ".hg"):
            with contextlib.suppress(Exception):
                if (candidate / marker).exists():
                    return _normalize_path_key(candidate)
    return _normalize_path_key(cur)


def _detect_caller_actor() -> tuple[str, bool]:
    """Return `(actor_tag, is_explicit_session)`. Isolates co-located agents automatically."""
    explicit = (_SESSION_OVERRIDE or os.environ.get("RMCP_SESSION") or "").strip()
    if explicit:
        return f"session:{explicit}", True
    if not os.environ.get("RMCP_IGNORE_AGENT_ENV"):
        for env_key, prefix in (
            ("ANTIGRAVITY_CONVERSATION_ID", "agy"),
            ("CODEX_THREAD_ID", "codex"),
            ("CLAUDE_SESSION_ID", "claude"),
        ):
            val = (os.environ.get(env_key) or "").strip()
            if val:
                return f"{prefix}:{val[:12]}", False
    return "", False


def detect_caller_origin(node_id: str = "", alias: str = "") -> dict:
    """Capture caller provenance `(node_id, host, root_dir, cwd, actor)` & deterministic `caller_key`."""
    nid = node_id or compute_default_node_id()
    host = alias or os.environ.get("REMOTE_MCP_NODE_ALIAS") or socket.gethostname()
    try:
        raw_cwd_p = Path.cwd()
    except Exception:
        raw_cwd_p = Path.home()
    raw_cwd = _normalize_path_key(raw_cwd_p)
    root_dir = _find_project_root(raw_cwd_p)
    actor, is_explicit = _detect_caller_actor()
    if is_explicit:
        caller_key = f"{nid}@{actor}"
    elif actor:
        caller_key = f"{nid}:{root_dir}@{actor}"
    else:
        caller_key = f"{nid}:{root_dir}"
    return {
        "caller_key": caller_key,
        "node_id": nid,
        "host": host,
        "root_dir": root_dir,
        "cwd": raw_cwd,
        "actor": actor,
        "user": current_user(),
    }


def _format_origin_label(origin: dict | None) -> str:
    if not isinstance(origin, dict) or not origin:
        return ""
    host = origin.get("host") or origin.get("node_id") or "unknown"
    folder = origin.get("root_dir") or origin.get("cwd") or ""
    actor = origin.get("actor") or ""
    base = f"{host}:{folder}" if folder else str(host)
    return f"{base}@{actor}" if actor else base


def _session_file_for_key(caller_key: str) -> Path:
    digest = hashlib.sha256(caller_key.encode("utf-8")).hexdigest()[:16]
    return _sessions_dir() / f"{digest}.json"


def load_topology_state() -> dict:
    """Load machine-wide shared Mesh Topology (`node_id`, `alias`, `peers`, `routes`)."""
    rf = _router_file()
    topo: dict = {}
    if rf.exists():
        with contextlib.suppress(Exception):
            topo = json.loads(rf.read_text(encoding="utf-8"))
    if not isinstance(topo, dict):
        topo = {}

    topo.setdefault("node_id", compute_default_node_id())
    topo.setdefault("alias", os.environ.get("REMOTE_MCP_NODE_ALIAS") or socket.gethostname())
    topo.setdefault("default_active", topo.get("active", ""))
    topo.setdefault("peers", {})
    topo.setdefault("routes", {})
    legacy_cwds: dict[str, str] = dict(topo.get("cwds") or {})

    # Auto-import HTTP hosts from legacy hosts.json (non-destructively)
    # Note: Skip aliases that are already registered as multi-hop routes (via another node)
    # Also evict any peers that are now registered in routes
    for r_alias in list(topo.get("routes", {}).keys()):
        topo["peers"].pop(r_alias, None)

    hf = _legacy_hosts_file()
    if hf.exists():
        with contextlib.suppress(Exception):
            legacy = json.loads(hf.read_text(encoding="utf-8"))
            for alias, h in (legacy.get("hosts") or {}).items():
                if (
                    alias not in topo["peers"]
                    and alias not in topo.get("routes", {})
                    and isinstance(h, dict)
                    and h.get("url")
                ):
                    topo["peers"][alias] = {
                        "alias": alias,
                        "type": "http",
                        "url": h["url"],
                        "token": h.get("token", ""),
                        "platform": h.get("platform", ""),
                        "cwd": h.get("cwd", ""),
                    }
                if isinstance(h, dict) and h.get("cwd") and alias not in legacy_cwds:
                    legacy_cwds[alias] = h["cwd"]
            if not topo["default_active"] and legacy.get("active"):
                topo["default_active"] = legacy["active"]

    for alias, p in (topo.get("peers") or {}).items():
        if isinstance(p, dict) and p.get("cwd") and alias not in legacy_cwds:
            legacy_cwds[alias] = p["cwd"]
    topo["_default_cwds"] = legacy_cwds
    return topo


def save_topology_state(state: dict) -> None:
    """Atomically save ONLY shared topology fields to `router.json` under cross-process lock."""
    with _cross_process_lock(get_state_dir() / "router.lock"):
        rf = _router_file()
        existing: dict = {}
        if rf.exists():
            with contextlib.suppress(Exception):
                raw = json.loads(rf.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    existing = raw
        out = {
            "node_id": state.get("node_id") or existing.get("node_id") or compute_default_node_id(),
            "alias": state.get("alias") or existing.get("alias") or socket.gethostname(),
            "default_active": (
                state["default_active"]
                if "default_active" in state
                else existing.get("default_active", existing.get("active", ""))
            ),
            "peers": state.get("peers") if "peers" in state else existing.get("peers", {}),
            "routes": state.get("routes") if "routes" in state else existing.get("routes", {}),
        }
        _atomic_write_json(rf, out)


def load_caller_session(topo: dict | None = None) -> dict:
    t = topo or load_topology_state()
    origin = detect_caller_origin(node_id=t["node_id"], alias=t["alias"])
    sf = _session_file_for_key(origin["caller_key"])
    sess: dict = {}
    if sf.exists():
        with contextlib.suppress(Exception):
            raw = json.loads(sf.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                sess = raw
    return {
        "caller_key": origin["caller_key"],
        "caller": _format_origin_label(origin),
        "origin": origin,
        "active": sess.get("active", ""),
        "cwds": dict(sess.get("cwds") or {}),
        "updated_at": sess.get("updated_at", 0),
    }


def update_caller_session(
    *,
    active: str | None = None,
    cwd_updates: dict[str, str] | None = None,
) -> dict:
    """Atomically update ONLY this caller's `sessions/<hash>.json` without touching other callers."""
    topo = load_topology_state()
    origin = detect_caller_origin(node_id=topo["node_id"], alias=topo["alias"])
    sf = _session_file_for_key(origin["caller_key"])
    with _STATE_LOCK, _cross_process_lock(sf.with_suffix(".lock")):
        cur: dict = {}
        if sf.exists():
            with contextlib.suppress(Exception):
                raw = json.loads(sf.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    cur = raw
        cwds = dict(cur.get("cwds") or {})
        if cwd_updates:
            for k, v in cwd_updates.items():
                if k and v:
                    cwds[k] = v
        new_active = cur.get("active", "") if active is None else active
        doc = {
            "caller_key": origin["caller_key"],
            "caller": _format_origin_label(origin),
            "origin": origin,
            "active": new_active,
            "cwds": cwds,
            "updated_at": int(time.time()),
        }
        _atomic_write_json(sf, doc)
        return doc


def list_caller_sessions(current_key: str = "") -> list[dict]:
    sdir = _sessions_dir()
    if not sdir.exists():
        return []
    items: list[dict] = []
    for p in sdir.glob("*.json"):
        with contextlib.suppress(Exception):
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("caller_key"):
                items.append(
                    {
                        "caller_key": raw["caller_key"],
                        "caller": raw.get("caller") or _format_origin_label(raw.get("origin")),
                        "active": raw.get("active") or "",
                        "cwds": raw.get("cwds") or {},
                        "updated_at": raw.get("updated_at", 0),
                        "current": raw["caller_key"] == current_key,
                        "file": p.name,
                    }
                )
    items.sort(key=lambda x: (not x.get("current", False), -int(x.get("updated_at") or 0)))
    return items


def clear_caller_sessions(only_key: str = "") -> int:
    sdir = _sessions_dir()
    if not sdir.exists():
        return 0
    removed = 0
    for p in list(sdir.glob("*.json")):
        with contextlib.suppress(Exception):
            if only_key:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if not isinstance(raw, dict) or raw.get("caller_key") != only_key:
                    continue
            p.unlink(missing_ok=True)
            p.with_suffix(".lock").unlink(missing_ok=True)
            removed += 1
    return removed


def load_router_state() -> dict:
    """Return merged view: shared topology (`peers`/`routes`) + isolated caller session (`active`/`cwds`)."""
    topo = load_topology_state()
    sess = load_caller_session(topo)
    merged_cwds = dict(topo.get("_default_cwds") or {})
    merged_cwds.update(sess.get("cwds") or {})
    effective_active = sess.get("active") or topo.get("default_active") or ""
    return {
        "node_id": topo["node_id"],
        "alias": topo["alias"],
        "default_active": topo.get("default_active", ""),
        "peers": topo["peers"],
        "routes": topo["routes"],
        "active": effective_active,
        "cwds": merged_cwds,
        "caller_key": sess["caller_key"],
        "caller": sess["caller"],
        "origin": sess["origin"],
    }


def save_router_state(state: dict) -> None:
    """Backward-compatible helper saving shared topology fields to `router.json`."""
    save_topology_state(state)


def mark_packet_seen(pkt_id: str) -> bool:
    """Return True if pkt_id was ALREADY seen (loop/duplicate), False if new."""
    if not pkt_id:
        return False
    now = time.time()
    cutoff = now - 180.0
    with _STATE_LOCK:
        # 1. Check in-memory table
        if pkt_id in _MEM_SEEN and _MEM_SEEN[pkt_id] > cutoff:
            return True
        # 2. Check persisted table (protects across separate SSH --stdio-hop invocations)
        sf = _seen_file()
        disk_seen: dict[str, float] = {}
        if sf.exists():
            with contextlib.suppress(Exception):
                raw = json.loads(sf.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    disk_seen = {k: float(v) for k, v in raw.items() if float(v) > cutoff}
        if pkt_id in disk_seen:
            _MEM_SEEN[pkt_id] = disk_seen[pkt_id]
            return True
        # Record new packet
        _MEM_SEEN[pkt_id] = now
        if len(_MEM_SEEN) > 512:
            for k in [k for k, ts in list(_MEM_SEEN.items()) if ts <= cutoff]:
                _MEM_SEEN.pop(k, None)
        disk_seen[pkt_id] = now
        if len(disk_seen) > 256:
            oldest = sorted(disk_seen.items(), key=lambda kv: kv[1])[-256:]
            disk_seen = dict(oldest)
        with contextlib.suppress(Exception):
            _atomic_write_json(sf, disk_seen)
        return False


# ---------------------------------------------------------------------------
# Background Process Registry (Persisted + Origin-Tagged) & Auto-start
# ---------------------------------------------------------------------------

_PROCS: dict[int, dict] = {}
_PROCS_LOCK = threading.Lock()


def _proc_status(rec: dict) -> str:
    proc: subprocess.Popen = rec["_proc"]
    code = proc.poll()
    return "running" if code is None else f"exited:{code}"


def _is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if IS_WINDOWS:
        try:
            import ctypes

            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong(0)
                if not k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return int(exit_code.value) == 259  # STILL_ACTIVE
            finally:
                k32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    with contextlib.suppress(Exception):
        stat_txt = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        rparen = stat_txt.rfind(")")
        if rparen != -1 and stat_txt[rparen + 2 : rparen + 3] == "Z":
            return False
    return True


def _load_persisted_procs() -> dict[str, dict]:
    pf = _procs_file()
    if not pf.exists():
        return {}
    with contextlib.suppress(Exception):
        raw = json.loads(pf.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    return {}


def _save_persisted_procs(procs_map: dict[str, dict]) -> None:
    _atomic_write_json(_procs_file(), procs_map)


def _windows_startup_vbs_path() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "remote-mcp-node.vbs"
    )


def manage_autostart(
    mode: str = "status",
    port: int = 7777,
    host: str = "0.0.0.0",
    dial_url: str = "",
    dial_token: str = "",
    dial_alias: str = "",
) -> dict:
    """Install, remove, or inspect login/boot auto-start without admin rights."""
    script_path = Path(__file__).resolve()
    log_path = get_state_dir() / "daemon.log"

    if dial_url:
        daemon_args = f'--watchdog --dial "{dial_url}" --token "{dial_token}"'
        if dial_alias:
            daemon_args += f' --alias "{dial_alias}"'
    else:
        daemon_args = f"--watchdog --host {host} --port {port}"

    if IS_WINDOWS:
        vbs = _windows_startup_vbs_path()
        if mode == "status":
            return {
                "installed": vbs.exists(),
                "method": "windows-startup-vbs",
                "path": str(vbs),
                "log": str(log_path),
            }
        if mode == "off":
            existed = vbs.exists()
            with contextlib.suppress(FileNotFoundError):
                vbs.unlink()
            return {"installed": False, "removed": existed, "path": str(vbs)}
        if mode == "on":
            vbs.parent.mkdir(parents=True, exist_ok=True)
            pyw = Path(sys.executable).with_name("pythonw.exe")
            py_exe = str(pyw if pyw.exists() else Path(sys.executable))
            cmd_line = f'""{py_exe}"" ""{script_path}"" {daemon_args}'
            vbs_body = (
                'Set WshShell = CreateObject("WScript.Shell")\r\n'
                f'WshShell.Run "{cmd_line}", 0, False\r\n'
            )
            vbs.write_text(vbs_body, encoding="utf-8")
            return {
                "installed": True,
                "method": "windows-startup-vbs",
                "path": str(vbs),
                "command": f'"{py_exe}" "{script_path}" {daemon_args}',
                "log": str(log_path),
            }
    else:
        marker = "# remote-mcp-autostart"
        py_exe = sys.executable or shutil.which("python3") or "python3"
        cron_cmd = (
            f'@reboot "{py_exe}" "{script_path}" {daemon_args} '
            f'>> "{log_path}" 2>&1 {marker}'
        )
        cur = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, check=False
        )
        existing_lines = (
            cur.stdout.splitlines() if cur.returncode == 0 else []
        )
        kept = [ln for ln in existing_lines if marker not in ln]

        if mode == "status":
            active_lines = [ln for ln in existing_lines if marker in ln]
            return {
                "installed": bool(active_lines),
                "method": "posix-crontab",
                "entries": active_lines,
                "log": str(log_path),
            }
        if mode == "off":
            new_body = ("\n".join(kept) + "\n") if kept else ""
            subprocess.run(
                ["crontab", "-"], input=new_body, text=True, check=False
            )
            return {
                "installed": False,
                "removed": len(kept) != len(existing_lines),
                "method": "posix-crontab",
            }
        if mode == "on":
            kept.append(cron_cmd)
            new_body = "\n".join(kept) + "\n"
            res = subprocess.run(
                ["crontab", "-"],
                input=new_body,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                # Fallback: write ~/.config/autostart desktop file
                autostart_file = get_state_dir() / "autostart.sh"
                autostart_file.write_text(
                    f"#!/bin/sh\nnohup \"{py_exe}\" \"{script_path}\" {daemon_args} >> \"{log_path}\" 2>&1 &\n",
                    encoding="utf-8",
                )
                autostart_file.chmod(0o755)
                return {
                    "installed": True,
                    "method": "script-fallback",
                    "path": str(autostart_file),
                    "note": f"crontab unavailable ({res.stderr.strip()}); wrote launcher script",
                }
            return {
                "installed": True,
                "method": "posix-crontab",
                "entry": cron_cmd,
                "log": str(log_path),
            }

    raise ValueError(f"unknown autostart mode: {mode} (expected on|off|status)")


# ---------------------------------------------------------------------------
# Local Node Action Executor
# ---------------------------------------------------------------------------

def _collect_env_snapshot() -> dict:
    def version_of(name: str, args: list[str]) -> str | None:
        p = shutil.which(name)
        if not p:
            return None
        try:
            out = subprocess.run(
                [p, *args], capture_output=True, text=True, timeout=3, check=False
            )
            blob = (out.stdout or out.stderr or "").strip()
            return blob.splitlines()[0] if blob else None
        except Exception:
            return None

    shells = {
        n: shutil.which(n)
        for n in ("bash", "sh", "zsh", "pwsh", "powershell", "cmd")
        if shutil.which(n)
    }
    tools = {}
    for name, args in (
        ("git", ["--version"]),
        ("python3", ["--version"]),
        ("python", ["--version"]),
        ("node", ["--version"]),
        ("ssh", ["-V"]),
    ):
        v = version_of(name, args)
        if v:
            tools[name] = v

    state = load_router_state()
    return {
        "agent_version": VERSION,
        "node_id": state["node_id"],
        "alias": state["alias"],
        "platform": sys.platform,
        "is_windows": IS_WINDOWS,
        "os": {
            "system": platform_mod.system(),
            "release": platform_mod.release(),
            "machine": platform_mod.machine(),
        },
        "python": {"version": sys.version.split()[0], "executable": sys.executable},
        "hostname": socket.gethostname(),
        "user": current_user(),
        "home": str(Path.home()),
        "cwd": str(Path.cwd()),
        "shells": shells,
        "tools": tools,
    }


def _run_local_exec(command: str, cwd: str | None = None, timeout: float | None = None) -> dict:
    workdir = cwd or str(Path.cwd())
    if not Path(workdir).is_dir():
        workdir = str(Path.cwd())

    child_env = os.environ.copy()
    child_env.setdefault("PYTHONIOENCODING", "utf-8")
    child_env.setdefault("PYTHONUTF8", "1")

    # Track directory changes across one-shot commands cleanly without breaking exit codes!
    tag = secrets.token_hex(6)
    pwd_marker = f"__RMCP_PWD_{tag}__"
    tmp_files: list[Path] = []

    try:
        if IS_WINDOWS:
            import tempfile as _tempfile
            tdir = Path(_tempfile.gettempdir())
            user_bat = tdir / f"rmcp_u_{os.getpid()}_{tag}.cmd"
            wrap_bat = tdir / f"rmcp_w_{os.getpid()}_{tag}.cmd"
            tmp_files.extend([user_bat, wrap_bat])
            user_bat.write_bytes(f"@chcp 65001 >nul\r\n{command}\r\n".encode("utf-8"))
            wrap_bat.write_bytes(
                (
                    "@echo off\r\n"
                    "chcp 65001 >nul\r\n"
                    f'call "{user_bat}"\r\n'
                    "set __RMCP_EC=%ERRORLEVEL%\r\n"
                    f"echo {pwd_marker}:%CD%\r\n"
                    "exit /b %__RMCP_EC%\r\n"
                ).encode("utf-8")
            )
            popen_cmd: str | list[str] = ["cmd.exe", "/d", "/c", str(wrap_bat)]
            use_shell = False
        else:
            popen_cmd = (
                f"{command}\n"
                "__rmcp_ec=$?\n"
                f'printf "\\n{pwd_marker}:%s\\n" "$PWD"\n'
                "exit $__rmcp_ec"
            )
            use_shell = True

        proc = subprocess.Popen(
            popen_cmd,
            shell=use_shell,
            cwd=workdir,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            raw_out, raw_err = proc.communicate(timeout=timeout)
            code = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            raw_out, raw_err = proc.communicate()
            code = 124
            timed_out = True
    except Exception as e:
        return {"stdout": "", "stderr": f"{type(e).__name__}: {e}\n", "exit_code": -1, "cwd": workdir}
    finally:
        for tf in tmp_files:
            with contextlib.suppress(Exception):
                tf.unlink()

    stdout_text = raw_out.decode("utf-8", errors="replace")
    stderr_text = raw_err.decode("utf-8", errors="replace")

    new_cwd = workdir
    clean_lines = []
    for line in stdout_text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(pwd_marker + ":"):
            candidate = stripped[len(pwd_marker) + 1 :].strip()
            if candidate:
                new_cwd = candidate
        else:
            clean_lines.append(line)

    cleaned_out = "".join(clean_lines)
    # Remove the extra trailing newline injected before pwd_marker on POSIX if original didn't have one
    if not IS_WINDOWS and cleaned_out.endswith("\n") and not stdout_text.startswith(pwd_marker):
        # Keep normal trailing newline of commands like `echo hi`, strip only the synthetic marker newline
        idx = stdout_text.rfind(f"\n{pwd_marker}:")
        if idx != -1:
            cleaned_out = stdout_text[:idx]

    return {
        "stdout": cleaned_out,
        "stderr": stderr_text,
        "exit_code": code,
        "cwd": new_cwd,
        "timed_out": timed_out,
    }


def _resolve_remote_path(raw_path: str, cwd: str | None = None) -> Path:
    p = Path(raw_path).expanduser()
    if not p.is_absolute() and cwd:
        p = Path(cwd) / p
    return p


def execute_local_action(action: str, params: dict, origin: dict | None = None) -> dict:
    """Execute a router envelope action on THIS machine."""
    state = load_topology_state()
    caller_label = _format_origin_label(origin)

    if action == "ping":
        out = {
            "ok": True,
            "version": VERSION,
            "node_id": state["node_id"],
            "alias": state["alias"],
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "cwd": str(Path.cwd()),
            "user": current_user(),
            "platform": sys.platform,
            "is_windows": IS_WINDOWS,
        }
        if caller_label:
            out["caller"] = caller_label
        return out

    if action == "env":
        return _collect_env_snapshot()

    if action == "exec":
        return _run_local_exec(
            command=str(params.get("command", "")),
            cwd=params.get("cwd"),
            timeout=params.get("timeout"),
        )

    if action == "cd":
        base = Path(params.get("cwd") or Path.cwd())
        target = Path(params.get("path") or str(Path.home())).expanduser()
        resolved = (target if target.is_absolute() else (base / target)).resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise ValueError(f"directory not found: {resolved}")
        return {"cwd": str(resolved)}

    if action == "read":
        p = _resolve_remote_path(params["path"], params.get("cwd"))
        if not p.exists():
            raise FileNotFoundError(f"not found: {p}")
        size = p.stat().st_size
        if size > SMALL_FILE_LIMIT:
            raise ValueError(f"file is {size} bytes (> 8 MiB); use :download")
        data = p.read_bytes()
        return {"path": str(p), "size": size, "data_b64": base64.b64encode(data).decode("ascii")}

    if action == "write":
        p = _resolve_remote_path(params["path"], params.get("cwd"))
        data = base64.b64decode(params.get("data_b64", ""))
        p.parent.mkdir(parents=True, exist_ok=True)
        part = p.with_suffix(p.suffix + f".part.{os.getpid()}.{threading.get_ident()}")
        part.write_bytes(data)
        os.replace(part, p)
        return {"ok": True, "path": str(p), "bytes": len(data)}

    if action == "edit":
        p = _resolve_remote_path(params["path"], params.get("cwd"))
        old_text = params["old_text"]
        new_text = params["new_text"]
        if not p.is_file():
            raise FileNotFoundError(f"not found: {p}")
        text = p.read_bytes().decode("utf-8", errors="replace")
        count = text.count(old_text)
        if count == 0:
            raise ValueError(f"old_text not found in {p}")
        if count > 1:
            raise ValueError(f"old_text matched {count} times in {p} — must be unique")
        updated = text.replace(old_text, new_text, 1).encode("utf-8")
        part = p.with_suffix(p.suffix + f".part.{os.getpid()}.{threading.get_ident()}")
        part.write_bytes(updated)
        os.replace(part, p)
        return {"ok": True, "path": str(p), "bytes": len(updated)}

    if action == "upload_chunk":
        p = _resolve_remote_path(params["path"], params.get("cwd"))
        upload_tag = str(params.get("upload_id") or "").strip()
        if not upload_tag and caller_label:
            upload_tag = hashlib.sha256(caller_label.encode("utf-8")).hexdigest()[:10]
        part_suffix = f".rmcp_part.{upload_tag}" if upload_tag else ".rmcp_part"
        part = p.with_suffix(p.suffix + part_suffix)
        offset = int(params.get("offset", 0))
        chunk = base64.b64decode(params.get("data_b64", ""))
        finalize = bool(params.get("finalize", False))
        expected_sha = params.get("sha256")

        p.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if offset == 0 else "r+b"
        if offset > 0 and not part.exists():
            raise ValueError(f"missing {part_suffix} for offset {offset}")
        with part.open(mode) as f:
            f.seek(offset)
            f.write(chunk)

        if finalize:
            h = hashlib.sha256()
            total = 0
            with part.open("rb") as f:
                for blk in iter(lambda: f.read(STREAM_CHUNK), b""):
                    h.update(blk)
                    total += len(blk)
            got_sha = h.hexdigest()
            if expected_sha and got_sha != expected_sha.lower():
                with contextlib.suppress(Exception):
                    part.unlink()
                raise ValueError(f"sha256 mismatch: got {got_sha}, expected {expected_sha}")
            os.replace(part, p)
            return {"ok": True, "path": str(p), "bytes": total, "sha256": got_sha, "finalized": True}
        return {"ok": True, "offset": offset + len(chunk), "finalized": False}

    if action == "download_chunk":
        p = _resolve_remote_path(params["path"], params.get("cwd"))
        if not p.is_file():
            raise FileNotFoundError(f"not found: {p}")
        offset = int(params.get("offset", 0))
        length = int(params.get("length", STREAM_CHUNK))
        size = p.stat().st_size
        with p.open("rb") as f:
            f.seek(offset)
            chunk = f.read(length)
        eof = (offset + len(chunk)) >= size
        res: dict = {
            "data_b64": base64.b64encode(chunk).decode("ascii"),
            "offset": offset,
            "bytes": len(chunk),
            "total_size": size,
            "eof": eof,
        }
        if eof:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for blk in iter(lambda: f.read(STREAM_CHUNK), b""):
                    h.update(blk)
            res["sha256"] = h.hexdigest()
        return res

    if action == "spawn":
        cmd = params.get("command")
        argv = params.get("argv")
        cwd = params.get("cwd") or str(Path.cwd())
        stdout_path = str(_resolve_remote_path(params["stdout"], cwd)) if params.get("stdout") else None
        stderr_path = str(_resolve_remote_path(params["stderr"], cwd)) if params.get("stderr") else None
        use_shell = bool(params.get("shell", True))
        if stdout_path:
            Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
        if stderr_path:
            Path(stderr_path).parent.mkdir(parents=True, exist_ok=True)
        out_f = open(stdout_path, "ab", buffering=0) if stdout_path else None  # noqa: SIM115
        err_f = (
            open(stderr_path, "ab", buffering=0)  # noqa: SIM115
            if stderr_path
            else out_f
        )
        kwargs: dict = {
            "cwd": cwd,
            "stdout": out_f or subprocess.DEVNULL,
            "stderr": err_f or subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if IS_WINDOWS:
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            )
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd if use_shell else argv, shell=use_shell, **kwargs)
        info: dict = {
            "pid": proc.pid,
            "command": cmd if use_shell else argv,
            "cwd": cwd,
            "stdout": stdout_path,
            "stderr": stderr_path,
            "started_at": time.time(),
            "caller": caller_label,
        }
        if isinstance(origin, dict) and origin:
            info["origin"] = origin
        with _PROCS_LOCK, _cross_process_lock(_procs_file().with_suffix(".lock")):
            _PROCS[proc.pid] = {**info, "_proc": proc, "_out": out_f, "_err": err_f}
            disk_procs = _load_persisted_procs()
            disk_procs[str(proc.pid)] = info
            _save_persisted_procs(disk_procs)
        return info

    if action == "list":
        with _PROCS_LOCK, _cross_process_lock(_procs_file().with_suffix(".lock")):
            disk_procs = _load_persisted_procs()
            items = []
            done_mem: list[int] = []
            dirty_disk = False
            seen_pids: set[int] = set()

            for pid, rec in _PROCS.items():
                seen_pids.add(pid)
                st = _proc_status(rec)
                entry = {
                    "pid": pid,
                    "command": rec["command"],
                    "cwd": rec["cwd"],
                    "stdout": rec["stdout"],
                    "status": st,
                    "caller": rec.get("caller", ""),
                }
                if rec.get("origin"):
                    entry["origin"] = rec["origin"]
                items.append(entry)
                if st != "running":
                    done_mem.append(pid)
                    if disk_procs.pop(str(pid), None) is not None:
                        dirty_disk = True

            for pid_s, drec in list(disk_procs.items()):
                try:
                    pid = int(pid_s)
                except ValueError:
                    disk_procs.pop(pid_s, None)
                    dirty_disk = True
                    continue
                if pid in seen_pids:
                    continue
                alive = _is_pid_running(pid)
                st = "running" if alive else "exited"
                entry = {
                    "pid": pid,
                    "command": drec.get("command"),
                    "cwd": drec.get("cwd"),
                    "stdout": drec.get("stdout"),
                    "status": st,
                    "caller": drec.get("caller", ""),
                }
                if drec.get("origin"):
                    entry["origin"] = drec["origin"]
                items.append(entry)
                if not alive:
                    disk_procs.pop(pid_s, None)
                    dirty_disk = True

            for pid in done_mem:
                rec = _PROCS.pop(pid, None)
                if rec:
                    for f in {rec.get("_out"), rec.get("_err")}:
                        if f and not f.closed:
                            with contextlib.suppress(Exception):
                                f.close()
            if dirty_disk:
                _save_persisted_procs(disk_procs)
        return {"processes": items}

    if action == "kill":
        pid = int(params["pid"])
        sig_name = str(params.get("signal", "TERM")).upper()
        with _PROCS_LOCK, _cross_process_lock(_procs_file().with_suffix(".lock")):
            rec = _PROCS.get(pid)
            disk_procs = _load_persisted_procs()
            drec = disk_procs.get(str(pid))
            if not rec and not drec:
                raise ValueError(f"pid {pid} not tracked by this node")
            if rec is not None:
                proc = rec["_proc"]
                if proc.poll() is None:
                    if IS_WINDOWS:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(pid)],
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
                        with contextlib.suppress(Exception):
                            proc.kill()
                    else:
                        sig = signal.SIGKILL if sig_name == "KILL" else signal.SIGTERM
                        with contextlib.suppress(Exception):
                            os.killpg(pid, sig)
                        with contextlib.suppress(Exception):
                            proc.send_signal(sig)
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=3)
            elif _is_pid_running(pid):
                if IS_WINDOWS:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                else:
                    sig = signal.SIGKILL if sig_name == "KILL" else signal.SIGTERM
                    with contextlib.suppress(Exception):
                        os.killpg(pid, sig)
                    with contextlib.suppress(Exception):
                        os.kill(pid, sig)
            if disk_procs.pop(str(pid), None) is not None:
                _save_persisted_procs(disk_procs)
        return {"pid": pid, "action": "signal-sent", "signal": sig_name}

    if action == "autostart":
        return manage_autostart(
            mode=params.get("mode", "status"),
            port=int(params.get("port", 7777)),
            host=params.get("host", "0.0.0.0"),
            dial_url=params.get("dial_url", ""),
            dial_token=params.get("dial_token", ""),
            dial_alias=params.get("dial_alias", ""),
        )

    if action == "peer_add":
        # Connect and register a downstream peer directly FROM this node!
        return connect_peer_local(
            alias=params["alias"],
            endpoint=params["endpoint"],
            token=params.get("token", ""),
            bootstrap=bool(params.get("bootstrap", False)),
            remote_path=params.get("remote_path", ""),
            ssh_port=params.get("ssh_port"),
        )

    if action == "peer_remove":
        alias = str(params["alias"])
        with _STATE_LOCK:
            st = load_topology_state()
            removed = st["peers"].pop(alias, None)
            st["routes"] = {
                k: v for k, v in st["routes"].items() if k != alias and v.get("next_hop") != alias
            }
            if st.get("default_active") == alias:
                st["default_active"] = next(iter(st["peers"].keys()), "")
            save_topology_state(st)
        return {"ok": True, "alias": alias, "removed": removed is not None}

    if action == "peers_list":
        st = load_topology_state()
        return {
            "node_id": st["node_id"],
            "alias": st["alias"],
            "peers": {
                k: {pk: pv for pk, pv in v.items() if pk != "token"}
                for k, v in st["peers"].items()
            },
            "routes": st["routes"],
            "reverse_peers": list_reverse_peers(),
        }

    if action == "shutdown":
        delay = max(0.1, min(30.0, float(params.get("delay", 1.0))))
        threading.Thread(
            target=lambda: (time.sleep(delay), os._exit(0)),
            daemon=True,
        ).start()
        return {"ok": True, "pid": os.getpid(), "exit_in_seconds": delay}

    raise ValueError(f"unknown action: {action}")


# ---------------------------------------------------------------------------
# Reverse-Tunnel Hub State (for NAT / Inbound-Blocked Nodes)
# ---------------------------------------------------------------------------

class _ReversePeerSession:
    def __init__(self, alias: str, node_id: str, info: dict):
        self.alias = alias
        self.node_id = node_id
        self.info = info
        self.last_seen = time.time()
        self.outbox: queue.Queue[dict] = queue.Queue()


_REV_LOCK = threading.Lock()
_REV_PEERS: dict[str, _ReversePeerSession] = {}  # alias -> session
_REV_WAITERS: dict[str, tuple[threading.Event, dict]] = {}  # req_id -> (event, holder)


def register_reverse_poll(info: dict) -> _ReversePeerSession:
    node_id = str(info.get("node_id") or "")
    alias = str(info.get("alias") or info.get("hostname") or node_id)
    with _REV_LOCK:
        sess = _REV_PEERS.get(alias)
        if sess is None:
            sess = _ReversePeerSession(alias=alias, node_id=node_id, info=info)
            _REV_PEERS[alias] = sess
        else:
            sess.node_id = node_id or sess.node_id
            sess.info = info
            sess.last_seen = time.time()
        return sess


def list_reverse_peers() -> dict[str, dict]:
    now = time.time()
    out = {}
    with _REV_LOCK:
        stale = [k for k, s in _REV_PEERS.items() if now - s.last_seen > 90.0]
        for k in stale:
            _REV_PEERS.pop(k, None)
        for k, s in _REV_PEERS.items():
            out[k] = {
                "alias": s.alias,
                "node_id": s.node_id,
                "type": "reverse",
                "hostname": s.info.get("hostname", ""),
                "platform": s.info.get("platform", ""),
                "cwd": s.info.get("cwd", ""),
                "last_seen_ago_sec": round(now - s.last_seen, 1),
            }
    return out


def _find_reverse_session(target: str) -> _ReversePeerSession | None:
    now = time.time()
    with _REV_LOCK:
        for sess in _REV_PEERS.values():
            if now - sess.last_seen > 90.0:
                continue
            if target in (sess.alias, sess.node_id, sess.info.get("hostname")):
                return sess
    return None


def send_via_reverse(sess: _ReversePeerSession, env: dict, timeout: float = 120.0) -> dict:
    req_id = f"{env.get('pkt_id')}:{secrets.token_hex(4)}"
    ev = threading.Event()
    holder: dict = {}
    with _REV_LOCK:
        _REV_WAITERS[req_id] = (ev, holder)
    try:
        sess.outbox.put({"req_id": req_id, "envelope": env})
        if not ev.wait(timeout=timeout):
            return {"ok": False, "error": f"reverse peer '{sess.alias}' timed out"}
        return holder.get("response") or {"ok": False, "error": "empty reverse reply"}
    finally:
        with _REV_LOCK:
            _REV_WAITERS.pop(req_id, None)


def deliver_reverse_reply(req_id: str, response: dict) -> bool:
    with _REV_LOCK:
        entry = _REV_WAITERS.get(req_id)
        if not entry:
            return False
        ev, holder = entry
        holder["response"] = response
        ev.set()
        return True


# ---------------------------------------------------------------------------
# SSH, Local-Subprocess & HTTP Transports + Self-Bootstrap
# ---------------------------------------------------------------------------

def _parse_ssh_endpoint(endpoint: str, default_port: int | None = None) -> tuple[str, int | None]:
    ep = endpoint.strip()
    if ep.startswith("ssh://"):
        parsed = urllib.parse.urlsplit(ep)
        user_host = parsed.username + "@" + parsed.hostname if parsed.username else (parsed.hostname or "")
        return user_host, parsed.port or default_port
    return ep, default_port


def _ssh_base_cmd(target: str, port: int | None = None) -> list[str]:
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if port:
        cmd.extend(["-p", str(port)])
    cmd.append(target)
    return cmd


def bootstrap_ssh_target(
    target: str,
    ssh_port: int | None = None,
    remote_path: str = "",
) -> dict:
    """Copy THIS single-file rmcp.py over SSH stdin to the remote host and verify it."""
    my_bytes = Path(__file__).resolve().read_bytes()
    my_sha = hashlib.sha256(my_bytes).hexdigest()
    b64_src = base64.b64encode(my_bytes).decode("ascii")

    # Probe remote python executable (works on both Windows cmd.exe and POSIX sh)
    probe_py = None
    last_ssh_err = ""
    for candidate in ("python3", "python", "py -3"):
        probe_cmd = _ssh_base_cmd(target, ssh_port) + [
            f'{candidate} -c "import sys; print(\'RMCP_PY:\' + sys.executable)"'
        ]
        try:
            res = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"SSH connection timed out reaching '{target}'") from exc
        if res.returncode == 0 and "RMCP_PY:" in res.stdout:
            for ln in res.stdout.splitlines():
                if "RMCP_PY:" in ln:
                    probe_py = ln.split("RMCP_PY:", 1)[1].strip()
                    break
            if probe_py:
                break
        if res.returncode == 255:
            err_detail = (res.stderr or res.stdout).strip()[:240]
            raise RuntimeError(f"SSH unreachable for '{target}': {err_detail or 'exit 255'}")
        last_ssh_err = (res.stderr or res.stdout).strip()[:200]

    if not probe_py:
        raise RuntimeError(
            f"no working Python 3 found on SSH target '{target}'"
            + (f" ({last_ssh_err})" if last_ssh_err else "")
        )

    # Stream rmcp.py bytes via stdin into remote ~/.rmcp/rmcp.py (zero nested double-quotes or backslashes!)
    rpath_b64 = base64.b64encode(remote_path.encode("utf-8")).decode("ascii")
    stdin_payload = f"{rpath_b64}\n{b64_src}\n"
    installer_one_liner = (
        "import base64,hashlib,os,pathlib,sys;"
        "lines=sys.stdin.read().splitlines();"
        "rp=base64.b64decode(lines[0]).decode() if lines and lines[0] else '';"
        "raw=base64.b64decode(''.join(lines[1:]));"
        "dest=pathlib.Path(rp).expanduser() if rp else (pathlib.Path.home()/'.rmcp'/'rmcp.py');"
        "dest.parent.mkdir(parents=True,exist_ok=True);"
        "tmp=dest.with_suffix('.tmp');tmp.write_bytes(raw);os.replace(tmp,dest);"
        "print('RMCP_BOOT:'+hashlib.sha256(raw).hexdigest()+'|'+str(dest))"
    )
    quoted_py = f'"{probe_py}"' if " " in probe_py else probe_py
    install_cmd = _ssh_base_cmd(target, ssh_port) + [
        f'{quoted_py} -c "{installer_one_liner}"'
    ]
    res = subprocess.run(
        install_cmd,
        input=stdin_payload,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if res.returncode != 0 or "RMCP_BOOT:" not in res.stdout:
        raise RuntimeError(
            f"bootstrap failed on '{target}' (rc={res.returncode}): "
            f"{(res.stderr or res.stdout).strip()[:300]}"
        )

    got_sha = ""
    got_path = ""
    for ln in res.stdout.splitlines():
        if "RMCP_BOOT:" in ln:
            tail = ln.split("RMCP_BOOT:", 1)[1].strip()
            got_sha, _, got_path = tail.partition("|")
            break

    if got_sha != my_sha:
        raise RuntimeError("bootstrap sha256 mismatch on remote target")

    return {
        "python": probe_py,
        "remote_path": got_path.replace("\\", "/"),
        "sha256": my_sha,
    }


def _send_framed_stdio(cmd: list[str], env: dict, extra_os_env: dict | None = None, timeout: float = 120.0) -> dict:
    wire = FRAME_REQ_PREFIX + base64.b64encode(
        json.dumps(env, separators=(",", ":")).encode("utf-8")
    ).decode("ascii") + "\n"
    run_env = os.environ.copy()
    if extra_os_env:
        run_env.update(extra_os_env)

    try:
        res = subprocess.run(
            cmd,
            input=wire.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            env=run_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "stdio transport timed out"}
    except Exception as e:
        return {"ok": False, "error": f"stdio transport failed: {e}"}

    stdout_txt = res.stdout.decode("utf-8", errors="replace")
    for line in stdout_txt.splitlines():
        idx = line.find(FRAME_RES_PREFIX)
        if idx != -1:
            b64_part = line[idx + len(FRAME_RES_PREFIX) :].strip()
            try:
                return json.loads(base64.b64decode(b64_part).decode("utf-8"))
            except Exception as e:
                return {"ok": False, "error": f"corrupt stdio frame: {e}"}

    stderr_txt = res.stderr.decode("utf-8", errors="replace").strip()
    return {
        "ok": False,
        "error": f"remote stdio hop exited rc={res.returncode}: {(stderr_txt or stdout_txt)[:300]}",
    }


class _StdioSession:
    """Persistent multiplexed `--stdio-loop` pipe for interactive REPL & multi-chunk transfers."""

    def __init__(self, cmd: list[str], extra_os_env: dict | None = None) -> None:
        run_env = os.environ.copy()
        if extra_os_env:
            run_env.update(extra_os_env)
        self.lock = threading.Lock()
        self.requests_ok = 0
        self.closed = False
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=run_env,
        )
        self._res_q: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        try:
            while True:
                raw_line = self.proc.stdout.readline()
                if not raw_line:
                    self._res_q.put(None)
                    break
                line = raw_line.decode("utf-8", errors="replace")
                idx = line.find(FRAME_RES_PREFIX)
                if idx != -1:
                    self._res_q.put(line[idx + len(FRAME_RES_PREFIX) :].strip())
        except Exception:
            self._res_q.put(None)

    def is_alive(self) -> bool:
        return not self.closed and self.proc.poll() is None and self.proc.stdin is not None

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(Exception):
            if self.proc.stdin:
                self.proc.stdin.close()
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=0.5)
        if self.proc.poll() is None:
            with contextlib.suppress(Exception):
                self.proc.kill()
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=0.5)

    def request(self, env: dict, timeout: float = 120.0) -> dict | None:
        with self.lock:
            if not self.is_alive():
                self.close()
                return None
            assert self.proc.stdin is not None
            wire = (
                FRAME_REQ_PREFIX
                + base64.b64encode(json.dumps(env, separators=(",", ":")).encode("utf-8")).decode("ascii")
                + "\n"
            ).encode("utf-8")
            try:
                self.proc.stdin.write(wire)
                self.proc.stdin.flush()
            except BaseException:
                self.close()
                return None

            try:
                b64_part = self._res_q.get(timeout=timeout)
            except queue.Empty:
                self.close()
                return {"ok": False, "error": "stdio transport timed out"}
            except BaseException:
                self.close()
                raise

            if b64_part is None:
                self.close()
                return None
            try:
                parsed = json.loads(base64.b64decode(b64_part).decode("utf-8"))
                self.requests_ok += 1
                return parsed
            except Exception as e:
                self.close()
                return {"ok": False, "error": f"corrupt stdio frame: {e}"}


_STDIO_POOL_LOCK = threading.Lock()
_STDIO_POOL: dict[str, _StdioSession] = {}
_STDIO_LOOP_UNSUPPORTED: set[str] = set()
_PERSISTENT_STDIO_DEPTH = 0


def close_all_stdio_sessions() -> None:
    with _STDIO_POOL_LOCK:
        sessions = list(_STDIO_POOL.values())
        _STDIO_POOL.clear()
    for sess in sessions:
        sess.close()


atexit.register(close_all_stdio_sessions)


@contextlib.contextmanager
def persistent_stdio_context():
    """Keep SSH / stdio-loop peer pipes open across commands within this context."""
    global _PERSISTENT_STDIO_DEPTH
    with _STDIO_POOL_LOCK:
        _PERSISTENT_STDIO_DEPTH += 1
    try:
        yield
    finally:
        should_close = False
        with _STDIO_POOL_LOCK:
            _PERSISTENT_STDIO_DEPTH = max(0, _PERSISTENT_STDIO_DEPTH - 1)
            if _PERSISTENT_STDIO_DEPTH == 0:
                should_close = True
        if should_close:
            close_all_stdio_sessions()


def _send_persistent_or_oneshot_stdio(
    peer_key: str,
    loop_cmd: list[str],
    hop_cmd: list[str],
    env: dict,
    extra_os_env: dict | None = None,
    timeout: float = 120.0,
) -> dict:
    with _STDIO_POOL_LOCK:
        use_pool = _PERSISTENT_STDIO_DEPTH > 0 and peer_key not in _STDIO_LOOP_UNSUPPORTED

    if use_pool:
        for attempt in range(2):
            with _STDIO_POOL_LOCK:
                sess = _STDIO_POOL.get(peer_key)
                if sess is None or not sess.is_alive():
                    if sess is not None:
                        sess.close()
                    try:
                        sess = _StdioSession(loop_cmd, extra_os_env=extra_os_env)
                        _STDIO_POOL[peer_key] = sess
                    except Exception:
                        sess = None
            if sess is None:
                break
            was_warm = sess.requests_ok > 0
            resp = sess.request(env, timeout=timeout)
            if resp is not None:
                return resp
            with _STDIO_POOL_LOCK:
                if _STDIO_POOL.get(peer_key) is sess:
                    _STDIO_POOL.pop(peer_key, None)
            if not was_warm:
                # First request on `--stdio-loop` failed (peer may be older rmcp.py or unreachable)
                with _STDIO_POOL_LOCK:
                    _STDIO_LOOP_UNSUPPORTED.add(peer_key)
                break
            # Warm session dropped mid-flight; loop once to reconnect cleanly
            if attempt == 1:
                break

    return _send_framed_stdio(hop_cmd, env, extra_os_env=extra_os_env, timeout=timeout)


def send_via_ssh(peer: dict, env: dict, timeout: float = 120.0) -> dict:
    # Support local://state_dir transport for zero-SSH multi-hop router testing
    target = str(peer.get("target", ""))
    if target.startswith("local://"):
        peer_state_dir = target[len("local://") :]
        script = peer.get("remote_path") or str(Path(__file__).resolve())
        extra_env = {
            "REMOTE_MCP_STATE_DIR": peer_state_dir,
            "RMCP_STATE_DIR": peer_state_dir,
            "REMOTE_MCP_NODE_ALIAS": peer.get("alias", ""),
            "RMCP_SESSION": "",
            "ANTIGRAVITY_CONVERSATION_ID": "",
            "CODEX_THREAD_ID": "",
            "CLAUDE_SESSION_ID": "",
        }
        return _send_persistent_or_oneshot_stdio(
            peer_key=f"local:{peer_state_dir}:{script}",
            loop_cmd=[sys.executable, script, "--stdio-loop"],
            hop_cmd=[sys.executable, script, "--stdio-hop"],
            env=env,
            extra_os_env=extra_env,
            timeout=timeout,
        )

    py_exe = peer.get("python") or "python3"
    rpath = (peer.get("remote_path") or "~/.rmcp/rmcp.py").replace("\\", "/")
    quoted_py = f'"{py_exe}"' if " " in py_exe else py_exe
    quoted_rpath = f'"{rpath}"' if (" " in rpath and not rpath.startswith("~")) else rpath
    base_ssh = _ssh_base_cmd(target, peer.get("ssh_port"))
    return _send_persistent_or_oneshot_stdio(
        peer_key=f"ssh:{target}:{peer.get('ssh_port') or 22}:{rpath}",
        loop_cmd=base_ssh + [f"{quoted_py} {quoted_rpath} --stdio-loop"],
        hop_cmd=base_ssh + [f"{quoted_py} {quoted_rpath} --stdio-hop"],
        env=env,
        timeout=timeout,
    )


def _http_request_json(
    url: str,
    method: str,
    token: str,
    payload: dict | None = None,
    timeout: float = 120.0,
) -> tuple[int, dict | str]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        with contextlib.suppress(Exception):
            return e.code, json.loads(raw)
        return e.code, raw
    except Exception as e:
        return 0, str(e)


def _legacy_http_exec_ndjson(base_url: str, token: str, params: dict, timeout: float = 120.0) -> dict:
    body_dict: dict = {"command": params.get("command", "")}
    if params.get("cwd"):
        body_dict["cwd"] = params["cwd"]
    if params.get("timeout") is not None:
        body_dict["timeout"] = params["timeout"]

    data = json.dumps(body_dict).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/exec",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    out_parts: list[str] = []
    err_parts: list[str] = []
    exit_code = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line)
                except Exception:
                    continue
                if not isinstance(frame, dict):
                    continue
                t = frame.get("t")
                if t == "out":
                    out_parts.append(frame.get("d") or "")
                elif t == "err":
                    err_parts.append(frame.get("d") or "")
                elif t == "exit":
                    exit_code = frame.get("code")
                elif t == "error":
                    return {"ok": False, "error": frame.get("msg", "remote exec error")}
    except Exception as e:
        return {"ok": False, "error": f"legacy /exec failed: {e}"}

    return {
        "ok": True,
        "result": {
            "stdout": "".join(out_parts),
            "stderr": "".join(err_parts),
            "exit_code": exit_code,
            "cwd": params.get("cwd") or "",
        },
    }


def _fallback_legacy_agent_http(peer: dict, env: dict, timeout: float = 120.0) -> dict:
    """Translate router envelope into legacy agent.py v0.4 REST endpoints."""
    base = peer["url"].rstrip("/")
    tok = peer.get("token", "")
    action = env.get("action")
    params = env.get("params") or {}
    via = list(env.get("via") or []) + [peer.get("alias", "http-peer")]

    if action == "ping":
        code, res = _http_request_json(base + "/ping", "GET", tok, timeout=timeout)
        if code == 200 and isinstance(res, dict):
            res.setdefault("node_id", peer.get("alias"))
            return {"ok": True, "node_id": res["node_id"], "via": via, "result": res}
        return {"ok": False, "error": f"/ping {code}: {res}"}

    if action == "env":
        code, res = _http_request_json(base + "/env", "GET", tok, timeout=timeout)
        if code == 200 and isinstance(res, dict):
            return {"ok": True, "node_id": peer.get("alias"), "via": via, "result": res}
        return {"ok": False, "error": f"/env {code}: {res}"}

    if action == "exec":
        r = _legacy_http_exec_ndjson(base, tok, params, timeout=timeout)
        if r.get("ok"):
            r["via"] = via
            r["node_id"] = peer.get("alias")
        return r

    if action in ("read", "write", "spawn", "kill", "shutdown"):
        code, res = _http_request_json(base + f"/{action}", "POST", tok, params, timeout=timeout)
        if code == 200 and isinstance(res, dict):
            return {"ok": True, "node_id": peer.get("alias"), "via": via, "result": res}
        return {"ok": False, "error": f"/{action} {code}: {res}"}

    if action == "upload_chunk":
        if params.get("offset", 0) == 0 and params.get("finalize"):
            code, res = _http_request_json(
                base + "/write",
                "POST",
                tok,
                {"path": params["path"], "cwd": params.get("cwd"), "data_b64": params["data_b64"]},
                timeout=timeout,
            )
            if code == 200 and isinstance(res, dict):
                res.setdefault("bytes", len(base64.b64decode(params["data_b64"])))
                res.setdefault("sha256", params.get("sha256", ""))
                return {"ok": True, "node_id": peer.get("alias"), "via": via, "result": res}
            return {"ok": False, "error": f"legacy /write {code}: {res}"}

    if action == "list":
        code, res = _http_request_json(base + "/list", "GET", tok, timeout=timeout)
        if code == 200 and isinstance(res, dict):
            return {"ok": True, "node_id": peer.get("alias"), "via": via, "result": res}
        return {"ok": False, "error": f"/list {code}: {res}"}

    if action == "edit":
        c1, r1 = _http_request_json(base + "/read", "POST", tok, {"path": params["path"]}, timeout=timeout)
        if c1 != 200 or not isinstance(r1, dict):
            return {"ok": False, "error": f"/read {c1}: {r1}"}
        txt = base64.b64decode(r1.get("data_b64", "")).decode("utf-8", errors="replace")
        cnt = txt.count(params["old_text"])
        if cnt != 1:
            return {"ok": False, "error": f"old_text matched {cnt} times (expected 1)"}
        new_b64 = base64.b64encode(
            txt.replace(params["old_text"], params["new_text"], 1).encode("utf-8")
        ).decode("ascii")
        c2, r2 = _http_request_json(
            base + "/write", "POST", tok, {"path": params["path"], "data_b64": new_b64}, timeout=timeout
        )
        if c2 == 200 and isinstance(r2, dict):
            return {"ok": True, "node_id": peer.get("alias"), "via": via, "result": r2}
        return {"ok": False, "error": f"/write {c2}: {r2}"}

    return {"ok": False, "error": f"legacy agent does not support '{action}' (upgrade agent to rmcp.py)"}


def send_via_http(peer: dict, env: dict, timeout: float = 120.0) -> dict:
    base = peer["url"].rstrip("/")
    tok = peer.get("token", "")

    # Encrypt sensitive inner body over HTTP when token is configured
    wire_env = dict(env)
    if tok and "enc" not in wire_env:
        inner: dict = {"action": wire_env.pop("action"), "params": wire_env.pop("params", {})}
        if "origin" in wire_env:
            inner["origin"] = wire_env.pop("origin")
        wire_env["enc"] = encrypt_obj(inner, tok)

    code, res = _http_request_json(base + "/route", "POST", tok, wire_env, timeout=timeout)
    if code == 200 and isinstance(res, dict):
        if tok and "enc" in res:
            try:
                dec = decrypt_obj(res["enc"], tok)
                res = {k: v for k, v in res.items() if k != "enc"}
                res.update(dec)
            except Exception as e:
                return {"ok": False, "error": f"response decryption failed: {e}"}
        return res

    err_msg = res.get("error") if isinstance(res, dict) else str(res)

    # Automatic fallback for older v0.4 agent.py instances without /route
    # Note: Older Windows agent.py closes connection on 404 without draining POST body,
    # causing TCP RST (WinError 10054 / ConnectionResetError) on the client side.
    dst = env.get("dst")
    is_reset_or_404 = (
        code == 404
        or (code == 0 and any(w in str(err_msg).lower() for w in ("10054", "reset", "closed", "broken pipe")))
    )
    if is_reset_or_404 and dst in ("self", peer.get("alias"), peer.get("node_id"), peer.get("hostname")):
        return _fallback_legacy_agent_http(peer, env, timeout=timeout)

    return {"ok": False, "error": f"HTTP {code} from {peer.get('alias')}: {err_msg}"}


def _send_to_peer(peer_alias: str, peer: dict, env: dict, timeout: float = 120.0) -> dict:
    ptype = peer.get("type", "ssh")
    if ptype == "ssh":
        return send_via_ssh(peer, env, timeout=timeout)
    if ptype == "http":
        return send_via_http(peer, env, timeout=timeout)
    return {"ok": False, "error": f"unsupported peer type '{ptype}' on {peer_alias}"}


# ---------------------------------------------------------------------------
# Core Mesh Router Engine (Unicast Route Cache + Safe Flood Discovery)
# ---------------------------------------------------------------------------

def _is_local_target(dst: str, state: dict) -> bool:
    if not dst or dst in ("self", "local"):
        return True
    return dst in (state.get("node_id"), state.get("alias"), socket.gethostname())


def _peer_matches_target(peer_alias: str, peer: dict, dst: str) -> bool:
    return dst in (
        peer_alias,
        peer.get("alias"),
        peer.get("node_id"),
        peer.get("hostname"),
    )


def _peer_in_via(peer_alias: str, peer: dict, via: list[str]) -> bool:
    via_set = set(via)
    for ident in (peer_alias, peer.get("alias"), peer.get("node_id"), peer.get("hostname")):
        if ident and ident in via_set:
            return True
    return False


def _learn_route(dst: str, next_hop_alias: str, resp: dict) -> None:
    if not dst or dst == next_hop_alias:
        return
    plat = resp.get("platform") or (resp.get("result") or {}).get("platform") or ""
    with _STATE_LOCK:
        state = load_topology_state()
        if dst in state["peers"]:
            return
        prev_plat = (state["routes"].get(dst) or {}).get("platform", "")
        state["routes"][dst] = {
            "next_hop": next_hop_alias,
            "path": resp.get("via") or [],
            "node_id": resp.get("node_id", ""),
            "platform": plat or prev_plat,
            "updated_at": int(time.time()),
        }
        save_topology_state(state)


def route_envelope(env: dict, timeout: float = 120.0) -> dict:
    """Process or route a mesh envelope with loop prevention and route caching."""
    pkt_id = str(env.get("pkt_id") or uuid.uuid4())
    if mark_packet_seen(pkt_id):
        return {"ok": False, "error": "duplicate_packet_dropped", "loop": True}

    state = load_topology_state()
    my_id = state["node_id"]
    my_alias = state["alias"]
    dst = str(env.get("dst") or "self")
    via = list(env.get("via") or [])

    if my_id in via or (my_alias and my_alias in via):
        return {"ok": False, "error": "routing_loop_detected", "loop": True}

    # 1. Destination is THIS node!
    if _is_local_target(dst, state):
        action = str(env.get("action") or "ping")
        params = env.get("params") or {}
        origin = env.get("origin") if isinstance(env.get("origin"), dict) else None
        try:
            result = execute_local_action(action, params, origin=origin)
            return {
                "ok": True,
                "reached_dst": True,
                "node_id": my_id,
                "alias": my_alias,
                "hostname": socket.gethostname(),
                "platform": sys.platform,
                "via": via + [my_alias or my_id],
                "result": result,
            }
        except Exception as e:
            return {
                "ok": False,
                "reached_dst": True,
                "node_id": my_id,
                "via": via + [my_alias or my_id],
                "error": f"{type(e).__name__}: {e}",
            }

    # 2. Check TTL before forwarding
    ttl = int(env.get("ttl", DEFAULT_TTL)) - 1
    if ttl <= 0:
        return {"ok": False, "error": f"ttl_expired reaching '{dst}'", "ttl_expired": True}

    fwd_env = {
        **env,
        "pkt_id": pkt_id,
        "ttl": ttl,
        "via": via + [my_alias or my_id],
    }

    # 3. Direct Reverse-Connected Peer match?
    rev_sess = _find_reverse_session(dst)
    if rev_sess is not None:
        return send_via_reverse(rev_sess, {**fwd_env, "dst": "self"}, timeout=timeout)

    # 4. Direct Outbound Peer match?
    peers: dict[str, dict] = state.get("peers") or {}
    for p_alias, p_cfg in peers.items():
        if _peer_matches_target(p_alias, p_cfg, dst):
            if _peer_in_via(p_alias, p_cfg, via):
                return {"ok": False, "error": "target peer already in via path"}
            return _send_to_peer(p_alias, p_cfg, {**fwd_env, "dst": "self"}, timeout=timeout)

    # 5. Cached Multi-Hop Route (Unicast fast path — zero broadcast!)
    routes: dict[str, dict] = state.get("routes") or {}
    cached = routes.get(dst)
    tried_hops: set[str] = set()
    if cached:
        nh = cached.get("next_hop", "")
        if nh in peers and not _peer_in_via(nh, peers[nh], via):
            tried_hops.add(nh)
            resp = _send_to_peer(nh, peers[nh], fwd_env, timeout=timeout)
            if resp.get("ok") or resp.get("reached_dst"):
                _learn_route(dst, nh, resp)
                return resp
            # Otherwise dynamically learned route is stale; evict and fall through to discovery flood
            if not cached.get("explicit"):
                with _STATE_LOCK:
                    st2 = load_topology_state()
                    st2["routes"].pop(dst, None)
                    save_topology_state(st2)
        else:
            rev_nh = _find_reverse_session(nh)
            if rev_nh is not None and nh not in via:
                tried_hops.add(nh)
                resp = send_via_reverse(rev_nh, fwd_env, timeout=timeout)
                if resp.get("ok") or resp.get("reached_dst"):
                    _learn_route(dst, nh, resp)
                    return resp

    # 6. Controlled Flood Discovery across remaining neighbors (anti-storm protected)
    errors: list[str] = []
    for p_alias, p_cfg in peers.items():
        if p_alias in tried_hops or _peer_in_via(p_alias, p_cfg, via):
            continue
        resp = _send_to_peer(p_alias, p_cfg, fwd_env, timeout=timeout)
        if resp.get("ok") or resp.get("reached_dst"):
            _learn_route(dst, p_alias, resp)
            return resp
        errors.append(f"{p_alias}: {resp.get('error', 'unreachable')}")

    with _REV_LOCK:
        rev_candidates = list(_REV_PEERS.values())
    for rs in rev_candidates:
        if rs.alias in tried_hops or rs.alias in via or rs.node_id in via:
            continue
        if time.time() - rs.last_seen > 90.0:
            continue
        resp = send_via_reverse(rs, fwd_env, timeout=timeout)
        if resp.get("ok") or resp.get("reached_dst"):
            _learn_route(dst, rs.alias, resp)
            return resp
        errors.append(f"rev/{rs.alias}: {resp.get('error', 'unreachable')}")

    detail = "; ".join(errors) if errors else "no reachable neighbors"
    return {"ok": False, "error": f"no route to '{dst}' ({detail})"}


def send_action(dst: str, action: str, params: dict | None = None, timeout: float = 120.0) -> dict:
    state = load_router_state()
    env = {
        "v": 1,
        "pkt_id": str(uuid.uuid4()),
        "ttl": DEFAULT_TTL,
        "src": state["node_id"],
        "dst": dst or "self",
        "via": [],
        "origin": state["origin"],
        "action": action,
        "params": params or {},
    }
    return route_envelope(env, timeout=timeout)


def connect_peer_local(
    alias: str,
    endpoint: str,
    token: str = "",
    bootstrap: bool = False,
    remote_path: str = "",
    ssh_port: int | None = None,
) -> dict:
    """Establish a direct connection from THIS node to `endpoint` and save peer edge."""
    ep = endpoint.strip()
    if ep.startswith(("http://", "https://")):
        peer_entry: dict = {
            "alias": alias,
            "type": "http",
            "url": ep.rstrip("/"),
            "token": token,
        }
        probe_env = {
            "v": 1,
            "pkt_id": str(uuid.uuid4()),
            "ttl": 2,
            "src": load_router_state()["node_id"],
            "dst": "self",
            "via": [],
            "action": "ping",
            "params": {},
        }
        resp = send_via_http(peer_entry, probe_env, timeout=15.0)
        if not resp.get("ok"):
            raise RuntimeError(f"failed to connect HTTP peer '{alias}' ({ep}): {resp.get('error')}")
        info = resp.get("result") or {}
        peer_entry.update(
            {
                "node_id": info.get("node_id") or resp.get("node_id") or "",
                "hostname": info.get("hostname", ""),
                "platform": info.get("platform", ""),
                "cwd": info.get("cwd", ""),
            }
        )
    elif ep.startswith("local://"):
        peer_entry = {
            "alias": alias,
            "type": "ssh",
            "target": ep,
            "remote_path": remote_path or str(Path(__file__).resolve()),
        }
        probe_env = {
            "v": 1,
            "pkt_id": str(uuid.uuid4()),
            "ttl": 2,
            "src": load_router_state()["node_id"],
            "dst": "self",
            "via": [],
            "action": "ping",
            "params": {},
        }
        resp = send_via_ssh(peer_entry, probe_env, timeout=15.0)
        if not resp.get("ok"):
            raise RuntimeError(f"failed to connect local peer '{alias}': {resp.get('error')}")
        info = resp.get("result") or {}
        peer_entry.update(
            {
                "node_id": info.get("node_id", ""),
                "hostname": info.get("hostname", ""),
                "platform": info.get("platform", ""),
                "cwd": info.get("cwd", ""),
            }
        )
    else:
        target, port = _parse_ssh_endpoint(ep, ssh_port)
        peer_entry = {
            "alias": alias,
            "type": "ssh",
            "target": target,
            "ssh_port": port,
            "remote_path": remote_path or "~/.rmcp/rmcp.py",
            "python": "python3",
        }
        bootstrapped = False
        if bootstrap:
            binfo = bootstrap_ssh_target(target, port, remote_path)
            peer_entry["python"] = binfo["python"]
            peer_entry["remote_path"] = binfo["remote_path"]
            bootstrapped = True

        probe_env = {
            "v": 1,
            "pkt_id": str(uuid.uuid4()),
            "ttl": 2,
            "src": load_router_state()["node_id"],
            "dst": "self",
            "via": [],
            "action": "ping",
            "params": {},
        }
        resp = send_via_ssh(peer_entry, probe_env, timeout=20.0)
        if not resp.get("ok") and not bootstrapped:
            # Auto-bootstrap if remote rmcp.py is missing!
            binfo = bootstrap_ssh_target(target, port, remote_path)
            peer_entry["python"] = binfo["python"]
            peer_entry["remote_path"] = binfo["remote_path"]
            bootstrapped = True
            probe_env["pkt_id"] = str(uuid.uuid4())
            resp = send_via_ssh(peer_entry, probe_env, timeout=20.0)

        if not resp.get("ok"):
            raise RuntimeError(f"SSH connection to '{target}' failed: {resp.get('error')}")

        info = resp.get("result") or {}
        peer_entry.update(
            {
                "node_id": info.get("node_id", ""),
                "hostname": info.get("hostname", ""),
                "platform": info.get("platform", ""),
                "cwd": info.get("cwd", ""),
                "bootstrapped": bootstrapped,
            }
        )

    with _STATE_LOCK:
        topo = load_topology_state()
        topo["peers"][alias] = peer_entry
        if not topo.get("default_active"):
            topo["default_active"] = alias
        save_topology_state(topo)

    return {k: v for k, v in peer_entry.items() if k != "token"}


# ---------------------------------------------------------------------------
# HTTP Daemon (Router /route + Reverse Hub + Legacy agent.py Compatibility)
# ---------------------------------------------------------------------------

def load_or_create_daemon_token(token_file: Path | None = None) -> str:
    env_tok = os.environ.get("REMOTE_AGENT_TOKEN") or os.environ.get("PI_REMOTE_AGENT_TOKEN")
    if env_tok:
        return env_tok.strip()
    if token_file:
        tf = token_file
    else:
        # Prefer agent.token in same directory as the script (for legacy agent.py deployments)
        local_tf = Path(__file__).resolve().parent / "agent.token"
        if local_tf.exists():
            tok = local_tf.read_text(encoding="utf-8").strip()
            if tok:
                return tok
        tf = get_state_dir() / "agent.token"
    if tf.exists():
        tok = tf.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(32)
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.write_text(tok, encoding="utf-8")
    return tok


class NodeHTTPHandler(BaseHTTPRequestHandler):
    server_version = f"rmcp-node/{VERSION}"
    daemon_token: str = ""

    def log_message(self, fmt: str, *args) -> None:
        if sys.stderr is not None:
            with contextlib.suppress(Exception):
                sys.stderr.write(f"[rmcp] {self.client_address[0]} - {fmt % args}\n")

    def _authed(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return secrets.compare_digest(auth[7:].strip(), self.daemon_token)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def _send_json(self, status: int, obj: dict) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path_only = self.path.split("?", 1)[0]
        if path_only == "/ping":
            self._send_json(200, execute_local_action("ping", {}))
            return
        if not self._authed():
            self._send_json(401, {"error": "unauthorized"})
            return
        try:
            if path_only == "/env":
                self._send_json(200, execute_local_action("env", {}))
            elif path_only == "/list":
                self._send_json(200, execute_local_action("list", {}))
            elif path_only == "/download":
                qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                src = Path((qs.get("path") or [""])[0])
                if not src.is_file():
                    self._send_json(404, {"error": f"not found: {src}"})
                    return
                size = src.stat().st_size
                h = hashlib.sha256()
                with src.open("rb") as f:
                    for blk in iter(lambda: f.read(STREAM_CHUNK), b""):
                        h.update(blk)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header("X-Sha256", h.hexdigest())
                self.end_headers()
                with src.open("rb") as f:
                    for blk in iter(lambda: f.read(STREAM_CHUNK), b""):
                        self.wfile.write(blk)
            else:
                self._send_json(404, {"error": f"no route: GET {path_only}"})
        except Exception as e:
            self._send_json(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authed():
            self._send_json(401, {"error": "unauthorized"})
            return
        path_only = self.path.split("?", 1)[0]
        try:
            if path_only == "/route":
                env = self._read_json()
                was_encrypted = "enc" in env
                if was_encrypted:
                    inner = decrypt_obj(env.pop("enc"), self.daemon_token)
                    env["action"] = inner["action"]
                    env["params"] = inner.get("params") or {}
                    if "origin" in inner:
                        env["origin"] = inner["origin"]
                resp = route_envelope(env)
                if was_encrypted:
                    outer = {k: v for k, v in resp.items() if k not in ("result", "error")}
                    inner_resp = {k: resp[k] for k in ("result", "error") if k in resp}
                    outer["enc"] = encrypt_obj(inner_resp, self.daemon_token)
                    self._send_json(200, outer)
                else:
                    self._send_json(200, resp)
                return

            if path_only == "/reverse/poll":
                body = self._read_json()
                if "enc" in body:
                    body = decrypt_obj(body["enc"], self.daemon_token)
                sess = register_reverse_poll(body)
                wait_sec = min(30.0, max(0.5, float(body.get("wait_sec", 20.0))))
                try:
                    item = sess.outbox.get(timeout=wait_sec)
                    sess.last_seen = time.time()
                    out = {"idle": False, **item}
                except queue.Empty:
                    sess.last_seen = time.time()
                    out = {"idle": True}
                self._send_json(200, {"enc": encrypt_obj(out, self.daemon_token)})
                return

            if path_only == "/reverse/reply":
                body = self._read_json()
                if "enc" in body:
                    body = decrypt_obj(body["enc"], self.daemon_token)
                ok = deliver_reverse_reply(str(body.get("req_id", "")), body.get("response") or {})
                self._send_json(200, {"ok": ok})
                return

            if path_only == "/upload":
                dest_hdr = self.headers.get("X-Path")
                expected_sha = (self.headers.get("X-Sha256") or "").lower().strip() or None
                length = int(self.headers.get("Content-Length", "0") or "0")
                if not dest_hdr or length < 0:
                    self._send_json(400, {"error": "missing X-Path or Content-Length"})
                    return
                dest = Path(dest_hdr)
                dest.parent.mkdir(parents=True, exist_ok=True)
                part = dest.with_suffix(dest.suffix + ".part")
                h = hashlib.sha256()
                rem = length
                with part.open("wb") as f:
                    while rem > 0:
                        blk = self.rfile.read(min(STREAM_CHUNK, rem))
                        if not blk:
                            break
                        f.write(blk)
                        h.update(blk)
                        rem -= len(blk)
                got_sha = h.hexdigest()
                if expected_sha and got_sha != expected_sha:
                    part.unlink(missing_ok=True)
                    self._send_json(400, {"error": f"sha256 mismatch: {got_sha}"})
                    return
                os.replace(part, dest)
                self._send_json(200, {"ok": True, "bytes": length, "sha256": got_sha, "path": str(dest)})
                return

            if path_only == "/exec":
                body = self._read_json()
                r = _run_local_exec(body.get("command", ""), body.get("cwd"), body.get("timeout"))
                frames = []
                if r["stdout"]:
                    frames.append({"t": "out", "d": r["stdout"]})
                if r["stderr"]:
                    frames.append({"t": "err", "d": r["stderr"]})
                frames.append({"t": "exit", "code": r["exit_code"]})
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for fr in frames:
                    line = (json.dumps(fr) + "\n").encode("utf-8")
                    self.wfile.write(f"{len(line):X}\r\n".encode("ascii") + line + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
                return

            if path_only in ("/read", "/write", "/edit", "/spawn", "/kill", "/shutdown"):
                body = self._read_json()
                self._send_json(200, execute_local_action(path_only[1:], body))
                return

            self._send_json(404, {"error": f"no route: POST {path_only}"})
        except FileNotFoundError as e:
            self._send_json(404, {"error": str(e)})
        except Exception as e:
            self._send_json(500, {"error": f"{type(e).__name__}: {e}"})


def run_http_listener(host: str = "0.0.0.0", port: int = 7777, token: str = "") -> None:
    tok = token or load_or_create_daemon_token()
    state = load_router_state()
    NodeHTTPHandler.daemon_token = tok
    srv = ThreadingHTTPServer((host, port), NodeHTTPHandler)
    if sys.stdout is not None:
        print(f"[rmcp] node={state['node_id']} alias={state['alias']} v{VERSION}", flush=True)
        print(f"[rmcp] listening on http://{host}:{port}", flush=True)
        print(f"[rmcp] token: {tok}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Outbound Reverse-Tunnel Client & Self-Healing Watchdog & Stdio Hop
# ---------------------------------------------------------------------------

def run_reverse_client(
    hub_url: str,
    token: str,
    alias: str = "",
    poll_wait: float = 20.0,
    stop_event: threading.Event | None = None,
) -> None:
    base = hub_url.rstrip("/")
    state = load_router_state()
    my_alias = alias or state["alias"]
    if alias and alias != state["alias"]:
        state["alias"] = alias
        save_router_state(state)

    backoff = 1.0
    if sys.stdout is not None:
        print(f"[rmcp-dial] node={state['node_id']} alias={my_alias} -> {base}", flush=True)

    while not (stop_event and stop_event.is_set()):
        hello = {
            "node_id": state["node_id"],
            "alias": my_alias,
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "cwd": str(Path.cwd()),
            "wait_sec": poll_wait,
        }
        code, res = _http_request_json(
            base + "/reverse/poll",
            "POST",
            token,
            {"enc": encrypt_obj(hello, token)},
            timeout=poll_wait + 15.0,
        )
        if code == 200 and isinstance(res, dict) and "enc" in res:
            backoff = 1.0
            try:
                msg = decrypt_obj(res["enc"], token)
            except Exception as e:
                if sys.stderr is not None:
                    sys.stderr.write(f"[rmcp-dial] decrypt error: {e}\n")
                time.sleep(2.0)
                continue
            if msg.get("idle"):
                continue
            req_id = msg.get("req_id", "")
            env = msg.get("envelope") or {}
            # Execute or route further in a worker thread so concurrent requests don't block!
            def _handle_job(rid: str, job_env: dict) -> None:
                resp = route_envelope(job_env)
                reply_payload = {"req_id": rid, "response": resp}
                _http_request_json(
                    base + "/reverse/reply",
                    "POST",
                    token,
                    {"enc": encrypt_obj(reply_payload, token)},
                    timeout=30.0,
                )

            threading.Thread(target=_handle_job, args=(req_id, env), daemon=True).start()
        else:
            if sys.stderr is not None:
                sys.stderr.write(f"[rmcp-dial] poll HTTP {code}: {res}; retry in {backoff:.1f}s\n")
            time.sleep(backoff)
            backoff = min(30.0, backoff * 1.8)


def run_watchdog(child_args: list[str]) -> None:
    """Supervisor loop: auto-restarts listener/dialer child if it crashes."""
    script = str(Path(__file__).resolve())
    while True:
        proc = subprocess.Popen([sys.executable, script, *child_args])
        rc = proc.wait()
        if rc == 0:
            # Clean shutdown requested (e.g. /shutdown)
            break
        time.sleep(2.0)


def run_stdio_hop() -> int:
    """Read one framed envelope from stdin, route/execute it, write framed response."""
    raw_in = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    env = None
    for line in raw_in.splitlines():
        idx = line.find(FRAME_REQ_PREFIX)
        if idx != -1:
            b64_part = line[idx + len(FRAME_REQ_PREFIX) :].strip()
            env = json.loads(base64.b64decode(b64_part).decode("utf-8"))
            break
    if env is None and raw_in.strip():
        env = json.loads(raw_in.strip())
    if env is None:
        resp = {"ok": False, "error": "empty stdio hop input"}
    else:
        resp = route_envelope(env)

    out_frame = FRAME_RES_PREFIX + base64.b64encode(
        json.dumps(resp, separators=(",", ":")).encode("utf-8")
    ).decode("ascii") + "\n"
    sys.stdout.buffer.write(out_frame.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


def run_stdio_loop() -> int:
    """Persistent multiplexed router loop over stdin/stdout (keeps downstream hops warm too)."""
    with persistent_stdio_context():
        while True:
            raw_line = sys.stdin.buffer.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            idx = line.find(FRAME_REQ_PREFIX)
            if idx == -1:
                continue
            b64_part = line[idx + len(FRAME_REQ_PREFIX) :].strip()
            try:
                env = json.loads(base64.b64decode(b64_part).decode("utf-8"))
                resp = route_envelope(env)
            except Exception as e:
                resp = {"ok": False, "error": f"stdio-loop error: {e}"}
            out_frame = (
                FRAME_RES_PREFIX
                + base64.b64encode(json.dumps(resp, separators=(",", ":")).encode("utf-8")).decode("ascii")
                + "\n"
            )
            sys.stdout.buffer.write(out_frame.encode("utf-8"))
            sys.stdout.buffer.flush()
    return 0


# ---------------------------------------------------------------------------
# CLI Helpers & Colon-Command Dispatcher (One-Shot Bot & Human Friendly)
# ---------------------------------------------------------------------------

_MGMT_COMMANDS = {
    "help",
    "repl",
    "shell",
    "local",
    "q",
    "quit",
    "exit",
    "id",
    "whoami",
    "sessions",
    "nodes",
    "hosts",
    "peers",
    "routes",
    "status",
    "use",
    "to",
    "connect",
    "disconnect",
    "rm",
    "dial",
    "listen",
    "autostart",
    "ping",
    "env",
    "pwd",
    "cd",
    "read",
    "write",
    "edit",
    "upload",
    "download",
    "ps",
    "proclist",
    "spawn",
    "kill",
    "shutdown",
}


def _detect_mgmt_command(arg0: str) -> str | None:
    """Return normalized management command name (without leading ':') or None for normal commands."""
    if arg0 and arg0.startswith(":") and len(arg0) > 1:
        return arg0[1:].lower()
    return None


def _is_target_windows(target: str, state: dict) -> bool:
    if _is_local_target(target, state):
        return IS_WINDOWS
    peer = (state.get("peers") or {}).get(target)
    if peer and peer.get("platform"):
        return str(peer["platform"]).startswith("win")
    for p in (state.get("peers") or {}).values():
        if _peer_matches_target("", p, target) and p.get("platform"):
            return str(p["platform"]).startswith("win")
    route = (state.get("routes") or {}).get(target)
    if route and route.get("platform"):
        return str(route["platform"]).startswith("win")
    return IS_WINDOWS


def _format_passthrough_cmd(args: list[str], target_is_win: bool) -> str:
    if len(args) == 1:
        return args[0]
    if target_is_win:
        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(a) for a in args)


def _resolve_active_target(explicit_to: str, state: dict) -> str:
    if explicit_to:
        return explicit_to
    active = state.get("active") or ""
    if active:
        return active
    peers = state.get("peers") or {}
    if len(peers) == 1:
        return next(iter(peers.keys()))
    return "self"


def _spawn_detached_self(child_args: list[str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_f = open(log_path, "ab", buffering=0)  # noqa: SIM115
    exe = sys.executable
    if IS_WINDOWS:
        pyw = Path(exe).with_name("pythonw.exe")
        if pyw.exists():
            exe = str(pyw)
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_f,
        "stderr": log_f,
    }
    if IS_WINDOWS:
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([exe, str(Path(__file__).resolve()), *child_args], **kwargs)
    return proc.pid


def _cli_upload(
    target: str,
    local_path: str,
    remote_path: str,
    cwd: str | None = None,
    timeout: float = 120.0,
) -> int:
    src = Path(local_path).expanduser()
    if not src.is_file():
        sys.stderr.write(f"[rmcp] local file not found: {src}\n")
        return 1

    size = src.stat().st_size
    h = hashlib.sha256()
    with src.open("rb") as f:
        for blk in iter(lambda: f.read(STREAM_CHUNK), b""):
            h.update(blk)
    expected_sha = h.hexdigest()

    offset = 0
    upload_id = secrets.token_hex(6)
    with persistent_stdio_context(), src.open("rb") as f:
        while True:
            chunk = f.read(STREAM_CHUNK)
            eof = (offset + len(chunk)) >= size
            resp = send_action(
                target,
                "upload_chunk",
                {
                    "path": remote_path,
                    "cwd": cwd,
                    "upload_id": upload_id,
                    "offset": offset,
                    "data_b64": base64.b64encode(chunk).decode("ascii"),
                    "finalize": eof,
                    "sha256": expected_sha if eof else None,
                },
                timeout=timeout,
            )
            if not resp.get("ok"):
                sys.stderr.write(f"[rmcp] upload failed at offset {offset}: {resp.get('error')}\n")
                return 1
            offset += len(chunk)
            if eof:
                res = resp.get("result") or {}
                via_str = " -> ".join(resp.get("via") or [target])
                print(
                    f"[rmcp] uploaded {src} -> {target}:{res.get('path', remote_path)} "
                    f"({res.get('bytes', size)} bytes, sha256={res.get('sha256', expected_sha)[:12]}..., via {via_str})"
                )
                return 0


def _cli_download(
    target: str,
    remote_path: str,
    local_path: str,
    cwd: str | None = None,
    timeout: float = 120.0,
) -> int:
    dst = Path(local_path).expanduser()
    dst.parent.mkdir(parents=True, exist_ok=True)
    part = dst.with_suffix(dst.suffix + f".rmcp_dl.{os.getpid()}")
    offset = 0
    h = hashlib.sha256()
    remote_sha = ""
    via_str = target

    try:
        with persistent_stdio_context(), part.open("wb") as f:
            while True:
                resp = send_action(
                    target,
                    "download_chunk",
                    {"path": remote_path, "cwd": cwd, "offset": offset, "length": STREAM_CHUNK},
                    timeout=timeout,
                )
                if not resp.get("ok"):
                    sys.stderr.write(f"[rmcp] download failed at offset {offset}: {resp.get('error')}\n")
                    with contextlib.suppress(Exception):
                        part.unlink()
                    return 1
                via_str = " -> ".join(resp.get("via") or [target])
                res = resp.get("result") or {}
                chunk = base64.b64decode(res.get("data_b64", ""))
                f.write(chunk)
                h.update(chunk)
                offset += len(chunk)
                if res.get("eof") or not chunk:
                    remote_sha = res.get("sha256", "")
                    break
        got_sha = h.hexdigest()
        if remote_sha and got_sha != remote_sha.lower():
            with contextlib.suppress(Exception):
                part.unlink()
            sys.stderr.write(f"[rmcp] sha256 mismatch: local={got_sha} != remote={remote_sha}\n")
            return 1
        os.replace(part, dst)
        print(
            f"[rmcp] downloaded {target}:{remote_path} -> {dst} "
            f"({offset} bytes, sha256={got_sha[:12]}..., via {via_str})"
        )
        return 0
    except Exception as e:
        with contextlib.suppress(Exception):
            part.unlink()
        sys.stderr.write(f"[rmcp] download error: {e}\n")
        return 1


def _print_help() -> None:
    print(
        f"""rmcp v{VERSION} — Unified Multi-Hop Mesh Router & CLI for remote-mcp

Usage:
  rmcp                                    Start interactive REPL (in a TTY; prints help for bots)
  rmcp -i | :repl [target]                Start interactive shell with persistent multi-hop pipes
  rmcp <command...>                       Run shell command on active remote node (cwd preserved)
  rmcp --to <node> <command...>           Run one-shot command on <node> without switching active
  rmcp --session <name> <command...>      Pin an explicit caller session scope (overrides auto-scope)
  rmcp :<mgmt-cmd> [args...]              Execute rmcp mesh/node management command

Mesh & Routing Commands:
  :repl | :shell [target]                 Enter interactive REPL (inside REPL: :q / exit, !<cmd>)
  :local <command...>                     Run a command on THIS local machine without switching :use
  :id                                     Show node_id, alias, and current caller origin/session
  :sessions [--clear|--clear-all]         List (or clear) isolated per-caller sessions on this host
  :nodes | :peers | :routes [target]      Show local (or remote node's) known peers & cached routes
  :connect <alias> <endpoint> [options]   Connect & record a peer edge (SSH preferred, HTTP fallback)
      Endpoints:  ssh://user@host[:port]  |  user@host  |  http://host:port
      Options:    --bootstrap             Copy rmcp.py to SSH host (~/.rmcp/rmcp.py) automatically
                  --token <tok>           Shared token for HTTP endpoint
                  --via <hop_node>        Ask <hop_node> to connect using ITS keys/network (multi-hop!)
                  --port <ssh_port>       Override SSH port
                  --remote-path <path>    Custom remote path for rmcp.py on SSH host
  :disconnect <alias> [--via <hop_node>]  Remove a recorded peer edge
  :use <target>                           Switch active target node (alias, node_id, or multi-hop peer)
  :ping [target]                          Probe target and display hop-by-hop `via` path
  :env [target]                           Inspect OS, shells, Python, disk & environment on target

Daemon, Reverse-Tunnel & Self-Healing Commands (for SSH-less / NAT hosts):
  :listen [--port 7777] [--host 0.0.0.0] [--token T] [--daemon] [--watchdog]
                                          Listen as encrypted HTTP node + reverse-tunnel hub
  :dial <hub_url> --token <T> [--alias A] [--daemon] [--watchdog]
                                          Dial outbound reverse connection to a hub (no inbound port!)
  :autostart [status|on|off] [--port 7777] [--dial <url> --token <T>] [--local]
                                          Configure boot auto-start + watchdog on target (or --local)

Remote File & Process Commands (work across arbitrary multi-hop chains):
  :pwd                                    Show tracked working directory for active target
  :cd <dir>                               Change tracked working directory for active target
  :read <remote_path>                     Print UTF-8 file from target (<= 8 MiB)
  :write <remote_path> <content>          Atomically write text file on target
  :edit <remote_path> <old> <new>         Replace unique occurrence of <old> with <new> on target
  :upload <local_path> <remote_path>      Stream file to target with SHA-256 verification
  :download <remote_path> <local_path>    Stream file from target with SHA-256 verification
  :spawn <command> [--stdout <log_path>]  Start detached background process on target
  :ps                                     List spawned background processes on target
  :kill <pid> [TERM|KILL]                 Terminate a spawned process on target
  :shutdown [--delay 1.0]                 Shut down a remote HTTP/dial daemon cleanly
"""
    )


def _pop_flag(args: list[str], flag: str, has_value: bool = False) -> tuple[bool, str, list[str]]:
    """Extract `--flag` (or `--flag=val`) from args list without rigid position rules."""
    rest: list[str] = []
    found = False
    val = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a == flag:
            found = True
            if has_value and i + 1 < len(args):
                val = args[i + 1]
                i += 2
                continue
            i += 1
            continue
        if has_value and a.startswith(flag + "="):
            found = True
            val = a.split("=", 1)[1]
            i += 1
            continue
        rest.append(a)
        i += 1
    return found, val, rest


def _exec_remote_shell(
    target: str,
    cmd_str: str,
    state: dict,
    exec_timeout: float = 120.0,
    persist_cwd: bool = True,
) -> int:
    cur_cwd = state.get("cwds", {}).get(target) if persist_cwd else str(Path.cwd())
    resp = send_action(
        target,
        "exec",
        {"command": cmd_str, "cwd": cur_cwd, "timeout": exec_timeout},
        timeout=exec_timeout + 15.0,
    )
    if not resp.get("ok"):
        sys.stderr.write(f"[rmcp] exec error on '{target}': {resp.get('error')}\n")
        return 1

    res = resp.get("result") or {}
    new_cwd = res.get("cwd")
    if persist_cwd and new_cwd and new_cwd != cur_cwd:
        update_caller_session(cwd_updates={target: new_cwd})

    out_s = res.get("stdout") or ""
    err_s = res.get("stderr") or ""
    if out_s:
        sys.stdout.flush()
        sys.stdout.buffer.write(out_s.encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()
    if err_s:
        sys.stderr.flush()
        sys.stderr.buffer.write(err_s.encode("utf-8", errors="replace"))
        sys.stderr.buffer.flush()
    if res.get("timed_out"):
        sys.stderr.write(f"\n[rmcp] command timed out after {exec_timeout}s\n")
        return 124
    return int(res.get("exit_code", 0))


def _handle_mgmt_command(cmd: str, args: list[str], explicit_to: str = "") -> int:
    if cmd not in _MGMT_COMMANDS:
        sys.stderr.write(f"[rmcp] unknown management command ':{cmd}'. Run `rmcp :help` for usage.\n")
        return 2

    if cmd == "help":
        _print_help()
        return 0

    if cmd in ("q", "quit", "exit"):
        return 0

    if cmd in ("repl", "shell"):
        init_tgt = args[0] if args else ""
        return run_repl(initial_target=init_tgt, pinned_to=explicit_to)

    state = load_router_state()

    if cmd == "local":
        if not args:
            sys.stderr.write("Usage: rmcp :local <command...>\n")
            return 2
        cmd_str = _format_passthrough_cmd(args, IS_WINDOWS)
        return _exec_remote_shell("self", cmd_str, state, exec_timeout=120.0, persist_cwd=False)

    if cmd in ("id", "whoami"):
        if args and args[0] == "--alias" and len(args) >= 2:
            with _STATE_LOCK:
                topo = load_topology_state()
                topo["alias"] = args[1]
                save_topology_state(topo)
            state = load_router_state()
        print(
            json.dumps(
                {
                    "node_id": state["node_id"],
                    "alias": state["alias"],
                    "hostname": socket.gethostname(),
                    "caller": state["caller"],
                    "caller_key": state["caller_key"],
                    "active": _resolve_active_target("", state),
                    "state_dir": str(get_state_dir()),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if cmd == "sessions":
        clear_cur, _, args = _pop_flag(args, "--clear", False)
        clear_all, _, args = _pop_flag(args, "--clear-all", False)
        if clear_all:
            n = clear_caller_sessions()
            print(json.dumps({"ok": True, "cleared": n, "scope": "all"}, indent=2, ensure_ascii=False))
            return 0
        if clear_cur:
            n = clear_caller_sessions(only_key=state["caller_key"])
            print(
                json.dumps(
                    {"ok": True, "cleared": n, "caller_key": state["caller_key"]},
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        print(
            json.dumps(
                {
                    "current_caller": state["caller"],
                    "current_caller_key": state["caller_key"],
                    "sessions": list_caller_sessions(current_key=state["caller_key"]),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if cmd in ("nodes", "hosts", "peers", "routes", "status"):
        target = explicit_to or (args[0] if args else "")
        if target and not _is_local_target(target, state):
            resp = send_action(target, "peers_list", {})
            if not resp.get("ok"):
                sys.stderr.write(f"[rmcp] failed to query '{target}': {resp.get('error')}\n")
                return 1
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            return 0
        summary = {
            "node_id": state["node_id"],
            "alias": state["alias"],
            "caller": state["caller"],
            "caller_key": state["caller_key"],
            "active": _resolve_active_target("", state),
            "peers": {
                k: {pk: pv for pk, pv in v.items() if pk != "token"}
                for k, v in (state.get("peers") or {}).items()
            },
            "routes": state.get("routes") or {},
            "cwds": state.get("cwds") or {},
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    if cmd == "connect":
        has_boot, _, args = _pop_flag(args, "--bootstrap", False)
        _, token, args = _pop_flag(args, "--token", True)
        _, via_hop, args = _pop_flag(args, "--via", True)
        _, rpath, args = _pop_flag(args, "--remote-path", True)
        _, port_s, args = _pop_flag(args, "--port", True)
        ssh_port = int(port_s) if port_s else None

        if len(args) < 2:
            sys.stderr.write("Usage: rmcp :connect <alias> <endpoint> [--bootstrap] [--token T] [--via <hop>]\n")
            return 2
        alias, endpoint = args[0], args[1]
        hop = via_hop or explicit_to
        if hop and not _is_local_target(hop, state):
            resp = send_action(
                hop,
                "peer_add",
                {
                    "alias": alias,
                    "endpoint": endpoint,
                    "token": token,
                    "bootstrap": has_boot,
                    "remote_path": rpath,
                    "ssh_port": ssh_port,
                },
                timeout=90.0,
            )
            if not resp.get("ok"):
                sys.stderr.write(f"[rmcp] remote :connect via '{hop}' failed: {resp.get('error')}\n")
                return 1
            info = resp.get("result") or {}
            # Cache route in shared topology & switch ONLY this caller's active session!
            first_hop = hop if hop in state["peers"] else (state["routes"].get(hop, {}).get("next_hop") or hop)
            with _STATE_LOCK:
                topo = load_topology_state()
                if first_hop in topo["peers"]:
                    topo["routes"][alias] = {
                        "next_hop": first_hop,
                        "path": (resp.get("via") or [hop]) + [alias],
                        "node_id": info.get("node_id", ""),
                        "platform": info.get("platform", ""),
                        "updated_at": int(time.time()),
                        "explicit": True,
                    }
                    topo["peers"].pop(alias, None)
                if not topo.get("default_active"):
                    topo["default_active"] = alias
                save_topology_state(topo)
            update_caller_session(
                active=alias,
                cwd_updates={alias: info["cwd"]} if info.get("cwd") else None,
            )
            print(json.dumps({"ok": True, "via": resp.get("via"), "peer": info}, indent=2, ensure_ascii=False))
            return 0

        try:
            info = connect_peer_local(
                alias=alias,
                endpoint=endpoint,
                token=token,
                bootstrap=has_boot,
                remote_path=rpath,
                ssh_port=ssh_port,
            )
            update_caller_session(
                active=alias,
                cwd_updates={alias: info["cwd"]} if info.get("cwd") else None,
            )
            print(json.dumps({"ok": True, "active": alias, "peer": info}, indent=2, ensure_ascii=False))
            return 0
        except Exception as e:
            sys.stderr.write(f"[rmcp] :connect failed: {e}\n")
            return 1

    if cmd in ("disconnect", "rm"):
        _, via_hop, args = _pop_flag(args, "--via", True)
        if not args:
            sys.stderr.write("Usage: rmcp :disconnect <alias> [--via <hop>]\n")
            return 2
        alias = args[0]
        hop = via_hop or explicit_to
        if hop and not _is_local_target(hop, state):
            resp = send_action(hop, "peer_remove", {"alias": alias})
            if not resp.get("ok"):
                sys.stderr.write(f"[rmcp] :disconnect via '{hop}' failed: {resp.get('error')}\n")
                return 1
            print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
            return 0
        res = execute_local_action("peer_remove", {"alias": alias})
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if cmd in ("use", "to"):
        if not args:
            cur = _resolve_active_target("", state)
            print(
                f"[rmcp] active target: {cur} "
                f"(cwd: {state.get('cwds', {}).get(cur, '(default)')}, caller: {state['caller']})"
            )
            return 0
        target = args[0]
        if _is_local_target(target, state):
            update_caller_session(active="self")
            print(f"[rmcp] switched active target -> self ({state['node_id']}, caller={state['caller']})")
            return 0
        resp = send_action(target, "ping", {}, timeout=30.0)
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] cannot reach '{target}': {resp.get('error')}\n")
            return 1
        info = resp.get("result") or {}
        init_cwd = {target: info["cwd"]} if (info.get("cwd") and target not in state.get("cwds", {})) else None
        update_caller_session(active=target, cwd_updates=init_cwd)
        via_str = " -> ".join(resp.get("via") or [target])
        print(
            f"[rmcp] switched active target -> {target} "
            f"(node={info.get('node_id')}, platform={info.get('platform')}, via={via_str}, caller={state['caller']})"
        )
        return 0

    if cmd == "listen":
        is_daemon, _, args = _pop_flag(args, "--daemon", False)
        is_wd, _, args = _pop_flag(args, "--watchdog", False)
        _, host_s, args = _pop_flag(args, "--host", True)
        _, port_s, args = _pop_flag(args, "--port", True)
        _, tok_s, args = _pop_flag(args, "--token", True)
        _, alias_s, args = _pop_flag(args, "--alias", True)
        host = host_s or "0.0.0.0"
        port = int(port_s) if port_s else 7777
        tok = tok_s or load_or_create_daemon_token()
        if alias_s:
            with _STATE_LOCK:
                topo = load_topology_state()
                topo["alias"] = alias_s
                save_topology_state(topo)
        child_args = ["--listen", "--host", host, "--port", str(port), "--token", tok]
        if is_wd:
            child_args = ["--watchdog", *child_args]
        if is_daemon:
            log_p = get_state_dir() / f"listen-{port}.log"
            pid = _spawn_detached_self(child_args, log_p)
            print(
                json.dumps(
                    {"ok": True, "pid": pid, "host": host, "port": port, "token": tok, "log": str(log_p)},
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        if is_wd:
            run_watchdog(child_args[1:])
        else:
            run_http_listener(host=host, port=port, token=tok)
        return 0

    if cmd == "dial":
        is_daemon, _, args = _pop_flag(args, "--daemon", False)
        is_wd, _, args = _pop_flag(args, "--watchdog", False)
        _, tok_s, args = _pop_flag(args, "--token", True)
        _, alias_s, args = _pop_flag(args, "--alias", True)
        _, via_hop, args = _pop_flag(args, "--via", True)
        if not args or not tok_s:
            sys.stderr.write("Usage: rmcp :dial <hub_url> --token <token> [--alias <name>] [--daemon] [--watchdog]\n")
            return 2
        hub_url = args[0]
        child_args = ["--dial", hub_url, "--token", tok_s]
        if alias_s:
            child_args.extend(["--alias", alias_s])
        if is_wd:
            child_args = ["--watchdog", *child_args]
        hop = via_hop or explicit_to
        if hop and not _is_local_target(hop, state):
            # Spawn reverse dialer on a remote node!
            rcmd = subprocess.list2cmdline([ "python", "~/.rmcp/rmcp.py", *child_args ])
            resp = send_action(hop, "spawn", {"command": rcmd})
            if not resp.get("ok"):
                sys.stderr.write(f"[rmcp] remote :dial failed: {resp.get('error')}\n")
                return 1
            print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
            return 0
        if is_daemon:
            log_p = get_state_dir() / "dial.log"
            pid = _spawn_detached_self(child_args, log_p)
            print(
                json.dumps(
                    {"ok": True, "pid": pid, "hub": hub_url, "alias": alias_s or state["alias"], "log": str(log_p)},
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        if is_wd:
            run_watchdog(child_args[1:])
        else:
            run_reverse_client(hub_url=hub_url, token=tok_s, alias=alias_s)
        return 0

    # Remaining commands operate on `target` (defaults to active target, or `--local` for autostart)
    is_local_flag, _, args = _pop_flag(args, "--local", False)
    target = "self" if is_local_flag else _resolve_active_target(explicit_to, state)

    if cmd == "autostart":
        _, port_s, args = _pop_flag(args, "--port", True)
        _, host_s, args = _pop_flag(args, "--host", True)
        _, dial_s, args = _pop_flag(args, "--dial", True)
        _, tok_s, args = _pop_flag(args, "--token", True)
        _, alias_s, args = _pop_flag(args, "--alias", True)
        mode = args[0] if args else "status"
        resp = send_action(
            target,
            "autostart",
            {
                "mode": mode,
                "port": int(port_s) if port_s else 7777,
                "host": host_s or "0.0.0.0",
                "dial_url": dial_s,
                "dial_token": tok_s,
                "dial_alias": alias_s,
            },
        )
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :autostart failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd in ("ping", "env"):
        tgt = explicit_to or (args[0] if args else target)
        resp = send_action(tgt, cmd, {})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :{cmd} failed on '{tgt}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp, indent=2, ensure_ascii=False))
        return 0

    if cmd == "pwd":
        saved = state.get("cwds", {}).get(target)
        if saved:
            print(saved)
            return 0
        resp = send_action(target, "ping", {})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :pwd failed on '{target}': {resp.get('error')}\n")
            return 1
        cwd = (resp.get("result") or {}).get("cwd", "")
        print(cwd)
        return 0

    if cmd == "cd":
        path_arg = args[0] if args else ""
        cur_cwd = state.get("cwds", {}).get(target)
        resp = send_action(target, "cd", {"cwd": cur_cwd, "path": path_arg})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :cd failed on '{target}': {resp.get('error')}\n")
            return 1
        new_cwd = (resp.get("result") or {}).get("cwd", "")
        update_caller_session(cwd_updates={target: new_cwd})
        print(new_cwd)
        return 0

    cur_cwd = state.get("cwds", {}).get(target)

    if cmd == "read":
        if not args:
            sys.stderr.write("Usage: rmcp :read <remote_path>\n")
            return 2
        resp = send_action(target, "read", {"path": args[0], "cwd": cur_cwd})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :read failed on '{target}': {resp.get('error')}\n")
            return 1
        raw = base64.b64decode((resp.get("result") or {}).get("data_b64", ""))
        sys.stdout.flush()
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0

    if cmd == "write":
        if len(args) < 2:
            sys.stderr.write("Usage: rmcp :write <remote_path> <content>\n")
            return 2
        content = " ".join(args[1:]).encode("utf-8")
        resp = send_action(
            target,
            "write",
            {"path": args[0], "cwd": cur_cwd, "data_b64": base64.b64encode(content).decode("ascii")},
        )
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :write failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd == "edit":
        if len(args) < 3:
            sys.stderr.write("Usage: rmcp :edit <remote_path> <old_text> <new_text>\n")
            return 2
        resp = send_action(
            target,
            "edit",
            {"path": args[0], "cwd": cur_cwd, "old_text": args[1], "new_text": args[2]},
        )
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :edit failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd == "upload":
        if len(args) < 2:
            sys.stderr.write("Usage: rmcp :upload <local_path> <remote_path>\n")
            return 2
        return _cli_upload(target, args[0], args[1], cwd=cur_cwd)

    if cmd == "download":
        if len(args) < 2:
            sys.stderr.write("Usage: rmcp :download <remote_path> <local_path>\n")
            return 2
        return _cli_download(target, args[0], args[1], cwd=cur_cwd)

    if cmd in ("ps", "proclist"):
        resp = send_action(target, "list", {})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :ps failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd == "spawn":
        _, out_s, args = _pop_flag(args, "--stdout", True)
        _, err_s, args = _pop_flag(args, "--stderr", True)
        if not args:
            sys.stderr.write("Usage: rmcp :spawn <command...> [--stdout <path>]\n")
            return 2
        cmd_str = _format_passthrough_cmd(args, _is_target_windows(target, state))
        resp = send_action(
            target,
            "spawn",
            {"command": cmd_str, "cwd": cur_cwd, "stdout": out_s or None, "stderr": err_s or None},
        )
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :spawn failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd == "kill":
        if not args:
            sys.stderr.write("Usage: rmcp :kill <pid> [TERM|KILL]\n")
            return 2
        sig = args[1] if len(args) >= 2 else "TERM"
        resp = send_action(target, "kill", {"pid": int(args[0]), "signal": sig})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :kill failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    if cmd == "shutdown":
        _, delay_s, args = _pop_flag(args, "--delay", True)
        delay = float(delay_s) if delay_s else 1.0
        resp = send_action(target, "shutdown", {"delay": delay})
        if not resp.get("ok"):
            sys.stderr.write(f"[rmcp] :shutdown failed on '{target}': {resp.get('error')}\n")
            return 1
        print(json.dumps(resp.get("result"), indent=2, ensure_ascii=False))
        return 0

    return 2


# ---------------------------------------------------------------------------
# Interactive REPL Shell (Persistent Multi-Hop Pipes + History + Completion)
# ---------------------------------------------------------------------------

def _is_interactive_tty() -> bool:
    if os.environ.get("RMCP_NO_REPL"):
        return False
    return bool(
        sys.stdin is not None
        and sys.stdout is not None
        and hasattr(sys.stdin, "isatty")
        and hasattr(sys.stdout, "isatty")
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )


def _enable_windows_vt_ansi() -> bool:
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _split_repl_args(line: str) -> list[str]:
    """Split a REPL `:mgmt` line into tokens while preserving Windows backslashes `\\`."""
    tokens: list[str] = []
    cur: list[str] = []
    in_token = False
    quote: str | None = None
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]
        if quote is None:
            if ch.isspace():
                if in_token:
                    tokens.append("".join(cur))
                    cur.clear()
                    in_token = False
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                in_token = True
                i += 1
                continue
            cur.append(ch)
            in_token = True
            i += 1
        elif quote == "'":
            if ch == "'":
                quote = None
            else:
                cur.append(ch)
            i += 1
        else:  # double quote '"'
            if ch == '"':
                quote = None
                i += 1
            elif ch == "\\" and i + 1 < n and line[i + 1] == '"':
                cur.append('"')
                i += 2
            else:
                cur.append(ch)
                i += 1

    if in_token:
        tokens.append("".join(cur))
    return tokens


def _shorten_cwd_for_prompt(cwd: str, is_local: bool) -> str:
    if not cwd:
        return "~" if is_local else "."
    if is_local:
        home = str(Path.home())
        if cwd == home:
            return "~"
        if cwd.startswith(home + os.sep):
            cwd = "~" + cwd[len(home) :]
    sep = "\\" if ("\\" in cwd and "/" not in cwd) else "/"
    parts = [p for p in cwd.split(sep) if p]
    if len(parts) > 3 and len(cwd) > 38:
        prefix = cwd[:3] if (len(cwd) >= 3 and cwd[1:3] == ":\\") else (sep if cwd.startswith(sep) else "")
        return f"{prefix}...{sep}{sep.join(parts[-2:])}"
    return cwd


def _format_repl_prompt(target: str, cwd: str, last_rc: int, use_color: bool) -> str:
    is_loc = target in ("self", "local")
    short_cwd = _shorten_cwd_for_prompt(cwd, is_loc)
    rc_part = f" !{last_rc}" if last_rc != 0 else ""
    if not use_color:
        return f"[{target} {short_cwd}{rc_part}]> "
    # Note: \001 / \002 wrap non-printing ANSI codes so readline calculates cursor width accurately
    c_target = "\001\x1b[1;36m\002" if not is_loc else "\001\x1b[1;32m\002"
    c_cwd = "\001\x1b[0;33m\002"
    c_err = "\001\x1b[1;31m\002"
    c_rst = "\001\x1b[0m\002"
    err_seg = f" {c_err}!{last_rc}{c_rst}" if last_rc != 0 else ""
    return f"[{c_target}{target}{c_rst} {c_cwd}{short_cwd}{c_rst}{err_seg}]> "


def _setup_repl_readline():
    try:
        import readline
    except Exception:
        return None, None

    hist_file = get_state_dir() / "repl_history"
    with contextlib.suppress(Exception):
        if hist_file.exists():
            readline.read_history_file(str(hist_file))
        readline.set_history_length(500)

    def _completer(text: str, state_idx: int) -> str | None:
        buf = readline.get_line_buffer().lstrip()
        options: list[str] = []
        if buf.startswith(":") and " " not in buf:
            options = sorted(f":{c}" for c in _MGMT_COMMANDS if f":{c}".startswith(text.lower()))
        elif buf.startswith((":use ", ":to ", ":ping ", ":env ", ":nodes ", ":disconnect ", ":rm ")):
            st = load_router_state()
            known = sorted(
                {"self", *st.get("peers", {}).keys(), *st.get("routes", {}).keys()}
            )
            options = [n for n in known if n.startswith(text)]
        return options[state_idx] if state_idx < len(options) else None

    with contextlib.suppress(Exception):
        readline.set_completer_delims(" \t\n")
        readline.set_completer(_completer)
        doc = getattr(readline, "__doc__", "") or ""
        if "libedit" in doc:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    return readline, hist_file


def run_repl(
    initial_target: str = "",
    pinned_to: str = "",
    exec_timeout: float = 120.0,
) -> int:
    """Interactive REPL shell with persistent multi-hop pipes, history, and `:mgmt` commands."""
    is_tty = _is_interactive_tty()
    use_color = bool(is_tty and not os.environ.get("NO_COLOR") and _enable_windows_vt_ansi())
    readline_mod, hist_file = _setup_repl_readline() if is_tty else (None, None)
    last_rc = 0

    with persistent_stdio_context():
        if initial_target:
            rc = _handle_mgmt_command("use", [initial_target])
            if rc != 0:
                return rc
            pinned_to = ""

        state = load_router_state()
        cur_target = _resolve_active_target(pinned_to, state)

        # Warm up remote pipe & fetch initial cwd if unknown
        via_banner = cur_target
        if not _is_local_target(cur_target, state):
            probe = send_action(cur_target, "ping", {}, timeout=15.0)
            if probe.get("ok"):
                pinfo = probe.get("result") or {}
                via_banner = " -> ".join(probe.get("via") or [cur_target])
                if pinfo.get("cwd") and cur_target not in state.get("cwds", {}):
                    update_caller_session(cwd_updates={cur_target: pinfo["cwd"]})
        elif "self" not in state.get("cwds", {}):
            update_caller_session(cwd_updates={"self": str(Path.cwd())})

        if is_tty:
            print(
                f"[rmcp v{VERSION}] interactive mode -> {cur_target} (via {via_banner}) | "
                ":help for commands, !<cmd> for local shell, :q to exit",
                flush=True,
            )

        try:
            while True:
                state = load_router_state()
                cur_target = _resolve_active_target(pinned_to, state)
                cur_cwd = state.get("cwds", {}).get(cur_target) or (
                    str(Path.cwd()) if _is_local_target(cur_target, state) else ""
                )

                try:
                    if is_tty:
                        raw_line = input(_format_repl_prompt(cur_target, cur_cwd, last_rc, use_color))
                    else:
                        raw_line = sys.stdin.readline()
                        if raw_line == "":
                            break
                except KeyboardInterrupt:
                    if is_tty:
                        sys.stdout.write("^C\n")
                        sys.stdout.flush()
                    last_rc = 130
                    continue
                except EOFError:
                    if is_tty:
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                    break

                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if stripped in (":q", ":quit", ":exit", "exit", "quit"):
                    break

                try:
                    # 1. `!<cmd>` or `:local <cmd>` runs raw command on THIS local machine
                    if stripped.startswith("!"):
                        local_cmd = stripped[1:].strip()
                        if local_cmd:
                            last_rc = _exec_remote_shell(
                                "self", local_cmd, state, exec_timeout=exec_timeout, persist_cwd=False
                            )
                        continue

                    if stripped == ":local" or stripped.startswith(":local "):
                        local_cmd = stripped[len(":local") :].strip()
                        if not local_cmd:
                            sys.stderr.write("Usage: :local <command...>\n")
                            last_rc = 2
                        else:
                            last_rc = _exec_remote_shell(
                                "self", local_cmd, state, exec_timeout=exec_timeout, persist_cwd=False
                            )
                        continue

                    # 2. Check optional leading `--to` / `--timeout` or `:mgmt` command
                    line_to = pinned_to
                    line_timeout = exec_timeout
                    if stripped.startswith("--to") or stripped.startswith("--timeout"):
                        parts = _split_repl_args(stripped)
                        idx = 0
                        while idx < len(parts):
                            if parts[idx] == "--to" and idx + 1 < len(parts):
                                line_to = parts[idx + 1]
                                idx += 2
                                continue
                            if parts[idx].startswith("--to="):
                                line_to = parts[idx].split("=", 1)[1]
                                idx += 1
                                continue
                            if parts[idx] == "--timeout" and idx + 1 < len(parts):
                                line_timeout = float(parts[idx + 1])
                                idx += 2
                                continue
                            if parts[idx].startswith("--timeout="):
                                line_timeout = float(parts[idx].split("=", 1)[1])
                                idx += 1
                                continue
                            break
                        rem_parts = parts[idx:]
                        if not rem_parts:
                            continue
                        mcmd = _detect_mgmt_command(rem_parts[0])
                        if mcmd is not None:
                            last_rc = _handle_mgmt_command(mcmd, rem_parts[1:], explicit_to=line_to)
                            if mcmd in ("use", "to", "connect") and last_rc == 0:
                                pinned_to = ""
                            continue
                        tgt = _resolve_active_target(line_to, state)
                        cmd_str = _format_passthrough_cmd(rem_parts, _is_target_windows(tgt, state))
                        last_rc = _exec_remote_shell(tgt, cmd_str, state, exec_timeout=line_timeout)
                        continue

                    tokens = _split_repl_args(stripped) if stripped.startswith(":") else []
                    mgmt_cmd = _detect_mgmt_command(tokens[0]) if tokens else None
                    if mgmt_cmd is not None:
                        if mgmt_cmd in ("repl", "shell"):
                            if len(tokens) > 1:
                                last_rc = _handle_mgmt_command("use", tokens[1:])
                                if last_rc == 0:
                                    pinned_to = ""
                            continue
                        last_rc = _handle_mgmt_command(mgmt_cmd, tokens[1:], explicit_to=line_to)
                        sys.stdout.flush()
                        sys.stderr.flush()
                        if mgmt_cmd in ("use", "to", "connect") and last_rc == 0:
                            pinned_to = ""
                        continue

                    # 3. Raw shell command pass-through (pipes |, &&, >, quotes all intact!)
                    last_rc = _exec_remote_shell(cur_target, stripped, state, exec_timeout=line_timeout)
                except KeyboardInterrupt:
                    close_all_stdio_sessions()
                    sys.stderr.write("\n^C [interrupted]\n")
                    last_rc = 130
        finally:
            if readline_mod is not None and hist_file is not None:
                with contextlib.suppress(Exception):
                    hist_file.parent.mkdir(parents=True, exist_ok=True)
                    readline_mod.write_history_file(str(hist_file))

    return last_rc


def cli_main(argv: list[str] | None = None) -> int:
    global _SESSION_OVERRIDE
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        # Backward-compatibility for legacy agent.py supervisory loops (e.g. run-agent.cmd)
        inv_name = Path(sys.argv[0]).name.lower()
        if inv_name in ("agent.py", "remote-agent.py", "agent-server.py"):
            return _handle_mgmt_command("listen", ["--host", "0.0.0.0", "--port", "7777"])
        if _is_interactive_tty():
            return run_repl()
        _print_help()
        return 0

    # 1. Node daemon / internal transport modes
    if raw[0] == "--stdio-hop":
        return run_stdio_hop()

    if raw[0] == "--stdio-loop":
        return run_stdio_loop()

    if raw[0] == "--watchdog":
        run_watchdog(raw[1:])
        return 0

    if raw[0] == "--listen":
        return _handle_mgmt_command("listen", raw[1:])

    if raw[0] == "--dial":
        return _handle_mgmt_command("dial", raw[1:])

    if raw[0] in ("-h", "--help"):
        _print_help()
        return 0

    if raw[0] in ("-v", "--version"):
        print(f"rmcp {VERSION}")
        return 0

    # 2. Optional leading `--to <target>`, `--timeout <sec>`, or `--session <name>` before command
    explicit_to = ""
    exec_timeout = 120.0
    sess_override = ""
    idx = 0
    while idx < len(raw):
        if raw[idx] == "--to" and idx + 1 < len(raw):
            explicit_to = raw[idx + 1]
            idx += 2
            continue
        if raw[idx].startswith("--to="):
            explicit_to = raw[idx].split("=", 1)[1]
            idx += 1
            continue
        if raw[idx] == "--timeout" and idx + 1 < len(raw):
            exec_timeout = float(raw[idx + 1])
            idx += 2
            continue
        if raw[idx].startswith("--timeout="):
            exec_timeout = float(raw[idx].split("=", 1)[1])
            idx += 1
            continue
        if raw[idx] == "--session" and idx + 1 < len(raw):
            sess_override = raw[idx + 1]
            idx += 2
            continue
        if raw[idx].startswith("--session="):
            sess_override = raw[idx].split("=", 1)[1]
            idx += 1
            continue
        break

    prev_sess = _SESSION_OVERRIDE
    if sess_override:
        _SESSION_OVERRIDE = sess_override
    try:
        rem = raw[idx:]
        if not rem:
            if _is_interactive_tty():
                return run_repl(pinned_to=explicit_to, exec_timeout=exec_timeout)
            _print_help()
            return 0

        if rem[0] in ("-i", "--repl", "--interactive"):
            init_tgt = rem[1] if len(rem) > 1 else ""
            return run_repl(initial_target=init_tgt, pinned_to=explicit_to, exec_timeout=exec_timeout)

        # 3. Colon management command (`:use`, `:nodes`, ...) vs normal shell command pass-through
        mgmt_cmd = _detect_mgmt_command(rem[0])
        if mgmt_cmd is not None:
            return _handle_mgmt_command(mgmt_cmd, rem[1:], explicit_to=explicit_to)

        state = load_router_state()
        target = _resolve_active_target(explicit_to, state)
        cmd_str = _format_passthrough_cmd(rem, _is_target_windows(target, state))
        return _exec_remote_shell(target, cmd_str, state, exec_timeout=exec_timeout)
    finally:
        _SESSION_OVERRIDE = prev_sess


if __name__ == "__main__":
    raise SystemExit(cli_main())
