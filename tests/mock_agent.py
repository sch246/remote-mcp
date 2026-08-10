#!/usr/bin/env python3
"""
Local mock of the pi agent.py REST daemon, used to test the MCP server without
touching any real remote host. Mirrors the wire protocol the real agent exposes:

  GET  /ping            -> {ok, version, hostname, cwd, user, platform, is_windows}
  POST /read  {path}    -> {data_b64}
  POST /write {path, data_b64}
  POST /stat  {path}    -> {exists, size, image_mime}
  POST /mkdir {path}
  POST /exec  {command, cwd, timeout} -> NDJSON {t:'out'|'err', d} / {t:'exit', code} / {t:'error', msg}
  POST /upload          raw stream + X-Path / X-Sha256 headers
  GET  /download?path=  raw stream + X-Sha256 header
  GET  /env             -> platform / shells / tools snapshot
  POST /shell/open      {shell, label, cwd} -> {id}
  POST /shell/exec      {id, command, timeout_sec} -> {exit_code, status, output}
  GET  /shell/list      -> {sessions: [{id, label}]}
  POST /shell/peek      {id, lines} -> {lines, output}
  POST /shell/close     {id} -> {closed}
  POST /shell/input     {id, data} -> {written}
  POST /shell/interrupt {id} -> {signalled}
  POST /shell/resize    {id, cols, rows} -> {cols, rows}
  POST /shell/relabel   {id, label} -> {label}
  POST /spawn           {command|argv, cwd, stdout, stderr, shell, env} -> {pid, ...}
  GET  /list            -> {processes: [...]}
  POST /kill            {pid, signal} -> {action, signal, status}
  POST /shutdown        {delay} -> {exit_in_seconds, pid, version}

Behavior notes:
  * Sessions are simulated: `cd <dir>` updates the session's cwd, `pwd`/`echo %CD%`
    echoes it, everything else runs through a real subprocess in the session cwd.
  * `__mock_fail__` as an /exec command emits an error frame without an exit frame
    (client must treat this as a hard failure).
  * `__mock_slow__` as a /shell/exec command returns {status:"timeout", exit_code:null}.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "test-token"

SESSIONS: dict[str, dict] = {}       # id -> {label, cwd, output_buffer}
PROCS: dict[int, dict] = {}          # pid -> {command, cwd, stdout, stderr, status}
NEXT_PID = [1000]
DIED_ONCE = [False]                  # __mock_die__ only kills once, to test 410 recovery


def _json_resp(handler, status, obj):
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _err(handler, status, msg):
    _json_resp(handler, status, {"error": msg})


def _authed(handler) -> bool:
    if handler.headers.get("Authorization") == f"Bearer {TOKEN}":
        return True
    _err(handler, 401, "unauthorized")
    return False


def _run_cmd(command: str, cwd: str | None, timeout=None):
    """Run a real subprocess, return (out, err, code)."""
    try:
        p = subprocess.Popen(
            command, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        out, err = p.communicate(timeout=timeout)
        return out, err, p.returncode
    except subprocess.TimeoutExpired:
        return "", "timed out", None
    except Exception as e:
        return "", str(e), -1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- GET ----

    def do_GET(self):
        if self.path == "/ping":
            _json_resp(self, 200, {
                "ok": True, "version": "0.4.0", "hostname": socket.gethostname(),
                "cwd": os.getcwd(), "user": "mock", "platform": sys.platform,
                "is_windows": os.name == "nt",
            })
            return
        if self.path == "/env":
            if not _authed(self):
                return
            _json_resp(self, 200, {
                "agent_version": "0.4.0", "platform": sys.platform,
                "os": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
                "user": "mock", "hostname": socket.gethostname(),
                "home": os.path.expanduser("~"), "cwd": os.getcwd(),
                "python": {"version": platform.python_version(), "executable": sys.executable},
                "shells": {"cmd": "cmd.exe"},
                "tools": {"python": platform.python_version(), "git": "mock-2.0"},
            })
            return
        if self.path == "/shell/list":
            if not _authed(self):
                return
            _json_resp(self, 200, {"sessions": [
                {"id": sid, "label": s.get("label")} for sid, s in SESSIONS.items()
            ]})
            return
        if self.path == "/list":
            if not _authed(self):
                return
            _json_resp(self, 200, {"processes": [
                {"pid": pid, "command": p["command"], "cwd": p["cwd"],
                 "stdout": p["stdout"], "stderr": p["stderr"], "status": p["status"]}
                for pid, p in PROCS.items()
            ]})
            return
        if self.path.startswith("/download"):
            if not _authed(self):
                return
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            path = (qs.get("path") or [""])[0]
            if not os.path.isfile(path):
                _err(self, 404, f"no such file: {path}")
                return
            data = open(path, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Sha256", hashlib.sha256(data).hexdigest())
            self.end_headers()
            self.wfile.write(data)
            return
        _err(self, 404, f"no route: {self.path}")

    # ---- POST ----

    def do_POST(self):
        if not _authed(self):
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        ct = self.headers.get("Content-Type", "")

        # /upload: raw octet-stream
        if self.path == "/upload" and "octet-stream" in ct:
            remote_path = self.headers.get("X-Path")
            expected_sha = (self.headers.get("X-Sha256") or "").lower()
            if not remote_path:
                _err(self, 400, "missing X-Path")
                return
            got = hashlib.sha256(raw).hexdigest()
            if expected_sha and got != expected_sha:
                _err(self, 400, "sha256 mismatch")
                return
            part = remote_path + ".part"
            with open(part, "wb") as f:
                f.write(raw)
            os.replace(part, remote_path)
            _json_resp(self, 200, {"bytes": len(raw), "sha256": got})
            return

        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            _err(self, 400, "bad JSON")
            return
        path = self.path

        if path == "/read":
            p = body.get("path")
            if not os.path.isfile(p):
                _err(self, 404, f"ENOENT: {p}")
                return
            data = open(p, "rb").read()
            _json_resp(self, 200, {"path": p, "data_b64": base64.b64encode(data).decode("ascii")})
            return

        if path == "/write":
            p = body.get("path")
            data = base64.b64decode(body.get("data_b64", ""))
            os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
            part = p + ".part"
            with open(part, "wb") as f:
                f.write(data)
            os.replace(part, p)
            _json_resp(self, 200, {"ok": True, "bytes": len(data)})
            return

        if path == "/stat":
            p = body.get("path")
            exists = os.path.isfile(p)
            _json_resp(self, 200, {
                "path": p, "exists": exists,
                "size": os.path.getsize(p) if exists else 0,
                "image_mime": None,
            })
            return

        if path == "/mkdir":
            os.makedirs(body.get("path"), exist_ok=True)
            _json_resp(self, 200, {"ok": True})
            return

        if path == "/exec":
            command = body.get("command", "")
            cwd = body.get("cwd")
            timeout = body.get("timeout")
            if command == "__mock_fail__":
                frames = [{"t": "error", "msg": "mock failure"}]
            else:
                out, err, code = _run_cmd(command, cwd, timeout=timeout)
                frames = []
                if out:
                    frames.append({"t": "out", "d": out})
                if err:
                    frames.append({"t": "err", "d": err})
                frames.append({"t": "exit", "code": code})
            # Real agent.py hand-rolls HTTP-style chunk framing into the body:
            # "<hex-len>\r\n<frame>\r\n" ... then a final "0\r\n\r\n". Reproduce
            # it so the client's lenient parser is exercised in tests too.
            body = b""
            for fr in frames:
                fb = json.dumps(fr).encode()
                body += b"%x\r\n%s\r\n" % (len(fb), fb)
            body += b"0\r\n\r\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)
            return

        if path == "/shell/open":
            sid = str(uuid.uuid4())
            SESSIONS[sid] = {
                "label": body.get("label"),
                "cwd": body.get("cwd") or os.getcwd(),
                "buffer": [],
            }
            _json_resp(self, 200, {"id": sid})
            return

        if path == "/shell/exec":
            sid = body.get("id")
            sess = SESSIONS.get(sid)
            if not sess:
                _err(self, 404, f"session {sid} not found")
                return
            command = body.get("command", "")
            if command.strip() == "__mock_die__":
                if not DIED_ONCE[0]:
                    DIED_ONCE[0] = True
                    SESSIONS.pop(sid, None)
                    _err(self, 410, f"session {sid} gone (simulated agent restart)")
                    return
                out = sess["cwd"] + "\n"
                sess["buffer"].append(out)
                _json_resp(self, 200, {"exit_code": 0, "status": "ok", "output": out})
                return
            if command.strip() == "__mock_slow__":
                _json_resp(self, 200, {"exit_code": None, "status": "timeout", "output": "partial output"})
                return
            stripped = command.strip()
            if stripped.startswith("cd "):
                newdir = stripped[3:].strip().strip('"')
                if os.path.isabs(newdir) or not newdir:
                    sess["cwd"] = os.path.normpath(newdir) if newdir else sess["cwd"]
                else:
                    sess["cwd"] = os.path.normpath(os.path.join(sess["cwd"], newdir))
                sess["buffer"].append("")
                _json_resp(self, 200, {"exit_code": 0, "status": "ok", "output": ""})
                return
            if stripped in ("pwd", "echo %CD%"):
                out = sess["cwd"] + "\n"
                sess["buffer"].append(out)
                _json_resp(self, 200, {"exit_code": 0, "status": "ok", "output": out})
                return
            out, err, code = _run_cmd(command, sess["cwd"])
            out_text = out + (err if err else "")
            sess["buffer"].append(out_text)
            _json_resp(self, 200, {"exit_code": code, "status": "ok", "output": out_text})
            return

        if path == "/shell/peek":
            sid = body.get("id")
            sess = SESSIONS.get(sid)
            if not sess:
                _err(self, 404, f"session {sid} not found")
                return
            lines = body.get("lines", 50)
            out = "".join(sess["buffer"][-lines:])
            _json_resp(self, 200, {"lines": lines, "output": out})
            return

        if path == "/shell/close":
            sid = body.get("id")
            closed = SESSIONS.pop(sid, None) is not None
            _json_resp(self, 200, {"closed": closed})
            return

        if path == "/shell/input":
            sid = body.get("id")
            sess = SESSIONS.get(sid)
            if not sess:
                _err(self, 404, f"session {sid} not found")
                return
            sess["buffer"].append(body.get("data", ""))
            _json_resp(self, 200, {"written": len(body.get("data", ""))})
            return

        if path == "/shell/interrupt":
            sid = body.get("id")
            if sid not in SESSIONS:
                _err(self, 404, f"session {sid} not found")
                return
            _json_resp(self, 200, {"signalled": True})
            return

        if path == "/shell/resize":
            sid = body.get("id")
            if sid not in SESSIONS:
                _err(self, 404, f"session {sid} not found")
                return
            _json_resp(self, 200, {"cols": body.get("cols"), "rows": body.get("rows")})
            return

        if path == "/shell/relabel":
            sid = body.get("id")
            sess = SESSIONS.get(sid)
            if not sess:
                _err(self, 404, f"session {sid} not found")
                return
            sess["label"] = body.get("label")
            _json_resp(self, 200, {"label": body.get("label")})
            return

        if path == "/spawn":
            pid = NEXT_PID[0]
            NEXT_PID[0] += 1
            command = body.get("command") or json.dumps(body.get("argv"))
            PROCS[pid] = {
                "command": command, "cwd": body.get("cwd"), "status": "running",
                "stdout": body.get("stdout"), "stderr": body.get("stderr"),
            }
            _json_resp(self, 200, {
                "pid": pid, "command": command, "cwd": body.get("cwd"),
                "stdout": body.get("stdout"), "stderr": body.get("stderr"),
            })
            return

        if path == "/kill":
            pid = body.get("pid")
            if pid not in PROCS:
                _err(self, 404, f"pid {pid} not tracked")
                return
            PROCS[pid]["status"] = "exited"
            _json_resp(self, 200, {"action": "signal-sent", "signal": body.get("signal"), "status": "exited"})
            return

        if path == "/shutdown":
            _json_resp(self, 200, {"exit_in_seconds": body.get("delay", 1.0), "pid": 4242, "version": "0.4.0"})
            return

        _err(self, 404, f"no route: {self.path}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock agent listening on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
