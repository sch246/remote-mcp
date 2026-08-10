#!/usr/bin/env python3
"""End-to-end test of the remote-mcp server against the local mock agent."""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402

MOCK_PORT = 9876
MOCK_URL = f"http://127.0.0.1:{MOCK_PORT}"

PASS = 0
FAIL = 0


def check(name, fn):
    global PASS, FAIL
    try:
        out = fn()
        print(f"  PASS  {name}: {out if isinstance(out, str) else ''}")
        PASS += 1
    except Exception as e:
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")
        FAIL += 1


def expect_raises(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  FAIL  {name}: expected an exception but none raised")
        FAIL += 1
    except Exception:
        print(f"  PASS  {name} (raised as expected)")
        PASS += 1


def wait_ping(url, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/ping", timeout=2) as r:
                return r.status == 200
        except Exception:
            time.sleep(0.2)
    return False


def main():
    global PASS, FAIL
    tmp = tempfile.mkdtemp(prefix="remote-mcp-test-")
    cfg_path = os.path.join(tmp, "hosts.json")
    cfg = {
        "hosts": {"mock": {"url": MOCK_URL, "token": "test-token", "cwd": tmp, "platform": "win32"}},
        "active": "mock",
    }
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    server._CONFIG = __import__("pathlib").Path(cfg_path)
    os.environ.pop("REMOTE_AGENT_HOST", None)
    os.environ.pop("REMOTE_AGENT_CONFIG", None)

    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "mock_agent.py"), str(MOCK_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_ping(MOCK_URL):
            raise RuntimeError("mock agent did not come up")
        print(f"mock agent up at {MOCK_URL}")

        print("\n[hosts + env]")
        check("remote_hosts lists mock as active", lambda: server.remote_hosts())
        check("remote_env", lambda: server.remote_env(host="mock"))

        print("\n[read / write / edit]")
        hello = os.path.join(tmp, "hello.txt")
        check("remote_write", lambda: server.remote_write(hello, "hello world hello\n", host="mock"))
        check("remote_read returns content",
              lambda: server.remote_read(hello, host="mock"))
        check("remote_edit replaces unique old_text",
              lambda: server.remote_edit(hello, "world", "brave", host="mock"))
        got = server.remote_read(hello, host="mock")
        check("remote_edit result persisted",
              lambda: "hello brave hello" in server.remote_read(hello, host="mock"))
        expect_raises("remote_edit old_text not found",
                      lambda: server.remote_edit(hello, "zzz", "x", host="mock"))
        expect_raises("remote_edit non-unique old_text",
                      lambda: server.remote_edit(hello, "hello", "x", host="mock"))
        expect_raises("remote_read missing file",
                      lambda: server.remote_read(os.path.join(tmp, "nope.txt"), host="mock"))
        expect_raises("unknown host",
                      lambda: server.remote_read(hello, host="nope"))

        print("\n[bash]")
        check("remote_bash echo", lambda: server.remote_bash("echo hello from exec", host="mock"))
        check("remote_bash exit code", lambda: server.remote_bash("exit /b 3", host="mock"))
        expect_raises("remote_bash hard failure", lambda: server.remote_bash("__mock_fail__", host="mock"))

        print("\n[persistent shell]")
        check("remote_shell_exec open + pwd", lambda: server.remote_shell_exec("pwd", host="mock"))
        subdir = os.path.join(tmp, "sub")
        os.makedirs(subdir, exist_ok=True)
        check("remote_shell_exec cd persists",
              lambda: server.remote_shell_exec(f"cd {subdir}", host="mock"))
        out = server.remote_shell_exec("pwd", host="mock")
        ok = subdir in out
        print(f"  {'PASS' if ok else 'FAIL'}  remote_shell_exec state carried to next call: {out!r}")
        PASS, FAIL = PASS + (1 if ok else 0), FAIL + (0 if ok else 1)
        check("remote_shell list shows session",
              lambda: server.remote_shell("list", host="mock"))
        check("remote_shell peek",
              lambda: server.remote_shell("peek", host="mock"))
        check("remote_shell relabel",
              lambda: server.remote_shell("relabel", label="renamed", host="mock"))
        check("remote_shell input",
              lambda: server.remote_shell("input", data="hi\n", host="mock"))
        check("remote_shell interrupt",
              lambda: server.remote_shell("interrupt", host="mock"))
        check("remote_shell resize",
              lambda: server.remote_shell("resize", cols=120, rows=40, host="mock"))
        check("remote_shell close",
              lambda: server.remote_shell("close", host="mock"))
        expect_raises("remote_shell action on closed session",
                      lambda: server.remote_shell("peek", host="mock"))
        expect_raises("remote_shell unknown action",
                      lambda: server.remote_shell("bogus", host="mock"))

        print("\n[shell 404/410 recovery]")
        server.remote_shell_exec("pwd", session="recover", host="mock")
        try:
            out = server.remote_shell_exec("__mock_die__", session="recover", host="mock")
        except Exception as e:
            out = f"EXC {type(e).__name__}: {e}"
        ok = "recover" in out and "410" not in out
        print(f"  {'PASS' if ok else 'FAIL'}  stale session auto-reopen after 410: {out!r}")
        PASS, FAIL = PASS + (1 if ok else 0), FAIL + (0 if ok else 1)

        print("\n[upload / download]")
        blob = os.path.join(tmp, "big.bin")
        data = bytes(random.randrange(256) for _ in range(300_000))
        with open(blob, "wb") as f:
            f.write(data)
        expected_sha = hashlib.sha256(data).hexdigest()
        remote_blob = os.path.join(tmp, "remote-big.bin")
        check("remote_upload",
              lambda: server.remote_upload(blob, remote_blob, host="mock"))
        check("remote_upload sha verified",
              lambda: f"sha256={expected_sha}" in server.remote_upload(blob, remote_blob, host="mock"))
        out_local = os.path.join(tmp, "back.bin")
        check("remote_download",
              lambda: server.remote_download(remote_blob, out_local, host="mock"))
        with open(out_local, "rb") as f:
            got = f.read()
        ok = got == data
        print(f"  {'PASS' if ok else 'FAIL'}  download roundtrip byte-identical")
        PASS, FAIL = PASS + (1 if ok else 0), FAIL + (0 if ok else 1)
        expect_raises("remote_upload missing local file",
                      lambda: server.remote_upload(os.path.join(tmp, "nope.bin"), "x", host="mock"))

        print("\n[spawn / proclist / kill]")
        check("remote_spawn", lambda: server.remote_spawn(command="python -m http.server 0", stdout=os.path.join(tmp, "srv.log"), host="mock"))
        check("remote_proclist", lambda: server.remote_proclist(host="mock"))
        check("remote_kill", lambda: server.remote_kill(1000, host="mock"))
        expect_raises("remote_kill untracked pid",
                      lambda: server.remote_kill(999999, host="mock"))

        print("\n[shutdown]")
        check("remote_shutdown", lambda: server.remote_shutdown(delay=0.5, host="mock"))

        print("\n[mcp registry]")
        import asyncio
        tools = asyncio.run(server.mcp.list_tools())
        names = sorted(t.name for t in tools)
        check("14 tools registered", lambda: f"registered {len(names)}: {', '.join(names)}" if len(names) == 14 else "FAIL")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
