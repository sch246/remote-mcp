#!/usr/bin/env python3
"""Comprehensive unit & integration tests for rmcp.py (mesh router, crypto, CLI, reverse tunnel)."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import rmcp  # noqa: E402
from tests import mock_agent  # noqa: E402

RMCP_SCRIPT = str(ROOT_DIR / "rmcp.py")


def run_cli(state_dir: Path, *args: str, alias: str = "") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["REMOTE_MCP_STATE_DIR"] = str(state_dir)
    env["RMCP_STATE_DIR"] = str(state_dir)
    if alias:
        env["REMOTE_MCP_NODE_ALIAS"] = alias
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, RMCP_SCRIPT, *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )


class CryptoAndParserTest(unittest.TestCase):
    def test_aead_roundtrip_and_tamper_rejection(self):
        payload = {"msg": "你好喵 🐾", "nested": [1, 2, 3]}
        box = rmcp.encrypt_obj(payload, "super-secret-token")
        recovered = rmcp.decrypt_obj(box, "super-secret-token")
        self.assertEqual(recovered, payload)

        # Wrong secret rejected
        with self.assertRaises(ValueError):
            rmcp.decrypt_obj(box, "wrong-token")

        # Tampered ciphertext rejected
        bad_ct = bytearray(base64.b64decode(box["ct"]))
        bad_ct[0] ^= 0xFF
        tampered = {**box, "ct": base64.b64encode(bytes(bad_ct)).decode("ascii")}
        with self.assertRaises(ValueError):
            rmcp.decrypt_obj(tampered, "super-secret-token")

        # Expired timestamp rejected
        old_box = dict(box)
        old_box["ts"] = int(time.time()) - 3600
        with self.assertRaises(ValueError):
            rmcp.decrypt_obj(old_box, "super-secret-token")

    def test_colon_command_detection(self):
        self.assertEqual(rmcp._detect_mgmt_command(":nodes"), "nodes")
        self.assertEqual(rmcp._detect_mgmt_command(":Connect"), "connect")
        self.assertEqual(rmcp._detect_mgmt_command(":use"), "use")
        # Bare ':', paths starting with '/', and normal commands pass straight through!
        self.assertIsNone(rmcp._detect_mgmt_command(":"))
        self.assertIsNone(rmcp._detect_mgmt_command("/nodes"))
        self.assertIsNone(rmcp._detect_mgmt_command("/bin/echo"))
        self.assertIsNone(rmcp._detect_mgmt_command("echo"))


class MeshRouterAndStormTest(unittest.TestCase):
    def test_multihop_discovery_unicast_cache_and_cycle_immunity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dir_a = base / "nodeA"
            dir_b = base / "nodeB"
            dir_c = base / "nodeC"
            dir_d = base / "nodeD"

            # Initialize aliases on all 4 nodes
            for d, name in ((dir_a, "nodeA"), (dir_b, "nodeB"), (dir_c, "nodeC"), (dir_d, "nodeD")):
                rc = run_cli(d, ":id", "--alias", name)
                self.assertEqual(rc.returncode, 0, rc.stderr)

            # Build a triangle cycle A -> B -> C -> A plus a leaf B -> D:
            # A -> B
            self.assertEqual(run_cli(dir_a, ":connect", "nodeB", f"local://{dir_b}").returncode, 0)
            # B -> C and B -> D
            self.assertEqual(run_cli(dir_b, ":connect", "nodeC", f"local://{dir_c}").returncode, 0)
            self.assertEqual(run_cli(dir_b, ":connect", "nodeD", f"local://{dir_d}").returncode, 0)
            # C -> A (closes the routing cycle!)
            self.assertEqual(run_cli(dir_c, ":connect", "nodeA", f"local://{dir_a}").returncode, 0)

            # 1. Node A pings `nodeD` (2 hops away: A -> B -> D) with zero prior route configuration!
            ping_res = run_cli(dir_a, ":ping", "nodeD")
            self.assertEqual(ping_res.returncode, 0, ping_res.stderr)
            data = json.loads(ping_res.stdout)
            self.assertTrue(data["ok"])
            self.assertEqual(data["alias"], "nodeD")
            self.assertEqual(data["via"], ["nodeA", "nodeB", "nodeD"])

            # 2. Verify Node A learned and cached the unicast route `nodeD -> next_hop: nodeB`
            nodes_res = run_cli(dir_a, ":nodes")
            self.assertEqual(nodes_res.returncode, 0)
            a_state = json.loads(nodes_res.stdout)
            self.assertIn("nodeD", a_state["routes"])
            self.assertEqual(a_state["routes"]["nodeD"]["next_hop"], "nodeB")

            # 3. Switch active target to `nodeD` and run a shell command directly!
            self.assertEqual(run_cli(dir_a, ":use", "nodeD").returncode, 0)
            exec_res = run_cli(dir_a, sys.executable, "-c", "print('hello from D 喵')")
            self.assertEqual(exec_res.returncode, 0, exec_res.stderr)
            self.assertIn("hello from D 喵", exec_res.stdout)

            # 4. Anti-broadcast-storm test on unreachable target inside cycle A -> B -> C -> A!
            ghost_res = run_cli(dir_a, ":ping", "ghost-node-999")
            self.assertNotEqual(ghost_res.returncode, 0)
            self.assertIn("no route to 'ghost-node-999'", ghost_res.stderr)

            # 5. Delegated `:connect --via nodeC` (connect a 5th nodeE using nodeC's local credentials/network)
            dir_e = base / "nodeE"
            self.assertEqual(run_cli(dir_e, ":id", "--alias", "nodeE").returncode, 0)
            delegated = run_cli(dir_a, ":connect", "nodeE", f"local://{dir_e}", "--via", "nodeC")
            self.assertEqual(delegated.returncode, 0, delegated.stderr)

            # Node A is now active on nodeE (3 hops: A -> B -> C -> E)!
            hop3_ping = run_cli(dir_a, ":ping")
            self.assertEqual(hop3_ping.returncode, 0, hop3_ping.stderr)
            hop3_data = json.loads(hop3_ping.stdout)
            self.assertEqual(hop3_data["via"], ["nodeA", "nodeB", "nodeC", "nodeE"])


def _pick_free_port() -> int:
    import socket as _sock
    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class HttpAndReverseTunnelTest(unittest.TestCase):
    def test_hybrid_ssh_http_and_reverse_tunnel_e2e(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dir_cli = base / "cliA"
            dir_hop = base / "hopB"
            dir_hub = base / "hubH"
            dir_nat = base / "natR"
            work_dir = base / "workspace"
            work_dir.mkdir(parents=True, exist_ok=True)
            sub_dir = work_dir / "inner_dir"
            sub_dir.mkdir(parents=True, exist_ok=True)

            port = _pick_free_port()
            hub_tok = "test-hub-secret-token-99"
            hub_url = f"http://127.0.0.1:{port}"

            # 1. Start HTTP Hub H in a background subprocess
            env_hub = os.environ.copy()
            env_hub["REMOTE_MCP_STATE_DIR"] = str(dir_hub)
            env_hub["RMCP_STATE_DIR"] = str(dir_hub)
            hub_proc = subprocess.Popen(
                [
                    sys.executable,
                    RMCP_SCRIPT,
                    "--listen",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--token",
                    hub_tok,
                    "--alias",
                    "hubH",
                ],
                env=env_hub,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # 2. Start isolated NAT Node R dialing outbound into Hub H (`--dial`)
            env_nat = os.environ.copy()
            env_nat["REMOTE_MCP_STATE_DIR"] = str(dir_nat)
            env_nat["RMCP_STATE_DIR"] = str(dir_nat)
            nat_proc = subprocess.Popen(
                [
                    sys.executable,
                    RMCP_SCRIPT,
                    "--dial",
                    hub_url,
                    "--token",
                    hub_tok,
                    "--alias",
                    "nat-box",
                ],
                env=env_nat,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            try:
                # Wait for Hub H to accept connections and NAT Node R to register its reverse poll
                deadline = time.time() + 10.0
                ready = False
                while time.time() < deadline:
                    code, _ = rmcp._http_request_json(f"{hub_url}/ping", "GET", hub_tok, timeout=1.0)
                    if code == 200:
                        ready = True
                        break
                    time.sleep(0.1)
                self.assertTrue(ready, "Hub H failed to start listening")

                # Build hybrid topology: cliA --(stdio/SSH)--> hopB --(HTTP)--> hubH <--(Reverse)-- nat-box
                self.assertEqual(run_cli(dir_cli, ":id", "--alias", "cliA").returncode, 0)
                self.assertEqual(run_cli(dir_hop, ":id", "--alias", "hopB").returncode, 0)
                self.assertEqual(run_cli(dir_cli, ":connect", "hopB", f"local://{dir_hop}").returncode, 0)
                self.assertEqual(
                    run_cli(dir_hop, ":connect", "hubH", hub_url, "--token", hub_tok).returncode,
                    0,
                )

                # Wait up to 5s for `nat-box` reverse session to appear on hubH
                rev_ok = False
                for _ in range(25):
                    p = run_cli(dir_cli, ":ping", "nat-box")
                    if p.returncode == 0:
                        rev_ok = True
                        pdata = json.loads(p.stdout)
                        self.assertEqual(pdata["via"], ["cliA", "hopB", "hubH", "nat-box"])
                        break
                    time.sleep(0.2)
                self.assertTrue(rev_ok, "Reverse client nat-box was not reachable across A->B->H->nat-box")

                # Switch active node on cliA to `nat-box`
                self.assertEqual(run_cli(dir_cli, ":use", "nat-box").returncode, 0)

                # Test cwd persistence across one-shot runs!
                self.assertEqual(run_cli(dir_cli, ":cd", str(work_dir)).returncode, 0)
                pwd1 = run_cli(dir_cli, ":pwd")
                self.assertEqual(Path(pwd1.stdout.strip()).resolve(), work_dir.resolve())

                # Shell `cd inner_dir` inside normal command should ALSO persist to next one-shot run!
                cd_shell = run_cli(dir_cli, f"cd {sub_dir.name}")
                self.assertEqual(cd_shell.returncode, 0, cd_shell.stderr)
                pwd2 = run_cli(dir_cli, ":pwd")
                self.assertEqual(Path(pwd2.stdout.strip()).resolve(), sub_dir.resolve())

                # Non-zero exit code propagation
                bad_cmd = run_cli(dir_cli, sys.executable, "-c", "import sys; sys.exit(42)")
                self.assertEqual(bad_cmd.returncode, 42)

                # File :write, :edit, :read over 3-hop reverse mesh
                remote_txt = sub_dir / "note.txt"
                self.assertEqual(run_cli(dir_cli, ":write", str(remote_txt), "alpha beta 喵").returncode, 0)
                self.assertEqual(run_cli(dir_cli, ":edit", str(remote_txt), "beta", "omega").returncode, 0)
                rd = run_cli(dir_cli, ":read", str(remote_txt))
                self.assertEqual(rd.returncode, 0, rd.stderr)
                self.assertEqual(rd.stdout, "alpha omega 喵")

                # Multi-chunk (> 512 KiB) binary :upload and :download with SHA-256 verification
                src_bin = base / "local_payload.bin"
                dst_bin = sub_dir / "remote_payload.bin"
                dl_bin = base / "downloaded_payload.bin"
                blob = os.urandom(600 * 1024)  # > STREAM_CHUNK (512 KiB) -> multi-chunk transfer!
                src_bin.write_bytes(blob)

                up = run_cli(dir_cli, ":upload", str(src_bin), str(dst_bin))
                self.assertEqual(up.returncode, 0, up.stderr)
                dl = run_cli(dir_cli, ":download", str(dst_bin), str(dl_bin))
                self.assertEqual(dl.returncode, 0, dl.stderr)
                self.assertEqual(dl_bin.read_bytes(), blob)
                self.assertEqual(
                    hashlib.sha256(dl_bin.read_bytes()).hexdigest(),
                    hashlib.sha256(blob).hexdigest(),
                )

                # Background process :spawn, :ps, :kill on remote nat-box
                sp = run_cli(dir_cli, ":spawn", sys.executable, "-c", "import time; time.sleep(30)")
                self.assertEqual(sp.returncode, 0, sp.stderr)
                sp_pid = json.loads(sp.stdout)["pid"]

                ps1 = run_cli(dir_cli, ":ps")
                self.assertEqual(ps1.returncode, 0)
                pids = [p["pid"] for p in json.loads(ps1.stdout)["processes"]]
                self.assertIn(sp_pid, pids)

                kl = run_cli(dir_cli, ":kill", str(sp_pid), "KILL")
                self.assertEqual(kl.returncode, 0, kl.stderr)
            finally:
                nat_proc.kill()
                hub_proc.kill()
                nat_proc.wait(timeout=5)
                hub_proc.wait(timeout=5)


class LegacyAgentCompatTest(unittest.TestCase):
    def test_fallback_to_legacy_v04_http_agent(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), mock_agent.Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cli_dir = Path(tmp) / "cli"
                url = f"http://127.0.0.1:{port}"
                c = run_cli(cli_dir, ":connect", "oldbox", url, "--token", mock_agent.TOKEN)
                self.assertEqual(c.returncode, 0, c.stderr)

                ex = run_cli(cli_dir, "echo legacy_works")
                self.assertEqual(ex.returncode, 0, ex.stderr)
                self.assertIn("legacy_works", ex.stdout)

                target_f = Path(tmp) / "legacy_file.txt"
                self.assertEqual(run_cli(cli_dir, ":write", str(target_f), "v04-ok").returncode, 0)
                rd = run_cli(cli_dir, ":read", str(target_f))
                self.assertEqual(rd.returncode, 0)
                self.assertEqual(rd.stdout, "v04-ok")
        finally:
            srv.shutdown()
            srv.server_close()


class InteractiveReplAndPersistentHopTest(unittest.TestCase):
    def test_repl_arg_splitter_and_prompt_formatting(self):
        self.assertEqual(
            rmcp._split_repl_args(r':download "D:\my folder\a.txt" C:\Users\98000\b.txt'),
            [":download", r"D:\my folder\a.txt", r"C:\Users\98000\b.txt"],
        )
        self.assertEqual(
            rmcp._split_repl_args(':write note.txt "hello \\"world\\" 喵"'),
            [":write", "note.txt", 'hello "world" 喵'],
        )
        self.assertEqual(
            rmcp._format_repl_prompt("win", r"D:\github\remote-mcp", 0, use_color=False),
            r"[win D:\github\remote-mcp]> ",
        )
        self.assertEqual(
            rmcp._format_repl_prompt("win", r"D:\github", 42, use_color=False),
            r"[win D:\github !42]> ",
        )

    def test_non_tty_no_args_prints_help_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = run_cli(Path(tmp) / "bot_state")
            self.assertEqual(res.returncode, 0)
            self.assertIn("Usage:", res.stdout)

    def test_multihop_repl_session_and_persistent_stdio_loop_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dir_a = base / "nodeA"
            dir_b = base / "nodeB"
            dir_c = base / "nodeC"
            work_dir = base / "repl_work"
            work_dir.mkdir(parents=True, exist_ok=True)

            for d, name in ((dir_a, "nodeA"), (dir_b, "nodeB"), (dir_c, "nodeC")):
                self.assertEqual(run_cli(d, ":id", "--alias", name).returncode, 0)

            # 2-hop chain: nodeA -> nodeB -> nodeC
            self.assertEqual(run_cli(dir_a, ":connect", "nodeB", f"local://{dir_b}").returncode, 0)
            self.assertEqual(run_cli(dir_b, ":connect", "nodeC", f"local://{dir_c}").returncode, 0)

            py = f'"{sys.executable}"' if " " in sys.executable else sys.executable
            repl_script = "\n".join(
                [
                    "# 1. Two consecutive pings to nodeC must hit the EXACT SAME persistent --stdio-loop PID!",
                    f'{py} -c "print(\'MARK_P1\')"',
                    ":ping",
                    f'{py} -c "print(\'MARK_P2\')"',
                    ":ping",
                    f'{py} -c "print(\'MARK_P3\')"',
                    f':cd "{work_dir}"',
                    ":write rel_hello.txt 你好交互模式🐾",
                    ":read rel_hello.txt",
                    "",
                    f'{py} -c "print(\'\\nREPL_RAW_OK\')"',
                    "!echo LOCAL_BANG_OK",
                    ":use nodeB",
                    f'{py} -c "print(\'SWITCHED_TO_B\')"',
                    ":q",
                    "",
                ]
            )

            env = os.environ.copy()
            env["REMOTE_MCP_STATE_DIR"] = str(dir_a)
            env["RMCP_STATE_DIR"] = str(dir_a)
            env["PYTHONIOENCODING"] = "utf-8"

            proc = subprocess.run(
                [sys.executable, RMCP_SCRIPT, ":repl", "nodeC"],
                input=repl_script,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = proc.stdout

            # Extract the two :ping JSON blobs between markers and verify remote PID reuse!
            _, after_p1 = out.split("MARK_P1", 1)
            ping1_txt, after_p2 = after_p1.split("MARK_P2", 1)
            ping2_txt, rest = after_p2.split("MARK_P3", 1)

            # First JSON object in ping1_txt & ping2_txt
            p1_json = json.loads(ping1_txt[ping1_txt.index("{") : ping1_txt.rindex("}") + 1])
            p2_json = json.loads(ping2_txt[ping2_txt.index("{") : ping2_txt.rindex("}") + 1])
            self.assertEqual(p1_json["via"], ["nodeA", "nodeB", "nodeC"])
            self.assertEqual(p2_json["via"], ["nodeA", "nodeB", "nodeC"])
            self.assertEqual(
                p1_json["result"]["pid"],
                p2_json["result"]["pid"],
                "Persistent --stdio-loop should reuse the same multi-hop worker process across REPL commands",
            )

            # Verify relative :write / :read resolved inside `work_dir`
            self.assertEqual((work_dir / "rel_hello.txt").read_text(encoding="utf-8"), "你好交互模式🐾")
            self.assertIn("你好交互模式🐾", rest)
            self.assertIn("REPL_RAW_OK", rest)
            self.assertIn("LOCAL_BANG_OK", rest)
            self.assertIn("SWITCHED_TO_B", rest)

            # Active target after REPL `:use nodeB` is persisted as nodeB
            st_after = json.loads(run_cli(dir_a, ":nodes").stdout)
            self.assertEqual(st_after["active"], "nodeB")

    @unittest.skipIf(sys.platform.startswith("win"), "POSIX pty auto-REPL test")
    def test_auto_tty_enters_repl_with_zero_args(self):
        import pty
        import select

        with tempfile.TemporaryDirectory() as tmp:
            master_fd, slave_fd = pty.openpty()
            env = os.environ.copy()
            env["REMOTE_MCP_STATE_DIR"] = str(Path(tmp) / "tty_state")
            env["RMCP_STATE_DIR"] = str(Path(tmp) / "tty_state")
            env["NO_COLOR"] = "1"
            proc = subprocess.Popen(
                [sys.executable, RMCP_SCRIPT],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                close_fds=True,
            )
            os.close(slave_fd)
            collected = bytearray()
            sent_cmds = False
            try:
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    rlist, _, _ = select.select([master_fd], [], [], 0.2)
                    if rlist:
                        try:
                            chunk = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        collected.extend(chunk)
                        txt = collected.decode("utf-8", errors="replace")
                        if not sent_cmds and "]>" in txt:
                            os.write(master_fd, b"echo PTY_AUTO_REPL_OK\n:q\n")
                            sent_cmds = True
                    if proc.poll() is not None and not rlist:
                        break
                proc.wait(timeout=5)
            finally:
                os.close(master_fd)
                if proc.poll() is None:
                    proc.kill()

            full_txt = collected.decode("utf-8", errors="replace")
            self.assertEqual(proc.returncode, 0, full_txt)
            self.assertIn("interactive mode", full_txt)
            self.assertIn("PTY_AUTO_REPL_OK", full_txt)


if __name__ == "__main__":
    unittest.main()
