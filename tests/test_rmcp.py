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


def run_cli(
    state_dir: Path,
    *args: str,
    alias: str = "",
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("REMOTE_AGENT_TOKEN", None)
    env.pop("PI_REMOTE_AGENT_TOKEN", None)
    env["REMOTE_MCP_STATE_DIR"] = str(state_dir)
    env["RMCP_STATE_DIR"] = str(state_dir)
    if alias:
        env["REMOTE_MCP_NODE_ALIAS"] = alias
    if extra_env:
        env.update(extra_env)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, RMCP_SCRIPT, *args],
        cwd=str(cwd) if cwd else None,
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


class CallerSessionIsolationAndOriginTest(unittest.TestCase):
    def test_multi_caller_folder_and_agent_isolation_plus_persisted_spawn_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shared_state = base / "shared_client_state"
            dir_b = base / "nodeB"
            dir_c = base / "nodeC"

            # Simulated local caller workspaces
            bot_repo = base / "bot"
            (bot_repo / ".git").mkdir(parents=True, exist_ok=True)
            bot_subdir = bot_repo / "mods" / "tools"
            bot_subdir.mkdir(parents=True, exist_ok=True)

            other_ws = base / "other_workspace"
            other_ws.mkdir(parents=True, exist_ok=True)

            # Simulated remote working directories
            rem_bot_b = base / "rem_bot_on_B"
            rem_agy_b = base / "rem_agy_on_B"
            rem_agy_c = base / "rem_agy_on_C"
            for d in (rem_bot_b, rem_agy_b, rem_agy_c):
                d.mkdir(parents=True, exist_ok=True)

            bot_env = {
                "ANTIGRAVITY_CONVERSATION_ID": "",
                "CODEX_THREAD_ID": "",
                "CLAUDE_SESSION_ID": "",
                "RMCP_SESSION": "",
            }
            agy_env = {
                "ANTIGRAVITY_CONVERSATION_ID": "conv-agy-isolated-9999",
                "CODEX_THREAD_ID": "",
                "CLAUDE_SESSION_ID": "",
                "RMCP_SESSION": "",
            }

            # Initialize aliases: client, nodeB, nodeC, and 2-hop topology client -> nodeB -> nodeC
            self.assertEqual(
                run_cli(shared_state, ":id", "--alias", "linuxHost", cwd=bot_repo, extra_env=bot_env).returncode,
                0,
            )
            self.assertEqual(run_cli(dir_b, ":id", "--alias", "nodeB").returncode, 0)
            self.assertEqual(run_cli(dir_c, ":id", "--alias", "nodeC").returncode, 0)
            self.assertEqual(
                run_cli(
                    shared_state, ":connect", "nodeB", f"local://{dir_b}", cwd=bot_repo, extra_env=bot_env
                ).returncode,
                0,
            )
            self.assertEqual(run_cli(dir_b, ":connect", "nodeC", f"local://{dir_c}").returncode, 0)

            # 1. Bot caller (`bot_repo`) sets `:use nodeB` and `:cd rem_bot_b`
            self.assertEqual(
                run_cli(shared_state, ":use", "nodeB", cwd=bot_repo, extra_env=bot_env).returncode, 0
            )
            self.assertEqual(
                run_cli(shared_state, ":cd", str(rem_bot_b), cwd=bot_repo, extra_env=bot_env).returncode, 0
            )

            # 2. Antigravity caller standing IN THE EXACT SAME `bot_repo` folder switches to `nodeC` & `rem_agy_c`,
            #    AND sets its own cwd on `nodeB` to `rem_agy_b`!
            self.assertEqual(
                run_cli(shared_state, ":use", "nodeC", cwd=bot_repo, extra_env=agy_env).returncode, 0
            )
            self.assertEqual(
                run_cli(shared_state, ":cd", str(rem_agy_c), cwd=bot_repo, extra_env=agy_env).returncode, 0
            )
            self.assertEqual(
                run_cli(
                    shared_state, "--to", "nodeB", ":cd", str(rem_agy_b), cwd=bot_repo, extra_env=agy_env
                ).returncode,
                0,
            )

            # 3. Third caller in `other_ws` sees shared topology (`nodeB`) without interfering with either!
            other_nodes = json.loads(
                run_cli(shared_state, ":nodes", cwd=other_ws, extra_env=bot_env).stdout
            )
            self.assertIn("nodeB", other_nodes["peers"])

            # 4. Verify Bot caller — EVEN FROM SUBFOLDER `bot/mods/tools` (git-root anchoring!) —
            #    remains on `nodeB` in `rem_bot_b`!
            bot_state = json.loads(
                run_cli(shared_state, ":nodes", cwd=bot_subdir, extra_env=bot_env).stdout
            )
            self.assertEqual(bot_state["active"], "nodeB")
            bot_pwd = run_cli(shared_state, ":pwd", cwd=bot_subdir, extra_env=bot_env).stdout.strip()
            self.assertEqual(Path(bot_pwd).resolve(), rem_bot_b.resolve())

            # 5. Verify Antigravity caller remains on `nodeC` in `rem_agy_c` AND its `nodeB` cwd is `rem_agy_b`!
            agy_state = json.loads(
                run_cli(shared_state, ":nodes", cwd=bot_repo, extra_env=agy_env).stdout
            )
            self.assertEqual(agy_state["active"], "nodeC")
            agy_pwd_c = run_cli(shared_state, ":pwd", cwd=bot_repo, extra_env=agy_env).stdout.strip()
            self.assertEqual(Path(agy_pwd_c).resolve(), rem_agy_c.resolve())
            agy_pwd_b = run_cli(
                shared_state, "--to", "nodeB", ":pwd", cwd=bot_repo, extra_env=agy_env
            ).stdout.strip()
            self.assertEqual(Path(agy_pwd_b).resolve(), rem_agy_b.resolve())

            # 6. Verify `--session` explicit override and `:sessions` listing / clearing
            self.assertEqual(
                run_cli(
                    shared_state, "--session", "manual-ops", ":use", "self", cwd=bot_repo, extra_env=bot_env
                ).returncode,
                0,
            )
            sess_list = json.loads(
                run_cli(
                    shared_state, "--session", "manual-ops", ":sessions", cwd=bot_repo, extra_env=bot_env
                ).stdout
            )
            self.assertGreaterEqual(len(sess_list["sessions"]), 3)
            self.assertTrue(sess_list["sessions"][0]["current"])
            self.assertIn("session:manual-ops", sess_list["current_caller"])
            self.assertEqual(
                run_cli(
                    shared_state,
                    "--session",
                    "manual-ops",
                    ":sessions",
                    "--clear",
                    cwd=bot_repo,
                    extra_env=bot_env,
                ).returncode,
                0,
            )

            # 7. Multi-hop `origin` provenance + persisted `:spawn` / `:ps` / `:kill` across one-shot stdio hops!
            sp = run_cli(
                shared_state,
                "--to",
                "nodeC",
                ":spawn",
                sys.executable,
                "-c",
                "import time; time.sleep(30)",
                cwd=bot_subdir,
                extra_env=bot_env,
            )
            self.assertEqual(sp.returncode, 0, sp.stderr)
            sp_info = json.loads(sp.stdout)
            sp_pid = sp_info["pid"]
            self.assertIn(str(bot_repo.resolve()), sp_info["caller"])

            # Separate one-shot invocation from Antigravity queries `:ps` on `nodeC` -> sees running PID + Bot's caller!
            ps_res = run_cli(shared_state, ":ps", cwd=bot_repo, extra_env=agy_env)
            self.assertEqual(ps_res.returncode, 0, ps_res.stderr)
            procs = json.loads(ps_res.stdout)["processes"]
            matched = [p for p in procs if p["pid"] == sp_pid]
            self.assertEqual(len(matched), 1, f"Persisted spawned PID {sp_pid} missing from :ps: {procs}")
            self.assertEqual(matched[0]["status"], "running")
            self.assertIn("linuxHost:", matched[0]["caller"])
            self.assertIn(str(bot_repo.resolve()), matched[0]["caller"])

            # Kill across a third separate `--stdio-hop` invocation!
            kl = run_cli(
                shared_state, "--to", "nodeC", ":kill", str(sp_pid), "KILL", cwd=bot_subdir, extra_env=bot_env
            )
            self.assertEqual(kl.returncode, 0, kl.stderr)


class CodeHashAndExclusivePortTest(unittest.TestCase):
    def test_code_hash_crlf_normalization_and_exclusive_bind(self):
        with tempfile.TemporaryDirectory() as tmp:
            p_lf = Path(tmp) / "a_lf.py"
            p_crlf = Path(tmp) / "a_crlf.py"
            src_lf = b"#!/usr/bin/env python3\nprint('hello')\n"
            src_crlf = b"#!/usr/bin/env python3\r\nprint('hello')\r\n"
            p_lf.write_bytes(src_lf)
            p_crlf.write_bytes(src_crlf)
            self.assertEqual(rmcp.compute_code_hash(p_lf), rmcp.compute_code_hash(p_crlf))
            self.assertEqual(len(rmcp.CODE_HASH), 12)

        port = _pick_free_port()
        srv = rmcp._bind_listener_port("127.0.0.1", port, "tok-test")
        try:
            self.assertIsNotNone(srv)
            self.assertIn(port, rmcp.get_active_listen_ports())
            self.assertFalse(rmcp._can_bind_exclusive("127.0.0.1", port))
        finally:
            self.assertTrue(rmcp._close_listener_port(port))
        self.assertTrue(rmcp._can_bind_exclusive("127.0.0.1", port))


class BlueGreenUpgradeAndReclaimTest(unittest.TestCase):
    def test_blue_green_upgrade_rapid_switches_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cli_dir = base / "cli"
            srv_state = base / "srv_state"
            install_dir = base / "srv_install"
            install_dir.mkdir(parents=True, exist_ok=True)

            primary_port = _pick_free_port()
            cand1 = _pick_free_port()
            cand2 = _pick_free_port()
            cand3 = _pick_free_port()
            cand_csv = f"{cand1},{cand2},{cand3}"
            srv_tok = "upgrade-secret-token-888"

            # Create an "older" v0.7.5 copy of rmcp.py with a distinct CODE_HASH
            raw_src = Path(RMCP_SCRIPT).read_text(encoding="utf-8")
            old_src = raw_src.replace('VERSION = "0.8.0"', 'VERSION = "0.7.5"', 1)
            agent_py = install_dir / "agent.py"
            agent_py.write_text(old_src, encoding="utf-8")
            (install_dir / "agent.token").write_text(srv_tok, encoding="utf-8")
            old_hash = rmcp.compute_code_hash(agent_py)
            self.assertNotEqual(old_hash, rmcp.CODE_HASH)

            srv_env = os.environ.copy()
            srv_env.pop("REMOTE_AGENT_TOKEN", None)
            srv_env.pop("PI_REMOTE_AGENT_TOKEN", None)
            srv_env["REMOTE_MCP_STATE_DIR"] = str(srv_state)
            srv_env["RMCP_STATE_DIR"] = str(srv_state)
            blue_proc = subprocess.Popen(
                [sys.executable, str(agent_py), "--listen", "--host", "127.0.0.1", "--port", str(primary_port)],
                cwd=str(install_dir),
                env=srv_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            current_pid = blue_proc.pid
            try:
                # Wait for Blue (v0.7.5) to start
                for _ in range(40):
                    c, r = rmcp._http_request_json(f"http://127.0.0.1:{primary_port}/ping", "GET", "")
                    if c == 200:
                        break
                    time.sleep(0.1)

                conn = run_cli(
                    cli_dir,
                    ":connect",
                    "winbox",
                    f"http://127.0.0.1:{primary_port}",
                    "--token",
                    srv_tok,
                    "--ports",
                    cand_csv,
                )
                self.assertEqual(conn.returncode, 0, conn.stderr)

                # 1. Rollback safety test: occupy cand_occupied with a dummy plain TCP socket so Green fails to bind!
                import socket as _sock

                blocker = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                blocker.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
                blocker.bind(("127.0.0.1", 0))
                blocker.listen(1)
                blocked_port = blocker.getsockname()[1]
                try:
                    bad_upg = run_cli(cli_dir, ":upgrade", "winbox", "--ports", str(blocked_port))
                    self.assertNotEqual(bad_upg.returncode, 0)
                    # Verify Blue on primary_port is 100% untouched!
                    p_after_fail = json.loads(run_cli(cli_dir, ":ping", "winbox").stdout)["result"]
                    self.assertEqual(p_after_fail["pid"], blue_proc.pid)
                    self.assertEqual(p_after_fail["version"], "0.7.5")
                finally:
                    blocker.close()

                # 2. Start continuous background ping traffic during upgrades to verify zero dropped requests!
                stop_traffic = threading.Event()
                traffic_failures: list[str] = []
                traffic_ok_count = 0

                def _traffic_worker() -> None:
                    nonlocal traffic_ok_count
                    while not stop_traffic.is_set():
                        pr = run_cli(cli_dir, ":ping", "winbox")
                        if pr.returncode != 0:
                            traffic_failures.append(pr.stderr or pr.stdout)
                        else:
                            traffic_ok_count += 1
                        time.sleep(0.08)

                t_worker = threading.Thread(target=_traffic_worker, daemon=True)
                t_worker.start()

                try:
                    # 3. Initial Blue-Green upgrade: 0.7.5 -> 0.8.0 + reclaim primary_port!
                    u1 = run_cli(cli_dir, ":upgrade", "winbox", "--ports", cand_csv)
                    self.assertEqual(u1.returncode, 0, u1.stderr + u1.stdout)
                    u1_doc = json.loads(u1.stdout)
                    self.assertEqual(u1_doc["status"], "upgraded")
                    self.assertEqual(u1_doc["old_version"], "0.7.5")
                    self.assertEqual(u1_doc["new_version"], rmcp.VERSION)
                    self.assertEqual(u1_doc["new_hash"], rmcp.CODE_HASH)
                    self.assertTrue(u1_doc["reclaimed_primary_port"])
                    self.assertNotEqual(u1_doc["green_pid"], blue_proc.pid)
                    current_pid = u1_doc["green_pid"]
                    self.assertTrue((install_dir / "agent.py.bak").exists())
                    self.assertEqual(rmcp.compute_code_hash(agent_py), rmcp.CODE_HASH)

                    # 4. Idempotent check without --force -> status == "up_to_date"
                    u_noop = json.loads(run_cli(cli_dir, ":upgrade", "winbox", "--ports", cand_csv).stdout)
                    self.assertEqual(u_noop["status"], "up_to_date")
                    self.assertEqual(u_noop["pid"], current_pid)

                    # 5. Rapid back-to-back forced upgrades (x3 in tight sequence)!
                    seen_pids = {blue_proc.pid, current_pid}
                    for round_idx in range(3):
                        ur = run_cli(cli_dir, ":upgrade", "winbox", "--ports", cand_csv, "--force")
                        self.assertEqual(ur.returncode, 0, f"round {round_idx} failed: {ur.stderr}\n{ur.stdout}")
                        ur_doc = json.loads(ur.stdout)
                        self.assertEqual(ur_doc["status"], "upgraded")
                        self.assertTrue(ur_doc["reclaimed_primary_port"])
                        self.assertEqual(ur_doc["primary_port"], primary_port)
                        self.assertNotIn(ur_doc["green_pid"], seen_pids)
                        seen_pids.add(ur_doc["green_pid"])
                        current_pid = ur_doc["green_pid"]
                finally:
                    stop_traffic.set()
                    t_worker.join(timeout=5.0)

                self.assertGreater(traffic_ok_count, 5)
                self.assertEqual(traffic_failures, [], f"Dropped traffic during rapid upgrades: {traffic_failures}")

                # Wait 0.5s for final candidate port delayed release, then confirm ONLY primary_port is held!
                time.sleep(0.5)
                final_ping = json.loads(run_cli(cli_dir, ":ping", "winbox").stdout)["result"]
                self.assertEqual(final_ping["pid"], current_pid)
                self.assertEqual(final_ping["listen_ports"], [primary_port])
                for cp in (cand1, cand2, cand3):
                    self.assertTrue(rmcp._can_bind_exclusive("127.0.0.1", cp), f"candidate port {cp} leaked!")
            finally:
                run_cli(cli_dir, "--to", "winbox", ":shutdown", "--delay", "0.05")
                if blue_proc.poll() is None:
                    blue_proc.kill()
                    blue_proc.wait(timeout=3)


class TwoTierBlindRelayTest(unittest.TestCase):
    def test_two_tier_stranger_blind_relay_and_ssrf_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            relay_dir = base / "relay"
            tgt_http_dir = base / "tgt_http"
            tgt_nat_dir = base / "tgt_nat"
            unreg_dir = base / "unreg_http"
            unreg_install = base / "unreg_install"
            unreg_install.mkdir(parents=True, exist_ok=True)
            stranger_dir = base / "stranger"

            p_relay = _pick_free_port()
            p_tgt = _pick_free_port()
            p_unreg = _pick_free_port()
            p_unreg_c1 = _pick_free_port()
            p_unreg_c2 = _pick_free_port()

            k_relay = "SECRET-RELAY-TOKEN-NEVER-SHARED"
            k_tgt = "SECRET-TARGET-HTTP-TOKEN"
            k_nat = "SECRET-TARGET-NAT-TOKEN"
            k_unreg = "SECRET-UNREG-CIDR-TOKEN"

            relay_url = f"http://127.0.0.1:{p_relay}"
            tgt_url = f"http://127.0.0.1:{p_tgt}"
            unreg_url = f"http://127.0.0.1:{p_unreg}"

            # 1. Prepare SSRF unit checks (without RMCP_TEST_ALLOW_LOOPBACK_RELAY, loopback & link-local MUST fail!)
            pol_all = {"mode": "cidr", "cidrs": ["0.0.0.0/0"], "ports": [7777, p_unreg]}
            with self.assertRaises(PermissionError):
                rmcp._validate_stranger_dst_url(f"http://127.0.0.1:{p_unreg}", pol_all)
            with self.assertRaises(PermissionError):
                rmcp._validate_stranger_dst_url("http://169.254.169.254:7777", pol_all)
            with self.assertRaises(PermissionError):
                rmcp._validate_stranger_dst_url("http://192.168.88.188:9999", pol_all)  # disallowed port

            # 2. Launch Relay, Registered HTTP Target, Reverse-Tunnel NAT Target, and Unregistered v0.7.5 Target
            def _spawn_daemon(st_dir: Path, script: str, args: list[str], extra: dict | None = None, cwd: Path | None = None):
                e = os.environ.copy()
                e.pop("REMOTE_AGENT_TOKEN", None)
                e.pop("PI_REMOTE_AGENT_TOKEN", None)
                e["REMOTE_MCP_STATE_DIR"] = str(st_dir)
                e["RMCP_STATE_DIR"] = str(st_dir)
                if extra:
                    e.update(extra)
                return subprocess.Popen(
                    [sys.executable, script, *args],
                    cwd=str(cwd) if cwd else None,
                    env=e,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            # Pre-seed NAT node's own agent.token so Stranger can address it E2E without K_relay!
            tgt_nat_dir.mkdir(parents=True, exist_ok=True)
            (tgt_nat_dir / "agent.token").write_text(k_nat, encoding="utf-8")

            # Prepare Unregistered HTTP target as pre-0.8.0 (no `e2e` support) to verify downgrade rejection!
            old_src = (
                Path(RMCP_SCRIPT)
                .read_text(encoding="utf-8")
                .replace('VERSION = "0.8.0"', 'VERSION = "0.7.5"', 1)
                .replace('was_e2e = "e2e" in env', "was_e2e = False", 1)
            )
            unreg_script = unreg_install / "agent.py"
            unreg_script.write_text(old_src, encoding="utf-8")
            (unreg_install / "agent.token").write_text(k_unreg, encoding="utf-8")

            procs: list[subprocess.Popen] = []
            try:
                procs.append(
                    _spawn_daemon(
                        relay_dir,
                        RMCP_SCRIPT,
                        ["--listen", "--host", "127.0.0.1", "--port", str(p_relay), "--token", k_relay, "--alias", "relayBox"],
                        extra={"RMCP_TEST_ALLOW_LOOPBACK_RELAY": "1"},
                    )
                )
                procs.append(
                    _spawn_daemon(
                        tgt_http_dir,
                        RMCP_SCRIPT,
                        ["--listen", "--host", "127.0.0.1", "--port", str(p_tgt), "--token", k_tgt, "--alias", "innerHttp"],
                    )
                )
                procs.append(
                    _spawn_daemon(
                        unreg_dir,
                        str(unreg_script),
                        ["--listen", "--host", "127.0.0.1", "--port", str(p_unreg)],
                        cwd=unreg_install,
                    )
                )

                for port_chk in (p_relay, p_tgt, p_unreg):
                    for _ in range(40):
                        c, _ = rmcp._http_request_json(f"http://127.0.0.1:{port_chk}/ping", "GET", "")
                        if c == 200:
                            break
                        time.sleep(0.1)

                # Start NAT reverse dialer into Relay (authenticated to Relay, registered as `innerNat`)
                procs.append(
                    _spawn_daemon(
                        tgt_nat_dir,
                        RMCP_SCRIPT,
                        ["--dial", relay_url, "--token", k_relay, "--alias", "innerNat"],
                    )
                )

                # Relay admin connects `innerHttp` (storing `k_tgt` inside Relay's own peers!)
                self.assertEqual(
                    run_cli(relay_dir, ":connect", "innerHttp", tgt_url, "--token", k_tgt).returncode,
                    0,
                )
                # Wait for `innerNat` reverse session to register on Relay
                for _ in range(30):
                    pl = json.loads(run_cli(relay_dir, ":connect", "--help").stdout or "{}") if False else None
                    code, rlist = rmcp._http_request_json(relay_url + "/route", "POST", k_relay, {"dst": "self", "action": "peers_list"})
                    if code == 200 and "innerNat" in ((rlist.get("result") or {}).get("reverse_peers") or {}):
                        break
                    time.sleep(0.15)

                # --- Mode 0: Relay is OFF by default -> Stranger MUST be rejected (403)! ---
                off_try = run_cli(
                    stranger_dir, ":connect", "innerHttp", "--token", k_tgt, "--relay", relay_url
                )
                self.assertNotEqual(off_try.returncode, 0)
                self.assertIn("disabled", off_try.stderr)

                # Stranger trying to execute on Relay `self` without k_relay -> MUST get 401!
                self_attack = run_cli(
                    stranger_dir, ":connect", "self", "self", "--token", k_tgt, "--relay", relay_url
                )
                self.assertNotEqual(self_attack.returncode, 0)

                # --- Tier 1 (`peers`): Registered peers & reverse tunnels ONLY! ---
                admin_dir = base / "admin_cli"
                allowed_ports_csv = f"7777,{p_tgt},{p_unreg},{p_unreg_c1},{p_unreg_c2}"
                # Update live Relay policy via authenticated admin call to Relay!
                self.assertEqual(
                    run_cli(admin_dir, ":connect", "relaySelf", relay_url, "--token", k_relay).returncode,
                    0,
                )
                rel_t1 = run_cli(
                    admin_dir, "--to", "relaySelf", ":relay", "peers", "--ports", allowed_ports_csv
                )
                self.assertEqual(rel_t1.returncode, 0, rel_t1.stderr)

                # CRITICAL SECURITY CHECK: Stranger supplies WRONG target token for `innerHttp`.
                # Even though Relay itself holds the real `k_tgt` in `peers["innerHttp"]`, Relay MUST NOT inject it!
                wrong_tok = run_cli(
                    stranger_dir, ":connect", "innerHttp", "--token", "WRONG-TARGET-TOKEN", "--relay", relay_url
                )
                self.assertNotEqual(wrong_tok.returncode, 0)
                self.assertIn("401", wrong_tok.stderr)

                # Stranger with REAL `k_tgt` (and ZERO `k_relay`) connects to `innerHttp` & executes UTF-8 command!
                ok_http = run_cli(
                    stranger_dir, ":connect", "innerHttp", "--token", k_tgt, "--relay", relay_url
                )
                self.assertEqual(ok_http.returncode, 0, ok_http.stderr)
                ex_http = run_cli(
                    stranger_dir, "--to", "innerHttp", sys.executable, "-c", "print('blind-http-ok 喵')"
                )
                self.assertEqual(ex_http.returncode, 0, ex_http.stderr)
                self.assertIn("blind-http-ok 喵", ex_http.stdout)

                # Stranger with REAL `k_nat` connects to `--dial` reverse-tunnel node `innerNat` through Relay!
                ok_nat = run_cli(
                    stranger_dir, ":connect", "innerNat", "--token", k_nat, "--relay", relay_url
                )
                self.assertEqual(ok_nat.returncode, 0, ok_nat.stderr)
                ex_nat = run_cli(
                    stranger_dir, "--to", "innerNat", sys.executable, "-c", "print('blind-nat-ok 🐾')"
                )
                self.assertEqual(ex_nat.returncode, 0, ex_nat.stderr)
                self.assertIn("blind-nat-ok 🐾", ex_nat.stdout)

                # Tier 1 MUST block unregistered `unreg_url`!
                t1_unreg = run_cli(
                    stranger_dir, ":connect", "unregBox", unreg_url, "--token", k_unreg, "--relay", relay_url
                )
                self.assertNotEqual(t1_unreg.returncode, 0)
                self.assertIn("forbids arbitrary dst_url", t1_unreg.stderr)

                # --- Tier 2 (`cidr`): Allow explicit CIDR + allowed ports, then run Blue-Green `:upgrade` through Blind Relay! ---
                rel_t2 = run_cli(
                    admin_dir, "--to", "relaySelf", ":relay", "127.0.0.1/32", "--ports", allowed_ports_csv
                )
                self.assertEqual(rel_t2.returncode, 0, rel_t2.stderr)

                # Connect to unregistered v0.7.5 `unregBox` via Tier-2 Blind Relay!
                # Note: v0.7.5 does not know `e2e` yet — let's verify that an older v0.7.5 node rejects `_e2e` downgrade,
                # and a v0.8.0 node on an unregistered CIDR URL works + upgrades cleanly!
                self.assertNotEqual(
                    run_cli(stranger_dir, ":connect", "unregOld", unreg_url, "--token", k_unreg, "--relay", relay_url).returncode,
                    0,
                )

                # Launch a v0.8.0 unregistered node (`unregV8`, tweaked comment so hash differs -> triggers real Blue-Green upgrade!)
                p_unreg8 = _pick_free_port()
                allowed_ports_csv2 = f"{allowed_ports_csv},{p_unreg8}"
                run_cli(admin_dir, "--to", "relaySelf", ":relay", "127.0.0.1/32", "--ports", allowed_ports_csv2)

                unreg8_install = base / "unreg8_install"
                unreg8_install.mkdir(parents=True, exist_ok=True)
                unreg8_script = unreg8_install / "agent.py"
                unreg8_script.write_text(Path(RMCP_SCRIPT).read_text(encoding="utf-8") + "\n# slightly-older-build\n", encoding="utf-8")
                (unreg8_install / "agent.token").write_text(k_unreg, encoding="utf-8")
                procs.append(
                    _spawn_daemon(
                        base / "unreg8_state",
                        str(unreg8_script),
                        ["--listen", "--host", "127.0.0.1", "--port", str(p_unreg8)],
                        cwd=unreg8_install,
                    )
                )
                for _ in range(40):
                    c, _ = rmcp._http_request_json(f"http://127.0.0.1:{p_unreg8}/ping", "GET", "")
                    if c == 200:
                        break
                    time.sleep(0.1)

                t2_conn = run_cli(
                    stranger_dir,
                    ":connect",
                    "unreg8",
                    f"http://127.0.0.1:{p_unreg8}",
                    "--token",
                    k_unreg,
                    "--relay",
                    relay_url,
                    "--ports",
                    f"{p_unreg_c1},{p_unreg_c2}",
                )
                self.assertEqual(t2_conn.returncode, 0, t2_conn.stderr)

                # Run full Blue-Green `:upgrade` + primary port reclaim RIGHT THROUGH the Zero-Knowledge Blind Relay!
                t2_upg = run_cli(
                    stranger_dir, ":upgrade", "unreg8", "--ports", f"{p_unreg_c1},{p_unreg_c2}"
                )
                self.assertEqual(t2_upg.returncode, 0, t2_upg.stderr + t2_upg.stdout)
                upg_doc = json.loads(t2_upg.stdout)
                self.assertEqual(upg_doc["status"], "upgraded")
                self.assertTrue(upg_doc["reclaimed_primary_port"])
                self.assertEqual(upg_doc["primary_port"], p_unreg8)
                self.assertEqual(upg_doc["new_hash"], rmcp.CODE_HASH)
                run_cli(stranger_dir, "--to", "unreg8", ":shutdown", "--delay", "0.05")
            finally:
                for pr in procs:
                    if pr.poll() is None:
                        pr.kill()
                        pr.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
