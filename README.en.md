# remote-mcp (English)

> 📖 **中文版 → [README.md](README.md)**

---

> ⚠️ **Disclaimer: AI-Generated**
>
> This project (including `rmcp.py`, `agent.py`, `server.py`, the tests, and all
> documentation) was generated with AI assistance and has not been independently
> human-reviewed. Review the code, tests, and security-sensitive logic yourself
> before use. The authors make no warranty of correctness, security, or fitness
> for any purpose.

---

Cross-platform (Linux & Windows) remote execution toolkit with two entrypoints:

1. **`rmcp.py` (Zero-dependency single-file CLI + Multi-Hop Encrypted Mesh Router + Remote Node)** — built for one-shot bots (without interactive REPL support) and multi-hop networks:
   - **Normal command pass-through**: any command not starting with `:` runs directly on the active remote node, preserving working directory (`cwd`) across invocations and propagating the exact exit code.
   - **`:` management commands**: commands starting with `:` (Vim-style — literal across Bash, Zsh, Fish, Git Bash, `cmd.exe`, and PowerShell with zero path-expansion collisions) manage node connections, active target switching, multi-hop routing tables, file transfers, background processes, and boot autostart.
   - **Router-like multi-hop forwarding + anti-broadcast-storm**: each host has a deterministic `node_id`; edges are recorded passively on connection (no background polling), packets route via `local -> direct/reverse peers -> cached unicast route -> controlled flood discovery`, and broadcast storms are prevented via `pkt_id` deduplication, `ttl` hop decrement, and `via` split-horizon loop detection.
   - **SSH preferred + self-bootstrap + encrypted HTTP listener + outbound reverse tunnel (`--dial`)**:
     - Over SSH, Base64-framed envelopes stream over `ssh --stdio-hop` pipes — bypassing `bash`/`cmd.exe` multi-hop quoting issues and Windows GBK mojibake. `--bootstrap` automatically streams `rmcp.py` to `~/.rmcp/rmcp.py` on the target, and `--via <hop>` lets an intermediate jump host connect onward using **its own SSH keys or private network access**.
     - On SSH-less machines, `--listen` binds an HTTP port with token-derived authenticated encryption (`BLAKE2b-CTR + HMAC-SHA256`) while staying backward-compatible with legacy `agent.py` v0.4.
     - On NAT / inbound-blocked machines without SSH, `--dial <hub_url> --token <T>` establishes an outbound long-polling reverse tunnel to any listening hub node so the whole mesh can route into it.
     - Built-in `--watchdog` crash supervisor and `:autostart on` (silent user `Startup` `.vbs` on Windows requiring no admin rights; user `crontab @reboot` on Linux).
2. **`server.py` + `agent.py` (MCP Server + Lightweight HTTP Agent)** — exposes 14 `remote_*` MCP tools to Claude Code and other MCP clients.

```
Bot / Shell ──▶ rmcp.py (CLI) ══ SSH stdio ══▶ Jump rmcp.py ══ Encrypted HTTP ══▶ Hub rmcp.py ◀══ Reverse Poll (--dial) ══ NAT Host
```

---

## `rmcp.py` Quick Start (Single file, Python 3.10+ stdlib only)

### 1. Connect Nodes & Build a Multi-Hop Mesh

```bash
# A. Connect over SSH (auto-bootstraps ~/.rmcp/rmcp.py if missing)
python rmcp.py :connect win6 ssh://user@10.12.23.6 --bootstrap

# B. Ask jump host `win6` to connect onward using ITS OWN SSH keys / LAN access
python rmcp.py :connect inner-linux ssh://dev@192.168.50.10 --via win6 --bootstrap

# C. SSH-less target: start encrypted HTTP listener (writes token to agent.token)
python rmcp.py :listen --port 7777 --watchdog --daemon
python rmcp.py :autostart on --port 7777 --local   # enable boot autostart + watchdog

# Connect to that HTTP node directly or via a jump host
python rmcp.py :connect box7 http://192.168.50.20:7777 --token <TOKEN> --via win6

# D. Inbound-blocked NAT host (no SSH, no open ports): dial outbound to a hub
python rmcp.py :dial http://10.12.23.6:7777 --token <HUB_TOKEN> --alias nat-pc --watchdog --daemon
```

### 2. Daily CLI Usage (One-Shot Bot Friendly)

Once edges are recorded anywhere in the mesh, `:use <alias_or_node_id>` discovers and caches the multi-hop path automatically:

```bash
python rmcp.py :nodes                         # inspect peers, cached routes, and active target
python rmcp.py :use nat-pc                    # auto-discover path (e.g. local -> win6 -> nat-pc)
python rmcp.py :ping                          # inspect end-to-end `via` hops

# Commands without leading `:` pass straight through with persistent remote cwd
python rmcp.py cd D:/github/remote-mcp
python rmcp.py git status -sb
python rmcp.py python -c "print('clean multi-hop quotes & UTF-8!')"

# One-shot override without changing active target
python rmcp.py --to win6 hostname

# Multi-hop file read/write/edit & SHA-256 verified streaming upload/download
python rmcp.py :read D:/github/remote-mcp/README.md
python rmcp.py :write /tmp/hello.txt "hello mesh"
python rmcp.py :edit /tmp/hello.txt hello hi
python rmcp.py :upload ./build.zip D:/releases/build.zip
python rmcp.py :download D:/logs/app.log ./app.log
```

### 3. `:` Management Command Reference

| Command | Purpose |
|---|---|
| `:help` | Show CLI usage and command reference |
| `:id [--alias <name>]` | Show deterministic `node_id` and alias (or set local alias) |
| `:nodes` (`:peers`, `:routes`) | Show local or remote node's peers, cached routes, and reverse sessions |
| `:connect <alias> <endpoint> [--bootstrap] [--token T] [--via <hop>]` | Connect and record an SSH or HTTP peer edge |
| `:disconnect <alias> [--via <hop>]` | Remove a recorded peer edge and invalidated routes |
| `:use <target>` (`:to <target>`) | Probe reachability and switch active target (`:use self` for local) |
| `:listen [--port 7777] [--token T] [--daemon] [--watchdog]` | Run encrypted HTTP router + reverse-tunnel hub |
| `:dial <hub_url> --token <T> [--alias A] [--daemon] [--watchdog]` | Dial outbound reverse long-polling tunnel into a hub |
| `:autostart [status\|on\|off] [--port P] [--dial URL --token T] [--local]` | Configure boot autostart on active target (or `--local`) |
| `:ping [target]` / `:env [target]` | Probe hop path / inspect OS, shells, Python, and disk |
| `:pwd` / `:cd <dir>` | Show or change persistent working directory for active target |
| `:read` / `:write` / `:edit` | Read, atomically write, or replace unique text on remote files (≤ 8 MiB) |
| `:upload <local> <remote>` / `:download <remote> <local>` | Chunked streaming transfer with end-to-end SHA-256 verification |
| `:spawn <cmd> [--stdout <log>]` / `:ps` / `:kill <pid>` | Manage detached background processes on target |
| `:shutdown [--delay sec]` | Cleanly stop a remote HTTP/dial daemon |

---

## MCP Server Mode (`server.py` + `agent.py`)

Exposes 14 `remote_*` MCP tools for Claude Code and other MCP clients:

```
Claude Code (MCP client)
   │  stdio
   ▼
server.py (local)  ── HTTP (JSON / NDJSON / raw stream, Bearer-token auth) ──▶  agent.py or rmcp.py --listen (remote)
```

| Tool | Purpose |
|---|---|
| `remote_hosts` | list configured hosts + the active one |
| `remote_read` / `remote_write` | read / write remote text files (`write` ≤ 8 MiB) |
| `remote_edit` | exact string replace on a remote file |
| `remote_bash` | one-shot command (Windows defaults to cmd.exe) |
| `remote_shell_exec` | persistent PTY session; `cd`/env/REPL state survives across calls, auto-reconnects on restart |
| `remote_shell` | session management: list/peek/close/input/interrupt/resize/relabel |
| `remote_upload` / `remote_download` | streaming large-file transfer, sha256 end-to-end verified |
| `remote_env` | snapshot of remote platform / shell / tools |
| `remote_spawn` / `remote_proclist` / `remote_kill` | background process management |
| `remote_shutdown` | stop the remote agent itself (hot-reload only) |

### Setup

```bash
pip install -r requirements.txt   # Python 3.10+; mcp pinned <2.0 (rmcp.py & agent.py need zero deps)
python agent.py                   # or: python rmcp.py --listen (wire-compatible)
claude mcp add --scope user remote-mcp -- python /path/to/server.py
```

Default config path: `~/.config/remote-agent-mcp/hosts.json` (`rmcp.py` automatically imports hosts from this file non-destructively).

---

## Testing

All test suites run locally without requiring external remote hosts:

```bash
python tests/test_rmcp.py          # AEAD crypto, cycle storm immunity, 3-hop SSH+HTTP+Reverse e2e, v0.4 fallback
python tests/test_agent.py         # agent.py consoleless pythonw regression test
python tests/test_server.py        # 37 MCP server assertions against local mock
python tests/test_mcp_protocol.py  # real MCP stdio client -> server -> mock agent e2e
```

---

## Security

- **SSH links** use system OpenSSH key authentication and transport encryption.
- **HTTP `/route` and `/reverse/*` links** derive separate encryption and MAC keys from the shared token (`BLAKE2b-256` counter-mode stream cipher + `HMAC-SHA256` + 16-byte random nonce + 600s replay window).
- Tokens are stored with `0600` user-only permissions under `~/.config/remote-agent-mcp/`. Use strong tokens and firewall rules whenever binding `--listen` on untrusted networks.

---

## License

MIT. `agent.py` is a de-pi'd derivative of the remote-execution agent from the pi coding-agent project — see [NOTICE](NOTICE) for provenance.
