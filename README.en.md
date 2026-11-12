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

1. **`rmcp.py` (Zero-dependency single-file CLI + Interactive REPL + Multi-Hop Encrypted Mesh Router + Remote Node)** — built for both one-shot bots and interactive human shells:
   - **Normal command pass-through & Interactive REPL**: running `python rmcp.py` in a TTY (or `python rmcp.py :repl [target]` / `-i`) opens an interactive shell with persistent multi-hop pipe reuse, readline history, Tab completion, raw shell pipelines (`|`, `>`, `&&`), `!<local_cmd>`, and `:q` to exit; in non-TTY / one-shot invocations, any command not starting with `:` runs directly on the active remote node, preserving `cwd` and propagating exit codes.
   - **Shared mesh topology + per-caller session isolation (zero multi-agent crosstalk)**: `router.json` shares peers and routes machine-wide, while mutable `:use` target and per-node `cwds` are isolated into `sessions/<hash>.json` keyed by `(node_id, project_root_or_cwd, agent_conversation_id)` (or explicit `--session <name>` / `RMCP_SESSION`); envelopes carry `origin` provenance across hops so remote `:ps` attributes background processes to their exact caller.
   - **`:` management commands**: commands starting with `:` (Vim-style — literal across Bash, Zsh, Fish, Git Bash, `cmd.exe`, and PowerShell with zero path-expansion collisions) manage node connections, active target switching, multi-hop routing tables, file transfers, background processes, and boot autostart.
   - **Router-like multi-hop forwarding + anti-broadcast-storm**: each host has a deterministic `node_id`; edges are recorded passively on connection (no background polling), packets route via `local -> direct/reverse peers -> cached unicast route -> controlled flood discovery`, and broadcast storms are prevented via `pkt_id` deduplication, `ttl` hop decrement, and `via` split-horizon loop detection.
   - **SSH preferred (persistent multiplexing) + self-bootstrap + encrypted HTTP listener + outbound reverse tunnel (`--dial`)**:
     - Over SSH, Base64-framed envelopes stream over `ssh --stdio-hop` / `--stdio-loop` pipes (interactive REPL and multi-chunk file transfers keep multi-hop SSH pipes warm across commands, avoiding repeated SSH handshakes) — bypassing `bash`/`cmd.exe` multi-hop quoting issues and Windows GBK mojibake. `--bootstrap` automatically streams `rmcp.py` to `~/.rmcp/rmcp.py` on the target, and `--via <hop>` lets an intermediate jump host connect onward using **its own SSH keys or private network access**.
     - On SSH-less machines, `--listen` binds an HTTP port with token-derived authenticated encryption (`BLAKE2b-CTR + HMAC-SHA256`) while staying backward-compatible with legacy `agent.py` v0.4.
     - On NAT / inbound-blocked machines without SSH, `--dial <hub_url> --token <T>` establishes an outbound long-polling reverse tunnel to any listening hub node so the whole mesh can route into it.
     - **Blue-Green multi-port self-upgrade + primary port reclaim (`:upgrade`)**: computes an LF-normalized runtime source hash (`code_hash`, avoiding self-referential hash recursion); brings up the Green instance on a candidate port (`7778,7779,7780` by default) and verifies end-to-end external reachability BEFORE shutting down Blue, immediately reclaims the primary port (`7777`), and releases the candidate port (or rolls back cleanly with zero downtime if Green fails). Supports `--standby-if-busy` for external batch supervisor scripts.
     - **Two-tier zero-knowledge stranger blind relay (`--allow-relay` / `:relay` / `:connect --relay`)**: when a relay node opts into stranger forwarding, callers can connect to target hosts **without knowing the relay's token** — knowing only the target's token (`e2e` envelopes bound to `pkt_id`; the relay never decrypts payloads or injects stored peer tokens). Supports Tier 1 (`peers`: registered peers/routes and `--dial` reverse sessions only) and Tier 2 (`private` or explicit CIDRs + allowed ports, with hard SSRF blocks on loopback, link-local, multicast, and cloud metadata IPs).
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

# E. Zero-knowledge stranger blind relay (connect using ONLY target's token, without relay's token)
python rmcp.py --to relay-hub :relay peers                              # Tier 1: registered peers / --dial nodes only
python rmcp.py --to relay-hub :relay 192.168.88.0/24 --ports 7777,7778  # Tier 2: explicit subnet + allowed ports
python rmcp.py :connect nat-pc --token <TARGET_TOKEN> --relay http://10.12.23.6:7777
python rmcp.py :connect cam188 http://192.168.88.188:7777 --token <TARGET_TOKEN> --relay http://10.12.23.6:7777

# F. Blue-Green self-upgrade (verify Green on candidate port -> stop Blue -> reclaim primary port 7777)
python rmcp.py :upgrade box7
python rmcp.py :upgrade --all
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

# Multi-hop file read/write/edit & SHA-256 verified streaming upload/download (relative remote cwd paths supported)
python rmcp.py :read README.md
python rmcp.py :write /tmp/hello.txt "hello mesh"
python rmcp.py :edit /tmp/hello.txt hello hi
python rmcp.py :upload ./build.zip D:/releases/build.zip
python rmcp.py :download D:/logs/app.log ./app.log

# Interactive REPL shell (keeps multi-hop SSH pipes warm across commands)
python rmcp.py :repl nat-pc                   # or simply run `python rmcp.py` in a TTY / `python rmcp.py -i`
# [nat-pc D:\github\remote-mcp]> git status -sb
# [nat-pc D:\github\remote-mcp]> !ls -lh ./local_patch.diff   # !<cmd> runs locally without changing :use
# [nat-pc D:\github\remote-mcp]> :use win6                    # switch active node live inside REPL
# [win6 C:\Users\user]> :q
```

### 3. `:` Management Command Reference

| Command | Purpose |
|---|---|
| `:help` | Show CLI usage and command reference |
| `:repl [target]` (`:shell`, `-i`) | Enter interactive REPL (persistent multi-hop pipes, history, Tab completion, `:q` to exit) |
| `:local <cmd>` (`!<cmd>` inside REPL) | Run a command on THIS local machine without changing active `:use` target |
| `:id [--alias <name>]` | Show deterministic `node_id`, alias, and current caller origin (`caller`) |
| `:sessions [--clear\|--clear-all]` | List or clear isolated per-caller sessions on this machine |
| `:nodes` (`:peers`, `:routes`) | Show local or remote node's peers, cached routes, and reverse sessions |
| `:connect <alias> [endpoint] [--bootstrap] [--token T] [--via <hop>] [--relay <relay>]` | Connect an SSH, HTTP, or zero-knowledge blind-relayed (`--relay`) peer |
| `:disconnect <alias> [--via <hop>]` | Remove a recorded peer edge and invalidated routes |
| `:use <target>` (`:to <target>`) | Probe reachability and switch active target (`:use self` for local) |
| `:upgrade [target\|--all] [--ports 7778,7779,7780] [--force]` | Blue-Green self-upgrade + primary port reclaim (verifies Green before stopping Blue) |
| `:relay [status\|off\|peers\|private\|<CIDR,...>] [--ports ...] [--local]` | Inspect or configure 2-tier stranger zero-knowledge blind relay policy |
| `:listen [--port 7777] [--token T] [--allow-relay ...] [--standby-if-busy] [--daemon] [--watchdog]` | Run encrypted HTTP router + reverse-tunnel hub |
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
