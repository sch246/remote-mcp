# remote-mcp (English)

> 📖 **中文版 / Chinese version → [README.md](README.md)**

An MCP (Model Context Protocol) server for executing on **remote machines** that
run a tiny, stdlib-only HTTP daemon (`agent.py`). Works on Linux and Windows,
and is specifically designed for hosts where SSH / WinRM / SMB are not
available — e.g. a passwordless Windows box whose user accounts and registry
you cannot change.

```
Claude Code (MCP client)
   │  stdio
   ▼
server.py (local)  ── HTTP (JSON / NDJSON / raw stream, Bearer-token auth) ──▶  agent.py (remote)
```

`agent.py` is a single self-contained Python file you copy to the target
machine and run with no dependencies beyond the Python standard library. It
exposes everything the MCP server needs over a small REST API: file
read/write/edit, one-shot commands, persistent PTY shell sessions, streaming
large-file transfer with sha256 verification, and background process
management.

## What you get

14 MCP tools, all prefixed `remote_`:

| Tool | Purpose |
|---|---|
| `remote_hosts` | list configured hosts + the active one |
| `remote_read` / `remote_write` | read / write remote text files (`write` ≤ 8 MiB) |
| `remote_edit` | exact string replace on a remote file |
| `remote_bash` | one-shot command (Windows defaults to cmd.exe) |
| `remote_shell_exec` | persistent PTY session; `cd`/env/REPL state survives across calls, lazy-open, auto-reconnects on agent restart (404/410) |
| `remote_shell` | session management: list/peek/close/input/interrupt/resize/relabel |
| `remote_upload` / `remote_download` | streaming large-file transfer, sha256 end-to-end verified |
| `remote_env` | snapshot of remote platform / shell / tools — run this first |
| `remote_spawn` / `remote_proclist` / `remote_kill` | background process management (`spawn` needs a `stdout` file path or output is discarded) |
| `remote_shutdown` | stop the remote agent itself (hot-reload only — use with care) |

## Setup

**1. Install the server (the machine you run Claude Code on):**

```bash
pip install -r requirements.txt   # Python 3.10+; mcp pinned <2.0 (2.0 removed FastMCP)
```

**2. Run the agent on the target machine** (Python 3.10+ only, stdlib — no
dependencies to install):

```bash
python agent.py                  # binds 0.0.0.0:7777 by default; use --host/--port
```

It writes its token to `agent.token` next to the script (or set
`REMOTE_AGENT_TOKEN`). The token is required in the config below.

**3. Configure hosts (the machine running the server):**

Default path: `~/.config/remote-agent-mcp/hosts.json`

```jsonc
{
  "hosts": {
    "win188": { "url": "http://192.168.88.188:7777", "token": "…", "cwd": "C:\\Users\\me", "platform": "win32" },
    "linux":  { "url": "http://10.0.0.5:7777",       "token": "…", "cwd": "/home/me",  "platform": "linux" }
  },
  "active": "win188"
}
```

**4. Register with Claude Code:**

```bash
claude mcp add --scope user remote-mcp -- python /path/to/server.py
claude mcp list
```

### Optional flags / env

- `--config <path>` — hosts file (default `~/.config/remote-agent-mcp/hosts.json`).
  This format is compatible with the pi coding-agent's `~/.pi/remote-hosts.json`,
  so `--config ~/.pi/remote-hosts.json` lets both tools share one config.
- `--host <alias>` — default host, overrides `active`.
- `REMOTE_AGENT_CONFIG` — env override for the config path.
- `REMOTE_AGENT_HOST` — env override for the default host (precedence:
  explicit `host=` parameter > env > config `active`).
- `REMOTE_AGENT_TOKEN` — token override for the *agent* (legacy name
  `PI_REMOTE_AGENT_TOKEN` still works).

## Design notes

- **Explicit over implicit.** Tools are named `remote_*` so the model knows a
  call leaves the local machine. No local tools are ever redirected.
- **Paths are sent verbatim** — there is no local↔remote path mapping. Call
  `remote_env` first to learn the remote cwd / platform / shell.
- **Windows shells default to cmd.exe**, not bash.
- **Session cache is in-memory** (lost on server restart). If the agent.py
  restarts, `remote_shell_exec` recovers via a 404/410 retry.
- **Large files use upload/download.** `remote_write` is capped at 8 MiB
  (base64 expansion in JSON); upload streams and verifies sha256 end-to-end.

## Testing

`tests/` contains a local mock of the agent.py wire protocol plus full test
suites — no real remote host needed:

```bash
python tests/test_server.py        # 37 assertions against the mock
python tests/test_mcp_protocol.py  # real MCP stdio client → server → mock agent
```

The mock reproduces real-world quirks of `agent.py`, including the
hand-rolled HTTP-style chunk framing in the `/exec` response body, so the
parser is exercised against faithful output.

## Security

- The token lives **in plaintext** in the hosts file (same design as the pi
  agent). The server runs locally, in your trust domain; the agent binds
  `0.0.0.0` by default, so put it behind a firewall or tunnel if your remote
  is exposed.
- `remote_shutdown` genuinely stops the remote agent — only use it when
  hot-reloading the agent.
- `agent.py` enforces the Bearer token on every endpoint except `/ping`.

## License

MIT. `agent.py` is a de-pi'd derivative of the remote-execution agent from the
pi coding-agent project — see [NOTICE](NOTICE) for provenance.
