> 📖 **英文版 / English version → [README.en.md](README.en.md)**

# remote-mcp

一个 MCP（Model Context Protocol）服务器，用于在**远程机器**上执行操作。远程机器上只需跑一个零依赖（仅标准库）的 HTTP 守护进程 `agent.py`。支持 Linux 和 Windows，特别适合**没有 SSH / WinRM / SMB 可用**的场景——比如一台密码空白的 Windows 机器，账户和注册表都不能动，只能靠用户态 HTTP 守护进程 + 自带 token 来访问。

```
Claude Code (MCP 客户端)
   │  stdio
   ▼
server.py (本地)  ── HTTP（JSON / NDJSON / 原始字节流，Bearer token 鉴权）──▶  agent.py (远端)
```

`agent.py` 是**单个自包含 Python 文件**，拷到目标机器上直接 `python agent.py` 就能跑，除标准库外无需任何依赖。它通过一个很小的 REST API 把所有能力暴露给 MCP 服务器：文件读/写/改、一次性命令、持久 PTY shell 会话、带 sha256 端到端校验的大文件流式传输、后台进程管理。

---

## 工具清单（14 个）

全部以 `remote_` 开头：

| 工具 | 作用 |
|---|---|
| `remote_hosts` | 列出已配置主机 + 当前 active 主机 |
| `remote_read` / `remote_write` | 读写远端文本文件（`write` 上限 8 MiB） |
| `remote_edit` | 在远端文件上做精确字符串替换 |
| `remote_bash` | 一次性命令（Windows 默认 cmd.exe） |
| `remote_shell_exec` | 持久 PTY 会话；`cd`/环境变量/REPL 状态跨调用保留，惰性建会话，agent 重启后自动重连（404/410） |
| `remote_shell` | 会话管理：list/peek/close/input/interrupt/resize/relabel |
| `remote_upload` / `remote_download` | 大文件流式传输，sha256 端到端校验 |
| `remote_env` | 远端平台 / shell / 工具快照——开始干活前先跑这个 |
| `remote_spawn` / `remote_proclist` / `remote_kill` | 后台进程管理（`spawn` 必须给 `stdout` 文件路径，否则输出丢弃） |
| `remote_shutdown` | 关掉远端 agent 自身（仅热重载用，慎用） |

---

## 安装与使用

**1. 安装 server（在你跑 Claude Code 的那台机器上）：**

```bash
pip install -r requirements.txt   # 需要 Python 3.10+；mcp 锁在 <2.0（2.0 删了 FastMCP）
```

**2. 在目标机器上跑 agent（只需 Python 3.10+，标准库，不用装任何依赖）：**

```bash
python agent.py                  # 默认绑定 0.0.0.0:7777；可用 --host/--port 改
```

它会把自己的 token 写到脚本旁边的 `agent.token` 文件（或设环境变量 `REMOTE_AGENT_TOKEN`）。这个 token 要填进下面的配置里。

**3. 配置主机（在跑 server 的机器上）：**

默认路径：`~/.config/remote-agent-mcp/hosts.json`

```jsonc
{
  "hosts": {
    "win188": { "url": "http://192.168.88.188:7777", "token": "…", "cwd": "C:\\Users\\me", "platform": "win32" },
    "linux":  { "url": "http://10.0.0.5:7777",       "token": "…", "cwd": "/home/me",  "platform": "linux" }
  },
  "active": "win188"
}
```

**4. 注册到 Claude Code：**

```bash
claude mcp add --scope user remote-mcp -- python /path/to/server.py
claude mcp list
```

### 可选参数 / 环境变量

- `--config <路径>` — 配置文件（默认 `~/.config/remote-agent-mcp/hosts.json`）。此格式与 pi 编码代理的 `~/.pi/remote-hosts.json` 兼容，所以 `--config ~/.pi/remote-hosts.json` 可以让两个工具共享同一份配置。
- `--host <别名>` — 默认主机，覆盖配置里的 `active`。
- `REMOTE_AGENT_CONFIG` — 环境变量覆盖配置路径。
- `REMOTE_AGENT_HOST` — 环境变量覆盖默认主机（优先级：显式 `host=` 参数 > 环境变量 > 配置 `active`）。
- `REMOTE_AGENT_TOKEN` — 覆盖 agent 的 token（旧名 `PI_REMOTE_AGENT_TOKEN` 仍兼容）。

---

## 设计约束

- **显式优先于隐式（explicit over implicit）。** 工具都以 `remote_*` 命名，让模型明确知道这次调用是打到远端去的；本地工具永远不会被偷偷重定向。
- **路径原样直发**，不做本地↔远端的路径映射。先用 `remote_env` 了解远端的 cwd / 平台 / shell。
- **Windows 远端默认 cmd.exe**，不是 bash。
- **会话缓存在内存里**（server 重启即丢）。agent.py 重启后，`remote_shell_exec` 靠 404/410 重试自动恢复。
- **大文件走 upload/download。** `remote_write` 上限 8 MiB（JSON 里 base64 膨胀所致）；upload 流式传输并端到端校验 sha256。

---

## 测试

`tests/` 下有一个本地 mock agent（完整镜像 agent.py 的协议），无需真实远端即可跑全套测试：

```bash
python tests/test_server.py        # 37 条断言，打本地 mock
python tests/test_mcp_protocol.py  # 真实 MCP stdio 客户端 → server → mock agent 的端到端
```

mock 复刻了 `agent.py` 的真实坑，包括 `/exec` 响应体里**手工拼的 HTTP 式 chunk 帧**，确保解析器在忠实的输出下也被验证到。

---

## 安全

- token 以**明文**存在 hosts 文件里（与 pi agent 同设计）。server 跑在本机、同信任域；agent 默认绑定 `0.0.0.0`，如果远端暴露在外网请用防火墙或隧道包起来。
- `remote_shutdown` 会真的停掉远端 agent，只在热重载时用。
- 除 `/ping` 外，`agent.py` 对所有端点强制 Bearer token。

---

## 许可证

MIT。`agent.py` 是 pi 编码代理项目里 remote-execution agent 的去 pi 化衍生品——来源见 [NOTICE](NOTICE)。
