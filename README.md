> 📖 **English version → [README.en.md](README.en.md)**

---

> ⚠️ **免责声明：AI 生成**
>
> 本项目（含 `rmcp.py`、`agent.py`、`server.py`、测试与全部文档）由 AI 辅助编写，尚未经过独立的人工安全审查。
> 使用前请自行审查代码、测试与安全相关逻辑；作者不对其正确性、安全性或适用性作任何保证。

---

# remote-mcp

跨平台（Linux & Windows）远程执行工具集，提供两种入口：

1. **`rmcp.py`（零依赖单文件 CLI + 交互式 REPL + 多跳加密 Mesh 路由器 + 远端节点）** —— 同时兼顾单次调用 Bot 与人类交互终端：
   - **普通命令直穿 & 交互式 REPL**：不带参数在终端运行 `python rmcp.py`（或显式 `python rmcp.py :repl [目标]` / `-i`）即可进入带命令历史、Tab 补全与持久长连接复用的交互式 Shell（支持管道 `|`、重定向 `>`、`!<本地命令>` 与 `:q` 退出）；非 TTY 环境下单次调用不带 `:` 的命令直接发往当前激活远端节点执行，跨调用保持远端工作目录（`cwd`）并透传退出码。
   - **拓扑共享 + 按调用源头会话隔离（多 Agent 零串台）**：全机共享 `router.json` 路由拓扑，但每个调用源头按 `(源主机 node_id, 本地仓库根目录/目录, Agent 会话标识)` 自动分片落盘至独立的 `sessions/<hash>.json`（也可通过 `--session <名>` / `RMCP_SESSION` 显式指定）；多个终端、Bot 或 AI Agent 并发调用 `:use` 与 `:cd` 互不覆盖，跨跳信封自动附带 `origin` 溯源并在远端 `:ps` 标注后台进程归属。
   - **`:` 管理命令**：以 `:` 开头（Vim 风格，在 Bash / Zsh / Fish / Git Bash / `cmd.exe` / PowerShell 下均原样透传、零路径展开冲突）执行节点连接、切换、多跳路由查看、文件传输、后台进程管理与自启动配置。
   - **路由器式多跳转发 + 防广播风暴**：每台机器拥有确定性 `node_id`；建连即被动记录拓扑边（不主动轮询探测），收包按「本机 → 直连/反向邻居 → 缓存单播路由 → 受控洪泛发现」转发，依靠 `pkt_id` 去重、`ttl` 跳数递减与 `via` 路径分裂视野彻底杜绝广播风暴。
   - **SSH 优先（持久多路复用）+ 自举复制 + HTTP 加密监听 + 反向连接（`--dial`）**：
     - 有 SSH 时走 `ssh --stdio-hop` / `--stdio-loop` 管道传输 Base64 帧（交互模式与大文件分块传输自动保持全链路多跳 SSH 管道常驻热复用，免除重复握手耗时），彻底绕过 `bash`/`cmd.exe` 多跳引号转义地狱与 GBK 乱码；支持 `--bootstrap` 自动把单文件 `rmcp.py` 流式部署到目标机 `~/.rmcp/rmcp.py`；跳板机还能用**自己的 SSH Key 或内网权限**连接下一跳（`--via <跳板>`）。
     - 无 SSH 时可运行 `--listen` 监听端口并生成 token（`BLAKE2b-CTR + HMAC-SHA256` 认证加密），兼容旧版 `agent.py` v0.4。
     - 无公网 IP / 防火墙禁入站时可运行 `--dial <hub_url> --token <T>` 主动向外长轮询连入中枢节点，全网即可反向路由访问该内网节点。
     - 支持 `--watchdog` 崩溃自愈守护与 `:autostart on` 开机自启（Windows 写入用户 `Startup` 目录无窗口 `.vbs`，无需管理员权限；Linux 写入用户 `crontab @reboot`）。
2. **`server.py` + `agent.py`（MCP 服务器 + 轻量 HTTP Agent）** —— 供 Claude Code 等 MCP 客户端通过 14 个 `remote_*` 工具调用远端主机。

```
Bot / 终端 ──▶ rmcp.py (CLI) ══ SSH stdio ══▶ 跳板机 rmcp.py ══ HTTP(加密) ══▶ Hub rmcp.py ◀══ 反向长轮询(--dial) ══ 内网无SSH机器
```

---

## `rmcp.py` 快速上手（单文件，仅依赖 Python 3.10+ 标准库）

### 1. 连接节点与组建多跳网络

```bash
# A. 通过 SSH 连接（目标机没有 rmcp.py 时会自动自举上传到 ~/.rmcp/rmcp.py）
python rmcp.py :connect win6 ssh://user@10.12.23.6 --bootstrap

# B. 让跳板机 win6 用它自己的 SSH Key 或内网权限连接下一跳主机（无需手工拼多跳转义！）
python rmcp.py :connect inner-linux ssh://dev@192.168.50.10 --via win6 --bootstrap

# C. 无 SSH 目标机：在目标机上启动加密 HTTP 监听（默认 0.0.0.0:7777，自动生成 agent.token）
python rmcp.py :listen --port 7777 --watchdog --daemon
python rmcp.py :autostart on --port 7777 --local   # 配置开机自启 + 崩溃自愈

# 从控制端或任意跳板连接该 HTTP 节点
python rmcp.py :connect box7 http://192.168.50.20:7777 --token <TOKEN> --via win6

# D. 内网隔离机（无 SSH 且无法开入站端口）：主动反向连入任意监听中的 Hub 节点
python rmcp.py :dial http://10.12.23.6:7777 --token <HUB_TOKEN> --alias nat-pc --watchdog --daemon
```

### 2. 日常使用（对单次调用 Bot 完全友好）

一旦拓扑里某处建立了边，任意节点只需 `:use <名字或node_id>` 即可自动寻路并缓存下一跳，无需手写连接路径：

```bash
python rmcp.py :nodes                         # 查看已知邻居、缓存路由表与当前 active 节点
python rmcp.py :use nat-pc                    # 自动多跳寻路（如 local -> win6 -> nat-pc）并设为当前目标
python rmcp.py :ping                          # 查看端到端实际经过的 via 跳数路径

# 不带 : 的普通命令直接穿透到当前远端执行，工作目录跨调用持久化！
python rmcp.py cd D:/github/remote-mcp
python rmcp.py git status -sb
python rmcp.py python -c "print('多跳引号和中文都不乱码喵')"

# 临时向指定节点发单条命令（不改变当前 active）
python rmcp.py --to win6 hostname

# 跨任意多跳读写改文件与流式大文件传输（端到端 SHA-256 校验，支持相对远端 cwd 路径）
python rmcp.py :read README.md
python rmcp.py :write /tmp/hello.txt "hello mesh"
python rmcp.py :edit /tmp/hello.txt hello hi
python rmcp.py :upload ./build.zip D:/releases/build.zip
python rmcp.py :download D:/logs/app.log ./app.log

# 进入人类交互式 REPL 模式（多跳 SSH 管道自动保持常驻复用，毫秒级响应）
python rmcp.py :repl nat-pc                   # 或在终端直接运行 python rmcp.py / python rmcp.py -i
# [nat-pc D:\github\remote-mcp]> git status -sb | head -n 5
# [nat-pc D:\github\remote-mcp]> !ls -lh ./local_patch.diff   # !<命令> 临时在本机执行
# [nat-pc D:\github\remote-mcp]> :use win6                    # 会话内秒切其他节点
# [win6 C:\Users\user]> :q
```

### 3. `:` 管理命令速查

| 命令 | 作用 |
|---|---|
| `:help` | 显示完整命令帮助 |
| `:repl [目标]`（或 `:shell` / `-i`） | 进入交互式 REPL（持久复用多跳管道、方向键历史、Tab 补全、`:q` 退出） |
| `:local <命令>`（REPL 内可简写 `!<命令>`） | 不切换当前激活节点，直接在本机执行一条命令 |
| `:id [--alias <名>]` | 查看本机确定性 `node_id`、别名与当前调用源头（`caller`） |
| `:sessions [--clear\|--clear-all]` | 查看或清理本机各调用源头（目录/Agent）的独立会话状态 |
| `:nodes`（或 `:peers` / `:routes`） | 查看本机或指定节点的邻居表、缓存路由与反向在线会话 |
| `:connect <别名> <地址> [--bootstrap] [--token T] [--via <跳板>]` | 建立 SSH 或 HTTP 边并记录拓扑 |
| `:disconnect <别名> [--via <跳板>]` | 删除已记录的邻居边与关联缓存路由 |
| `:use <目标>`（或 `:to <目标>`） | 探测可达性并切换默认穿透目标（`:use self` 切回本机） |
| `:listen [--port 7777] [--token T] [--daemon] [--watchdog]` | 启动加密 HTTP 路由监听 + 反向连接 Hub |
| `:dial <hub_url> --token <T> [--alias A] [--daemon] [--watchdog]` | 主动发起反向长轮询隧道接入 Hub |
| `:autostart [status\|on\|off] [--port P] [--dial URL --token T] [--local]` | 管理目标机（或 `--local` 本机）开机自启 |
| `:ping [目标]` / `:env [目标]` | 探测路由跳数路径 / 查看目标系统、Shell、Python 与磁盘快照 |
| `:pwd` / `:cd <目录>` | 查看或切换目标节点的持久化工作目录 |
| `:read` / `:write` / `:edit` | 跨多跳读取、原子写入、精确替换远端文本文件（≤ 8 MiB） |
| `:upload <本地> <远端>` / `:download <远端> <本地>` | 跨多跳分块流式传输任意大小文件（SHA-256 校验） |
| `:spawn <命令> [--stdout <日志>]` / `:ps` / `:kill <pid>` | 远端后台进程启动、列表与终止 |
| `:shutdown [--delay 秒]` | 远程停止 HTTP/dial 守护进程 |

---

## MCP 服务器模式（`server.py` + `agent.py`）

用于 Claude Code 等 MCP 客户端，提供 14 个 `remote_*` 工具：

```
Claude Code (MCP 客户端)
   │  stdio
   ▼
server.py (本地)  ── HTTP（JSON / NDJSON / 原始字节流，Bearer token 鉴权）──▶  agent.py 或 rmcp.py --listen (远端)
```

| 工具 | 作用 |
|---|---|
| `remote_hosts` | 列出已配置主机 + 当前 active 主机 |
| `remote_read` / `remote_write` | 读写远端文本文件（`write` 上限 8 MiB） |
| `remote_edit` | 在远端文件上做精确字符串替换 |
| `remote_bash` | 一次性命令（Windows 默认 cmd.exe） |
| `remote_shell_exec` | 持久 PTY 会话；`cd`/环境变量/REPL 状态跨调用保留，agent 重启后自动重连 |
| `remote_shell` | 会话管理：list/peek/close/input/interrupt/resize/relabel |
| `remote_upload` / `remote_download` | 大文件流式传输，sha256 端到端校验 |
| `remote_env` | 远端平台 / shell / 工具快照 |
| `remote_spawn` / `remote_proclist` / `remote_kill` | 后台进程管理 |
| `remote_shutdown` | 关闭远端 agent 自身（仅热重载用） |

### 安装与注册 MCP

```bash
pip install -r requirements.txt   # 需要 Python 3.10+；mcp 锁在 <2.0（rmcp.py 与 agent.py 无需安装依赖）
python agent.py                   # 或 python rmcp.py --listen（两者协议兼容）
claude mcp add --scope user remote-mcp -- python /path/to/server.py
```

配置文件默认位于 `~/.config/remote-agent-mcp/hosts.json`（`rmcp.py` 会自动无损导入该文件中的已知主机）。

---

## 测试

无需真实远端机器即可在本地运行全套单元测试与多跳集成测试：

```bash
python tests/test_rmcp.py          # AEAD 加密、多跳环路防风暴、SSH stdio + HTTP + 反向隧道三跳端到端、旧版兼容
python tests/test_agent.py         # agent.py 无控制台 pythonw 回归测试
python tests/test_server.py        # MCP 工具层 37 条断言（需安装 requirements.txt）
python tests/test_mcp_protocol.py  # 真实 MCP stdio 客户端端到端测试
```

---

## 安全说明

- **SSH 链路**直接复用系统 OpenSSH 的密钥认证与通道加密。
- **HTTP `/route` 与 `/reverse/*` 链路**使用共享 token 派生的独立加密密钥与认证密钥（`BLAKE2b-256` 计数器流密码 + `HMAC-SHA256` + 16 字节随机 Nonce + 600 秒时间戳防重放窗口）。
- 配置文件中的 token 以本机用户只读权限（`0600`）存储在 `~/.config/remote-agent-mcp/`。若将 `--listen` 端口暴露在公网，请务必使用高强度随机 token 并配合防火墙使用。

---

## 许可证

MIT。`agent.py` 是 pi 编码代理项目里 remote-execution agent 的去 pi 化衍生品——来源见 [NOTICE](NOTICE)。
