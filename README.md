# Charles-Mcp（charles5-mcp）

让 AI 直接读取和分析 **Charles Proxy 5.2.2** 抓到的包的 MCP Server。

接入 Claude Code、Codex CLI、Grok、Cursor、Claude Desktop、VS Code、Gemini CLI 等 MCP 客户端后，可以直接对 AI 说「看看这个 app 刚才发了哪些请求」「把登录接口的请求头和提交的数据给我」「这个签名参数服务端到底校验没有」。

本项目基于 [heizaheiza/Charles-mcp](https://github.com/heizaheiza/Charles-mcp) **完整重构**，并针对 Charles 5.2.2 的真实行为做了大量修复。所有和 Charles 交互的行为都在真实的 Charles 5.2.2 上验证过，验证时录下的数据放在 `tests/fixtures/charles-5.2.2/`，作为回归测试用例。

---

## 致谢

- **[heizaheiza/Charles-mcp](https://github.com/heizaheiza/Charles-mcp)**：本项目的原型。实时抓包、历史录包、逆向分析这三大块的设计思路，以及大部分工具的功能定义，都来自这个项目。感谢原作者 [@heizaheiza](https://github.com/heizaheiza) 的开源工作。原项目同样采用 MIT 许可证。
- [Charles Proxy](https://www.charlesproxy.com/)，作者 Karl von Randow。
- [Model Context Protocol](https://modelcontextprotocol.io/) 及其 Python SDK。

---

## 目录

- [能做什么](#能做什么)
- [快速开始](#快速开始)
- [在各个 AI 客户端中使用](#在各个-ai-客户端中使用)
- [使用示例](#使用示例)
- [工具一览](#工具一览)
- [相比原项目：重构了什么](#相比原项目重构了什么)
- [相比原项目：优化了什么](#相比原项目优化了什么)
- [修复的 Bug](#修复的-bug)
- [Charles 5.2.2 的实测行为](#charles-522-的实测行为)
- [环境变量](#环境变量)
- [局限与注意事项](#局限与注意事项)
- [开发](#开发)
- [许可证](#许可证)

---

## 能做什么

- **读包**
  - 读取指定的包，或按条件筛选出全部匹配的包。
  - 每个包给出完整 URL、解码后的 query 参数、请求头、响应头，以及解码后的请求体和响应体。
- **各种格式的请求体和响应体**

  | 类型 | 处理方式 |
  | --- | --- |
  | JSON | 解析成结构化数据。带 BOM、Content-Type 写错的情况也能处理 |
  | 压缩 | 自动解压 gzip、deflate、br、zstd，以及多层编码。Charles 本身不解 zstd，由本工具处理 |
  | 表单（`x-www-form-urlencoded`） | 解析成字段，按声明的 charset（如 GBK）解码 |
  | 文件上传（`multipart/form-data`） | 按字节拆出每个部分，给出字段名、文件名、大小和真实类型（如上传的图片），可以把上传的文件存到本地 |
  | 图片、PDF、zip、音视频 | 根据文件头识别真实类型，即使 Content-Type 写的是 `octet-stream` |
  | protobuf / gRPC | 没有 `.proto` 定义也能解码，结果是字段号加值 |
  | JSONP、XML、SSE、纯文本 | 没有声明编码时，依次按 UTF-8 和 GB18030 解码，中文不会乱码 |
  | WebSocket | 解码两个方向的每条消息，支持 permessage-deflate |

- **实时抓包**：增量读取新产生的请求，用游标管理已读位置，进行中的请求完成后会原地更新。
- **历史录包**：读取的格式包括 `.chlz`、`.chlsj`、`.chlsx`、`.xml`、`.har`；如果本机装了 Charles，还可以读 `.chls`、`.trace`、Fiddler 的 `.saz` 和 `.pcap`。
- **逆向分析**
  - 识别签名、时间戳、nonce、token 等参数。
  - 回放请求、做变异测试，逐个字段验证服务端是否真的校验。
- **控制 Charles**
  - 开始或停止录制、导出 session、转换格式。
  - 设置弱网，查看和开关 Map Remote、Rewrite、Breakpoints 等工具。

---

## 快速开始

### 1. 准备

- Charles Proxy 5.2.x（在 5.2.2 上验证）
- Python 3.10 或更高版本
- [uv](https://docs.astral.sh/uv/)，安装命令：

  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
  # Windows：powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```

### 2. 设置 Charles（只需做一次）

1. **开启 Web Interface**
   - 打开 **Proxy → Web Interface Settings**，勾选 **Enable web interface**。
   - 添加一个用户，用户名和密码要与后面配置里的 `CHARLES_USER` / `CHARLES_PASS` 一致。默认是 `admin` / `123456`。
2. **把 `control.charles` 排除在录制之外（必做）**
   - 打开 **Proxy → Recording Settings → Exclude → Add**，Host 填 `control.charles`。
   - 不加这一条的话，Charles 会把 MCP 的轮询请求也录进去，session 会随轮询次数指数增长。实测约 30 次轮询后，单次导出就会超过 1.6 GB。
3. **抓 HTTPS 需要开启 SSL Proxying**
   - 打开 **Proxy → SSL Proxying Settings**，添加 `*:443`。
   - 在被抓的设备上安装并信任 Charles 根证书（菜单 **Help → SSL Proxying**）。
4. **保持 Charles 处于录制状态**：只有在录制时才能读取当前 session。

### 3. 安装与自检

不需要手动安装，`uvx` 会直接从 GitHub 拉取并运行：

```bash
uvx --from git+https://github.com/Xiao7XS/Charles-Mcp charles5-mcp --check
```

如果看到 `"connected": true` 和 `"charles_version": "5.2.2"`，说明可以用了。

也可以先 clone 到本地，再从本地目录运行：

```bash
git clone https://github.com/Xiao7XS/Charles-Mcp.git ~/Charles-Mcp
uvx --from ~/Charles-Mcp charles5-mcp --check
```

> 下文的配置都用 GitHub 地址 `git+https://github.com/Xiao7XS/Charles-Mcp`。如果用的是本地目录，就把它换成本地目录的**绝对路径**，例如 `/Users/你的用户名/Charles-Mcp`。

---

## 在各个 AI 客户端中使用

所有客户端的配置本质上一样：运行命令是 `uvx`，参数是 `--from <地址> charles5-mcp`，环境变量传入 Charles Web Interface 的账号密码。

> **常见问题：** Claude Desktop、Cursor 这类图形界面应用，可能找不到命令行里装的 `uvx`，报 `spawn uvx ENOENT`。这时在终端执行 `which uvx`（Windows 上是 `where uvx`），把配置里的 `"uvx"` 换成它输出的绝对路径，例如 `/Users/你的用户名/.local/bin/uvx`。

### Claude Code

```bash
claude mcp add charles --scope user \
  -e CHARLES_USER=admin -e CHARLES_PASS=123456 \
  -- uvx --from git+https://github.com/Xiao7XS/Charles-Mcp charles5-mcp
```

- 用 `claude mcp list` 确认连接状态；在会话里输入 `/mcp` 可以查看这个 server 提供的工具。
- `--scope user` 表示所有项目都能用。如果改成 `--scope project`，配置会写进当前项目的 `.mcp.json`，方便团队共享。

### Codex CLI（OpenAI）

命令行添加：

```bash
codex mcp add charles \
  --env CHARLES_USER=admin --env CHARLES_PASS=123456 \
  -- uvx --from git+https://github.com/Xiao7XS/Charles-Mcp charles5-mcp
```

或者直接编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.charles]
command = "uvx"
args = ["--from", "git+https://github.com/Xiao7XS/Charles-Mcp", "charles5-mcp"]
startup_timeout_sec = 60

[mcp_servers.charles.env]
CHARLES_USER = "admin"
CHARLES_PASS = "123456"
```

在 Codex 会话里输入 `/mcp` 可以查看已加载的 server。

### Grok CLI（xAI）

编辑 `~/.grok/config.toml`：

```toml
[mcp_servers.charles]
command = "uvx"
args = ["--from", "git+https://github.com/Xiao7XS/Charles-Mcp", "charles5-mcp"]
env = { CHARLES_USER = "admin", CHARLES_PASS = "123456" }
startup_timeout_sec = 60
```

也可以用命令行添加：

```bash
grok mcp add charles -- uvx --from git+https://github.com/Xiao7XS/Charles-Mcp charles5-mcp
```

用命令行添加时，账号密码不是默认值的话，需要在 `config.toml` 里补上 `env`。

- `grok mcp list` 查看已配置的 server。
- `grok mcp doctor charles` 检查连接状态。
- 连接失败时，错误日志在 `~/.grok/logs/mcp/charles.stderr.log`。

> 第一次启动时 `uvx` 要下载依赖，可能比较慢，所以上面的配置都把 `startup_timeout_sec` 设成了 60 秒。

### Cursor

编辑 `~/.cursor/mcp.json`（全局生效），或者项目里的 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "charles": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Xiao7XS/Charles-Mcp", "charles5-mcp"],
      "env": { "CHARLES_USER": "admin", "CHARLES_PASS": "123456" }
    }
  }
}
```

保存后，在 **Settings → MCP** 里确认 `charles` 显示为绿色。在 Agent 模式下就可以调用这些工具。

### Claude Desktop

1. 打开 **Settings → Developer → Edit Config**，编辑 `claude_desktop_config.json`，内容与 Cursor 的 JSON 相同。
2. 保存后**完全退出并重新打开** Claude Desktop。
3. 配置文件位置：
   - macOS：`~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows：`%APPDATA%\Claude\claude_desktop_config.json`

### VS Code（GitHub Copilot Agent 模式）

在项目里创建 `.vscode/mcp.json`。注意这里顶层的键是 `servers`：

```json
{
  "servers": {
    "charles": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Xiao7XS/Charles-Mcp", "charles5-mcp"],
      "env": { "CHARLES_USER": "admin", "CHARLES_PASS": "123456" }
    }
  }
}
```

### Gemini CLI

```bash
gemini mcp add -e CHARLES_USER=admin -e CHARLES_PASS=123456 \
  charles uvx --from git+https://github.com/Xiao7XS/Charles-Mcp charles5-mcp
```

也可以在 `~/.gemini/settings.json` 的 `mcpServers` 中加入与 Cursor 相同的配置。

### Windsurf、Cline、Cherry Studio 等其他客户端

只要支持 stdio 类型的 MCP server，按下面填写即可：

- 命令：`uvx`
- 参数：`--from`、`git+https://github.com/Xiao7XS/Charles-Mcp`、`charles5-mcp`（三个参数）
- 环境变量：`CHARLES_USER`、`CHARLES_PASS`

例如 Windsurf 的配置文件是 `~/.codeium/windsurf/mcp_config.json`，格式与 Cursor 相同。

### 给 AI 的使用说明

仓库里的 [`AGENTS.md`](AGENTS.md) 写明了 AI 调用这些工具时应遵守的规则：

- 不同类型的 id 不能混用。
- 怎样节省 token。
- 回放请求时的注意事项。

使用方式：

- **Codex**：会自动读取 `AGENTS.md`。
- **Claude Code**：在 `CLAUDE.md` 里写一行 `@AGENTS.md` 引用它。
- **Cursor**：把 `AGENTS.md` 的内容放进 Rules。

---

## 使用示例

配置好后，直接用自然语言对 AI 说就可以：

- 「开始抓包，我去 app 里登录一下，然后告诉我登录接口的 URL、请求头、提交的数据和返回的数据」
- 「把刚才所有发往 api.example.com 的 POST 请求完整导出成文件」
- 「刚才上传头像的请求，把上传的图片存下来给我看」
- 「分析一下 /api/order 的 sign 参数是怎么来的，服务端有没有校验 timestamp」
- 「打开 ~/Desktop/xxx.chlz，按域名统计一下请求量，找出所有报错的请求」
- 「把网络限速成 3G，测完再恢复」

AI 调用工具的典型顺序如下：

| 场景 | 工具调用顺序 |
| --- | --- |
| 看 app 现在在请求什么 | `start_live_capture` → 在 app 里操作 → `group_capture_analysis` → `query_live_capture_entries` → `get_traffic_entries` |
| 取上传的图片或下载的文件 | `extract_entry_bodies` |
| 验证签名参数 | `reverse_start_live_analysis` → 在 app 里把目标操作触发 2～3 次 → `reverse_analyze_live_signature_flow` → `reverse_run_mutation_plan` |
| 分析已保存的录包 | `reverse_import_session(path=...)` → `reverse_analyze_capture` |

`reverse_run_mutation_plan` 会给每个字段一个结论：

- `enforced`：服务端会校验这个字段。
- `not_enforced`：修改后服务端照常返回。
- `affects_response`：修改后响应内容有变化，但请求没有被拒绝。

---

## 工具一览

共 41 个工具。

**状态与控制**

| 工具 | 说明 |
| --- | --- |
| `charles_status` | 连接状态、版本、录制状态，以及下一步建议 |
| `get_charles_controls` | 弱网状态和真实的预设列表，以及每个工具的开关状态 |
| `throttling` | 开启或关闭弱网，预设名会按 Charles 实际列表校验 |
| `set_charles_tool` | 开关 Map Remote、Rewrite、Breakpoints、Block List 等工具 |
| `export_charles_session` | 导出当前 session，格式可选 chlsj、chlz、xml、har、csv、trace |
| `convert_session_file` | 调用 `charles convert` 转换格式，可按 host、MIME、请求方法、大小过滤 |
| `reset_environment` | 恢复备份的 Charles 配置，不删除录包 |

**实时抓包**

`start_live_capture`、`read_live_capture`（读取并推进游标）、`peek_live_capture`（只读，不推进游标）、`query_live_capture_entries`、`stop_live_capture`

**历史录包**

`list_recordings`、`get_recording_snapshot`、`query_recorded_traffic`、`analyze_recorded_traffic`

**读包与分析**

| 工具 | 说明 |
| --- | --- |
| `get_traffic_entries` | 批量取完整记录：URL、query 参数、请求头、响应头、解码后的请求体和响应体。可以指定 `entry_ids`，也可以按条件筛选全部；用 `offset` 分页；`save_to_file=true` 导出成 .jsonl 文件 |
| `extract_entry_bodies` | 把请求体和响应体解码后存成文件：图片、下载的文件、multipart 上传的每个部分、WebSocket 消息 |
| `get_traffic_entry_detail` | 单个包的详情 |
| `group_capture_analysis` / `get_capture_analysis_stats` | 按 host、路径、状态码等分组统计 |

**逆向分析**

| 类别 | 工具 |
| --- | --- |
| 导入与管理 | `reverse_import_session`、`reverse_list_captures`、`reverse_delete_capture`、`reverse_query_entries`、`reverse_get_entry_detail` |
| 解码与回放 | `reverse_decode_entry_body`、`reverse_replay_entry` |
| 签名与变异测试 | `reverse_discover_signature_candidates`、`reverse_build_mutation_plan`、`reverse_run_mutation_plan`、`reverse_list_findings` |
| 实时逆向 | `reverse_charles_recording_status`、`reverse_start_live_analysis`、`reverse_peek_live_entries`、`reverse_read_live_entries`、`reverse_stop_live_analysis` |
| 一键工作流 | `reverse_analyze_live_login_flow`、`reverse_analyze_live_api_flow`、`reverse_analyze_live_signature_flow`、`reverse_analyze_capture` |

---

## 相比原项目：重构了什么

重写了全部代码，没有沿用原项目的模块结构。

| 方面 | 原项目 | 本项目 |
| --- | --- | --- |
| 数据模型 | 实时抓包、历史录包、逆向分析各写一套解析器，字段和行为不一致 | 统一的 `Transaction` / `Message` 模型，各种格式都先解析成同一个模型，三条线共用 |
| 分层 | 工具层直接拼 HTTP 请求、解析数据 | 分成 `charles/`（与 Charles 通信）、`session/`（解析与解码）、`traffic/`（实时、历史、查询、视图）、`reverse/`（存储、签名、回放、工作流）、`server.py`（只负责注册工具） |
| MCP SDK | 只支持 1.x，SDK 2.x 发布后新装即失败 | `compat.py` 同时适配 1.x 的 `FastMCP` 和 2.x 的 `MCPServer` |
| 错误处理 | 异常信息在 SDK 中被吞掉，AI 只能看到 "Error executing tool" | 统一的错误类型，每个错误都附带可操作的 `hint` |
| 参数校验 | 自由字符串 | 用 `Literal` 类型约束，MCP 客户端能看到全部可选值 |
| 逆向存储 | 每次轮询写一份完整快照 | SQLite 增量写入同一个 capture，流式扫描，内存占用不随抓包量增长 |
| 测试 | 少量 mock 测试 | 180 个单元测试，加上用真实 Charles 5.2.2 导出数据做的格式测试，以及可选的真实 Charles 端到端测试。CI 覆盖 Python 3.10、3.12、3.13 与 SDK 1.x、2.x 的组合 |
| 代码质量 | — | 通过 ruff 与 mypy 检查，带 `py.typed` 类型标记 |

## 相比原项目：优化了什么

- **读包**
  - 新增 `get_traffic_entries`，一次取多个包的完整内容，支持分页和导出 .jsonl。
  - 新增 `extract_entry_bodies`，把上传和下载的文件解码后存到本地。
- **请求体和响应体解析**
  - 解压支持 zstd、br、deflate、多层编码。
  - multipart 按字节解析，图片等二进制部分也能完整保留。
  - 根据文件头识别图片、PDF、zip、音视频的真实类型。
  - 支持 JSONP。
  - 没有声明编码的文本，依次按 UTF-8 和 GB18030 解码。
  - 解码 WebSocket 消息。
  - 没有 `.proto` 定义也能解码 protobuf 和 gRPC。
- **控制 Response 大小**：所有返回列表的工具都限制在约 4 万字符以内，超出部分可通过游标或 offset 继续读取，不会撑爆 AI 的上下文。
- **实时抓包**
  - 增量追踪。进行中的请求完成后原地更新，并在 `updated_entry_ids` 中告诉 AI 哪些请求有了新结果。
  - 能区分「Charles 清空了 session」和「Charles 丢弃了旧条目」这两种情况。
- **签名识别**
  - 原项目用子串匹配，误判较多；现在按完整词元匹配。
  - 结合取值形态（时间戳、哈希、nonce）和取值随请求时间变化的相关性来判断。
  - 扫描整个 capture，原项目只扫前 500 到 2000 条。
- **回放与变异测试**
  - 先回放原请求作为对照组，再逐个字段做变异。
  - 能识别业务错误码，例如 HTTP 200 但响应里是 `code: 40001`。
  - 回放时，原始 query 和表单的编码逐字节保留，不会因为重新编码而破坏签名。
  - 回放请求会带上 `X-Charles5-MCP-Replay` 标记，不会被误当成 app 自己的流量。
- **新增 Charles 控制能力**
  - 读取弱网预设和工具开关状态。
  - 调用 `charles convert` 转换和过滤录包。
  - 支持 csv 和 trace 导出。
  - 借助 Charles CLI 读取 `.chls`、`.trace`、`.saz`、`.pcap`。
- **写出的文件能被 Charles 直接导入**，已用真实 Charles 验证。

## 修复的 Bug

下面每一条都在真实的 Charles 5.2.2 上复现并验证过修复。

**数据丢失或解析错误**

- 实时抓包里的二进制请求体和响应体全部丢失：Charles 把它们存成 `{"encoding":"base64","encoded":…}`，原项目读错了字段。受影响的包括 protobuf、图片、zstd 压缩内容和 octet-stream。
- **中文乱码**：如果包没有声明 charset，Charles 在 JSON 和 XML 导出中会把正文当作 ISO-8859-1 写出，`你好` 就变成了 `ä½ å¥½`。现在会先还原出原始字节，再正确解码。
- 带 BOM 的 JSON 解析失败。
- 带图片的 multipart 上传整个被当成二进制；字段名写在 `filename` 后面时，取到的名字是错的；值里恰好包含 boundary 字符串时，会被错误拆分。
- Content-Type 是 octet-stream 的图片识别不出来。反过来，以 `BM` 开头的表单（比如 `BMI=22`）会被误判成 BMP 图片。
- HAR 文件的问题：
  - GBK 表单会乱码。
  - multipart 上传丢失文件名和文件内容。
  - Boundary 参数大写（`Boundary=`）时识别不了。
- `.chlz` 中带 `-enc` 后缀的文件，表示仍是压缩状态，原项目没有识别。另外没有按 meta 文件里的 `bodyFile` 找对应的正文文件。
- XML 格式缺少 `contentEncoding`、耗时、TLS 信息和声明的大小。
- 103 Early Hints 等 1xx 中间响应，只有在特定导出顺序下才能关联回最终请求。
- 经过 Map Remote 的请求，URL 和回放用的是 `actualPort`，应当用请求本来的 `port`。

**状态判断错误**

- Web Interface 被禁用时，Charles 仍返回 HTTP 200 加一个说明页，原项目把这当成「已连接」。
- 停止录制后，导出接口返回 HTML 菜单页。原项目要么报解析错误，要么把这个 HTML 当成录包保存。
- 失败请求的状态 `EXCEPTION` 被当成「进行中」。
- 进行中的请求完成后被重复计数。
- 弱网预设名不做校验：Charles 收到任何名字都返回成功，而原项目还列出了一个不存在的 5G 预设。

**稳定性与安全**

- **session 指数膨胀**：Charles 会把 Web Interface 的请求本身录进 session，导致每次轮询后 session 成倍增长，实测会导致内存耗尽。现在能自动检测到这种情况，并提示排除 `control.charles`。
- 如果包声明了 `charset=base64`、`charset=zlib` 这类不是文本编码的 charset，会导致整个 session 加载失败。
- **解压炸弹**：一个很小的压缩包可能解压出几个 GB 的数据。现在单个正文解压后最多 64 MB，`.chlz` 中单个文件最多 512 MB。
- 修改表单参数回放时，GBK 编码的表单会被重新编码成 UTF-8，导致没改的参数也变了；表单参数修改还会把 multipart 或 JSON 请求体弄坏。现在没改的参数逐字节保持不变，对非表单请求体会直接报错。
- 实时抓包达到条数上限、截掉旧条目之后，下一次轮询会把还在 Charles 里的旧条目当成新的重新读进来。
- 导出文件不会再覆盖已有文件。
- 用 `reset_environment` 重置环境时，不再删除所有录包。

完整的版本记录见 [CHANGELOG.md](CHANGELOG.md)。

---

## Charles 5.2.2 的实测行为

以下都是实测结果，MCP 已经按这些行为做了处理：

- **只有在录制时才能导出。** 停止录制后，导出接口返回的是 HTML 菜单页。之后重新开始录制，Charles 会新建一个空 session。所以要分析以前的 session，需要先在 Charles 里保存成文件，再导入。
- **二进制正文以 base64 存放，而且 Charles 不会解压 zstd。** 二进制内容存成 `{"encoding":"base64","encoded":"…"}`；zstd 压缩的内容原样保存，由本工具负责解压。
- **没有声明 charset 的正文，会按 ISO-8859-1 写出。** 这一点影响 JSON 和 XML 导出；HAR 和 chlz 导出中的字节是正确的。
- **1xx 中间响应单独记录。** 103 Early Hints 会被记录成一条独立的请求；在 `.chlz` 中，它排在最终响应之后。
- **WebSocket 存成原始帧。** 整个 WebSocket 会话记录为一条状态码 101 的请求，两个方向的原始帧分别存在请求体和响应体中。
- **弱网预设名不做校验，而且没有 5G 预设。**

---

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CHARLES_USER` / `CHARLES_PASS` | `admin` / `123456` | Web Interface 的账号和密码 |
| `CHARLES_PROXY_HOST` / `CHARLES_PROXY_PORT` | `127.0.0.1` / `8888` | Charles 代理的监听地址和端口 |
| `CHARLES_REQUEST_TIMEOUT` | `15` | 调用控制接口的超时时间，单位为秒 |
| `CHARLES_STATE_DIR` | macOS 下为 `~/Library/Application Support/charles5-mcp` | 录包、逆向数据库、导出文件的存放位置 |
| `CHARLES_RECORDINGS_DIR` | `<state>/recordings` | 录包目录。旧变量名 `CHARLES_PACKAGE_DIR` 仍可使用 |
| `CHARLES_EXTRA_RECORDING_DIRS` | 无 | 额外扫描的录包目录。多个目录在 macOS 和 Linux 上用 `:` 分隔，在 Windows 上用 `;` 分隔 |
| `CHARLES_CLI_PATH` | 自动探测 | Charles 可执行文件的路径，用于格式转换和读取版本号 |
| `CHARLES_CONFIG_PATH` | 自动探测 | Charles 配置文件的路径，用于备份和恢复 |
| `CHARLES_MANAGE_LIFECYCLE` | `false` | 设为 `true` 后，首次启动时会备份 Charles 配置，之后可以用 `reset_environment` 恢复 |
| `CHARLES_REPLAY_TIMEOUT` | `20` | 回放请求的超时时间，单位为秒 |
| `CHARLES_LIVE_MAX_ENTRIES` | `20000` | 每个实时 capture 最多保留的条目数 |
| `CHARLES_MAX_DETAIL_BODY_CHARS` | `16384` | 单个正文在返回结果中显示的最大字符数 |
| `CHARLES_LOG_LEVEL` | `WARNING` | 日志级别 |

---

## 局限与注意事项

- **以下情况无法通过 MCP 读取：**
  - **没有开启 SSL Proxying 的 HTTPS**：只能看到加密的 CONNECT 隧道。
  - **启用了 SSL Pinning（证书绑定）的 app**：请求会直接失败。
  - **HTTP/3（QUIC）流量**：不经过 Charles，根本抓不到。
  - **app 自己对正文做了加密**：只能显示密文。
- **正文大小**：在返回给 AI 的结果里，大正文会被截断。需要完整内容时，用 `save_to_file=true` 或 `extract_entry_bodies` 存成文件。
- **回放会真实发送请求**：`reverse_replay_entry`、`reverse_run_mutation_plan`，以及带 `run_replay=true` 参数的工作流，都会向目标服务器发出真实请求。**只对你有权测试的系统使用。**
- **默认不会清空 Charles 的 session**：只有显式传入 `reset_session=true` 时才会清空。
- **通过 Charles 回放 HTTPS**：如果系统没有信任 Charles 根证书，需要传 `verify_tls=false`。

---

## 开发

```bash
git clone https://github.com/Xiao7XS/Charles-Mcp.git && cd Charles-Mcp
uv venv && uv pip install -e '.[dev]'
pytest                        # 单元测试，以及基于真实 Charles 导出数据的测试
ruff check . && ruff format --check . && mypy charles5_mcp
```

连接真实 Charles 的端到端测试，要求 Charles 已开启 Web Interface、排除了 `control.charles`，并处于录制状态。测试只访问本地起的测试服务器，不会访问外网：

```bash
CHARLES5_MCP_LIVE=1 CHARLES_PROXY_PORT=8888 pytest tests/live
```

欢迎提 Issue 和 PR。如果遇到读不出来或乱码的包，在 Charles 里把它导出成 `.chlz` 附在 Issue 里，最方便定位问题。

## 许可证

[MIT](LICENSE)。部分设计来自 [heizaheiza/Charles-mcp](https://github.com/heizaheiza/Charles-mcp)（MIT，Copyright (c) heizaheiza）。
