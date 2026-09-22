# 统一工具执行证据

> 开发版说明（2026-09-22）：本文记录本机开发工作树的实现与验证结果。
> 本次博客发布不包含尚未提交的工具后端及平台代码；下方复现命令需要对应开发版本，
> 不表示当前公开 `main` 或已发布二进制已经具备全部能力。

录制详情 → **工具执行**（`?view=tools`）。这是工具执行的统一观测层，
原生日志适配不替代 Agent 的工具运行器，也不是完整 OS 审计。
另有显式启用的 Linux 命令包装器，用于新命令的进程与文件采样；不会重放旧录制脚本。
**Pi 0.86.1 的实际 `bash` 工具后端现已接入**，见下方启用方式；其他工具不能因此视为已覆盖。

## 三层证据，不混算步数

| 层 | 来源 | 能证明什么 |
| --- | --- | --- |
| 模型请求 / 协议返回 | 代理记录的模型请求、响应 | 模型提出了哪些操作，哪些返回值进入了后续模型输入 |
| 原生工具执行 | Hermes pre/post Hook；Codex rollout；Pi JSON；Hermes session export | Agent 报告的参数、返回值、错误、可用退出码与耗时 |
| 内部命令 / 文件变更 | Codex CLI item 事件 | Agent 报告的命令及退出码、文件变更；不冒充模型 tool call |
| 包装器进程 / 文件采样 | `tools/tool_exec.py` | `waitid`/`wait` 取得的进程结果、管道原始字节、选定文件前后哈希与 diff；仍为本机操作者提交的报告，不是远程证明 |

只有**唯一显式 call ID + 工具名 + 兼容会话**才关联模型与原生工具记录。
多个来源可组成同一条执行记录，保留各自证据；重用或歧义 ID 不猜测匹配。
不同原生来源报告相反结果时保留冲突。不使用时间接近、相似命令来补造父子关系。
没有父调用 ID 的 Codex 内部命令独立显示，不能和外层 `exec` 相加计算工具步数。

Pi 0.86.1 的 Responses 适配器以 `call_id|item_id` 组成原生工具 ID，发回协议时拆开。
查询仅对 `native:pi-json`，或带 `integration=pi-bash-0.86.1` 的 `native:exec-observer`，
以及明确的 `call_…|fc_…` 格式和 Responses 模型调用做此映射，
保留原生完整 ID 并显示关联规则。不是对任意 Agent 的 ID 做前缀匹配。

缺失不是零。协议中出现返回值、Hook 调度返回成功，都不等于脚本执行成功。
原生退出码 0 保留为 0；没有退出码则显示未知。最终 benchmark reward 仍单独保留。
消息时间只是原生观测时间，不作为精确进程耗时。

## 已接入的内容

- 工具名、调用 ID、原生会话 ID、参数、命令、可用 cwd。
- 原生返回值、明确提供的 stdout/stderr、退出码、错误状态、Hook 执行耗时。
- Codex `exec` 提交代码哈希；Pi `write` / `write_file` 请求内容哈希。
  **提交文本哈希不等于磁盘文件快照，也不证明实际运行了完全相同的文件。**
- 源文件 SHA-256、原生位置、录制事件 seq、模型调用链接、证据缺口。
  Hermes export 的“位置”是消息序号，其余附件是原生日志行号。

文本字段最多展示 32 KiB，标记截断，哈希与字节数对应截断前的提取值。
源 Agent 自身的输出截断可能更早发生，因此即使此处未截断，也不保证输出完整。
Codex `exec` 返回内容可能是嵌套 JSON/文本，不凭格式猜测独立 stdout、stderr 或子进程退出码。

## 复现 / 导入

Hermes Hook 随录制自动参与查询。Codex、Pi 等原生日志作为**单独补充附件**导入，
不重写原录制，不加入原始哈希链，不提升 transport qualification。
只在原生文件已结束写入后导入；同一录制的每种格式不可覆盖。

先 dry-run，只打印数量与哈希，不输出工具正文：

```bash
python3 tools/tool_execution_evidence.py \
  --source /private/harbor/task__trial/agent/pi.txt \
  --format pi-json \
  --recording-id 'run-EXAMPLE#0000'
```

确认源日志和目标录制属于同一次运行后，加 `--attach`，需要时加
`--token-file /private/platform-operator.token`。默认只连接本机 `127.0.0.1:18080`，
禁止跳转或通过环境代理转发。支持 `codex-rollout`、`codex-cli`、`pi-json`、`hermes-session`、`exec-observer`。

Harbor 流程可显式加 `--attach-tool-evidence`：严格录制审计及平台导入成功后，
自动提取该 trial 的原生日志，再做平台资格确认。开关、提取器及包装器源码哈希纳入流程配置。
若 `agent/tool-exec/` 存在，先验证其中已完成报告的原始输出文件，再一并附加；这不代表自动改写了 Agent 的工具实现。
多份 Codex rollout 不擅自选择，需要显式指定源文件。附件阶段失败不会重启 Agent；
恢复须使用相同命令和工作目录。历史审计不通过的录制可独立添加原生附件，但仍不通过原审计。

API：

- `PUT /v1/recordings/{id}/tool-evidence`：operator 权限；相同文档幂等，不同内容返回 409。
- `GET /v1/recordings/{id}/tool-executions?limit=20&offset=0`：viewer 权限；跨该运行可用分段。
  后续页传 `snapshot`，证据变化返回 409，需回第一页。
- 附件限 8 MiB、每运行最多 8 份 / 32 MiB、每份最多 10,000 条；原文件提取上限 64 MiB。
  查询有记录数、正文大小、关联工作量和超时限制，超限明确失败，不静默返回“全部”。
- 项目隔离、审计日志、删除/过期读写隔离；原始证据 TTL 与整运行删除均清理附件。
  TTL 不替用户删除本机保留的原生日志。

工具参数与输出可能包含源码、凭证及任务数据。附件默认不自动上传；仍按原始证据控制访问，
**本版本没有新增自动敏感信息脱敏器**。不要把原生日志或附件发布到公开 blog。

## 新命令的进程 / 文件采样（显式启用）

```bash
python3 tools/tool_exec.py \
  --evidence-dir /private/trial/tool-exec \
  --cwd /path/to/task/workspace \
  --script-file solve.py \
  --watch-file result.json \
  --timeout 300 \
  -- python3 solve.py
```

先创建证据目录的父目录；证据目录要求当前用户所有、0700，不能是符号链接。
`--script-file` 与 `--watch-file` 都是 cwd 内的显式相对文件路径，不递归扫描；脚本标记不决定执行的 argv。
`--` 后才是真实执行命令。包装器不隐式使用 shell；需要 shell 时显式传 `/bin/bash -lc '…'`。

这不是透明的通用替代品：Linux 专用、非交互、stdin 为 `/dev/null`、无 PTY。
stdout/stderr 分别写入本机 `.bin` 文件，包装器向调用者返回报告路径 JSON，**不原样转发目标输出**。
调用方须读取报告/输出，或通过 Python `observe()` 接口集成。
超时 CLI 返回 124；取消/信号返回约定的 `128+signal`；启动或观测异常返回 125。
这些 CLI 约定与报告中的真实子进程退出码、终止信号分开保留。

如果这一次包装确实对应完整的某个模型工具调用，可传原有的 `--call-id`、`--session-id`、`--tool-name`。
没有真实 ID 时留空：平台只显示独立命令，不伪造关联。不要把外层 `exec` 的 ID 复制到多个内部子命令上。
默认不会替换任何 Agent 工具后端；Pi 可通过下方扩展显式接入。不能给旧录制补回没采集过的字段。

每次执行生成独立 `exec-UUID/`：

- `intent.json`：持久化的执行意图与前置文件哈希；不代表启动或完成。
- `stdout.bin`、`stderr.bin`：原始字节，分别保留；默认每流 4 MiB，可通过 `--stream-limit` 调整，最大 16 MiB。
- `report.json`：终止原因、PID、包装器 PID、真实退出码或信号、单调时钟耗时、管道 EOF、原始字节哈希、截断/存储错误，以及选定文件变化。

输出超过保留上限仍持续读取并计数、计算“已读字节”哈希，避免额度触发管道堵塞。
未读到 EOF 时，总输出长度未知；已读哈希不是完整输出哈希。平台只存最多 32 KiB 原始前缀转换出的文本预览，
二进制/NUL 替换有显式标记，文本预览哈希不冒充原始字节哈希。
超时/取消先发信号，必要时升级 SIGKILL；保留 leader 为未回收状态，避免信号发到复用的 PID/进程组。
主进程退出后仍未关闭的后代输出管道有独立 drain 截止时间，不无限等待，不谎报 EOF。
正常退出不会追杀自行后台化的进程；脱离会话/进程组的后代不在完整性声明内。SIGKILL 不等于 OOM。

文件最多选择 64 个，每个前/后样本最大 1 MiB；只读普通文件，不跟随路径中任何符号链接，不读设备/FIFO。
记录文件内容哈希、大小及权限；文本 diff 输入每侧最多 32 KiB / 2,000 行。
记录新增、删除、内容/权限修改；不可读、过大、采样期间变化等标为未知。
**不是全工作区快照，不完整跟踪 inode/mtime 等元数据，不保留完整文件副本，也不能把并发修改归因给这条命令。**
脚本执行前文件哈希是真的文件采样，但不保证它到解释器读取时没有变化。

所有 `.bin`、报告和 diff 当前是 **0600 明文**，目录 0700；不在 iorec 原始加密/认证链内。
不要用于未批准的秘密文件；不默认采集环境变量。初始证据无法创建时不启动命令，
运行中不可恢复的观测异常可能终止被包裹命令；这是需要单独评估开销与行为影响的诊断模式，不是零干扰旁路。

所有命令完成后，验证并附加整个目录：

```bash
python3 tools/tool_execution_evidence.py \
  --source /private/trial/tool-exec \
  --format exec-observer \
  --recording-id 'run-EXAMPLE#0000' \
  --attach --token-file /private/platform-operator.token
```

不加 `--attach` 即本机 dry-run。支持单个 `report.json`，附加时验证对应原始流文件。
目录批量导入上限 1,000 次执行、报告约 8 MiB、被校验原始流总计 512 MiB；不静默跳过未完成的执行目录。
在同一录制下收齐再导入，同格式不可覆盖；原始流字节保留本机，平台只保留预览/元数据/diff。
平台保留策略仅清理平台附件，不删除本机目录。本机报告/字节校验是完整性检查，不是防同用户篡改的真实性证明。

### 本次离线端到端验证

使用 `tools/demo_tool_exec.py` 在新建私有目录生成测试文件，外层由 iorec 加密录制生命周期。
没有模型调用，不是 benchmark，也不影响既有 Codex / Pi / Hermes 的结果。
录制 ID：`run-01a0c723-8c0f-760b-9ead-d8258d88f8fc#0000`。

五个案例：exit 0、exit 7、超时 SIGKILL、8,192 bytes 输出仅保留 256 bytes、SIGTERM。
平台结果：5 条进程观测、3 条选定文件变化、1 条输出截断记录，模型调用数为 0。
单元测试另外覆盖取消、二进制/NUL、越界/符号链接/FIFO、未见 EOF、原始输出及预览篡改拒绝。

## 本机回填验证（2026-09-22）

使用已完成的 TB4 `bun-sourcemap-leak` 三组日志，没有启动新模型实验：

| Agent | 模型工具请求 | 已关联原生工具 | 额外分层观测 |
| --- | ---: | ---: | --- |
| Codex | 13 | 13 | 9 条内部命令、3 条文件变更 |
| Pi | 25 | 25 | Responses 复合 ID 按适配器规则拆解 |
| Hermes | 53 | 53 | 106 条 pre/post Hook 与 session 日志合并 |

四份附件重复导入均幂等，原 coverage 与 transport proof 不变。
这组数字只证明已观测请求与现有原生日志的关联，不证明完整 OS 活动已被捕获。
验证包括 Go 全包数据库测试、query/retention race 测试、Python 提取器与流程测试、
前端生产构建，以及三组录制在 1440 / 375 px 下的分页、键盘展开与无横向溢出检查。

## 后续值得补的关键证据（尚未完整实现）

1. **扩展工具后端接入**：Pi 0.86.1 的实际 `bash` 后端已接入并完成本地 recorder-on/off 对照；
   其他 Agent、其他工具及 Harbor 容器端到端仍需逐项验证，保留原有交互/后台进程语义，不能靠扫描进程名声称全覆盖。
2. **证据存储与文件范围**：原始输出加密对象存储、平台鉴权下载、可选工作区差异清单，
   保持大文件限额、敏感路径排除、采样失败/并发变化边界。
3. **可复现环境**：Agent/工具/模型版本、镜像 digest、任务 commit、沙箱权限、资源限制、
   白名单环境变量与配置哈希。已有输入指纹覆盖部分内容，不能称为整个环境已冻结。
4. **控制流与资源**：重试、上下文压缩、取消、预算/时限终止、子 Agent 父子关系；
   CPU、峰值内存、磁盘/OOM。与工具/模型调用共享明确因果 ID，不根据时间推断。
5. **外部副作用与采集健康**：MCP/HTTP 请求结果、目标与状态；队列丢弃、输出截断、时钟来源。
   不默认录全量环境变量、密钥、逐行追踪或无限量文件内容。

下一步优先验证 Harbor 容器端到端、补充其他工具后端与原始输出加密，不默认放大采集范围，再扩大资源与远程工具观测。

## Pi 实际 bash 后端接入（2026-09-22）

产品目标是跨 Agent 的统一录制与证据平台。这里的任务只提供真实工作负载，
不评判 Agent 或模型的能力。此实现使用 Pi 官方的
[工具覆盖与 operations 接口](https://pi.dev/docs/latest/extensions)，没有改写已安装的 Pi 文件，
没有全局 monkey patch，也不会在采集失败时偷偷重跑未录制的命令。

调用链：模型请求 → Pi 原始工具 ID → `pi-tool-observer.mjs` → `pi_exec_bridge.py` →
共享 `tool_exec.observe()` → 进程 / 管道 / 选定文件 → 原生与执行附件 → 平台同一工具行。

### 接入边界

- 目前只资格验证 Linux、Pi **0.86.1**、默认本地 Bash 配置。版本不符在配置阶段拒绝。
  自定义 shell / command prefix、其他路由扩展、交互式 `!` 命令、PTY、远程工具均未资格验证；不要叠加后声明透明兼容。
- 复用 Pi 的工具 schema、提示元信息、结果格式、输出累积与截断实现；扩展只替换 BashOperations。
  为每次调用单独保存原始 `call_id` 和会话 ID，支持并发调用，不使用共享“当前工具 ID”。
- stdout/stderr 独立保存原始字节，同时流式返回给 Pi。录制保留额度耗尽后继续读取、返回输出；
  **录制截断不变成 Agent 输出截断**。两路管道合并后的跨流先后不承诺完全一致。
- Bash stdin 仍为 `/dev/null`，没有 PTY。未传工具 timeout 时不偷偷加默认 300 秒：
  报告 `timeout_ms=0` 明确表示未设工具级时限，外层任务时限仍可生效。
  显式 timeout 当前只接受 `(0, 86400]` 秒，超过范围不执行。
- Pi 取消/超时使用立即 SIGKILL 的进程组终止策略；报告区分“取消/超时原因”与实际终止信号。
  主进程结束后的管道采用 100 ms 空闲等待，活跃输出会延长等待；未见 EOF 必须标为缺口。
  脱离进程组的后代、Agent 被 SIGKILL 等硬中断仍不保证最终报告，残留 intent 不能当完成。
- 文件仅按配置中的显式相对路径采样，不从任意 shell 字符串猜测执行文件或递归扫描整个工作区。
  `read`、`edit`、`write`、MCP、其他 Agent 的进程后端没有在本次接入。
- 原始工具输出/报告仍是私有目录中的 **0600 明文**，不是原始加密哈希链的一部分。
  模型流量原始录制仍使用 iorec 加密；这两类存储边界不要混淆。

### 单独启用扩展

预先创建属于 Agent 用户的 0700 证据目录，并准备该用户所有的 0600 配置：

```json
{
  "schema_version": 1,
  "pi_package": "/opt/iorec-agent/pi-0.86.1/node_modules/@earendil-works/pi-coding-agent",
  "python": "/usr/bin/python3",
  "bridge": "/path/to/inferenceIO/tools/pi_exec_bridge.py",
  "evidence_dir": "/private/new-trial/tool-exec",
  "watch": ["totals.json"],
  "scripts": ["summarize.py"],
  "stream_limit": 4194304
}
```

在已有 iorec 包裹的 Pi 启动命令上增加：

```bash
IOREC_PI_TOOL_CONFIG=/private/new-trial/observer.json \
  pi --no-extensions -e /path/to/inferenceIO/examples/pi-tool-observer.mjs ...
```

显式 `-e` 扩展仍可与 `--no-extensions` 共用；后者阻止自动发现其他扩展。
应使用固定版本的 Pi launcher，配置中的 SDK 包必须与运行版本一致。
此命令只说明工具接入，不自动启动 iorec 或上传附件。任务结束后沿用本页的 native / exec-observer 附件导入。

### Harbor 工作流开关

在既有、**全新工作目录**的 Pi audit 命令上附加：

```text
--observe-pi-bash --attach-tool-evidence
--tool-script-file solve.py --tool-watch-file result.json
```

路径选项可重复；不支持通配符展开，合计最多 64 项。不传路径时仍采集进程/输出，但不声称有文件快照。
开关只允许 fresh Pi、recording-mode=on，不能偷偷加入旧 M3 声明或恢复中的已冻结实验。
扩展、桥接器、共享包装器、提取器均进入上传输入哈希；文件选择也进入 fresh_inputs。
容器安装阶段校验配置及工具注册，不发模型请求；默认其他 Pi 工具保持原样。
导入阶段额外检查原生 `bash` ID 与进程记录严格一一对应，缺失、重复或错误来源会失败，
不会重启 Agent。这个检查只覆盖已记录的 Bash 请求，不等同于独立 OS 全覆盖证明。

### 一次真实 Agent → 平台验证

可复现小任务脚本：`tools/demo_pi_tool_recording.py`。默认只准备文件；`--execute`
才启动一次真实模型任务，必须使用新的私有 work-dir。没有自动重试，外层限时 180 秒，
Pi 的 agent/provider 自动重试和自动压缩关闭；时限不是金额硬上限。
只启用观察后的 Bash 工具，避免扩展加载失败时回落到未录制的内建 Bash。

```bash
python3 tools/demo_pi_tool_recording.py \
  --work-dir /private/new-pi-recording --key-file /private/iorec/master.key --execute

# 单独导入，不会重新调用模型或重放命令
python3 tools/demo_pi_tool_recording.py \
  --work-dir /private/new-pi-recording --key-file /private/iorec/master.key \
  --import-recording --token-file /private/platform-operator.token
```

节点/包路径可通过 `--node`、`--pi-package` 指定。密钥只从 `OPENAI_API_KEY` 环境读取，
不写入 models.json 或命令参数；平台导入后删除本次临时明文 tar，保留原始加密录制和私有工具证据。
模型配置价格为零表示不在此 smoke 脚本估价，**不代表真实调用免费**。

本机实际结果：`run-01a0c7bd-cf59-7377-8706-042a21f48323#0000`：

- Pi + 真实模型生成 CSV 汇总脚本及测试，执行后得到预期的 `alpha=4.60`、`beta=2.50`。
- 4 次模型调用；3 个模型工具请求、3 条 Pi 原生工具结果、3 条进程观测在平台合并为 **3 行**。
- 3 处选定文件变化；所有 3 次进程退出码为 0，stdout/stderr 6 路均见 EOF、没有截断/存储错误。
- 未匹配工具、关联冲突和规范化待处理均为 0；模型调用详情可从每个工具行直接跳转。
- 这是本地显式代理模式的真实录制 smoke，**不是 Harbor / Terminal-Bench 结果，也没有新取得 pcap/TLS 独立完整性资格**。
  本次没有新增付费 Harbor 长任务；Harbor 开关通过了控制器/配置测试，真实 Harbor 容器端到端仍待单独验证。

测试包括 11 项 Pi 原生/录制执行对照、Python 包装器与提取器、Harbor 配置/流程边界、
Go 数据库及 race 测试、前端构建、1440/375/812 px 页面与键盘/模型详情链接。

接下来的产品工作：扩展其他工具/Agent 后端、工具原始输出加密及鉴权取回、显式采集范围与健康状态，
再扩大工作负载覆盖。Agent 能力排名不作为录制系统的验收目标。
