# Agent Inference Flight Recorder：开发 Feature 路线图

> 版本：Draft v1  
> 日期：2026-09-15  
> 依据：[Agent 会话 / 任务完整 Inference I/O 获取方案调研](./agent-inference-io-capture-research.md)

## 1. 产品目标

在**不修改 Agent 源码**的前提下，围绕一个 Agent 命令或任务，尽可能完整地录制：

- Agent session、turn、tool、subagent、compaction 等生命周期事件。
- 每次逻辑 inference 的输入、输出及模型参数。
- 实际 HTTP、SSE、WebSocket 请求，包含重试、错误、取消和重连。
- 进程树、容器、网络连接与模型调用之间的归属关系。
- 当前采集范围、未识别项、丢失事件和不可观测边界。

最终交付物不是一份“看起来完整”的日志，而是：

1. 可持续追加、崩溃后可恢复的原始记录。
2. 可查询和回放的规范化事件。
3. 一份能够说明完整程度的 `coverage manifest`。

## 2. 设计约束

- 不要求 Agent SDK、框架或业务源码配合。
- 可以控制启动命令、环境变量；增强模式允许容器 root 或宿主机 eBPF 权限。
- 首版只录制，不修改模型 input/output。
- 采集端独立可用，不依赖平台在线；平台作为并行轨道同步开发，两端以统一事件协议为契约（见 [platform/](./platform/README.md)），契约冻结点是 v0.1 的事件 envelope。
- 不承诺获取闭源模型厂商内部 system prompt、隐藏推理或服务端 tokenization。
- 不承诺一个采集器自动覆盖所有 TLS/runtime；覆盖能力必须可检测、可声明。

## 3. 版本路线总览

以下排期以 **2 名核心工程师、双周迭代**为基准；单人推进可近似按 1.7～2 倍时间估算。平台轨道另需 1～2 名工程师，与采集端并行，见 3.2。

### 3.1 采集端轨道

M3 与 M4 的顺序为：先做完整性验证器（v0.4），再做 eBPF 无源码采集（v0.5）。四个目标 Agent 都支持 endpoint 改写，eBPF 在 v1.0 中的角色是独立校验与闭源兜底而非主路径；验证器是产品核心且依赖少，先落地可以在 eBPF 适配延期时仍交付可审计的 coverage manifest。eBPF 在 v1.0 支持矩阵中标 `experimental`。

| 里程碑 | 建议周期 | 版本目标 | 关键交付 | Release Gate |
|---|---:|---|---|---|
| M0 | 第 1～2 周 | `v0.1 Recorder Core` | 启动包装器、事件模型、本地流式落盘、HTTP/1.1 + SSE 代理 | 单 Agent 任务可完整落盘；取消/崩溃不丢已到达事件 |
| M1 | 第 3～4 周 | `v0.2 Agent Context` | Hermes、Gemini、Claude、Codex 薄适配器；task/turn/tool/subagent 关联 | 四类 Agent 的模型流量能以带 confidence 的方式归属到任务节点；并发 subagent 用例必须标出低置信而非误归属 |
| M2 | 第 5～7 周 | `v0.3 Transport Fidelity` | HTTP/2、WebSocket、重试、TLS key log + pcap | 每次物理 attempt 可辨识；双录可对账 |
| M3 | 第 8～9 周 | `v0.4 Completeness Verifier` | TLS surface 识别、丢失检测、旁路检测、egress 分类、状态链解析、完整 coverage manifest | 未知或未采全时自动降级，不能误报 complete；仅凭 proxy + key log/pcap 双录即可对支持矩阵内的 Agent 给出 `transport-complete` 判定 |
| M4 | 第 10～13 周 | `v0.5 No-source Capture` | Probe 规划器、AgentSight/eCapture 接入、容器/cgroup 追踪、Python/Node 注入 shim、透明代理 | 闭源 CLI 在声明支持的 TLS 矩阵内可稳定录制；eBPF 来源的 drop 计数接入 M3 的 gate；矩阵外一律 `experimental` / `unknown` |
| M5 | 第 14～15 周 | `v0.9 Hardening` | 安全、性能、兼容、故障恢复、打包安装 | 24 小时压力测试；敏感凭证不进入普通日志 |
| M6 | 第 16～19 周 | `v1.0 Local Recorder` | 稳定 CLI、插件接口、支持矩阵、回放与导出 | 支持矩阵内达到可审计的 client/transport completeness |
| M7 | 第 16～19 周（与 M6 并行） | `v1.1 Connected Recorder` | 与平台 P4 联调发布：上传器、控制客户端、文件导入 | 20 个采集端 × 24 小时联调无静默丢失；平台中断期间录制不受影响 |

### 3.2 平台轨道（并行）

平台四个部署单元（`platform-api`、`pipeline-worker`、`web-console`、`capture-agent` 的上传/控制部分）与采集端并行开发。契约是 v0.1 事件 envelope 加批次层；采集端 M0 结束前 envelope 不冻结，平台不开工写接收逻辑，只做 schema 与 fake collector。详细设计见 [platform/](./platform/README.md)。

| 里程碑 | 建议周期 | 对应采集端 | 关键交付 | Release Gate |
|---|---:|---|---|---|
| P0 | 第 2～3 周 | M0 结束 | 事件 envelope + 批次格式定稿为共享 schema 文件；fake collector 生成批次 | 采集端与平台引用同一份 schema，CI 双向校验 |
| P1 | 第 4～7 周 | M1～M2 | `platform-api` 接收、幂等、`durable_seq`、对象存储、任务表；Worker decode/assemble/normalize；最小控制台列出 attempt | 断网重传、乱序、冲突用例通过；ACK 只承诺原件已保存 |
| P2 | 第 8～12 周 | M2～M3 | resolve、coverage 重算、时间线、attempt 详情、输入 diff、SSE 通知 | Hermes 与 Claude Code 并发 subagent 用例归属带正确置信；未归属数量首屏可见 |
| P3 | 第 11～15 周 | M3～M5 | 规则与 Finding 裁决、collector 注册/能力/配置/补传、审计、保留与删除传播 | 能力缺失时规则显示"不可判定"；删除传播端到端 |
| P4 | 第 16～19 周 | M6～M7 | Compose 部署、导出、文件导入、文档 | 与 M7 共用同一 gate |

两条轨道的同步点：P0 依赖 M0 的 envelope 冻结；P2 的 resolve 依赖 M1 适配器产出的显式 ID 事件；P3 的 coverage 重算依赖 M3 的 drop/unknown/egress 指标事件；M7 与 P4 同时发布。

## 4. Feature 工作流

### 4.1 Runner 与任务边界

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| RUN-001 | `iorec run -- <command>` 启动包装器 | P0 | v0.1 | 创建唯一 `run_id`，透明转发 signal、stdin/stdout、exit code |
| RUN-002 | 运行元数据快照 | P0 | v0.1 | 保存命令、cwd、环境变量白名单、Agent 版本、二进制哈希和启动时间 |
| RUN-003 | 进程树追踪 | P0 | v0.2 | 主进程、子进程、退出状态与父子关系持续更新 |
| RUN-004 | cgroup v2 任务归属 | P1 | v0.5 | 权限允许时，主进程和后代默认进入任务 cgroup |
| RUN-005 | container / namespace 发现 | P1 | v0.5 | 记录 PID namespace、network namespace、container ID 和宿主 PID |
| RUN-006 | 共享 daemon 关联 | P2 | v1.x | 识别 Agent 到共享本地 daemon 的 IPC，并把后续网络请求映射回任务 |
| RUN-007 | 常驻多会话进程切分 | P1 | v0.5 | 对 `hermes gateway` 这类一个进程服务多个会话/cron 的模式，按 Agent `session_id` / `task_id` 切分任务，`run_id` 不再等同于一个任务 |

### 4.2 Runtime 与 TLS Surface 探测

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| DISC-001 | 运行时识别 | P0 | v0.1 | 识别 Python、Node/Bun、Go、Rust、JVM、native binary |
| DISC-002 | TLS 库识别 | P0 | v0.4 | 从 `/proc/<pid>/maps`、ELF、Build ID、符号识别动态/静态 TLS 实现 |
| DISC-003 | 协议识别 | P0 | v0.3 | 识别 HTTP/1.1、HTTP/2、SSE、WebSocket；未知协议显式登记 |
| DISC-004 | Agent 类型识别 | P1 | v0.2 | 自动识别 Claude Code（区分 npm 与原生安装包）、Codex、Gemini CLI、Hermes Agent 及版本 |
| DISC-005 | Probe 规划器 | P0 | v0.5 | 根据权限、runtime、TLS 库和协议选择候选采集器 |
| DISC-006 | 未知 Surface 阻断完整声明 | P0 | v0.4 | 活跃连接无法识别或未覆盖时，任务状态为 `coverage_unknown` |
| DISC-007 | QUIC / HTTP3 识别 | P2 | v1.x | 即使无法解析，也能发现 UDP/QUIC 模型流量并报告缺口 |
| DISC-008 | Egress 分类 | P0 | v0.4 | 按域名 / SNI / 端口把外联分为 model、auth、telemetry、update、other；VER-008 只对未分类连接和未被记录的 model 类连接降级，否则 OAuth、遥测流量会让每个 run 都变成 unknown |

### 4.3 原始事件与本地存储

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| EVT-001 | 统一事件 envelope | P0 | v0.1 | 定义 schema version、run/session/turn/inference/attempt/connection ID |
| EVT-002 | append-only writer | P0 | v0.1 | 事件到达即写入；慢请求之间互不阻塞 |
| EVT-003 | monotonic sequence/timestamp | P0 | v0.1 | 保留事件顺序、单调时钟与 wall clock |
| EVT-004 | blob content-addressing | P0 | v0.1 | 大 payload/附件使用 SHA-256 blob，事件只保存引用 |
| EVT-005 | raw + normalized 双表示 | P0 | v0.1 | 原始字节不可被规范化结构覆盖；两者可关联。此项决定 v0.1 envelope 形状，不能后置，否则 v0.1/v0.2 数据必须迁移 |
| EVT-006 | WAL 与崩溃恢复 | P0 | v0.1 | 强杀进程后已确认事件可读取；尾部截断可识别 |
| EVT-007 | schema migration | P1 | v0.9 | 旧记录可读取；迁移不修改 raw evidence |
| EVT-008 | 压缩与保留策略 | P1 | v0.9 | 支持分块压缩、容量限制和按策略清理 |

建议初始目录结构：

```text
run/
  manifest.json
  events.jsonl
  blobs/sha256-...
  capture.pcapng
  tls.keys.enc
```

### 4.4 Endpoint / Proxy 采集

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| NET-001 | OpenAI-compatible reverse proxy | P0 | v0.1 | 原样转发 request/response，不破坏认证与错误语义 |
| NET-002 | Anthropic-compatible reverse proxy | P0 | v0.2 | 支持 message API 与 SSE 流式事件 |
| NET-003 | HTTP/1.1 request/response tee | P0 | v0.1 | body 边接收、边落盘、边转发；不等待完整 body |
| NET-004 | SSE 原始流采集 | P0 | v0.1 | 保存原始 event/chunk、顺序、时间、结束或中断原因 |
| NET-005 | HTTP/2 multiplexing | P0 | v0.3 | proxy 侧自 v0.1 起只 advertise HTTP/1.1，客户端到 proxy 不出现 h2；h2 按 stream ID 重组只在 key log / eBPF 离线解码路径实现，并发 stream 不串流 |
| NET-006 | WebSocket frame 采集 | P0 | v0.3 | 保存方向、opcode、连接、sequence、重连和 close reason |
| NET-007 | 物理重试识别 | P0 | v0.3 | 一个 `inference_id` 可关联多个 `attempt_id` |
| NET-008 | 透明代理模式 | P1 | v0.5 | Agent 不支持 endpoint/proxy env 时仍可捕获支持协议 |
| NET-009 | egress allowlist / 防旁路 | P0 | v0.4 | 测试模式下模型流量只能通过指定 recorder 路径。基于 network namespace 的测试用 allowlist 自 v0.1 起随 TEST-001 提供，否则 v0.1 gate 的"100 次无截断"无法证明没有旁路；v0.4 交付的是产品化版本 |
| NET-010 | HTTP/3 / QUIC capture | P2 | v1.x | 能解码或明确报告不支持，不能静默忽略 |

### 4.5 Agent 原生适配器

适配器保持薄层设计：只负责配置发现、Hook 安装、session 解析和 ID 关联；原始传输能力不重复实现。

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| ADP-001 | Gemini CLI Model Hooks | P0 | v0.2 | 捕获 `BeforeModel`、逐 chunk `AfterModel` 及 session/tool 生命周期 |
| ADP-002 | Claude Code Lifecycle Hooks | P0 | v0.2 | 捕获 session、turn、tool、subagent、compaction；不伪装成 model hook。`ANTHROPIC_BASE_URL` 改写须分别在 API key、OAuth、Bedrock / Vertex 模式下验证，后两者签名绑定 Host，可能只能走透明代理或 key log |
| ADP-003 | Codex custom provider | P0 | v0.2 | 自动生成 recorder provider 配置，覆盖 Responses SSE 路径。Codex 为 Rust 实现，在 rustls probe 落地前没有独立传输校验路径，manifest 中须如实标注 |
| ADP-004 | Codex WebSocket 模式 | P1 | v0.3 | 记录 WS 连接、响应事件、重连和 state 链 |
| ADP-005 | Agent session reader | P0 | v0.2 | 读取 Claude/Codex/Gemini 本地 session 并映射至统一事件 |
| ADP-006 | 通用 Hook command 协议 | P1 | v0.2 | 任意 JSON stdin/stdout lifecycle hook 可接入 |
| ADP-007 | Adapter SDK | P1 | v1.0 | 第三方只实现 detect/configure/parse/correlate 四个接口 |
| ADP-008 | Hermes Agent observer plugin | P0 | v0.2 | 以 `~/.hermes/plugins/<name>/` 插件订阅 `pre_api_request`、`post_api_request`、`api_request_error`、`subagent_start/stop`、`on_session_*`，把 `session_id` / `task_id` / `turn_id` / `api_request_id` / `api_call_count` 映射到统一 ID 层级；自动把 `model.base_url` 与 `fallback_providers` 指向 recorder；用计数测试核实记忆、摘要、技能等辅助模型调用是否全部经过 hook；不直接把 Hermes 自带的 `request_dump_*.json`（含完整 headers）当作证据源 |

### 4.6 Runtime 无源码注入

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| INJ-001 | Python `sitecustomize` shim | P1 | v0.5 | 包装主流模型 SDK、httpx/requests；支持流式事件。首个验证目标为 Hermes（venv Python 3.11 + OpenAI SDK 2.x + httpx） |
| INJ-002 | Node `--require/--import` shim | P1 | v0.5 | 包装 fetch/undici/模型 SDK；覆盖 worker/fork。仅对 npm 安装的 Claude Code / Gemini CLI 有效；Claude Code 原生安装包为 Bun 编译单文件，不读取 `NODE_OPTIONS` |
| INJ-003 | Node TLS key log | P0 | v0.3 | 自动输出并安全保存 TLS secrets。同上，Bun 原生包不支持 `--tls-keylog`，需走 BoringSSL 静态 eBPF 路径 |
| INJ-004 | Python SSL key log | P0 | v0.3 | 支持采用默认 SSL context 的进程；Hermes 的 httpx 默认 context 满足此条件 |
| INJ-005 | JVM `-javaagent` | P2 | v1.x | 至少支持一种常用 HTTP client 与模型 SDK |
| INJ-006 | Frida / LD_PRELOAD 扩展点 | P2 | v1.x | 可按二进制版本加载外部 probe 包 |

### 4.7 eBPF 与系统级采集

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| BPF-001 | AgentSight runner 集成 | P0 | v0.5 | 录制任务进程、文件、网络与可解析 LLM 调用，导入统一事件 |
| BPF-002 | eCapture runner 集成 | P0 | v0.5 | 支持声明矩阵中的 OpenSSL/BoringSSL/GoTLS 捕获模式 |
| BPF-003 | 动态 probe 选择 | P0 | v0.5 | 根据 binary/TLS fingerprint 自动选择 uprobe，失败原因可见 |
| BPF-004 | 静态链接 binary path | P0 | v0.5 | 能向采集器传入准确二进制路径并验证 probe 命中 |
| BPF-005 | cgroup/PID filtering | P0 | v0.5 | 只收集目标任务及后代，降低宿主敏感数据泄漏 |
| BPF-006 | ring buffer drop 计数 | P0 | v0.5 | 丢事件计数进入 manifest；非零时禁止 complete |
| BPF-007 | 自研 rustls probes | P2 | v1.x | 基于真实目标二进制和版本决定是否开发。若确认 Codex CLI 使用 rustls，应提升为 P1，否则 P0 Agent 之一始终缺少独立校验 |
| BPF-008 | GoTLS 扩展验证 | P1 | v0.5 | 对至少两个 Go 版本完成回归，记录版本支持范围 |

### 4.8 TLS Key Log 与抓包

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| TLS-001 | 任务级 pcap capture | P0 | v0.3 | 记录目标 namespace/cgroup 相关网络包与 drop 计数。pcap 与 key log 组合后可解出 `Authorization` 与全部正文，因此与 `tls.keys.enc` 同属最高敏感分级，落盘即加密、同等权限与 TTL，不受 SEC-001 的"普通事件"过滤保护 |
| TLS-002 | NSS key log ingestion | P0 | v0.3 | key log 加密保存，可与连接五元组关联 |
| TLS-003 | TLS 解密离线流水线 | P0 | v0.3 | 使用标准工具解密并输出 HTTP stream |
| TLS-004 | HTTP/2 stream 重组 | P0 | v0.3 | 解密后请求/响应能正确按 stream 配对 |
| TLS-005 | Proxy 与 pcap 双录对账 | P0 | v0.3 | 对 raw body 进行 canonical hash/diff，差异可解释 |
| TLS-006 | Secrets 安全销毁 | P0 | v0.9 | 达到保留期或显式删除时可验证销毁 |

### 4.9 Task / Inference 关联

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| COR-001 | ID 层级模型 | P0 | v0.1 | `run → session → turn → inference → attempt → stream event` 可导航 |
| COR-002 | Tool / subagent 父子关系 | P0 | v0.2 | tool、subagent、summary inference 有明确 parent |
| COR-003 | 连接到进程映射 | P0 | v0.3 | 每条连接可归属 PID、container、run |
| COR-004 | 多源事件去重 | P0 | v0.3 | Hook、proxy、eBPF 观察到同一调用时合并证据而不丢 raw |
| COR-005 | 不确定关联表达 | P0 | v0.2 | 使用 confidence/evidence，不强行关联。Claude Code 与 Hermes 的 subagent 都在同一进程内并发，进程树无效、请求也不带 subagent 标识，时间窗关联必然歧义；可用 proxy 看到的 system prompt / tools 指纹辅助归属，仍需标出置信度 |
| COR-006 | 跨主机 trace propagation | P2 | v1.x | 远程 subagent 能通过显式 trace ID 关联 |

### 4.10 服务端状态与有效上下文

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| STATE-001 | `previous_response_id` 链 | P0 | v0.4 | 构建 response state DAG，可生成客户端可重建上下文 |
| STATE-002 | conversation/session state | P1 | v0.4 | 记录创建、更新、引用和缺失节点 |
| STATE-003 | Gemini cached content 引用 | P1 | v0.4 | 缓存创建已采集时可解析，否则标记 unresolved |
| STATE-004 | 服务端状态缺口声明 | P0 | v0.4 | 任一缺失引用阻止 `server-effective-complete` |
| STATE-005 | 自托管模型 server probe | P2 | v1.x | 捕获 chat template、输入/输出 token IDs、模型版本和采样参数 |

### 4.11 完整性验证器

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| TEST-001 | 可控 fake model server | P0 | v0.1 | OpenAI / Anthropic-compatible 假服务端，可编程注入 429、500、连接复位、慢 SSE、超长事件、流中断、h2 与 WS；VER-002～VER-005 与 NET-009 测试模式的前置 |
| VER-000 | 最小 Coverage Manifest | P0 | v0.1 | `manifest.json` 自 v0.1 起输出采集源、逻辑调用数、attempt 数与已知缺口；`claim` 固定为 `best-effort`，v0.4 前不得出现任何 complete 值 |
| VER-001 | Coverage Manifest | P0 | v0.4 | 在 VER-000 基础上输出 TLS surface、协议、丢失、未知项和 completeness claim |
| VER-002 | 已知调用计数测试 | P0 | v0.1 | 测试 Agent 的逻辑调用数与物理 attempt 数可核对 |
| VER-003 | Retry fault injection | P0 | v0.3 | 429/500/reset 下保存全部物理尝试 |
| VER-004 | Stream cancellation test | P0 | v0.1 | 中途取消后已收到 chunk 全部存在且标为 incomplete |
| VER-005 | 长载荷/分片测试 | P0 | v0.4 | 跨 socket/ring buffer 的 payload 可重组，无静默截断 |
| VER-006 | Multi-modal canary | P1 | v0.4 | 文本、图片、文件和 tool payload 缺失情况可检测 |
| VER-007 | Capture drop gate | P0 | v0.4 | ring buffer/pcap/queue drop 非零时自动降级 |
| VER-008 | Unknown egress gate | P0 | v0.4 | 未解析外联或旁路连接存在时自动降级 |
| VER-009 | 双录 payload diff | P0 | v0.4 | L2/L3/BPF 多源载荷一致性可机器检查 |
| VER-010 | 兼容性回归矩阵 | P0 | v0.9 | 每个 Agent/runtime/TLS/协议组合有自动化回归结果 |

### 4.12 安全与隐私

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| SEC-001 | Header 凭证过滤 | P0 | v0.1 | `Authorization`、cookie、proxy credential 不进入普通事件。只覆盖 events / blob；pcap + key log 解密面按 TLS-001 单独分级 |
| SEC-002 | 内容采集策略 | P0 | v0.1 | 支持关闭正文、字段脱敏、路径白名单和最大保存量 |
| SEC-003 | 静态加密 | P0 | v0.9 | events、blob 分级加密。pcap 与 TLS secrets 的加密不等到此版本，随 TLS-001 / TLS-002 在 v0.3 生效 |
| SEC-004 | 最小权限 | P0 | v0.5 | 高权限 probe 与普通 Agent/collector 进程分离 |
| SEC-005 | 租户/任务隔离 | P1 | v1.0 | 不同任务的 key、目录、权限与导出边界隔离 |
| SEC-006 | 审计日志 | P1 | v1.0 | 谁启动、读取、导出、删除录制数据可追踪 |
| SEC-007 | 保留与安全删除 | P1 | v0.9 | 正文、pcap、TLS secrets 可配置不同 TTL |

### 4.13 查询、回放与导出

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| VIEW-001 | `iorec inspect <run>` | P0 | v0.1 | 输出调用数、模型、token、错误、缺口和文件位置 |
| VIEW-002 | Timeline CLI | P0 | v0.2 | 按 task/turn/inference 展示调用与工具事件 |
| VIEW-003 | Raw payload export | P0 | v0.3 | 按权限导出原始请求、响应和 stream event |
| VIEW-004 | OpenInference / OTLP export | P1 | v1.0 | 规范化 trace 可导入现有可观测系统 |
| VIEW-005 | Deterministic replay bundle | P1 | v1.0 | 输出重放所需的客户端可见 payload、参数和引用清单 |
| VIEW-006 | Replay 可行性声明 | P0 | v1.0 | 缺附件、缓存或服务端状态时明确标记不可完全 replay |

### 4.14 平台接入（并行轨道，采集端侧）

本节只列采集端需要实现的部分；平台侧的接收、处理、控制面见 [platform/](./platform/README.md)。上传与控制客户端始终可关闭，关闭后采集端行为与 v1.0 Local Recorder 完全一致。

| ID | Feature | 优先级 | 版本 | 完成定义 |
|---|---|---:|---|---|
| UP-000 | 共享 schema 文件 | P0 | v0.1 | 事件 envelope 与批次头以单一 schema 文件发布，采集端与平台 CI 双向校验；对应平台 P0 |
| UP-001 | 本地 spool queue | P0 | v0.3 | 网络不可用不阻塞、不丢本地录制；`acked_seq` 之前的事件才允许按保留策略清理 |
| UP-002 | 固定批次与 blob 上传 | P0 | v0.3 | 批次由 `recording_id` + 序号区间确定 ID，带 sha256；blob 先 HEAD 后 PUT；对应 platform/03 |
| UP-003 | 幂等重传 | P0 | v0.3 | 相同批次重传命中服务端短路；批次边界一旦封定不变；hash 不同的重传被服务端 409 拒绝时停止并告警 |
| UP-004 | 断点续传 | P0 | v0.3 | 重启后从服务端返回的 `durable_seq + 1` 继续；乱序只发生在重传场景 |
| UP-005 | Backpressure | P1 | v0.5 | 收到 429/503 时退避并本地积压，不阻塞 Agent；磁盘满策略可配置并写 `gap` 事件 |
| UP-006 | 远端删除与 TTL | P1 | v0.9 | 执行平台下发的 `delete_local`，与本地策略一致，支持可审计删除 |
| UP-007 | 能力与健康上报 | P1 | v0.4 | 注册、能力清单（`iorec.capabilities.v1`）、心跳；对应 platform/09 |
| UP-008 | 版本化配置与本地策略合并 | P1 | v0.5 | 拉取配置、本地策略优先、回报生效值与拒绝项；配置只影响新 run |
| UP-009 | collector-requests 执行 | P1 | v0.5 | backfill / pause / resume / flush / seal；`upload_sensitive` 需审批 ID 且可被本地拒绝 |
| UP-010 | Recording 滚动与 seal | P0 | v0.3 | 按大小或时间滚动切段，run 结束时 seal 并上传 manifest；`stream_key` 以 run 为作用域跨段重组 |
| UP-011 | 文件导入包 | P2 | v0.9 | `iorec export --format raw` 产出可被平台 `recordings:import` 直接接收的 tar |

## 5. 关键依赖顺序

| 前置能力 | 解锁能力 | 原因 |
|---|---|---|
| 统一事件模型 + append-only writer | 所有采集器 | 没有稳定 raw evidence 层，后续数据会反复迁移 |
| Runner + process tree | Agent 关联、eBPF、容器追踪 | 先定义任务边界，才能判断流量属于谁 |
| HTTP/SSE proxy | Codex/Claude 等基础 PoC | 最快验证真实 inference 流量录制 |
| Runtime/TLS discovery | 自动选择 eBPF/proxy/keylog | 不识别采集面就无法证明覆盖率 |
| 多源 correlation | 双录对账、完整性验证 | 同一调用会被多个采集器观察 |
| Drop/unknown/egress 指标 | Coverage Manifest | 完整性必须建立在可检测失败上 |
| v0.1 事件 envelope 冻结（UP-000） | 平台轨道 P1 起全部工作 | envelope 不冻结，平台会反复迁移 |
| 本地录制稳定（v0.1 gate） | 上传器默认开启 | 线上故障不能反向破坏 Agent 与录制 |
| M3 的 drop/unknown/egress 指标事件 | 平台 coverage 重算（P3） | 平台不采信采集端声明，需要原始指标 |

## 6. MVP 范围

### MVP 必须包含

- Linux x86-64。
- `iorec run -- <command>`。
- HTTP/1.1 + SSE reverse proxy。
- Hermes Agent、Codex、Claude Code、Gemini CLI 基础适配。
- append-only JSONL + blob。
- task/turn/inference/attempt 关联。
- 凭证过滤。
- 重试、取消和崩溃验收。
- 最小 Coverage Manifest。

### MVP 明确不包含

- 修改或阻止模型请求/响应。
- 宣称覆盖宿主机所有 Agent。
- Windows/macOS eBPF。
- HTTP/3 / QUIC 完整解码。
- 所有 Go/Rust/TLS 版本的通用 uprobe。
- 闭源服务端隐藏 system prompt 或 chain-of-thought。
- 平台 Web 控制台（属于平台轨道 P2，不在采集端 MVP 内）。
- 完全确定性的模型输出重放。

## 7. Release Gate 定义

### `v0.1` Gate

- 连续录制 100 次 HTTP/SSE inference，无 payload 截断。
- Ctrl-C 中断时，已收到 chunk 全部落盘。
- Recorder 被强杀后，最后一个完整事件之前的数据可恢复。
- 原始日志不含 Authorization 值。

### `v0.3` Gate

- HTTP/2 并发 stream 不串流。
- 429、500、reset 能记录所有物理尝试。
- WebSocket 重连前后保持逻辑 inference 关联。
- Proxy 与 TLS key log + pcap 的测试载荷对账一致。
- 上传器：断网 10 分钟后恢复，`durable_seq` 续传无重复、无缺口；采集端被强杀后按本地 `acked_seq` 重发命中幂等短路。

### `v0.4` Gate

只有满足以下全部条件，才允许输出 `transport-complete`：

```text
unknown_tls_surfaces == 0
unparsed_connections == 0
capture_drops == 0
unknown_egress == 0
all_attempts_have_terminal_state == true
```

`client-complete` 还要求模型输入、公开输出事件和附件引用均已保存；`server-effective-complete` 仅允许由受控模型服务端采集器声明。

### `v1.0` Gate

- 支持矩阵中的所有组合通过自动回归。
- 24 小时并发压力录制无静默丢失。
- Recorder 对 Agent TTFT、吞吐和 CPU 的影响有基准报告。
- 每个 run 都有可验证的 coverage manifest。
- 未知环境只输出 best-effort / unknown，不误报 complete。

## 8. 建议支持矩阵

首版不要以“支持任意 Agent”为目标，而是维护一张可测试矩阵：

| 维度 | v1.0 建议范围 |
|---|---|
| OS | Linux x86-64；Linux arm64 作为 P1；macOS 只提供 proxy / key log / preload 路径，无 eBPF，作为 P1 tier 单列 |
| Agent | Hermes Agent、Claude Code（npm 与原生安装包分列）、Codex CLI、Gemini CLI、任意 OpenAI-compatible CLI |
| TLS | 动态 OpenSSL（Hermes 等 Python 进程）、已验证静态 BoringSSL/OpenSSL（Node、Bun 原生包）、已验证 GoTLS；rustls 标为 `unknown`，Codex CLI 的独立校验依赖它 |
| Protocol | HTTP/1.1、HTTP/2、SSE、WebSocket |
| Deployment | 宿主进程、Docker 单机容器；Kubernetes DaemonSet 后置 |
| Capture | endpoint proxy、TLS key log、AgentSight/eCapture、session hooks |

矩阵中的每个单元格必须标记：

- `verified`：自动测试通过。
- `experimental`：能够采集，但稳定性或完整性未达门槛。
- `unsupported`：已知不支持。
- `unknown`：尚未验证，不能等同于 unsupported，也不能宣称支持。

## 9. 开发优先级判断

### 必须最先解决

1. 原始事件是否能在流式和崩溃场景下可靠落盘。
2. 一次逻辑 inference 与多次网络 attempt 如何建模。
3. 如何发现未覆盖的进程、TLS runtime 和外联连接。
4. 如何防止“没有日志”被误判为“没有调用”。
5. 如何验证 AgentSight/eCapture 在实际 Agent 二进制上的 probe 命中与丢失率。

### 可以后置

- Web UI 与复杂可视化。
- 平台的扩容项：ClickHouse 投影、独立 ingest 服务、消息队列（平台本身为并行轨道，不后置）。
- 成本分析、质量评测和 prompt 优化。
- 更多 Agent 品牌适配器。
- 自动修改请求、记忆注入或策略控制。

## 10. 推荐的第一个端到端 Demo

首选 Hermes Agent（本机已安装；同时具备 model hook、`base_url`、Python 注入与动态 OpenSSL，四条路径可互相对账），备选 Codex CLI：

1. 使用 `iorec run` 启动 Agent。
2. 自动写入本地 recorder endpoint 配置（Hermes：`model.base_url` 与 `fallback_providers`；Codex：custom provider）。
3. 代理逐条保存 request 和 SSE event。
4. 适配器解析 turn、tool 和 subagent（Hermes 走 observer plugin，Codex 走 session 文件）。
5. 通过 TEST-001 注入一次 500 重试和一次流式中断。
6. M2 起同时开启 TLS key log + pcap 作为独立证据；M1 阶段此步可省略，Demo 的完整版本是 M2 的验收项。
7. 结束后生成 timeline、raw payload 和 coverage manifest。
8. 自动验证两次网络 attempt、部分流式响应、任务关联和零丢失；Hermes 场景额外核对 hook 的 `api_call_count` 与 proxy 观察到的逻辑调用数一致。

这个 Demo 能同时证明四件事：不改源码、真实流式录制、重试保真、完整性可验证。通过后再投入 eBPF 多 TLS 适配，技术风险最低。

## 11. v1.0 的最终产品形态

```bash
# 以普通用户身份启动 Agent；Agent 进程本身永不提权，否则 HOME/配置/登录态都会改变
iorec run -- claude
iorec run -- hermes

# 需要 eBPF / pcap 时，由独立的特权 helper 提供采集面（CAP_BPF、CAP_NET_ADMIN），与 SEC-004 一致
iorec run --probe=ebpf -- hermes

# 查看覆盖结论
iorec inspect ./runs/<run-id>

# 查看一次任务的 inference 时间线
iorec timeline ./runs/<run-id>

# 导出原始记录或标准 trace
iorec export ./runs/<run-id> --format raw
iorec export ./runs/<run-id> --format openinference
```

最终输出必须把以下三类结论分开：

- **Observed**：实际捕获并持久化的内容。
- **Verified complete**：经过覆盖和丢失检查，可在声明边界内认定完整。
- **Unknown / unresolved**：TLS、协议、远端状态或附件无法确认的部分。

这三个状态比“是否抓到 prompt/response”更重要，也是该产品区别于普通 Agent 日志工具的核心 Feature。
