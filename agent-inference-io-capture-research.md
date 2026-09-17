# Agent 会话 / 任务完整 Inference I/O 获取方案调研

> 调研日期：2026-09-15  
> 目标场景：无法取得第三方 Agent 的定制源码，但可以控制 Agent 的启动命令、环境变量、容器或宿主运行环境。  
> 不在本报告范围：共享记忆注入、分析平台产品设计、修改模型请求或响应。

## 1. 结论先行

不存在一个对所有 Agent 都适用、同时又能证明“完整”的单一 Hook。

当前可以成立的工程结论是：

> **不修改 Agent 源码，也有机会录制其 inference I/O；前提是具备必要权限、采集器适配实际运行时与 TLS 实现，并通过主动测试证明覆盖范围。现阶段不能认定 AgentSight、eCapture 或任何单一工具能自动抓全宿主机上的所有模型调用。**

最稳妥的方案是建立两条独立证据链，再补一条任务关系链：

1. **客户端逻辑调用录制**：在 SDK / Agent 真正调用模型前后，保存序列化前的请求对象和解析后的流式事件。它最适合理解 messages、tools、参数以及逻辑上的一次 inference。
2. **传输层录制**：保存实际发出的 HTTP 请求、SSE chunk、WebSocket frame、重试、取消和异常。它最适合证明“到底调用了几次、线上实际传了什么”。
3. **Agent 生命周期关联**：用会话 Hook、任务事件、工具调用日志和进程树补充 session、turn、tool、subagent、compaction 关系。

如果控制模型服务端，再增加第四层：在 chat template 展开、缓存解析和 tokenization 之后保存最终输入 token 与输出 token。**这是唯一能严格称为服务端有效 inference I/O 的位置。** 对闭源远端模型，客户端只能证明“客户端可见的完整 I/O”，不能证明厂商内部系统指令、缓存展开、截断或隐藏推理过程。

在当前约束下，建议 PoC 的主路径是：

> **启动包装器 + Agent 原生 Hook / endpoint 改写 + 流式代理 + 运行时注入 + eBPF 或 TLS key log 独立校验。**

不要把“终端录屏”“会话 JSON”“OpenTelemetry trace”或“抓到一条 HTTPS 请求”单独称为完整 inference 录制。

---

## 2. 先定义“完整”

“完整会话”和“完整 inference I/O”不是同一件事。建议把可观测对象分成五层：

| 层级 | 实际内容 | 能回答什么 | 典型缺口 |
|---|---|---|---|
| L0 终端 / UI | 用户看到的输入、最终回答、界面状态 | 用户经历了什么 | 隐藏指令、工具 schema、中间 inference、重试、流式原始事件 |
| L1 Agent 生命周期 | session、turn、工具、子 Agent、压缩、任务开始结束 | 一个任务如何展开 | 不一定包含模型请求与响应 |
| L2 客户端逻辑 inference | SDK 调用前的结构化请求；SDK 返回的事件 | Agent 认为自己发了什么、收到了什么 | SDK 内部重试；序列化和协议差异；服务端状态展开 |
| L3 传输尝试 | HTTP body、headers 白名单、SSE chunk、WS frame、错误、取消、重连 | 实际发出了几次请求；每次传输了什么 | TLS；请求可能只携带服务端状态引用；厂商内部处理不可见 |
| L4 服务端有效 inference | 缓存展开后的上下文、chat template、token IDs、模型配置、实际生成 token | 模型最终处理了什么 | 只有模型网关或推理服务端可保证；闭源 SaaS 通常不可得 |

一次录制是否“完整”，还应按五个正交维度声明：

- **调用覆盖率**：主 Agent、子 Agent、摘要模型、路由模型、fallback 和所有重试是否都被捕获。
- **载荷覆盖率**：system/developer/user 消息、工具定义、工具结果、附件、采样参数和响应事件是否齐全。
- **时序保真度**：chunk 顺序、到达时间、暂停、取消、断线和恢复是否被保存。
- **因果关系**：每次模型调用能否归属到正确的 task、session、turn、tool 和 subagent。
- **服务端状态解析度**：`previous_response_id`、显式缓存、服务端会话等引用是否已展开；若不能展开，是否明确标为 unresolved。

因此，推荐在产品和文档里使用精确名称：

- `client-complete`：客户端能够看见的语义请求与响应完整。
- `transport-complete`：运行环境发出的每个传输尝试完整。
- `server-effective-complete`：服务端最终送入模型的内容和 token 完整。

---

## 3. 所有可行接入思路

### 3.1 Agent 原生模型 Hook

这是成本最低、语义最清晰的入口，但依赖具体 Agent 是否暴露模型级事件。

Gemini CLI 提供 `BeforeModel` 和 `AfterModel`：前者接收稳定化的 `llm_request`，后者在流式模式下按响应 chunk 触发；适合直接录制模型调用。[Gemini CLI Hooks Reference](https://geminicli.com/docs/hooks/reference/)

不过，Gemini 的 Stable Model API 会过滤非文本 part，因此这个 Hook 不能单独承担多模态或原始传输的无损录制。它是优秀的 L2 入口，不是完整 L3 入口。

Claude Code 的公开 Hooks 覆盖会话、用户提交、工具前后、子 Agent、压缩、通知等生命周期，但没有等价的通用 `BeforeModel` / `AfterModel` 边界。因此 Claude Hook 适合建立 L1 任务拓扑，不能单独证明模型 I/O 完整。[Claude Code Hooks](https://code.claude.com/docs/en/hooks)

Hermes Agent（Nous Research，Python 实现，本机已安装 v0.16.0）通过插件 observer hooks 暴露真正的模型级事件：`pre_api_request` 携带最终发给 provider 的 `request_messages`（Chat Completions `messages` 或 Responses `input`）、`conversation_history`、`session_id` / `task_id` / `turn_id`、`api_request_id` 与 `api_call_count`；`post_api_request` / `api_request_error` 携带 response、usage、finish_reason、耗时和 `base_url`；`subagent_start` / `subagent_stop` 携带 parent/child 的 session 与 subagent ID；另有 `llm_execution` middleware 可以包裹实际 provider 调用。这是四个目标 Agent 中最完整的 L2 入口。边界有三点：observer hook 只在请求与最终响应两个时点触发，流式 chunk 不经过它；Hermes 内部还有大量辅助模型调用（记忆、摘要、技能、标题等）由独立 OpenAI client 发出，是否全部经过 `pre_api_request` 必须用计数测试核实；一次逻辑 inference 会叠加 agent 层重试（`agent.api_max_retries`）、OpenAI SDK 内部重试和 `fallback_providers` 切换 endpoint，物理 attempt 可能跨多个 `base_url`。[Hermes Plugins](https://hermes-agent.nousresearch.com/docs/plugins)；本地仓库 `~/.hermes/hermes-agent/docs/observability/README.md`、`docs/middleware/README.md`

**判断**：有模型 Hook 就启用，但仍应保留传输层副本进行覆盖率校验。

### 3.2 官方 endpoint / base URL 改写

让 Agent 保留原有运行方式和认证，但把模型请求发送到本地反向代理，再由代理转发至真实服务。这是最容易做成跨 Agent 方案的主路径。

Codex 的配置允许定义自定义 model provider、`base_url` 和 `responses` wire API，也定义了 SSE stream retry 与 WebSocket 支持相关配置。这给 Codex 提供了官方支持的流量中转入口。[Codex 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)；[Codex 高级配置](https://learn.chatgpt.com/docs/config-file/config-advanced)

许多 OpenAI-compatible、Anthropic-compatible SDK 也支持环境变量或构造参数形式的 endpoint 覆盖。具体 Agent 必须逐一探测，不能假设变量名统一。

代理必须做到：

- 请求体边读边落盘、边转发，避免大附件全部缓存。
- SSE 按事件或原始 chunk 追加记录，不能等待完整响应后再写。
- WebSocket 记录 frame 方向、opcode、顺序、时间和连接重建。
- 把“逻辑调用”和“物理尝试”分开；SDK 重试不能覆盖前一个失败尝试。
- 默认移除或加密 `Authorization`、cookie、临时签名 URL 等凭证。

局限是：Agent 可能绕过配置、使用多个域名、直接走 WebSocket/QUIC，或者把请求发给本地守护进程而不是模型厂商。需要用 egress 约束证明没有旁路。

### 3.3 显式代理、透明代理与按进程捕获

若 Agent 不支持 base URL，可尝试 `HTTP_PROXY` / `HTTPS_PROXY`，或者在宿主机使用透明代理、TUN / local capture。

mitmproxy 的 local capture 可以按进程名或 PID 捕获本机应用；透明模式适用于不能配置代理的客户端。其 addon API 能逐 chunk 处理流式 body，也能观察 WebSocket message。[mitmproxy 捕获模式](https://docs.mitmproxy.org/stable/concepts/modes/)；[mitmproxy streaming / WebSocket addon 示例](https://docs.mitmproxy.org/stable/addons/examples/)

代价是需要让客户端信任本地 CA。证书固定、私有证书库、QUIC、非 HTTP 协议可能导致失败。透明代理也更依赖宿主权限和网络拓扑。

服务网格的 tap 能记录流式 HTTP 段，例如 Envoy tap filter；但对发往公网的端到端 TLS，只有 TLS 在网格中终止或发起时才能看到明文。这一点属于基于网络边界的推论，不能把普通 sidecar 自动视为模型流量明文采集器。[Envoy tap filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/tap_filter.html)

### 3.4 TLS key log + pcap：不做 MITM 的独立证据

这里必须区分两类密钥：

- **服务器证书私钥**：用于证明服务器身份；采用现代临时密钥交换时，仅有证书私钥通常不能事后解密连接。
- **连接流量密钥 / TLS secrets**：由本次连接协商产生，客户端和服务器运行时都持有，用于实际加解密。

因此，不需要取得远端模型服务器的证书私钥。Agent 客户端必然在某个时刻持有本连接的流量密钥，也必然处理过加密前的请求和解密后的响应；问题不是明文是否存在，而是当前 TLS 实现是否提供了稳定、可访问的密钥或明文采集点。

TLS key log + pcap 是容易被忽略、但非常有价值的路线：让进程使用的 TLS 库输出连接 secrets，同时抓取原始网络包；之后用 Wireshark / tshark 解密。

- Node 可用 `--tls-keylog=file` 输出 NSS `SSLKEYLOGFILE` 格式密钥。[Node CLI TLS key log](https://nodejs.org/api/cli.html#--tls-keylogfile)
- Python 的默认 SSL context 在设置 `SSLKEYLOGFILE` 时支持密钥日志。[Python ssl](https://docs.python.org/3/library/ssl.html)
- Wireshark 能结合 key log 与 pcap 解密 TLS，包括使用临时密钥交换的连接。[Wireshark TLS](https://wiki.wireshark.org/TLS)

优势是不会改变目标服务器、证书链和 HTTP 客户端行为，很适合作为代理录制的独立校验。局限是应用必须使用支持 key log 的 TLS 库，且还需要抓包权限、HTTP/2 / HTTP/3 / WebSocket 重组以及任务关联。若只有密文包，既没有连接 secrets，也没有进程内明文采集点，就不能恢复 inference I/O。

### 3.5 eBPF / TLS uprobes：无源码 Linux 进程的强力兜底

当 Agent 是闭源二进制、忽略代理设置、但运行在可控 Linux 宿主上，可以在 TLS 库读写函数处捕获加密前 / 解密后的明文。

**TLS wire protocol 是通用的，但进程内采集位置不是通用的。** OpenSSL、BoringSSL、Go `crypto/tls`、rustls 等都能访问相同 HTTPS endpoint；然而它们的函数边界、符号、参数、对象布局以及静态链接方式不同。eBPF uprobe 依附的是这些具体实现，而不是抽象的 TLS 协议，所以仍然需要适配。

从原理上看有两条 eBPF 路线：

| 路线 | 采集对象 | 复用性 | 实际适配点 |
|---|---|---|---|
| 直接复制明文 | TLS 加密前的写缓冲区、解密后的读缓冲区 | 后续 HTTP 解析可复用 | 各 TLS 实现的函数、ABI、内存布局、静态链接符号 |
| 采集 secrets 后解密 pcap | TLS 连接密钥 + 原始网络包 | 拿到 secrets 后可复用标准 TLS 解密工具 | 不同 TLS 实现的密钥派生对象与导出位置 |

eCapture 是现成的开源实现，支持多种 OpenSSL/BoringSSL/GnuTLS/NSS 和 Go TLS 场景，可输出文本、pcapng 或 keylog。它不要求安装 MITM CA。[eCapture](https://github.com/gojue/ecapture)

这条路线很适合“没有源码但有宿主权限”，不过需要逐 Agent 验证：

- Linux 内核、BTF/eBPF 能力与容器权限是否满足。
- 二进制使用的 TLS 实现、版本和符号是否受支持。
- 静态链接、自研网络栈、Rustls、QUIC 等情况是否需要额外探针。
- 捕获到明文后仍要解析 HTTP/2 stream、SSE 或 WebSocket，并与 task 关联。

建议把 eBPF 定位为**旁路证据和不透明二进制兜底**，而不是唯一的数据模型。

#### AgentSight 的正确定位

[AgentSight](https://github.com/eunomia-bpf/agentsight) 很接近本项目目标：它使用 eBPF 与 TLS traffic tracing，把模型调用和进程、文件、网络事件关联起来，也能围绕一个命令启动录制。当前上游文档还描述了对静态链接 BoringSSL / OpenSSL 二进制的自动发现、容器进程和本地 Agent session 的支持。

但它本身也公开了明确边界：eBPF 录制需要 Linux 权限；某些 Electron IDE 的 TLS 位于 stripped framework / helper 进程且协议可能是 protobuf，因此只能改走原生 session 数据；静态链接二进制还可能要求显式 `binary-path`。[AgentSight README](https://github.com/eunomia-bpf/agentsight)

所以对 AgentSight 应作如下判断：

- 它是目前最值得直接实测和复用的系统级基线之一。
- 某个版本或分支没有适配 Go TLS，只能说明该实现当时缺少 probe，不能推出 eBPF 原理上抓不到 Go TLS；eCapture 已提供 GoTLS 等实现的采集能力。
- 反过来，上游声称支持“任意命令”也不能自动推出“宿主机全部 inference 完整”：仍要核验 TLS runtime、静态链接、子进程/容器、协议解析、旁路连接和任务关联。
- 选型应比较 **AgentSight 的任务关联与事件模型** 和 **eCapture 的 TLS 实现覆盖**，必要时组合，而不是只选一个工具后直接相信完整性。

#### 采集前必须自动识别的 TLS surface

录制器启动后应先建立 runtime inventory：

1. 枚举任务 cgroup / namespace 内的主进程、子进程和连接目标。
2. 通过 `/proc/<pid>/maps`、ELF metadata、Build ID、符号和启动命令识别动态或静态链接的 OpenSSL、BoringSSL、Go TLS、rustls 等。
3. 记录 ALPN 与实际应用协议：HTTP/1.1、HTTP/2、HTTP/3、SSE、WebSocket、protobuf 或私有 framing。
4. 为每个网络活跃进程登记已挂载 probe、命中次数、解析成功率和丢事件计数。
5. 发现未识别 TLS 实现或未解析连接时，将任务状态降级为 `coverage_unknown`，而不是输出空日志后判定“没有模型调用”。

### 3.6 无源码运行时注入

“拿不到 Agent 源码”不等于不能在进程启动阶段注入观测代码。

| 运行时 | 启动注入点 | 可做的事 | 主要限制 |
|---|---|---|---|
| Python | `sitecustomize`、`.pth`、自动 instrumentation | 包装 `httpx` / `requests` / 模型 SDK；保存序列化前对象和流式事件 | `-S`、自带解释器、静态打包或非标准 HTTP 栈会绕过 |
| Node.js | `NODE_OPTIONS=--require` 或 `--import` | 在主线程、worker 和 fork 启动前加载；包装 SDK、fetch、undici 或 TLS | 打包 runtime、清理 `NODE_OPTIONS`、原生扩展可能绕过 |
| JVM | `-javaagent` / Instrumentation API | 在 `premain` 修改类；拦截 HTTP 客户端或模型 SDK | 需要匹配类加载与模块限制；实现成本较高 |
| Native | Frida、LD_PRELOAD、动态链接探针 | Hook TLS、socket 或已知 SDK 函数 | 静态链接、版本漂移、安全策略和性能影响 |

官方入口参见 [Python `sitecustomize`](https://docs.python.org/3/library/site.html)、[Node `NODE_OPTIONS`](https://nodejs.org/api/cli.html#node_optionsoptions)、[Java Instrumentation](https://docs.oracle.com/en/java/javase/11/docs/api/java.instrument/java/lang/instrument/package-summary.html) 和 [Frida Interceptor](https://frida.re/docs/javascript-api/)。

本机 Hermes Agent 是典型的 Python 案例：venv 内 Python 3.11、OpenAI SDK 2.x、httpx，TLS 为系统动态 OpenSSL 3.x。`sitecustomize`、`SSLKEYLOGFILE`、`HTTPS_PROXY` / `NO_PROXY`（Hermes 在 `process_bootstrap` 中显式读取）以及 eCapture 的动态 OpenSSL 模式都适用，是少数四条采集路径能在同一目标上互相对账的 Agent。

运行时注入比网络代理更接近 L2：可以看到 SDK 的结构化消息、工具 schema 和解析后的事件；但它可能看不到 SDK 内部更低层的重试，也不一定保留原始字节。所以它和传输层应并行，而不是互相替代。

### 3.7 OpenTelemetry / OpenInference 零代码插桩

OpenTelemetry 的生成式 AI 约定和 OpenInference 都可以统一 agent、LLM、tool、retriever 的 trace/span 语义，适合做任务索引与跨框架查询。[OpenTelemetry GenAI attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)；[OpenInference Specification](https://arize-ai.github.io/openinference/spec/)

现有 Python 自动插桩可以在不改业务源码的情况下启动；但 prompts、completions、函数参数和返回值经常因为敏感性而默认不采集，需要显式开启内容捕获。例如 OpenTelemetry 的 OpenAI instrumentation 明确区分了内容捕获开关。[OpenAI GenAI instrumentation](https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation-genai/opentelemetry-instrumentation-openai-v2)

因此：

- OTLP / OpenInference 适合作为**规范化索引和因果关系层**。
- 原始请求、SSE chunk、WS frame 和附件应保存在独立的 append-only 事件或 blob 中。
- 不能因为 trace 中有 prompt / completion 字段，就认为完成了无损流量录制。

### 3.8 Agent 会话文件、Hooks 与 PTY 录制

Agent 的 transcript、session 文件、生命周期 Hook 和终端 PTY 仍然有价值，但用途应限定为：

- 定义 task/session/turn 边界。
- 发现 subagent、compaction、工具调用、审批和错误。
- 保存用户实际看到的输出，作为体验层校验。
- 把模型流量映射回具体任务。

它们通常无法证明 SDK 实际发送的 payload、重试和原始流式事件。Claude Code Hooks 是典型的 L1 来源；Gemini 的 `SessionStart`、`PreCompress`、tool hooks 也可补齐生命周期。[Claude Code Hooks](https://code.claude.com/docs/en/hooks)；[Gemini CLI Hooks Reference](https://geminicli.com/docs/hooks/reference/)

### 3.9 模型 API Gateway

LiteLLM、Helicone、Portkey 或自研兼容网关能集中记录请求响应；只要 Agent 能改 endpoint，这是快速验证跨模型方案的好方法。[LiteLLM proxy logging](https://docs.litellm.ai/docs/proxy/logging)

但“网关有日志”不等于无损：流式中间事件、异常、二进制附件、raw request、WebSocket、调用方的 `no-log` 选项和协议版本都需要单独验证。网关还可能被直接 egress 绕过。它更像可运营的 L3 实现，而不是一种天然完整性保证。

### 3.10 推理服务端插桩

若模型为自托管或企业平台代理，应把最终采集点放在：

1. 服务端解析会话引用与缓存之后；
2. chat template 渲染之后；
3. tokenizer 之后、模型 forward / generate 之前；
4. token 生成和停止判断处。

应保存：最终文本 prompt、输入 token IDs、输出 token IDs、模型与 adapter 版本、采样参数、seed（若有）、停止原因、批处理与 cache 标识。

这是唯一能够发现“客户端请求相同，但服务端模板、缓存、路由或截断不同”的方法。部分云平台代理提供请求/响应日志，可作为外部校验，但采样、脱敏和支持的 API 范围需逐项核查。

### 3.11 本地进程内模型

如果 Agent 直接通过 llama.cpp、MLX、Transformers 或其他库在进程内完成推理，没有任何模型网络请求，那么代理、pcap、TLS key log 都无效。

此时只剩三种路线：

- 使用框架 callback / monkey patch / runtime preload。
- Hook tokenizer、chat template 和 generate 函数。
- 把本地模型拆成独立 model server，再录制进程间 API。

这一类必须在自动探测阶段识别，不能简单归为“没有捕获到模型调用”。

---

## 4. 服务端状态为何会让“抓到 HTTP”仍不完整

现代模型 API 可能让一条请求只发送增量内容或状态引用。

OpenAI Responses API 可以通过 `previous_response_id` 继续上一响应；会话状态和 WebSocket 模式也会在客户端没有重发完整历史时复用服务端状态。[OpenAI conversation state](https://developers.openai.com/api/docs/guides/conversation-state?api-mode=responses)

Gemini 显式缓存允许请求只带 `cachedContent` 名称与新输入，而且缓存内容本身不能通过读取缓存元数据重新取回。[Gemini context caching](https://ai.google.dev/gemini-api/docs/generate-content/caching)

所以录制器必须：

- 保存所有状态创建与引用事件，构建链或 DAG。
- 维护 `previous_response_id`、conversation、cache key 的映射。
- 在能够重建时生成 `resolved_input`，同时保留原始 wire request。
- 无法重建时标记 `server_state: unresolved`，不能静默宣称完整。

即使链条全部重建，闭源提供方内部的系统指令、政策注入、tokenization、截断和未公开推理内容仍不可见。录制范围必须在报告中写成“客户端可见内容”。

---

## 5. 推荐的实际采集架构

### 5.1 启动包装器是统一入口

设计一个类似下面的入口：

```bash
iorec run -- agent-command [args...]
```

包装器只负责可观测性，不修改 Agent 语义：

- 创建 `run_id`，记录启动参数、工作目录、可执行文件哈希、版本和允许采集策略。
- 把主进程与后代进程放入专属 cgroup / network namespace（权限允许时）。
- 生成 runtime/TLS inventory，确定每个进程使用的 TLS 实现、链接方式和应用协议。
- 注入原生 Hook、endpoint、CA、TLS key log 或语言 runtime preload。
- 启动传输记录器与生命周期适配器。
- Agent 退出后生成 coverage manifest。

任务边界最好使用 cgroup / namespace，而不是只盯一个 PID：子 Agent 和 worker 可能派生新进程。不过，如果 Agent 把请求交给宿主共享 daemon，流量会离开该 cgroup，此时需要 trace propagation、Unix socket 映射或 daemon 侧采集。

相反的情况同样存在：`hermes gateway` 这类常驻进程在一个进程内并发服务 Telegram / Discord / Slack 多个会话和 cron 任务，此时一个 `run_id` 不再等于一个任务，必须按 Agent 自己的 `session_id` / `task_id` 切分。Claude Code 与 Hermes 的 subagent 都是进程内线程或协程，进程树对它们无效，只能依赖 lifecycle hook 或请求内容指纹归属。

### 5.2 三条同步记录流

| 记录流 | 首选来源 | 内容 |
|---|---|---|
| `lifecycle` | Agent hooks、session 文件、PTY、进程事件 | task/session/turn/tool/subagent/compaction |
| `logical_inference` | Model hook、SDK/runtime instrumentation | 结构化请求、结构化响应事件、模型逻辑调用 |
| `transport_attempt` | endpoint proxy、透明代理、TLS/eBPF | HTTP/SSE/WS、重试、错误、取消、连接 |

关键 ID 不要混用：

- `run_id`：一次被包装的任务执行。
- `agent_session_id` / `turn_id`：Agent 语义边界。
- `inference_id`：逻辑上的一次模型调用。
- `attempt_id`：一次实际网络尝试；一个 inference 可有多个 attempt。
- `connection_id`：SSE / WebSocket / HTTP 连接。
- `parent_span_id`：subagent、tool、summary 等因果父节点。

### 5.3 最小落盘格式

平台尚未开发时，先做本地 append-only 记录：

```text
run/
  manifest.json
  events.jsonl
  blobs/
    sha256-...
  capture.pcapng        # 可选
  tls.keys.enc          # 可选，落盘即加密并限制权限；pcap 与其同属最高敏感级
```

每个事件至少包含：

```json
{
  "schema_version": 1,
  "run_id": "...",
  "inference_id": "...",
  "attempt_id": "...",
  "source": "sdk|hook|proxy|ebpf|session",
  "event": "request|sse_chunk|ws_frame|response|error|cancel",
  "sequence": 17,
  "monotonic_ns": 123456789,
  "wall_time": "2026-09-15T00:00:00Z",
  "payload_ref": "sha256:...",
  "redaction": {"policy": "default", "fields": ["authorization"]}
}
```

设计原则：

- 数据到达即追加，不等完整 response。
- 原始载荷按内容哈希存 blob；规范化 trace 只保存引用。
- 同时保存 raw 与 normalized 两种表示，禁止规范化覆盖原始证据。
- 凭证永不进入普通日志；敏感正文加密、限权并设置保留期。
- 文件或 URL 附件应在授权范围内保存内容哈希；如果只捕获到远端 file ID，应显式标记为外部引用。

---

## 6. 不同权限下的最优组合

| 你能控制什么 | 推荐组合 | 可达到的等级 |
|---|---|---|
| 仅能控制启动命令和环境变量 | 原生 hooks + base URL / proxy env + Python/Node/JVM preload + session/PTY | 通常 L1+L2；endpoint 可用时到 L3 |
| 容器内 root，但无宿主 eBPF 权限 | 本地 CA + 显式/透明代理 + tcpdump + runtime preload | 高覆盖 L2+L3；需处理容器网络与 QUIC |
| 宿主 root / BPF capabilities | 上述方案 + cgroup 归属 + eCapture / uprobes + pcap | 不透明二进制的强 L3 兜底 |
| 控制模型 gateway | gateway 原始流 + 客户端双录 + egress 强制 | 可证明所有经过 gateway 的尝试 |
| 控制推理服务端 | chat template / tokenizer / generation 插桩 | 可达到 L4 |

---

## 7. 各类 Agent 的落地选择

| Agent 类型 | 第一选择 | 第二证据 | 主要边界 |
|---|---|---|---|
| Gemini CLI | `BeforeModel` / `AfterModel` + lifecycle hooks | endpoint/proxy 或 TLS capture | Model Hook 会过滤非文本 part |
| Claude Code | lifecycle hooks + `ANTHROPIC_BASE_URL` 代理 | npm 安装：Node preload、`--tls-keylog`；原生安装包（Bun 编译，BoringSSL 静态）：只能走 eBPF | lifecycle hook 不是 model hook；OAuth 模式、Bedrock / Vertex（签名绑定 Host）下 base_url 改写需实测 |
| Codex CLI | custom provider / `base_url` 代理 | session/OTel + TLS key log / eBPF | Rust 实现，TLS 很可能是 rustls，现有 eBPF 工具无 probe，独立校验路径待验证；Responses 状态链、SSE/WS 重试需专测 |
| Hermes Agent | observer hooks 插件（`pre/post_api_request`、`subagent_*`、`on_session_*`）+ `model.base_url` 代理 | Python `sitecustomize` / `SSLKEYLOGFILE` + pcap，或 eCapture 动态 OpenSSL | 辅助模型调用与 `fallback_providers` 多 endpoint；`hermes gateway` 常驻模式下 run ≠ task；subagent 为进程内线程；自带 `HERMES_DUMP_REQUESTS` 转储含完整 headers，不得未脱敏直接当证据 |
| Python 自定义 Agent | `sitecustomize` / OTel / SDK wrapper | transport proxy 或 key log | 自带解释器、`-S`、非标准网络栈 |
| Node 自定义 Agent | `NODE_OPTIONS --require/--import` | proxy、`--tls-keylog` + pcap | 打包 runtime 或清理环境变量 |
| JVM Agent | `-javaagent` | proxy / pcap | 类加载和 SDK 版本适配 |
| Go/Rust/闭源二进制 | endpoint/透明代理 | eBPF TLS、Frida、pcap+key log | 静态链接、Rustls、QUIC、证书固定 |
| 本地进程内模型 | 框架 / tokenizer / generate 插桩 | 拆成 model server | 网络层完全不可见 |

系统级工具的组合建议：AgentSight 优先承担进程树、文件行为、Agent session 和模型调用的关联；eCapture / 自研 uprobe 扩展 TLS runtime 覆盖；pcap + key log 或 endpoint proxy 作为独立传输证据。三者能力有重合，但验证目标不同。

---

## 8. 完整性验收，而不是“看起来有日志”

PoC 必须运行故障注入测试：

1. **Surface 清单**：列出所有产生网络活动的任务进程、TLS 实现、协议、已挂载探针和未识别项；存在未知项时不能声明完整。
2. **计数测试**：已知任务触发 N 次逻辑 inference；记录中必须有 N 个 `inference_id`，并允许有 M≥N 个网络 `attempt_id`。
3. **重试测试**：人为制造 429、500、连接复位；每个物理尝试都必须保留，SDK trace 不得把它们折叠丢失。
4. **长载荷与边界测试**：使用跨 ring buffer / socket buffer 的长 prompt、长 SSE event 和二进制附件，检测分段重组、截断和最大事件尺寸。
5. **流式中断**：生成过程中 Ctrl-C / timeout；已到达 chunk 必须落盘，状态为 cancelled / incomplete。
6. **SSE / WS 重连**：断线恢复后，连接、attempt 和逻辑 inference 的关系仍正确，重复事件可识别但不被悄悄删除。
7. **子 Agent 与摘要**：触发 subagent 和 context compaction；每次模型调用必须能归属到正确父节点。
8. **多模态与工具**：文件、图片、工具 schema、tool result 要么有内容/哈希，要么明确是不可解析引用。
9. **服务端状态**：测试 `previous_response_id` 或 cached content；可重建就生成 resolved view，不可重建就标记 unresolved。
10. **旁路测试**：限制 Agent 只能经指定代理 / gateway 访问模型域名；若任务仍能产生未被记录的模型调用，验收失败。
11. **双录比对**：对进程内明文、L2 结构化 payload 与 L3 解码 body 做 canonical hash 或字段 diff，找出 SDK 注入、压缩、重试和协议转换差异。
12. **丢失检测**：读取 eBPF ring buffer 丢包、pcap drop、解析失败、sequence gap 和 recorder backpressure 指标；任何计数非零都必须进入 manifest。
13. **崩溃恢复**：强杀 recorder；已落盘事件保持可解析，最后一条截断记录可以被识别和隔离。

每次任务结束都生成 coverage manifest，例如：

```json
{
  "claim": "client+transport-complete",
  "logical_inferences": 12,
  "transport_attempts": 14,
  "unresolved_server_state": 1,
  "unparsed_connections": 0,
  "capture_sources": ["agentsight-ebpf", "reverse-proxy"],
  "tls_surfaces": ["boringssl-static", "openssl-3-dynamic"],
  "unknown_tls_surfaces": 0,
  "capture_drops": 0,
  "known_gaps": ["non-text parts filtered by native hook"]
}
```

这样“完整”是一个可测试、可审计的声明，而不是产品宣传用语。

---

## 9. 容易绕远的方向

以下方法有用，但不应作为主录制路径：

- **只录 terminal / tmux / `script`**：只能得到用户可见文本。
- **只读 Agent transcript**：通常缺 SDK 重试、真实序列化、流式 chunk 和隐藏调用。
- **只做 tcpdump / strace**：TLS 下通常只能看到密文和连接元数据。
- **把 TLS 协议通用等同于 probe 通用**：wire format 可统一解析，但 OpenSSL、Go TLS、rustls 等进程内采集点不同。
- **把某个 AgentSight 分支的缺口当作 eBPF 上限**：这是实现覆盖问题；同样也不能因上游宣称支持任意命令就省略完整性验证。
- **只做 OTel trace**：内容可能默认关闭、过滤、截断或规范化。
- **只部署 gateway**：若没有 egress 强制，Agent 可以旁路；协议兼容也需验证。
- **只做内存插件 Hook**：生命周期注入点与模型传输边界不是一回事。
- **把“最终能看到全文”当作流式完整**：等待完整 response 后才写入会丢失真实时序，并在崩溃/取消时丢数据。
- **追求闭源厂商的隐藏推理**：客户端没有这个可观测面。目标应限定为公开响应事件与可见 reasoning item，而不是未暴露的内部 chain-of-thought。

---

## 10. 建议的 PoC 优先级

### P0：先证明一条真实任务可以完整复盘

- 实现启动包装器、`run_id`、append-only `events.jsonl` 和 blob。
- 选择一个支持 endpoint 改写的 Agent，完成 HTTP + SSE 实时 tee。首选 Hermes Agent：它同时具备 model hook、`base_url`、Python 注入和动态 OpenSSL，四条采集路径可在同一目标上对账；其次是 Codex CLI。
- 关联 session/turn/tool 事件。
- 通过重试、取消、崩溃测试。

### P1：证明无源码跨运行时覆盖

- Python `sitecustomize` 与 Node `--require/--import` 各做一个通用 shim。
- 增加 TLS key log + pcap，和代理结果做双录比对。
- 在 Linux 上验证 eCapture 对至少一个闭源或不可修改 CLI 的兜底能力。

### P2：处理真正困难的边界

- HTTP/2 multiplexing、WebSocket、QUIC / HTTP3。
- 共享 daemon、远程 subagent、本地进程内模型。
- 服务端状态链和 cache 引用解析。
- 自托管模型的 chat template / token 级采集。

PoC 的成功标准不应是“支持多少 Agent 名称”，而应是：**给定一个可控运行环境，能够自动识别其调用路径、选择采集器，并输出带已知缺口的 coverage manifest。**

---

## 11. 最终建议

把项目定位为 **Agent Inference Flight Recorder**，而不是某个 Agent 的日志插件。

其核心能力应是：

1. 以任务启动包装器统一建立边界和身份。
2. 优先使用 Agent 原生 model hook 或官方 endpoint。
3. 使用 runtime preload 获取 L2 语义副本。
4. 使用代理记录 L3 的 HTTP/SSE/WS 真实尝试。
5. 使用 TLS key log 或 eBPF 提供独立、无源码的覆盖校验与兜底。
6. 用生命周期 Hook / session 文件建立 task-turn-tool-subagent 拓扑。
7. 用服务端插桩解决缓存展开和最终 token 输入问题；没有服务端控制时明确降级声明。

这条路线既没有被“记忆插件”限制，也不依赖拿到每个定制 Agent 的源码；它把不同 Agent 的差异压缩到一组薄适配器，把真正通用的能力放在启动、运行时、传输与验证层。

---

## 主要一手资料

- [Gemini CLI Hooks Reference](https://geminicli.com/docs/hooks/reference/)
- [Claude Code Hooks](https://code.claude.com/docs/en/hooks)
- [Codex 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Codex 高级配置](https://learn.chatgpt.com/docs/config-file/config-advanced)
- [mitmproxy Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [mitmproxy Addon Examples](https://docs.mitmproxy.org/stable/addons/examples/)
- [eCapture](https://github.com/gojue/ecapture)
- [AgentSight](https://github.com/eunomia-bpf/agentsight)
- [Wireshark TLS](https://wiki.wireshark.org/TLS)
- [Python `site` / `sitecustomize`](https://docs.python.org/3/library/site.html)
- [Node.js CLI](https://nodejs.org/api/cli.html)
- [Java Instrumentation](https://docs.oracle.com/en/java/javase/11/docs/api/java.instrument/java/lang/instrument/package-summary.html)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [OpenTelemetry GenAI attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
- [OpenInference Specification](https://arize-ai.github.io/openinference/spec/)
- [OpenAI Conversation State](https://developers.openai.com/api/docs/guides/conversation-state?api-mode=responses)
- [Gemini Context Caching](https://ai.google.dev/gemini-api/docs/generate-content/caching)
- [Hermes Agent](https://github.com/NousResearch/hermes-agent)；[Hermes Plugins](https://hermes-agent.nousresearch.com/docs/plugins)；本地仓库 `docs/observability/README.md`（observer hooks，`hermes.observer.v1`）与 `docs/middleware/README.md`（`hermes.middleware.v1`）
