# tinybox 云原生录制验收结果

2026 年 9 月 22 日验收 · 2026 年 9 月 23 日整理发布 · 公开摘要

**结论：Controller / Platform 组合部署，以及 Pod 注入、录制、上传、解析、正文校验的完整链路通过。** 测试在真实 Kubernetes Pod 中执行，但模型服务是模拟器，没有付费推理。这不是所有 Agent、生产高可用或长期稳态的认证。

[返回：把 Agent 录制带进 Kubernetes](iorec-on-kubernetes.html#acceptance)

## 环境与部署范围

- 单节点 tinybox，Kubernetes **1.35.3+k0s / Linux amd64**。
- 两副本 Controller；API、Worker、Web 和 PostgreSQL 各一个实例。全部运行在同一节点，两副本 Controller 不代表跨节点容灾。
- PostgreSQL、正文对象和 Agent spool 使用三块持久卷，均完成绑定。存储为本地 hostpath，不能抵御节点或磁盘丢失。
- 五个 iorec 镜像均固定 digest，并通过匿名拉取校验。公开的是镜像，不是平台或录制数据。
- 仅对明确选中的 Namespace / Pod 注入，使用独立凭据和数据库；未修改已有业务工作负载。
- 初次安装于 2026-09-22 15:56:50 UTC 完成；16:34:12 UTC 的第二版部署只更新 Web 登录功能。

这里记录的是当次验收快照，不是集群的实时健康状态。

## 准入行为

| 检查项 | 结果 |
|---|---|
| 选中 Namespace 内、带接入标签的 Pod | 注入录制包装、安装容器和上传 sidecar |
| 同一 Namespace 内、不带接入标签的 Pod | 不注入 |
| 选择范围之外的 Pod | 不注入 |
| 选中但缺少显式数字非 root UID 的 Pod | 拒绝创建，避免无效注入 |
| 与已有准入组件共存 | 未停用已有 Webhook，实际注入任务完成 |

准入检查使用目标集群的服务端 dry-run；随后执行真实测试 Job，验证的不只是生成清单。

## 录制与交付结果

| 验收项 | 结果 |
|---|---|
| 模型调用 | **3 次**：1 次 JSON、2 次 SSE |
| 录制分段 | **2 个**，均已封存（sealed） |
| 全局最终事件序号 | **47** |
| 原始正文完整性 | **5 份不同正文对象**，下载后 SHA-256 全部匹配 |
| 初始化容器 / Agent / 上传器退出码 | **0 / 0 / 0** |
| 上传器重启 | **0 次**，结束时补传完成 |
| Kubernetes 来源关联 | **7 个字段**与实际 Pod 一致 |
| 解析与完整性检查 | 无缺失正文引用、完整性告警或失败 / 活跃解析任务 |

分段的事件序号是连续的全局边界，不是各段长度：

| 分段 | 调用数 | 起始边界 | durable / parsed / final | 状态 |
|---|---:|---:|---|---|
| #0000 | 2 | 0 | 27 / 27 / 27 | sealed |
| #0001 | 1 | 27 | 47 / 47 / 47 | sealed |

因此这里是 **47 个全局事件，不是 27 + 47**。模拟器返回的 usage 合计为 36 input / 12 output，仅用于核对字段传递，不是付费模型消耗。

来源校验覆盖 cluster、namespace、Pod 名称、Pod UID、node、目标 container 和 injection version。验收程序同时核对连续封存、事件边界、调用数、JSON / SSE 事件、响应文本、正文引用，并下载原始字节重新计算哈希；不是只看页面有没有记录。

## 实际录制数据长什么样

下面不是手写的理想格式：**2026-09-23 从 Platform 读取这份既有录制，重新下载并校验了 5 份正文。** 展示的是 API 实际返回字段的节选；没有重新运行实验。运行、调用及集群标识已一致替换，模型主机替换为 `model.example`；凭据、HTTP 头、本地命令与路径等不公开。

[下载完整脱敏样例 JSON（约 38 KB）](data/tinybox-recording-sample.json)

下载文件包含两段 recording、三次 attempt、全部 47 个事件的脱敏信封、事件计数和五份模拟正文。顶层 `summary / recordings / attempts / events / body_blobs` 是为本文整理的**导出包装**，不是一个新的 Platform API；事件载荷仅保留允许公开的字段，并非全部原始载荷。

### 先看对象之间的关系

| 对象 | 本次数据 | 用什么关联 |
|---|---|---|
| recording：一次运行的录制分段 | 2 段，同属 `run-demo` | `capture_run_id` 串起分段；`id` 标识某一段 |
| attempt：一次模型请求 | 3 次，均 HTTP 200 / completed | `recording_id` 指向分段；`native_id` 对应事件的 `attempt_id` |
| event：按序记录的事实 | 47 个，其中 SSE 事件 6 个 | `seq` 是运行内全局序号，事件还带时间、来源和关联 ID |
| body part / blob：正文块与字节 | 6 个正文引用、5 个不同对象 | `sha256` 引用正文；`size` 表示字节数 |
| normalized：便于跨协议阅读的结果 | 消息、文本、结束原因、usage | 挂在 attempt 下，是派生视图，不替代原始正文 |

**三个序号不要混淆：** `seq` 是全局事件序号，`event_sequence` 是一条 SSE 流内的事件编号，`chunk_sequence` 是捕获正文块的编号。它们都不是 token 数。

### 1. 分段摘要与 Kubernetes 来源

第一段的 API 字段节选：

```json
{
  "id": "run-demo#0000",
  "capture_run_id": "run-demo",
  "segment_no": 0,
  "sequence_base": 0,
  "state": "sealed",
  "durable_seq": 27,
  "parsed_seq": 27,
  "final_seq": 27,
  "model_call_count": 2,
  "input_token_count": 24,
  "output_token_count": 8,
  "run_metadata": {
    "runtime": "python",
    "recorder_version": "0.1.0",
    "kubernetes": {
      "cluster": "cluster-demo",
      "namespace": "agent-demo",
      "pod_name": "agent-demo-pod",
      "pod_uid": "00000000-0000-4000-8000-000000000001",
      "node_name": "node-demo",
      "container_name": "agent",
      "injection_version": "v1"
    }
  }
}
```

第二段的起始边界是 27，最终序号为 47。来源元数据回答“哪个集群、哪个 Pod、哪个容器产生了这份录制”；这里的集群、命名空间、Pod 和节点值均为别名。

### 2. 三次调用实际记录了什么

| 调用别名 | 所属分段 | 首 / 末事件序号 | 响应形式 | input / output |
|---|---|---|---|---|
| attempt-01 | #0000 | 9 / 15 | JSON | 12 / 4 |
| attempt-02 | #0000 | 16 / 26 | SSE（3 个事件） | 12 / 4 |
| attempt-03 | #0001 | 28 / 37 | SSE（3 个事件） | 12 / 4 |

三次均调用模拟模型 `iorec-smoke`。以第二次 SSE 调用为例：

```json
{
  "id": "run-demo~attempt-02",
  "native_id": "attempt-02",
  "recording_id": "run-demo#0000",
  "source": "proxy",
  "method": "POST",
  "api_mode": "chat_completions",
  "model": "iorec-smoke",
  "url": "http://model.example/v1/chat/completions",
  "status_code": 200,
  "terminal_state": "completed",
  "started_at": "2026-09-22T15:59:39.802424Z",
  "first_byte_at": "2026-09-22T15:59:39.80984Z",
  "ended_at": "2026-09-22T15:59:39.873021Z",
  "usage": {
    "completion_tokens": 4,
    "prompt_tokens": 12,
    "total_tokens": 16
  },
  "sse_event_count": 3,
  "response_text": "recorded in Kubernetes"
}
```

这些字段能区分请求何时开始、何时收到首字节、何时结束，以及响应状态与用量。这里的 usage 是模拟器返回的测试值，不是模型实际计费。

### 3. 原始正文与规范化视图

第二次调用的请求正文如下（为阅读重新排版）：

```json
{
  "model": "iorec-smoke",
  "messages": [
    {
      "role": "user",
      "content": "local smoke call 1"
    }
  ],
  "stream": true
}
```

同一次调用的规范化结果：

```json
{
  "api_mode": "chat_completions",
  "model": "iorec-smoke",
  "stream": true,
  "finish_reason": "stop",
  "response_id": "smoke-completion",
  "response_text": "recorded in Kubernetes",
  "stream_terminated": true,
  "usage": {
    "completion_tokens": 4,
    "prompt_tokens": 12,
    "total_tokens": 16
  },
  "messages": [
    {
      "role": "user",
      "text": "local smoke call 1"
    }
  ]
}
```

原始请求里的 `content` 被提取为规范化消息里的 `text`；SSE 的多个增量被合成为 `response_text`。规范化字段适合列表、检索和统计，正文则保留协议层的实际内容。**响应文本只是正文解析出来的一部分**，不包含全部流式边界和协议字段。

### 4. SSE 是怎样保存的

同一次调用的响应正文确实是 SSE，而不是事后伪造的“流式效果”：

```text
data: {"id": "smoke-completion", "object": "chat.completion.chunk", "model": "iorec-smoke", "choices": [{"index": 0, "delta": {"content": "recorded in Kubernetes"}, "finish_reason": null}]}

data: {"id": "smoke-completion", "object": "chat.completion.chunk", "model": "iorec-smoke", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}}

data: [DONE]
```

这段正文包含三个事件：文本增量、带 usage 的结束块、`[DONE]`。其中第一个事件的记录信封如下：

```json
{
  "seq": 23,
  "wall_time": "2026-09-22T15:59:39.84699Z",
  "monotonic_ns": 3284448933,
  "source": "proxy",
  "event": "sse_event",
  "attempt_id": "attempt-02",
  "inference_id": "native-inference-02",
  "payload_sha256": "083c96ebed1716bc5afc4635b3c0f9d07796e85ba0967ca3789987535b48ed9b",
  "payload_size": 191,
  "payload": {
    "data_sha256": "sha256:fbd8bef2a5885ab90d039f5e35f0e126e56c9e50543f8ae03ab9c23a7d49aea1",
    "data_size": 183,
    "event": null,
    "event_sequence": 1,
    "id": null,
    "raw_sha256": "sha256:083c96ebed1716bc5afc4635b3c0f9d07796e85ba0967ca3789987535b48ed9b",
    "raw_size": 191,
    "retry_ms": null,
    "valid_utf8": true
  }
}
```

外层 `event: "sse_event"` 是录制事件类型；内层 `payload.event: null` 只表示上游没有提供 SSE 的 `event:` 命名字段。这里 `payload_size` 是带 SSE 包装的原始字节数，`data_size` 是其中 data 内容的字节数。

事件的 `attempt_id: "attempt-02"` 对应调用的 `native_id`，不是调用的全局 `id`。事件层的 `native-inference-02` 和平台 `inf:run-demo~attempt-02` 也不是同一标识空间，不能仅凭名字直接关联。

### 5. 正文引用如何落到字节

同一调用的响应正文块：

```json
{
  "chunk_sequence": 1,
  "direction": null,
  "event": "response_body_chunk",
  "media_type": "text/event-stream",
  "raw_truncated": false,
  "recording_id": "run-demo#0000",
  "seq": 21,
  "sha256": "7b1c6b643c625d767b409c4db6a5de1f7461b4378cec7d3596fa86f852edea48",
  "size": 439
}
```

`seq: 21` 定位正文块事件；`sha256` 对应下载样例中 `body_blobs[].sha256`，其 `content_utf8` 保存正文内容。这个例子只捕获到 **1 个响应正文块，但里面有 3 个 SSE 事件**，正文块不等于流事件。

三次请求与响应一共有六个正文引用；两次 SSE 响应字节完全相同，因此按哈希去重后是五个对象。五份对象均重新核对了字节长度和 SHA-256。上面的请求 JSON 为阅读重新排版；**校验请以下载 JSON 中 `content_utf8` 解码后的 UTF-8 原字节为准**。事件信封里的其他载荷哈希不属于这五份正文对象，本文没有打包全部事件原始载荷。

### 6. 成功之外，数据也记录了未知与缺口

第一段的覆盖与旁路核验字段节选：

```json
{
  "coverage": {
    "claim": "unknown",
    "incomplete": false,
    "capture_drops": 0,
    "missing_blobs": 0,
    "body_unavailable": 0
  },
  "transport_proof": {
    "status": "unavailable",
    "verified": false,
    "pcap_records": 0,
    "tls_key_records": 0
  }
}
```

这表示本次没有报告采集丢弃或正文缺失，**不表示全流量覆盖已被证明**。`claim: "unknown"` 保持未知；没有启用独立 pcap / TLS 核验，所以 `verified` 仍为 false。

此外，三个调用都留下了关联未解析事件，下面是一条实际记录的节选：

```json
{
  "seq": 43,
  "source": "correlation",
  "event": "inference_correlation_unresolved",
  "inference_id": "native-inference-01",
  "payload": {
    "reason": "no_unique_agent_anchor",
    "transport_sequence": 12
  }
}
```

`no_unique_agent_anchor` 表示找不到可唯一关联的 Agent 原生锚点，不是请求或响应正文丢失。本次运行是通用 Python 模拟任务，`agent_kind` 和 `agent_version` 为 null，未配置 Agent 原生 hook；因此**没有逐工具的执行证据**。进程启动、退出和网络连接事件，不能冒充每次 tool call 的运行结果。

完整 JSON 还保留第二段的 `coverage.known_gaps`，包括进程轮询可能漏掉极短子进程、代理未暴露上游 HTTP/2 流标识等已知限制。这样读者看到的不只是“通过”，也能看到证据的边界。

## 遇到的问题与复验

**数据库首次启动出现重试。** PostgreSQL 的无头 Service 最初没有就绪端点，API / Worker 分别重启 3 / 2 次，随后自动恢复，无需修改凭据或手动重启。不能把这次安装描述成“全程零错误”。

**首次网页登录流程不完整。** 当时 HTTP 和带认证 API 校验通过，但新浏览器缺少可用的登录表单，显示凭据无效。修复后只更新 Web 镜像，认证和录制数据保持不变。

- 登录功能通过 13 项隔离浏览器检查。
- 已部署的 tinybox 平台通过 6 项真实浏览器检查，包含登录后访问录制详情。
- 登录修复后重新执行完整录制验收：仍为 3 次调用、2 个封存分段、最终序号 47，5 份正文哈希全部通过。

本页只公开经过逐字节校验的模拟请求 / 响应样例，不公开其他录制、平台入口、登录令牌、密钥或 kubeconfig。GitHub Pages 上的报告和样例无需平台登录，也不提供对私有录制的访问权限。

## 验收边界

**已验证的是：真实集群中的部署与统一录制链路。** 尚未由这次 tinybox 验收证明的项目包括：

- 真实 Agent 镜像与付费模型的兼容性，以及所有工具执行记录的覆盖。
- 多节点故障切换、托管 PostgreSQL / S3 兼容性与备份恢复。
- 新的 5 小时稳态或长时间负载测试。
- 公网入口、SSO 和完整的生产身份管理。

平台中断、上传器重启、Pod 删除后 PVC 保留等故障测试另在隔离 kind 集群进行；没有将它们冒充为 tinybox 上的故障验收。默认路径也未启用 pcap / TLS 独立旁路校验。

## 记录来源

本文根据 2026-09-22 留存的 tinybox 部署与验收记录整理，包含后续 Web 登录修复复验。2026-09-23 03:15 UTC 从 Platform 读取既有录制，导出脱敏字段与已校验的模拟正文；不是重新运行实验。详细运维记录和其他原始录制保留在受控环境。

[阅读云原生设计与部署流程](iorec-on-kubernetes.html) · [采集端工作原理](how-iorec-records.html) · [项目仓库](https://github.com/newdogwang-netizen/inferenceIO)
