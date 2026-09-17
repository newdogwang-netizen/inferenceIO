# 03 · 统一事件协议

采集端所有输入（代理、Hook、session 文件、eBPF、PTY）都先被 Event Writer 归一成同一种事件，再按固定批次上传。平台只需理解这一种协议。协议继承采集端路线图 EVT-001～EVT-006 的约束，本文补充上传所需的批次层。

## 1. 事件 envelope

```json
{
  "schema_version": 1,
  "event_id": "018bcfe5-6800-7000-8000-000000000001",
  "run_id": "run_01J8...",
  "sequence": 17,
  "monotonic_ns": 123456789,
  "wall_time": "2026-09-15T00:00:00.000Z",
  "source": "proxy",
  "event": "response_body_chunk",
  "session_id": "…",
  "turn_id": "…",
  "inference_id": "…",
  "attempt_id": "…",
  "connection_id": "…",
  "parent_id": "…",
  "pid": 4242,
  "container_id": "…",
  "raw": {
    "sha256": "sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
    "size": 18232,
    "media_type": "application/json",
    "truncated": false
  },
  "normalized": { "method": "POST" },
  "redaction": { "policy": "default", "fields": ["authorization"] }
}
```

规则：

- `recording_id` 是批次和 API 路由元数据，不进入事件 envelope；事件自身由 `run_id` 绑定到本地证据。平台接收批次时附加并校验 Recording 身份。
- `event_id` 是随 `sequence` 严格递增的 UUIDv7。`sequence` 在一个本地 run 内从 1 连续递增；丢失由明确的 capture-gap/drop 证据表达，不能伪造缺失的正文事件。
- `monotonic_ns` 用于排序与时长，`wall_time` 用于展示与跨机器对齐；平台以 `sequence` 为最终顺序。
- 关联 ID 是 envelope 的顶层可选字段，只填采集端确知的值；推断由平台做。纯 proxy 场景通常只有 `attempt_id`、`connection_id`、`pid`。
- 原始字节只通过 `raw` 指向 `sha256:<64 lowercase hex>` 内容寻址 blob；`normalized` 是可选 JSON 值，二者都不是强制字段。平台必须保留 raw 与派生结果的边界。
- `source` 是有界字符串而不是闭合枚举，以容纳 `hook:<name>`、`runtime:<name>` 等版本化来源；来源是否能支撑 coverage 由独立信任规则决定。
- `schema_version` 变化只允许增字段；删字段或改语义必须升主版本，平台保留旧版本解码器。

唯一规范以共享的 [`event.v1.schema.json`](../iorec-platform/schemas/event.v1.schema.json) 为准；Rust 序列化 fixture 与 Go 解码测试共同冻结跨语言字段名。

## 2. 事件类型

| 分组 | `event` 值 | 关键 payload |
|---|---|---|
| 运行 | `run_start` `run_end` `process_start` `process_exit` `capability_report` `gap` | 命令、环境白名单、pid 树、能力清单、缺口原因与估计数量 |
| 生命周期 | `session_start` `session_end` `turn_start` `turn_end` `tool_call` `tool_result` `subagent_start` `subagent_stop` `compaction` | 原生 ID、父子 ID、工具名、摘要 |
| 逻辑调用 | `inference_request` `inference_response` `inference_error` | 结构化 request（messages / input、tools、参数）、结构化 response、usage |
| 传输 | `attempt_start` `request_headers` `request_body` `response_headers` `sse_chunk` `ws_frame` `response_body` `attempt_end` `attempt_error` `attempt_cancel` `connection_open` `connection_close` | 方向、原始字节、状态码、header 白名单、终止原因 |
| 交互 | `pty_output` `pty_input` | 脱敏后文本、终端尺寸 |
| 完整性 | `drop_counter` `unknown_egress` `network_connection_observed` `tls_surface` `manifest` | 计数、目标五元组、固定 egress 类别、TLS 库指纹、采集端 coverage 声明 |

Rust recorder 的原生名字包括 `transport_request_started`、`request_body_chunk`、`request_body_finished`、`transport_response_started`、`response_body_chunk`、`sse_event`、`websocket_frame`、`transport_attempt_finished`。平台仍读取早期 fake collector 的语义别名，但新上传必须遵循共享 schema。正文原始字节只存 blob，Worker 的规范化结果与原始引用并存（EVT-005）。

## 3. 批次格式

采集端把连续事件封成固定批次上传。批次是幂等与 ACK 的单位。

```json
{
  "batch_id": "run_01J8...#0003:000000000120-000000000158",
  "recording_id": "run_01J8...#0003",
  "schema_version": 1,
  "first_seq": 120,
  "last_seq": 158,
  "event_count": 39,
  "byte_length": 84213,
  "sha256": "…",
  "prev_sha256": "…",
  "encoding": "ndjson+zstd",
  "blobs": [ {"sha256": "…", "size": 18232} ],
  "created_at": "2026-09-15T00:00:03Z"
}
```

- `batch_id` 由 `recording_id` 与序号区间确定，重传得到相同 ID。
- `sha256` 是压缩前 ndjson 的哈希；`prev_sha256` 形成连续的本地 hash 链。采集端固定批次计划并在每次重试时重新读取、校验不可变证据；平台校验区间、内容哈希与幂等键。首版平台保留但不以 `prev_sha256` 单独作 ACK 判据。
- 当前采集端按 4 MiB 压缩前或 2000 事件先到先封；单个线上的压缩批次（含 header）不超过 16 MiB。固定计划一旦持久化便不因重启重新切分。
- `blobs` 列出本批次引用到的 blob。blob 与批次分开上传，见 04。

传输体：HTTP `POST /recordings/{id}/batches`，`Content-Type: application/vnd.iorec.batch+zstd`，请求体前置一行 JSON 批次头，随后是 zstd 压缩的 ndjson 事件。头部字段同时以 `Idempotency-Key: {batch_id}` 与 `X-Batch-SHA256` 出现，便于反向代理层做幂等短路。

## 4. blob 上传

```text
HEAD /projects/{p}/blobs/{sha256}         -> 200 已存在 / 404 不存在
PUT  /projects/{p}/blobs/{sha256}         -> 201 / 200（已存在则不重复写）
```

- 采集端先 HEAD 再 PUT，存在即跳过；大量小 blob 时可用 `POST /projects/{p}/blobs:exists` 批量询问。
- 服务端校验 sha256 与 size，不匹配返回 422，不落盘。
- 批次可以先于 blob 到达。批次登记时若引用的 blob 缺失，批次照常 ACK（原始事件已保存），Recording 上记录 `missing_blobs`，`decode` 任务对缺 blob 的事件输出 `body_unavailable`，blob 到达后由 `blob_arrived` 触发局部重跑。

## 5. manifest 上传

采集端在 Recording 封存请求中上传本地 `manifest.json` 及其 SHA-256。平台校验 digest、持久化 manifest 与 digest，并把二者连同 `final_seq` 纳入幂等冲突判断。重复提交同一 final/digest 是空操作；不同 final 或不同 manifest 返回 409。平台不把采集端 manifest 当结论，而是当作重算 coverage 的输入之一（见 07）。

## 6. 本地上传状态

采集端在 `run/.upload/` 私有目录中按平台 origin 分开维护固定计划和 ACK 状态：

```json
{
  "recording_id": "…",
  "run_id": "…",
  "acked_seq": 158,
  "sealed": false,
  "collector_id": "…",
  "config_version": 7,
  "batches": [
    {"first_seq": 1, "last_seq": 158, "sha256": "…", "prev_sha256": null}
  ]
}
```

状态文件和锁为 `0600`、目录为 `0700`，不持久化 token、事件正文或解密后的 blob。重启时先读取服务端 `durable_seq` 并要求它位于固定批次边界，再从下一批继续。只要存在上传目标，整段 run 必须达到全部事件已 ACK 且远端 sealed 后，本地保留策略才允许删除；当前实现不做事件日志前缀截断。

## 7. 大小与限制

| 项 | 建议值 | 超限行为 |
|---|---|---|
| 单事件 JSON | 16 MiB（平台硬上限；采集端记录上限更严格） | 拒收批次 |
| 单 blob | 256 MiB 平台硬上限；当前 recorder 生成 64 MiB 以内 | 拒收 |
| 单批次压缩前 | 4 MiB 采集端切分；64 MiB 平台硬上限 | 拆批 / 拒收 |
| 单批次线上大小 | 16 MiB | 拒收 |
| 批次并发上传 | 每 Recording 1 路（保证顺序）；跨 Recording 并行 | 平台返回 429 + `Retry-After` |
| 序号缺口 | 不允许静默 | 必须有 `gap` 事件 |

## 8. 与 OTLP 的关系

平台可选接收 OTLP/OpenInference trace 作为**辅助输入**，映射为 `source: "observer"` 的 lifecycle 或 inference 事件，写入独立的 Recording。它不参与 `durable_seq` 语义，也不能单独支撑 completeness claim，与调研 §3.7 的结论一致。
