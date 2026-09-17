# 08 · 平台 API 与实时交互

以下是建议接口，不是已存在的服务。路径前缀 `/v1`，省略。

## 1. 资源

| 接口组 | 主要操作 | 调用方 |
|---|---|---|
| `/collectors` | 注册、心跳、能力、实际配置 | capture-agent |
| `/collector-requests` | 拉取待执行请求、回报结果 | capture-agent |
| `/recordings` | 创建、查询、封存、导入、导出、删除 | capture-agent、Web |
| `/recordings/{id}/batches` | 上传批次、查询确认位置 | capture-agent |
| `/recordings/{id}/manifest` | 上传采集端 manifest | capture-agent |
| `/recordings/{id}/coverage` | 平台重算的 coverage | Web |
| `/recordings/{id}/timeline` | 事件与行为时间线 | Web |
| `/projects/{p}/blobs/{sha256}` | HEAD / PUT / GET | capture-agent、Web |
| `/attempts/{id}` | 模型请求、响应、原件、diff | Web |
| `/inferences/{id}` | 逻辑调用、attempt 列表、resolved input、与上一轮 diff | Web |
| `/sessions/{id}` | 确定或推断的会话关系、turns、子会话 | Web |
| `/findings` | 列表、详情、确认或驳回 | Web |
| `/processing-jobs` | 重处理、失败查询、任务进度 | Web |
| `/notifications/stream` | SSE 实时通知 | Web |

## 2. 关键请求示例

### 上传批次

```http
POST /recordings/run_01J8...%230003/batches
Authorization: Bearer <collector token>
Content-Type: application/vnd.iorec.batch+zstd
Idempotency-Key: run_01J8...#0003:000000000120-000000000158
X-Batch-SHA256: <hex>

{"batch_id":"…","first_seq":120,"last_seq":158,"event_count":39,"byte_length":84213,"sha256":"…","blobs":[…]}
<zstd ndjson>
```

响应：

```json
{ "recording_id": "run_01J8...#0003", "durable_seq": 158, "state": "open", "missing_blobs": ["sha256:…"] }
```

### 封存

```http
POST /recordings/{id}:seal
{ "final_seq": 4021, "manifest_sha256": "…" }
```

### 时间线

```http
GET /recordings/{id}/timeline?from_seq=0&limit=500&kinds=inference,tool,subagent&revision=latest
```

```json
{
  "items": [
    { "kind": "turn", "session_id": "…", "turn_id": "…", "started_at": "…", "status": "observed" },
    { "kind": "inference", "id": "inf-42", "attempts": 2, "model": "…", "terminal_state": "completed", "relation_status": "inferred", "confidence": 0.95 },
    { "kind": "unattributed_attempt", "id": "attempt-88", "host": "…", "started_at": "…" }
  ],
  "next_cursor": "…",
  "relation_revision": 7,
  "coverage_claim": "best-effort"
}
```

### attempt 详情

```http
GET /attempts/{id}?view=raw|normalized|both
```

返回 header 白名单、`request_body_ref` / `response_body_ref` 的签名下载 URL、SSE 事件列表（含到达时间）、终态、`evidence_refs`。

### Finding 裁决

```http
POST /findings/{id}:review
{ "status": "dismissed", "note": "预期的 fallback 行为" }
```

### 重处理

```http
POST /processing-jobs
{ "type": "resolve", "scope": { "capture_run_id": "…" }, "processor_version": "resolver-v8", "priority": 10 }
```

## 3. 实时通知（SSE）

```http
GET /notifications/stream?project=…&cursor=18820
Accept: text/event-stream
```

```text
id: 18821
event: entity.updated
data: {"entity_type":"recording","entity_id":"run_01J8...#0003","kind":"durable_seq","revision":158}

id: 18822
event: entity.updated
data: {"entity_type":"finding","entity_id":"fnd-…","kind":"created","revision":12}
```

- 通知只传实体 ID、变化种类和版本，正文由查询接口获取。
- 通知来自 `notifications_outbox` 表，由 API 进程轮询或 `LISTEN/NOTIFY` 唤醒后推送；断线后用 `Last-Event-ID` / `cursor` 恢复，outbox 保留 24 小时。
- 通知不是唯一记录：页面定期全量刷新关键状态，防止漏通知。

## 4. 认证与授权

| 主体 | 凭证 | 范围 |
|---|---|---|
| capture-agent | 长期 collector token（project 级，可吊销），注册后换取短期 token | 只能写自己 project 的 Recording、读自己的 collector-requests |
| 用户 | OIDC（SSO） | 按 tenant / project 角色：viewer、reviewer（可裁决 Finding）、operator（可重跑、下发配置）、admin |
| 服务间 | mTLS 或内部 token | Worker 只连数据库与对象存储，不经过 API |

租户与 project 由凭证决定；请求体或事件中出现的租户字段一律忽略并记审计。

## 5. 错误格式

```json
{ "error": { "code": "batch_conflict", "message": "batch_id exists with different sha256", "retryable": false, "details": { "existing_sha256": "…" } } }
```

`retryable` 明确告诉采集端要不要重试；429 / 503 附 `Retry-After`。

## 6. 分页与版本

- 列表接口统一 cursor 分页，不用 offset。
- 派生对象的读取接受 `revision=latest|<n>`，默认 latest；审计场景可回看旧 revision。
- API 版本在路径前缀，事件协议版本在 `schema_version`，二者独立演进。
