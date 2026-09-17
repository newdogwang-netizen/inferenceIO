# 09 · 采集管理协议（控制面）

控制面解决三件事：平台知道每个采集端**能做什么、活着没有、实际按什么配置在跑**；平台能**请求**采集端做事（补传、改配置、暂停）；采集端**报告结果与拒绝原因**。设计参考 OpAMP 的能力、健康与配置反馈机制。[OpAMP](https://opentelemetry.io/docs/specs/opamp/)

所有调用由采集端发起，平台不需要能连到客户环境。

## 1. 注册

```http
POST /collectors:register
{ "name": "build-host-07", "version": "iorec 0.4.2", "hostname": "…", "os": "linux/amd64",
  "capabilities": { … }, "local_policy_version": "…" }
```

响应含 `collector_id`、短期 token、当前生效的配置文档与 `config_version`。

## 2. 能力清单

采集端在注册、每次 `iorec run` 探测后、以及能力变化时上报。平台据此决定哪些分析可执行。

```json
{
  "schema": "iorec.capabilities.v1",
  "transport": {
    "http_body": "visible",          // visible | headers_only | absent
    "sse": "visible",
    "websocket": "absent",
    "http2_decode": "via_keylog",    // native | via_keylog | absent
    "http3": "detect_only"
  },
  "sources": {
    "proxy": true, "hook": ["hermes"], "session_file": ["claude", "codex"],
    "ebpf": { "available": false, "reason": "no CAP_BPF" },
    "keylog": { "available": true, "runtimes": ["python", "node"] },
    "pcap": { "available": false, "reason": "no CAP_NET_RAW" },
    "pty": false
  },
  "runtime_inventory": {
    "agents_detected": [{"kind": "hermes", "version": "0.16.0", "install": "venv"}],
    "tls_surfaces": [{"lib": "openssl", "version": "3.5.5", "link": "dynamic", "status": "verified"}],
    "unknown_tls_surfaces": 0
  },
  "limits": { "max_blob_bytes": 268435456, "spool_bytes": 10737418240 },
  "privilege": { "helper_running": false, "agent_uid": 1000 }
}
```

"装上采集端"不代表所有能力都可用；页面上每个 Recording 的能力快照与 coverage 一起显示。

## 3. 健康心跳

```http
POST /collectors/{id}:heartbeat
{ "status": "healthy", "active_runs": 2, "spool_bytes_used": 1.2e9, "acked_lag_seconds": 4,
  "last_error": null, "config_version": 17, "effective_config_sha256": "…" }
```

- 间隔默认 30 秒；平台 3 次未收到标 `stale`，10 分钟标 `offline`。
- `acked_lag_seconds` 是本地最新事件与已 ACK 序号之间的时间差，是上传健康度的核心指标。

## 4. 版本化配置

配置文档有范围（project 默认 → collector 覆盖）和版本：

```json
{
  "config_version": 17,
  "scope": { "project": "…", "collector": "…" },
  "content_policy": { "capture_bodies": true, "max_body_bytes": 1048576, "redact_fields": ["authorization", "x-api-key", "cookie"], "pty": false },
  "upload": { "batch_max_bytes": 4194304, "batch_max_age_ms": 5000, "rate_limit_bytes_per_s": 5242880 },
  "sensitive_tier_upload": { "pcap": false, "tls_keys": false },
  "retention_local": { "acked_events_ttl_hours": 72, "spool_max_bytes": 10737418240, "on_full": "drop_oldest_blobs" },
  "egress_classification": { "model_hosts": ["api.openai.com", "api.anthropic.com", "api.fireworks.ai"], "ignore_hosts": ["statsig.anthropic.com", "telemetry.example"] }
}
```

采集端行为：

- 拉到新版本后，与本地策略（例如公司安全基线禁止上传正文）合并，**本地策略优先**。
- 回报 `effective_config`（实际生效值）与 `rejected`（被本地策略拒绝的项及原因）。平台展示的是生效值，不是下发值。
- 配置只影响新的 CaptureRun；进行中的 run 不热切换内容策略，避免同一 Recording 内脱敏规则不一致。

## 5. 采集端请求

平台向采集端下发的工作项，采集端长轮询拉取：

```http
GET /collector-requests?collector={id}&wait=30s
```

| `type` | payload | 采集端动作 |
|---|---|---|
| `backfill` | `{recording_id, first_seq, last_seq}` | 重发指定区间批次（平台发现缺口或对象丢失时） |
| `apply_config` | `{config_version}` | 拉取并应用配置 |
| `pause` / `resume` | `{reason}` | 暂停 / 恢复上传（不影响本地录制） |
| `flush` | `{recording_id}` | 立即封批上传 |
| `seal` | `{recording_id}` | 强制封存并上传 manifest |
| `upload_sensitive` | `{recording_id, kinds: ["pcap"]}` | 上传敏感层数据；必须有审批记录 ID，采集端校验后仍可拒绝 |

生命周期：`pending → delivered → acked → done | rejected | expired`。采集端回报：

```http
POST /collector-requests/{id}:result
{ "status": "rejected", "reason": "local policy forbids pcap upload" }
```

## 6. 离线行为

- 无法连接平台时，采集端继续录制、继续封批到本地 spool，心跳失败只记日志。
- 恢复连接后先注册（token 可能过期），再拉配置，再从 `acked_seq + 1` 续传，最后拉取积压的 collector-requests。
- 平台侧对 `offline` 采集端的 Recording 自动 seal 为 `incomplete`（见 04 §7），上线后补传照常触发重算。

## 7. 与 `iorec` CLI 的关系

控制面是 daemon 能力。单次 `iorec run` 也能工作：注册一次、上传、结束时 seal。团队环境建议以 daemon 方式常驻，`iorec run` 通过本地 IPC 交给 daemon 上传，共用 spool 与配置。
