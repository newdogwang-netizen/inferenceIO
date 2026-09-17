# 07 · 分析、评估与 coverage

## 1. Finding 结构

```json
{
  "id": "fnd-…",
  "rule_id": "retry_storm",
  "severity": "warn",
  "title": "同一逻辑调用 7 次物理重试",
  "detail": { "inference_id": "…", "attempts": 7, "hosts": ["api.fireworks.ai", "openrouter.ai"] },
  "evidence_refs": [ {"recording_id": "rec-…", "first_seq": 120, "last_seq": 402} ],
  "status": "open",
  "analysis_revision": 12,
  "processor_version": "rules-v12"
}
```

- 每条 Finding 必须有 `evidence_refs`，页面上可以一键跳到原始事件。
- `status` 生命周期：`open` → `confirmed` / `dismissed`；人工裁决带 `review_note`。规则重跑不改动已 `dismissed` 的同 `rule_id + 同证据` 发现。
- `severity` 只有三级，避免过度分类。

## 2. 首版确定性规则

| `rule_id` | 判定 | 需要的能力 |
|---|---|---|
| `retry_storm` | 一次 inference 的 attempt 数 ≥ 阈值（默认 4） | 传输层 |
| `stream_truncated` | attempt `terminal_state ∈ {truncated, unknown}` | 传输层 |
| `attempt_without_terminal` | Recording 封存后仍有无终态 attempt | 传输层 |
| `unattributed_ratio` | 未归属 attempt 占比 > 阈值（默认 10%） | 任意 |
| `context_growth` | 同一 Session 内 input tokens 连续 N 轮单调增长且超过模型上下文的 80% | usage 或 normalized messages |
| `compaction_detected` | `prefix_chain` 断裂但指纹相同（信息性） | normalized messages |
| `duplicate_request` | 相同 `input_hash` 在非重试语义下出现多次 | normalized messages |
| `tool_loop` | 同一工具、相同参数 hash 连续调用 ≥ 3 次 | tool 事件或 normalized messages |
| `secret_in_prompt` | 正文匹配凭证模式（API key、token、私钥头） | 正文可见 |
| `provider_switch` | 同一 inference 的 attempt 跨不同 provider host（fallback 生效） | 传输层 |
| `coverage_downgraded` | Recording claim 低于 project 期望 | coverage |
| `latency_outlier` | TTFT 或总时长超过同模型 P99 × 2 | 传输层时间 |
| `unknown_egress` | 存在未分类且未记录的模型域外联 | egress 分类 |

能力清单里缺少某项能力时，依赖它的规则不运行，并在 Recording 上记录 `rules_skipped: [...]`，页面显示"不可判定"而不是"未发现"。

## 3. 输入 diff

页面上最常用的视图是"这一轮相对上一轮，模型输入变了什么"。

算法（确定性，可缓存）：

1. 取同一 Session 相邻两次 inference 的 normalized `messages`。
2. 每条 message 计算 `content_hash`（role + 规范化 content）。
3. 用 LCS 对齐两个 hash 序列，得到 `added` / `removed` / `unchanged`。
4. 对 `unchanged` 之外且 role 相同、位置对应的消息对，做文本级 diff（system prompt 变化、工具结果被截断等）。
5. tools 定义单独 diff（新增 / 删除 / schema 变化）。
6. 结果写入 `derived/` 前缀作为缓存，携带 `processor_version`。

输出示例：

```json
{
  "from": "inf-41", "to": "inf-42",
  "messages": { "added": 2, "removed": 0, "modified": 1, "unchanged": 37 },
  "system_prompt_changed": false,
  "tools": { "added": [], "removed": ["web_search"] },
  "token_delta": 1834
}
```

对 `server_state = resolved` 的 inference，diff 基于 `resolved_input_ref`；`unresolved` 时页面明确提示"仅显示客户端发送的增量"。

## 4. 可选模型评审

- 评审是独立任务类型 `eval`，独立并发池，默认关闭；project 显式启用并选择评审模型 provider 与凭证。
- 输入是 normalized messages 与响应，输出是 `Finding(kind = evaluation)`，`evidence_refs` 指向被评审的 attempt。
- 评审结果永远标 `inferred`，不参与 coverage，不参与行为重建。
- 首版内置模板：回答是否遵循 system prompt 约束、工具调用是否有依据、是否出现敏感内容。用户自定义代码评估器需要隔离执行服务，不在首版。
- 发送到评审模型的内容受与上传相同的内容策略约束；含 PHI 的 project 默认禁用。

## 5. coverage 重算

平台不直接采信采集端 manifest，而是以它为输入之一重算：

| 字段 | 来源 |
|---|---|
| `capture_sources` | `capability_report` 事件 + 实际出现的 `source` 值 |
| `tls_surfaces` / `unknown_tls_surfaces` | `tls_surface` 事件 |
| `logical_inferences` / `transport_attempts` | resolve 结果 |
| `unattributed_attempts` | resolve 结果 |
| `unparsed_connections` | decode 结果 |
| `capture_drops` | `drop_counter` 与 `gap` 事件求和 |
| `unknown_egress` | `unknown_egress` 事件经 egress 分类后仍未分类的数量 |
| `observed_egress_classes` | `process/network_connection_observed` 原始事件按固定类别和 connection ID 去重重算；非法/缺失类别归入 `unknown_external` |
| `model_bypass_connections` | 原始连接事件与采集端 manifest 两者取保守最大值 |
| `all_attempts_have_terminal_state` | assemble 结果 |
| `unresolved_server_state` | resolve 结果 |
| `missing_blobs` | 接收记录 |
| `platform_transport_proof_verified` | 仅由平台自有的、有界 task-egress pcap/key-log 解码与 payload 对账阶段设置；采集端 manifest 和普通事件不能设置 |
| `claim` | 下表 |

claim 判定与采集端路线图 v0.4 gate 一致：

| claim | 条件 |
|---|---|
| `unknown` | 能力清单缺失，或 `unknown_tls_surfaces > 0`，或采集端声明 `unknown`，或 Recording `incomplete` |
| `best-effort` | 默认值；任一 gate 指标非零 |
| `transport-complete` | Recording 已 seal，`platform_transport_proof_verified == true`，且 `unknown_tls_surfaces == 0 && unparsed_connections == 0 && capture_drops == 0 && unknown_egress == 0 && model_bypass_connections == 0 && all_attempts_have_terminal_state && missing_blobs == 0` |
| `client-complete` | transport-complete 且每个 inference 都有结构化输入、公开输出事件与附件引用 |
| `server-effective-complete` | 只允许由受控模型服务端采集器（`source = server_probe`）声明，首版不实现 |

“没有观察到缺口”不是“完整”的证明。平台 `transport_audit` 只从服务器持有的原始 task-egress pcap/key-log、runner 终态和 proxy body blob 生成 proof；本地 `iorec transport-audit` 结论和采集端 manifest 都不能打开该 gate。Coverage 会重新验证 proof 的 schema、边界、processor version、decoder 身份、状态/计数一致性和零 gap 条件。普通在线上传明确排除 pcap/TLS-secret blob，因此默认保持 `best-effort`；当前只有 operator 控制的 plaintext platform bundle 导入能为服务器提供这两类敏感证据。采集端声明高于平台重算结果时，取平台结果并产生 `coverage_claim_mismatch` Finding。

页面把三类结论分开显示：**Observed**（捕获并持久化的内容）、**Verified complete**（在声明边界内认定完整）、**Unknown / unresolved**（TLS、协议、远端状态或附件无法确认的部分）。

## 6. 数据集与导出

| 格式 | 内容 | 用途 |
|---|---|---|
| `raw` | 原始批次 + blob，等价于本地 `run/` | 取证、离线重放 |
| `normalized-jsonl` | 每行一个 inference：messages、response、usage、relations、coverage | 训练数据、评测 |
| `openinference` / `otlp` | span 树 | 导入既有可观测系统 |
| `replay-bundle` | 客户端可见 payload、参数、引用清单，附 replay 可行性声明 | 回放（路线图 VIEW-005/006） |

导出是 `export` 任务，结果放 `exports/` 前缀，带过期时间的签名 URL 下载。导出受与查看相同的内容策略与脱敏约束。
