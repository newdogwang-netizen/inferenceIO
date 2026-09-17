# 06 · 行为重建

行为重建回答一个问题：**每个观察到的模型请求属于谁。** 它必须在没有 session ID、事件晚到、父事件缺失、多个候选并存的情况下工作，而且不能编造确定性。

## 1. 输入

| 输入 | 提供什么 | 可靠度 |
|---|---|---|
| Hook 事件（Hermes `pre/post_api_request`、`subagent_*`；Gemini `BeforeModel/AfterModel`；Claude Code lifecycle） | 显式 `session_id` / `turn_id` / `inference_id` / 父子 ID | 最高，直接 `observed` |
| 原生 session 文件（Claude、Codex、Gemini 本地 transcript） | turn 边界、工具调用、subagent 名称 | 高，但格式随版本漂移 |
| 代理 / eBPF 观察到的 `ModelAttempt` | 请求内容、时间、pid、连接 | 事实本身可靠，归属需推断 |
| 进程事件 | pid 树、启动命令 | 对进程内 subagent 无效 |
| PTY | 用户看到什么 | 只用于校验，不用于归属 |
| 能力清单 | 哪些来源本来就不存在 | 决定"缺证据"还是"没发生" |

## 2. 关系类型

| `Relation.type` | from → to | 含义 |
|---|---|---|
| `attempt_of` | ModelAttempt → ModelInference | 物理尝试属于哪次逻辑调用（重试、fallback 切换 endpoint） |
| `belongs_to_turn` | ModelInference → Session.turn | 逻辑调用属于哪个会话的哪一轮 |
| `parent_of` | Session → Session | subagent、summary、router 的父子 |
| `tool_call_of` | tool_result 事件 → ModelInference | 工具结果回填到哪次调用 |
| `process_of` | ModelAttempt → pid | 连接归属进程 |
| `continues` | Session → Session | 跨 CaptureRun 的同一业务会话（Codex thread 重开） |

## 3. 证据类型与默认权重

| 证据 `kind` | 说明 | 默认置信度 | 状态 |
|---|---|---|---|
| `explicit_id` | Hook 或 session 文件给出相同 ID | 1.0 | `observed` |
| `prefix_chain` | 后一次 inference 的规范化 `messages` 以前一次的 messages 为前缀（去掉最后一条 assistant/tool 之后） | 0.95 | `inferred` |
| `response_id_chain` | `previous_response_id` 指向已观察到的 `response.id` | 0.95 | `inferred` |
| `tool_call_id_match` | 请求中的 `tool_call_id` 与前一次响应的 tool_call 一致 | 0.9 | `inferred` |
| `fingerprint` | 相同 `request_fingerprint`（system prompt + tools 集合），同一 pid，时间相邻 | 0.6 | `inferred` |
| `temporal_pid` | 同一 pid，时间窗内无其他候选 | 0.4 | `inferred` |
| `temporal_only` | 仅时间相邻 | 0.2 | 不单独成立关系 |

规则：

- 一条关系至少需要一种置信度 ≥ 0.6 的证据，否则不建关系，attempt 留在未归属列表。
- 多个候选且最高分与次高分差距小于 0.15：标 `conflict`，页面列出全部候选让人裁决。
- 权重是可配置的规则版本的一部分，改动即升 `resolver` 版本。

`prefix_chain` 是无 session ID 场景最强的信号：Agent 每一轮都会重发完整历史，同一会话内相邻两次 inference 的 messages 必然构成前缀关系；不同会话几乎不可能。它同时能识别 compaction（前缀关系断裂但 system prompt 指纹相同且时间连续）。

## 4. 算法概要

对一个 CaptureRun 的一次 `resolve`：

1. **收集事实。** 读全部 normalized `ModelAttempt`、Hook 产生的 `ModelInference`、lifecycle 事件、进程事件、能力清单。
2. **attempt → inference。** 有显式 `inference_id` 直接绑定；否则按 `(pid, request_fingerprint, input_hash)` 聚合：`input_hash` 完全相同且时间相邻的 attempt 视为同一逻辑调用的重试（Hermes 的 agent 层重试 + SDK 重试 + fallback 切 `base_url` 会产生 input 相同、host 不同的 attempt，这条规则正好覆盖）。没有任何聚合依据的 attempt 各自成为 `inferred` inference。
3. **inference 排序与链接。** 按 pid 分组，按首个 attempt 的 `monotonic_ns` 排序，两两计算 `prefix_chain`、`response_id_chain`、`tool_call_id_match`。
4. **会话聚类。** 由第 3 步的链接构成有向链；每条链是一个候选 Session。有原生 `session_id` 的链与原生 Session 合并（`kind = native`），否则 `kind = inferred`，`native_id` 为空。
5. **轮次切分。** 链内以 user 消息新增为 turn 边界；有 Hook `turn_id` 时以 Hook 为准。
6. **父子会话。** Hook `subagent_start` 有显式父子；没有时，若某链的 system prompt 指纹不同于主链、时间上嵌套于主链某个 turn 内、且 pid 相同，标 `parent_of` 为 `inferred` 0.6。Claude Code 的 subagent 与 Hermes 的 delegate 线程都属于这种情况，进程树帮不上忙。
7. **常驻多会话进程。** `hermes gateway` 一个 pid 交错服务多个会话：第 3 步按 pid 分组后，`prefix_chain` 会自然把交错的调用拆成多条链，这是选择 `prefix_chain` 而不是"同 pid 相邻即同会话"的原因。
8. **跨 run 延续。** 新 CaptureRun 的第一条链若与既有 Session 最后一次 inference 构成 `prefix_chain`，建 `continues` 关系。
9. **写入。** 所有 Session / Relation 以新 `relation_revision` 写入，旧关系标 `superseded_by`。未归属 attempt 计入 `Recording.coverage.unattributed_attempts`。

## 5. 晚到证据与修订

- 补传的批次、稍后到达的 Hook 事件、导入的 session 文件都触发同一 CaptureRun 的 `resolve` 重跑。
- 一次请求暂时无法归属时，照常进入请求列表；后续获得新证据再更新关联关系。页面上 `inferred` → `observed` 的升级、`unknown` → `inferred` 的补齐都显示为修订历史。
- 重跑只允许**提高**置信或**补充**关系；要推翻一条 `observed` 关系，必须有新的 `explicit_id` 级证据，否则记为 `conflict` 而不是静默改写。

## 6. 服务端状态链

对 `previous_response_id`、`conversation`、Gemini `cachedContent` 等引用：

- 引用目标在本 project 内已观察到：生成 `resolved_input_ref`（把被引用的历史与本次增量拼成客户端可重建的完整输入），`server_state = resolved`。
- 未观察到：`server_state = unresolved`，Session 上记录缺失节点，coverage claim 不得高于 `transport-complete`。
- 无论是否解析成功，原始 wire request 始终保留。

## 7. 明确不做的事

- 不用 LLM 猜归属。行为重建必须是确定性的，同样输入同样版本得到同样结果，否则证据链无法审计。
- 不合并跨 project 的会话。
- 不在证据不足时生成"看起来完整"的调用树。未归属数量本身是一个一等指标，出现在 coverage 和页面首屏。
