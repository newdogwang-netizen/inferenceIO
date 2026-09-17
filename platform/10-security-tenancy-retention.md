# 10 · 安全、租户与保留

> **当前实现边界（2026-09-16）**：Collector/project token、查询过滤和对象 key 已按 project 强制隔离；静态用户与 OIDC subject 目前只进入部署配置的默认 tenant/project。下文的单实例用户多项目模型仍是目标设计，OIDC group→project 映射和用户项目选择尚未落地；在此之前，多项目用户场景必须拆分部署，且不能从请求字段取得授权范围。

## 1. 数据分级

| 级别 | 内容 | 存放 | 默认是否上传 |
|---|---|---|---|
| L-meta | 事件元数据、header 白名单、usage、时间、ID、进程信息 | events、PostgreSQL | 是 |
| L-body | 模型请求 / 响应正文、工具结果、附件 | blob、对象存储 | 是，受内容策略约束 |
| L-interaction | PTY 输出 | blob | 否，需显式开启 |
| L-sensitive | pcap、TLS secrets、PTY 输入、环境变量白名单外的值 | 仅采集端本地，加密 | 否，需审批记录 |

L-sensitive 与采集端路线图 TLS-001 / SEC-001 的分级一致：`Authorization` 等凭证不进入 L-meta / L-body；pcap + key log 能解出凭证，所以整体归 L-sensitive。

## 2. 脱敏

两道关：

1. **采集端**（第一道，不可绕过）：按 `content_policy.redact_fields` 删除凭证 header、按模式替换正文中的凭证串（记录替换位置与类型，不记录原值）、按 `max_body_bytes` 截断并标 `truncated_by_policy`。`redaction` 字段随事件上传，平台知道哪些字段被处理过。
2. **平台**（第二道，兜底）：`normalize` 阶段再跑一次凭证模式扫描；命中即生成 `secret_in_prompt` Finding，并对该 blob 打 `quarantine` 标记，页面默认遮蔽，operator 可解除。

脱敏不可逆；平台从不持有原值。

## 3. 租户隔离

- 租户与 project 由认证决定，事件里的任何租户字段被忽略。
- 所有表带 `project_id`，查询层强制过滤；对象存储 key 以 `{tenant}/{project}/` 开头，服务端凭证按前缀限制。
- blob 去重只在 project 内进行，避免跨租户 hash 探测。
- 导出文件与签名 URL 绑定 project 与用户，默认 15 分钟过期。
- 首版单实例部署即可多租户，隔离靠应用层与 key 前缀；需要更强隔离时按 tenant 拆数据库，不改代码模型。

## 4. 加密

- 传输：全部 HTTPS；采集端校验平台证书，可配置 pin。
- 对象存储：服务端加密（SSE-S3 或 KMS），按 tenant 使用不同 KMS key 为后续选项。
- PostgreSQL：磁盘加密；`blobs.object_key` 等不含明文正文。
- 采集端本地：`tls.keys.enc`、pcap 落盘即加密，密钥在采集端 keyring；L-body 本地 blob 可选加密。

## 5. 审计

记录并可查询：谁启动了录制（collector + 发起用户）、谁查看了哪个 attempt 正文、谁导出、谁下发配置、谁审批了敏感层上传、谁删除。审计日志 append-only，保留期独立于业务数据，与采集端路线图 SEC-006 对应。

## 6. 保留与删除

| 数据 | 默认 TTL | 说明 |
|---|---|---|
| L-meta（PostgreSQL 事实与关系） | 365 天 | 可按 project 调整 |
| L-body（blob） | 90 天 | 到期后 attempt 保留元数据，`body_ref` 标 `expired` |
| 原始批次对象 | 与 L-body 相同 | 到期后 Recording 不可重跑，coverage 标 `raw_expired` |
| 派生缓存（`derived/`） | 30 天或随时 | 可再生 |
| 导出文件 | 7 天 | |
| 审计日志 | 730 天 | |
| 采集端本地已 ACK 事件 | 72 小时 | 由配置控制 |

删除传播（对应路线图 UP-006）：

1. 用户在平台发起 Recording / CaptureRun / Session 删除，进入 `deleting`。
2. 平台删对象、删派生、删事实，写审计。
3. 向对应 collector 下发 `delete_local` 请求（`collector-requests` 的一种），采集端删本地副本并回报；采集端离线时请求保留到上线。
4. blob 的 `ref_count` 归零才真正删除对象；被其他 Recording 引用的 blob 保留。
5. 删除完成后 Recording 行保留为 `deleted` 墓碑（只含 ID、时间、操作者）用于审计，可配置墓碑保留期。

当前实现把该流程持久化为 `deletion_requests` + `deletion_objects` 状态机。对象 key 在执行前先落库，删除租约过期后可由任意 API 副本接管；只有全部对象删除完成后才在事务内清理派生事实并写最小墓碑。删除请求一旦接受，摄取、派生任务、相关控制请求以及敏感查询/导出立即被围栏。对象前缀扫描会恢复先于数据库事务发布的 batch/export 和其中的 blob 引用；blob 上传在对象发布前先提交 `uploading` 意图，失败后可重试，超过安全窗口且没有任何 Recording 引用才会被审计回收。`recording_blob_refs` 是 project 内共享 blob 的权威引用表，只有目标范围外没有引用时才删除对象，`ref_count` 在每次批次登记和删除后重算。平台自动生成的 `delete_local` 没有过期时间，Collector 离线时持续保留；拒绝结果进入 `local_failed`，管理员修正本地策略后可重发。整 run 的显式本地删除仍须通过 Collector 本地策略，但有意不以完整上传为前置；自动 TTL 和 class-only 删除仍保持上传完成门禁。

由于不可变原始批次可能同时包含多个逻辑 Session，首版无法证明只擦除一个 Session 或单个 Recording 而保留同一 CaptureRun 的其他原件。为避免产生虚假的删除声明，`DELETE /recordings/{id}` 和 `DELETE /sessions/{id}` 会明确升级为整个 CaptureRun 删除；响应返回有效 CaptureRun 范围。项目管理员通过 `/v1/projects/current/retention` 配置 1～3650 天的原始证据/元数据期限，且元数据期限不得短于原始证据期限。缩短策略立即收紧现存期限，延长只作用于新数据。

原始证据 TTL 会删除批次、非共享 blob、导出对象和正文派生字段，保留结构化元数据并把 Recording 标为 `expired/raw_expired`；元数据 TTL 复用整 CaptureRun 删除链。首版删除墓碑和删除请求随独立审计保留，不自动物理清除；外部备份与存储介质销毁仍由部署方的 PostgreSQL/S3 生命周期与合规流程负责。

## 7. 医疗场景的额外约束

本项目的使用方涉及医疗数据，prompt 与工具结果可能包含 PHI。建议：

- 含 PHI 的 project 默认 `capture_bodies: false`，只录 L-meta 与结构（消息数、token、工具名），需要正文时按 Recording 显式开启并审批。
- 模型评审（07 §4）在这些 project 默认禁用。
- 导出 `normalized-jsonl` 需要 admin 角色并留审计。
- 数据驻留：对象存储与数据库部署在合规区域；首版单区域，多区域不在范围内。
