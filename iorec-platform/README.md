# iorec-platform

Agent Inference Flight Recorder 的平台侧：接收采集端（`iorec` / `capture-agent`）上传的原始事件，归档、重建请求与会话关系、重算 coverage、运行规则分析，并提供控制台。

Coverage 重算是 fail-closed 的：平台自有的 `transport_audit` 阶段只从原始对象重建证据，验证 task-egress 启停终态，使用固定的 TShark 4.4.18 重组 HTTP/1.1/HTTP/2，并对 request/response body 做精确多集合比对。只有 schema、边界和 processor version 完全匹配且零 gap 时，coverage 才接受 `platform_transport_proof_verified`；零计数或采集端 manifest 不能设置该字段。该 proof 只证明受控 task-egress 和 proxy/wire 对账，最终 completeness 仍由 coverage 叠加 drop、unknown egress、model bypass、parser、终态和 missing-blob 门槛。

当前 schema-v3 的真实正/反导入证据记录在 [`../benchmarks/2026-09-16-platform-transport-audit-linux-x86_64.json`](../benchmarks/2026-09-16-platform-transport-audit-linux-x86_64.json)：正样本由生产 API/Worker 镜像生成平台 proof 后达到 `client-complete`；被 nftables 阻断的直连反样本虽然已知模型 payload 对账一致，仍因 `unknown_egress=2` 保持 `best-effort`。历史 schema-v2 bundle 在缺少当前严格边界字段时也会 fail closed 为 incomplete。

设计文档在 [`../platform/`](../platform/README.md)，本仓库实现其 P0～P4
发布路径；明确后置的扩展能力列在文末，不能从当前发布状态继承为已支持。

## 组成

| 目录 | 内容 |
|---|---|
| `schemas/` | 与采集端共享的 JSON Schema：`event.v1`、`batch.v1`、`capabilities.v1`（契约，见 platform/03、09） |
| `api/openapi.yaml` | 平台 API 契约（platform/08） |
| `migrations/` | PostgreSQL 表结构（platform/02 §3） |
| `internal/protocol` | envelope / 批次编解码 / schema 校验，可被采集端以 Go module 引用 |
| `internal/ingest` | 批次接收、提交边界、`durable_seq`、幂等与冲突、blob、seal、run 目录导入（platform/04） |
| `internal/jobs` | PostgreSQL 任务队列：租约、重试、去重（platform/05 §2） |
| `internal/pipeline` | decode → assemble → normalize → resolve → transport_audit → coverage → rules，以及输入 diff（platform/05～07） |
| `internal/exporter` | admin-only 异步 normalized JSONL 导出、对象完整性复核、认证下载、7 天到期清理与审计 |
| `internal/control` | 采集端注册、能力、心跳、版本化配置、collector-requests（platform/09） |
| `internal/query` | 控制台读模型 |
| `internal/notify` | 事务性 outbox + SSE |
| `internal/auth` | 项目 token / 采集端会话 token / 静态用户 token / OIDC；租户来自凭证 |
| `cmd/platform-api` `cmd/pipeline-worker` | 两个部署单元 |
| `cmd/fake-collector` | 生成 Hermes 风格的 run 并上传，支持故障注入（丢批、乱序、坏 hash、冲突、断连、纯代理无 Hook） |
| `web/` | React + TypeScript 控制台 |
| `deploy/` | Dockerfile × 3、Caddyfile、`compose.yaml`、`compose.dev.yaml` |

## 本地运行

```bash
make db-up                      # Docker 起 PostgreSQL 17（端口 54329）
make build
make run-api &                  # dev 认证模式，http://127.0.0.1:8080
make run-worker &
make fake                       # 上传一个带故障注入的 Hermes 风格 run
open http://127.0.0.1:8080      # 若设置了 IOREC_WEB_DIR=web/dist；或 cd web && npm run dev
```

fake collector 的两个关键场景：

```bash
bin/fake-collector --token $IOREC_BOOTSTRAP_PROJECT_TOKEN --drop-batch 2 --corrupt-hash 4 --conflict 5
bin/fake-collector --token $IOREC_BOOTSTRAP_PROJECT_TOKEN --no-hooks --register=false   # 纯代理，无任何 session/inference ID
```

第二个场景验证平台在**没有 session ID** 时仍能靠 `prefix_chain` 重建出同样的会话 / 轮次 / 子 Agent 结构（置信度 0.95，标 `inferred`）。

真实 recorder 支持两条摄取路径：

```bash
# 可恢复的在线批次上传；生产环境要求 HTTPS，token 文件必须是 0600
iorec upload ./runs/<run-id> --api https://iorec.example.com \
  --token-file ./platform.token --key-file ./iorec.key

# 显式解密为私有离线包后导入；bundle 是明文证据，硬上限 5 GiB
iorec export ./runs/<run-id> --format platform \
  --output ./run.platform.tar --key-file ./iorec.key
curl --fail-with-body -X POST :8080/v1/recordings:import \
  --data-binary @run.platform.tar -H "Authorization: Bearer $TOKEN"
```

在线 uploader 固定 2,000 事件/4 MiB 的批次计划，先按 SHA-256 去重上传普通 body blob，再上传 zstd NDJSON；普通上传和 backfill 会强制排除 pcap 与 TLS secrets，即使旧 spool 曾错误列出也会在消费前清除。它以平台 `durable_seq` 为准幂等恢复，并在所有事件 ACK 后携带 manifest 与 digest 封存。因而普通在线 run 的平台 transport proof 明确为 `unavailable`，不会假装 complete；需要服务器侧复核敏感传输证据时，operator 必须走受控的明文 platform bundle 导入边界。重复 seal 不会重复派生任务。平台按版本化的 `agent-task-or-session-v1` 策略在整个 CaptureRun 上重建逻辑任务：原生 `task_id` 优先，否则以 `session_id` 保守兜底；任务跨 Recording 分段保持稳定，并出现在 timeline、inference、attempt 与 Web 控制台中。

平台默认配置分别下发整 run 168 小时、body 72 小时、pcap 24 小时和 TLS secrets 24 小时的本地保留期。collector 只有在本地显式启用 `--allow-remote-delete` 时才接受这些值，class TTL 还必须配置本地加密 key；否则会在心跳的 rejected config 中报告原因。operator 创建 `delete_local` 请求时可在 payload 中加入 `"class":"body|pcap|tls_secrets"`，只销毁对应 class 的 wrapped key 与 ciphertext；不带 class 时保持整 run 删除语义。collector 的 capability 声明让平台在下发前识别 whole-run delete、class-keyed encryption、独立 class TTL 和 class delete request 支持。

平台端另有持久化保留/删除状态机。admin 对 CaptureRun、Recording 或 Session 发起带精确确认值的 DELETE 后，平台立即冻结摄取、派生任务、相关控制请求以及敏感读取/导出，再把批次/blob/export 对象清单持久化并以可接管租约分批删除，最后事务化清理事实表、写 append-only 审计并保留最小墓碑。对象前缀扫描会找回“对象已发布但数据库提交前崩溃”的 batch/export 与 blob 引用；blob 自身在发布前先写持久化 `uploading` 意图，失败后可重试，超过安全窗口且确定无引用才审计回收。Recording/Session 原始字节无法安全切分时会明确升级为整个 CaptureRun 擦除；共享 blob 只有 project 内引用归零才删除。自动生成的 `delete_local` 不设过期时间，离线 Collector 上线后继续接收；拒绝会显示为 `local_failed`，修正本地策略后可由 `/v1/deletions/{id}:retry-local` 重发。整 run 显式删除仍受 Collector 本地允许策略约束，但不会因上传未完成而变成不可删除；自动 TTL 与 class-only 删除继续要求完整上传。`GET/PUT /v1/projects/current/retention` 管理原始证据与元数据 TTL，缩短策略同步收紧现存期限，延长仅影响新数据。

版本化配置支持 project 默认与 collector 覆盖两级作用域。operator 通过 `PUT /v1/projects/current/collector-config` 替换 project 文档，通过 `PUT /v1/collectors/{id}/config` 设置 collector 深层覆盖，并可用同路径 `DELETE` 清除覆盖。平台在事务内为每次变更选择高于两级现有值的全局单调版本，返回带 `scope` / `config_version` 的合并结果；heartbeat 促使旧版本 collector 重新注册。每次更新均按认证 project 隔离并写不可变审计，collector 上报的 `effective_config` 仍单独保存为实际执行反馈。

## 测试

```bash
TEST_DATABASE_URL=postgres://iorec:iorec@127.0.0.1:54329/iorec_test make test
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
cd web && npm ci --no-audit --no-fund && npm run build && npm audit --omit=dev --audit-level=high
```

Go 1.25.13 is the minimum build version. Production Docker stages use exact toolchain/runtime versions and multi-architecture image digests; `.dockerignore` excludes VCS data, local binaries, object data, dependency/build directories, logs, private environment files, keys, and certificates from the build context.

`internal/ingest` 的集成测试覆盖 ACK 语义：乱序时 `durable_seq` 不前进、补洞后跳跃、相同批次幂等短路、同 ID 不同内容 409、区间重叠 409、坏 hash 400、Recording 身份绑定、manifest digest、seal 幂等/冲突、封存后补传、跨项目 403、blob 去重按项目隔离，以及有界流式 tar 导入。`internal/pipeline` 覆盖 OpenAI / Anthropic / Responses 的请求规范化与流重组、prefix_chain / response_id_chain 证据、输入 diff、重处理代际传播、跨 Recording 的交错任务切分与 Resolve 幂等性，以及 H1/H2/padded DATA 解码、严格 source-boundary 字段、对象 SHA/长度、proof 持久化、proof 撤销和 coverage fail-closed 消费。

文件对象存储对租户/项目/Recording 标识逐段转义，拒绝绝对路径与 `..` 逃逸，校验声明大小，以 fsync + 原子 no-replace 发布；S3 使用条件写避免并发覆盖。发布后会反读并校验不可变对象，防止数据库事务失败留下的孤儿键毒化后续目录。HTTP JSON、请求 ID、collector 注册/心跳、能力声明、collector-request 状态机和手工处理参数都有显式大小、类型与取值边界。API 默认按认证 project 执行每分钟 6,000 请求、burst 200 的副本内令牌桶，并在 PostgreSQL advisory lock 下原子执行 100 GiB 原始证据配额；多副本部署仍须在共享入口加全局限流。

## 部署

```bash
cp deploy/.env.example deploy/.env   # 填 token 与密码
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d --build
```

Caddy 以 UID/GID 65532 在容器内的非特权 `:8080` 统一入口提供服务：`/v1/*` → `platform-api`，其余 → 静态控制台。Compose 默认只发布到 `127.0.0.1`，设置 `IOREC_BIND_ADDR` 才能显式改变；Caddy 给 API/静态资源统一添加 CSP、反 framing、nosniff、referrer/permissions/cross-origin 头并移除 Server 头。单机 Compose 默认让 API 与 Worker 共享一个命名卷中的文件对象存储，避免依赖已停止维护的社区 MinIO 镜像。API、Worker 与 Web 均使用只读根文件系统、全 capability drop 和 `no-new-privileges`；只有显式卷或带 `noexec,nosuid,nodev` 的 tmpfs 可写。所有服务使用 20 MiB × 5 的本地 JSON 日志轮转；多机部署还应接入受访问控制的集中日志。Worker 镜像另固定 Debian 13.2 digest 与 TShark 4.4.18，启动时记录解码器版本和 SHA-256，删除 `dumpcap` 并清除镜像内所有 setuid/setgid 位，敏感临时文件仅进入私有 `/tmp`。多机生产环境应把 `DATABASE_URL` 与 `OBJECT_STORE_*` 指向托管 PostgreSQL 与 S3，并删掉内置的 `postgres` 服务；公网入口必须在 Caddy 前终止 TLS。

## 认证

| 主体 | 方式 | 环境变量 |
|---|---|---|
| 采集端 | 项目 token `iorp_…` 注册后换取 1 小时会话 token `iorc_…` | `IOREC_BOOTSTRAP_PROJECT_TOKEN` |
| 用户（dev） | 无 token 即 admin，`X-Dev-User` 指定身份 | `IOREC_AUTH_MODE=dev` |
| 用户（token） | 静态 bearer → `subject:role` | `IOREC_AUTH_MODE=token IOREC_USER_TOKENS="tok=alice@x:admin,..."` |
| 用户（OIDC） | 校验 ID token，`email` 作 subject，角色查 `user_roles` | `IOREC_OIDC_ISSUER` `IOREC_OIDC_CLIENT_ID` |

角色：`viewer` < `reviewer`（裁决 Finding）< `operator`（重跑、下发采集端请求、导入）< `admin`。

生产 project token 必须由密码学随机源生成并至少包含 32 个随机字节；不要沿用 Makefile / `compose.dev.yaml` 的开发占位值。例如：

```bash
printf 'iorp_%s\n' "$(openssl rand -hex 32)"
```

把结果交给部署环境的 secret manager；不要写入版本库、普通日志或命令行参数。静态用户 token 同样需要高熵，公网浏览器部署优先使用下述 OIDC-aware ingress。

生产浏览器访问应在 Caddy 前使用 OIDC-aware ingress / identity proxy 完成登录，并把已验证的 Bearer token 注入转发请求；API 仍会独立校验 issuer、audience 和签名。该前置层还必须限制可信 Origin、启用 CSRF 防护，并给浏览器会话 cookie 设置 `Secure`、`HttpOnly` 和适当的 `SameSite`。内置 SPA 不实现 Authorization Code redirect、refresh token 或服务端会话。手工写入 `localStorage` 的静态 token 仅用于本机或受控运维：该模式不会启动不能设置 Authorization header 的原生 EventSource，直接 blob 导航也不能附加 bearer header。含 PHI 的公网部署不得把这种静态-token 模式当作 SSO。

## 与设计文档的偏差

- 迁移用内嵌的最小迁移器（按文件名顺序、advisory lock），不用 goose；SQL 手写并直接用 pgx，不用 sqlc。理由：首版表数量少，少一层工具链。
- 前端路由用 react-router-dom 而非 TanStack Router；UI 用手写 CSS 而非 Radix + Tailwind。功能等价，依赖更少。
- 派生事件索引表 `recording_events` 是设计文档未列出的可重建表：Worker 需要按 attempt / inference 随机访问事件，从对象存储逐批重读不现实。它可以从批次原件完全重建。
- 采集端给的 attempt / inference / session ID 只在 run 内唯一，平台主键为 `<run>~<native_id>`，原始 ID 存 `native_id` 列。
- 实时通知先用 1 秒轮询 outbox 而非 `LISTEN/NOTIFY` 唤醒；连接数上来后再换。
- 导出文件通过 admin-only 认证 API 流式下载，而不是由对象存储签发 URL；文件对象存储与 S3 因而共用同一授权和审计路径。对象仍有 7 天 TTL，并在发布前反读复核长度与 SHA-256。

## 明确后置 / 当前限制

- 最终 Compose/E2E 与 20-collector Gate 使用共享文件对象后端。S3 适配器已实现不可变条件写、反读长度/摘要校验和 project 前缀，但尚无绑定最终版本的 AWS S3 / MinIO / GCS 兼容性矩阵，且当前仅接受静态 V4 access/secret，不支持 workload identity。多节点部署必须先在目标对象存储做同版本资格测试，不能继承本地文件后端的结论。
- 内置 Web 不提供 OAuth 登录/登出与 cookie session；生产 OIDC 浏览器流程必须由前置身份代理承担。静态 browser token 模式只适合受控运维，并缺少实时 SSE 与直接 blob-link 认证；普通 API 查询和显式 `fetch` 导出仍可使用 bearer header。
- 用户静态 token 与 OIDC subject 当前只映射到部署时配置的默认 tenant/project；Collector/project token、数据库查询和对象 key 仍强制 project 隔离，但单实例内的用户多项目选择及 OIDC group→project 映射尚未提供。需要多个用户项目时应先按 tenant/project 拆分部署，不能把请求字段当作授权范围。
- 平台端 OpenInference / OTLP / replay-bundle 转换（本地 `iorec` 已支持这些格式；平台现已支持有界的 `normalized-jsonl` export 任务）。
- 模型评审（`eval` 任务）。
- 跨 CaptureRun 的 `continues` 关系。
