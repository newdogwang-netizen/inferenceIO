# 13 · 技术栈与中间件选型

原则：首版每一类基础设施只选一个，并且优先选"团队已经在运维的东西"。每项都写明备选和切换条件，避免把选型变成信仰。

## 1. 一览

| 类别 | 首版选型 | 备选 | 首版不选 |
|---|---|---|---|
| 后端语言 | Go 1.23+ | Rust（若采集端以 AgentSight 为基底） | Python 作主干 |
| 前端 | TypeScript + React 18 + Vite | Svelte | Next.js SSR（无 SEO 需求） |
| 事务库 | PostgreSQL 17 | PostgreSQL 16 | MySQL、MongoDB |
| 对象存储 | S3 兼容 API；开发用 MinIO，生产接现有 S3 / GCS | Azure Blob（通过兼容层） | 自建 Ceph |
| 任务队列 | PostgreSQL `processing_jobs` + `SKIP LOCKED` | NATS JetStream | Kafka、RabbitMQ、Temporal |
| 实时通知 | PostgreSQL `LISTEN/NOTIFY` 唤醒 + SSE | Redis Pub/Sub | WebSocket、独立推送服务 |
| 缓存 | 不引入 | Redis（SSE 多实例扇出时） | Memcached |
| 分析库 | 不引入 | ClickHouse（见 11） | Druid、BigQuery |
| 认证（用户） | OIDC，对接现有 IdP | 自建 Dex 作为 IdP 聚合 | 自研账号体系 |
| 认证（采集端） | 项目级 opaque token + 短期 JWT | mTLS | API key 明文长期有效 |
| 反向代理 / TLS | Caddy | Traefik、Nginx | 应用自己终止 TLS |
| 可观测性 | OpenTelemetry SDK → OTLP；后端接现有 Datadog 或 Grafana 栈 | Prometheus 直采 | 自研指标 |
| 容器与编排 | Docker Compose（首版）→ Kubernetes（拆分后） | Nomad | 直接 systemd |
| CI | GitHub Actions | GitLab CI | Jenkins |
| 密钥 | 1Password Connect / 环境注入 | Vault | 仓库内 .env |

## 2. 后端

### Go

- 单一静态二进制，采集端、API、Worker 共用一份事件协议、解码器、数据模型代码。
- eCapture 是 Go 项目，采集端 eBPF 兜底以子进程集成为主，语言一致便于复用其 pcapng / keylog 输出解析。
- 标准库 `net/http` 已足够做 SSE 与流式代理；不引入重框架。

| 组件 | 选型 | 说明 |
|---|---|---|
| HTTP 路由 | `net/http` + `go-chi/chi` | 轻量中间件链：请求 ID、认证、租户注入、限流、日志 |
| OpenAPI | `oapi-codegen` | 从 OpenAPI 3.1 生成服务端接口与 TS 客户端；API 契约先行 |
| 数据库驱动 | `jackc/pgx/v5` | 原生协议、`LISTEN/NOTIFY`、COPY 批量写 |
| SQL 层 | `sqlc` | 手写 SQL 生成类型安全代码；不用 ORM，任务队列与 revision 查询需要精确 SQL |
| 迁移 | `pressly/goose` | 纯 SQL 迁移文件，随 API 镜像启动执行 |
| 对象存储 | `minio/minio-go/v7` | 兼容任何 S3 API；需要签名 URL、条件写（`If-None-Match`）保证 blob 幂等 |
| 压缩 | `klauspost/compress/zstd` | 批次编码；纯 Go 无 cgo |
| 哈希 | 标准库 `crypto/sha256` | |
| 配置 | `knadh/koanf` | 环境变量 + 文件，层叠覆盖 |
| 日志 | 标准库 `log/slog` | JSON 输出，携带 request_id / project_id / recording_id |
| 遥测 | `go.opentelemetry.io/otel` | trace + metrics，OTLP 导出 |
| 校验 | `santhosh-tekuri/jsonschema/v6` | 事件与批次头按共享 JSON Schema 校验（见 §6） |
| 测试 | `testcontainers-go`（PostgreSQL、MinIO） | 集成测试跑真实依赖，不 mock 数据库 |
| OIDC | `coreos/go-oidc/v3` | 校验 ID token，从 claims 映射租户与角色 |
| 限流 | `golang.org/x/time/rate` 按 project 键控 | 内存令牌桶；多实例后改 Redis 或在 Caddy 层限 |

### 任务队列为什么先用 PostgreSQL

- 任务状态本来就要落库（租约、重试次数、去重键），再引入一个队列只是多一份状态。
- `FOR UPDATE SKIP LOCKED` 在每秒数百任务量级下没有瓶颈；首版 20 个采集端远低于此。
- 切换条件：领取延迟 P95 超过 1 秒，或任务表锁等待成为慢查询前列。切到 NATS JetStream 时 PostgreSQL 仍是任务状态事实源，JetStream 只做分发。

### 实时通知为什么用 LISTEN/NOTIFY + SSE

- outbox 表事务性写入，API 进程 `LISTEN` 后推给已连接的 SSE 客户端；断线用 cursor 从 outbox 表补。
- 单 API 实例时零额外组件。多实例后每个实例都 `LISTEN`，各自推给自己的连接，仍不需要 Redis；只有连接数到数千才考虑独立扇出。

## 3. 前端

| 组件 | 选型 | 说明 |
|---|---|---|
| 框架 | React 18 + TypeScript + Vite | |
| 路由 | TanStack Router | 类型安全路径参数（recording_id、attempt_id） |
| 数据 | TanStack Query | 与 SSE 配合：收到 `entity.updated` 后按实体 key 失效缓存 |
| API 客户端 | `oapi-codegen` 生成的 TS 客户端或 `openapi-fetch` | 与后端同一份 OpenAPI |
| UI | Radix Primitives + Tailwind | 不锁进重组件库 |
| 长列表 | TanStack Virtual | 时间线与 SSE 事件列表可达数万行 |
| diff | `diff`（jsdiff）+ 自绘 message 级对齐 | 输入 diff 的 message 级对齐由后端算好（07 §3），前端只渲染文本级 |
| JSON 查看 | 自绘折叠树 | 正文 blob 按需拉取，不整段塞进状态 |
| 图 | 首版不引入 | Session 父子关系用缩进列表表达；需要图时用 `@xyflow/react` |
| 测试 | Vitest + Playwright | |

## 4. 数据层

### PostgreSQL 17

- 单主 + 每日快照 + WAL 归档；托管服务（RDS / Cloud SQL）优先。
- 连接池：应用内 `pgxpool`，每实例 ≤ 20 连接；实例增多后前置 PgBouncer（事务模式）。
- 分区：`relations`、`model_attempts` 按 `project_id` hash 分区在首版**不做**；行数过亿再做，分区键已在主键前缀里。
- 扩展：不依赖任何非默认扩展，方便托管迁移。`pg_trgm` 在需要正文搜索时再加。

### 对象存储

- 桶策略：单桶多前缀（02 §5），版本控制开启，生命周期规则按前缀设 TTL（`derived/` 30 天、`exports/` 7 天）。
- 幂等写：`PUT` 带 `If-None-Match: *`，已存在返回 412 视为成功。
- 服务端加密开启；访问凭证按前缀最小权限（API 可写 `recordings/` `blobs/`，Worker 可写 `derived/` `exports/`，Web 只经签名 URL）。
- 本地开发与 CI 用 MinIO 容器。

## 5. 安全组件

| 项 | 选型 |
|---|---|
| 用户认证 | OIDC Authorization Code + PKCE；前端不持有 client secret；后端换取并校验 |
| 角色 | claims 中的 group → 平台角色映射表；映射存 PostgreSQL，admin 可改 |
| 采集端凭证 | 注册用项目级 opaque token（哈希存储、可吊销）；注册后签发 1 小时 JWT，续期走 heartbeat |
| 签名 URL | 对象存储原生 presign，15 分钟 |
| 审计 | 独立 `audit_log` 表，append-only，触发器禁止 UPDATE/DELETE |
| 凭证扫描 | `gitleaks` 规则集移植为正文脱敏模式（10 §2） |
| 依赖扫描 | `govulncheck`、`npm audit`，CI 阻断高危 |

## 6. 契约与代码生成

契约先行，三份文件在 `schemas/` 目录，采集端与平台仓库同时引用：

| 文件 | 描述 | 生成物 |
|---|---|---|
| `schemas/event.v1.schema.json` | 事件 envelope（03 §1～2） | Go 结构体（`go-jsonschema`）、TS 类型（`json-schema-to-typescript`） |
| `schemas/batch.v1.schema.json` | 批次头（03 §3） | 同上 |
| `schemas/capabilities.v1.schema.json` | 能力清单（09 §2） | 同上 |
| `api/openapi.yaml` | 平台 API（08） | Go 服务端接口、TS 客户端 |

CI 规则：schema 文件改动必须同时更新 `CHANGELOG`，且只允许新增可选字段；破坏性变更必须新建 `v2` 文件。采集端 CI 拉平台仓库的 schema 做校验，平台 CI 用采集端 fake collector 的样例批次做回归。

## 7. 可观测性

- 三个后端进程都用 OTel SDK，trace 上下文从批次上传一直贯穿到 Worker 任务（任务表存 `traceparent`）。
- 指标最少集：批次接收速率与延迟、`durable_seq - parsed_seq`、任务积压与 dead 数、SSE 连接数、对象存储错误率、按 project 的存储用量。
- 导出到现有平台：团队已用 Datadog 则 OTLP → Datadog Agent；否则 Compose 内带 Grafana + Prometheus + Tempo + Loki 的最小栈。
- 日志统一 JSON，字段名与 trace 属性一致。

## 8. 部署与交付

- 三个镜像（`platform-api`、`pipeline-worker`、`web-console`）+ 采集端二进制，distroless 基础镜像，多架构（amd64 / arm64）。
- Compose 文件分 `compose.yaml`（生产最小）与 `compose.dev.yaml`（加 MinIO、Grafana 栈、热重载）。
- Caddy 作为唯一入口：自动 TLS、把 `/v1/*` 转到 API、其余转到 Web；SSE 需要关闭响应缓冲。
- 版本：语义化版本；API 路径 `/v1` 与事件 `schema_version` 独立。
- Kubernetes：拆分阶段再写 Helm chart，首版不做。

## 9. 实现时的偏差

首版实现（`iorec-platform/`）相对本文的偏差，均为减少工具链而非改变架构：内嵌最小迁移器替代 goose，手写 SQL + pgx 替代 sqlc，react-router-dom 替代 TanStack Router，手写 CSS 替代 Radix + Tailwind，outbox 轮询替代 LISTEN/NOTIFY 唤醒。详见仓库 README。

## 10. 明确不选与原因

| 不选 | 原因 |
|---|---|
| Kafka / Redpanda | 首版吞吐与运维成本不匹配；PostgreSQL 队列够用，切换路径已留 |
| Temporal | 流水线是简单 DAG，任务表 + 版本化重跑已覆盖；引入会带来第二套状态机 |
| Redis | 无缓存热点；SSE 扇出单实例不需要；等到多实例且连接数上千再评估 |
| gRPC 对外 | 采集端只需 HTTPS + 批次 POST，穿透企业代理更容易；内部服务间首版无 RPC |
| GraphQL | 页面查询形状固定，REST + 生成客户端足够 |
| ORM | revision 查询、`SKIP LOCKED`、部分索引都需要手写 SQL |
| 微服务拆分 | 见 11 §3，按瓶颈拆 |
