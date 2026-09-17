# Agent Inference Flight Recorder：平台侧设计

> 版本：Draft v1  
> 日期：2026-09-15  
> 上游文档：[调研](../agent-inference-io-capture-research.md) · [采集端路线图](../agent-inference-flight-recorder-feature-roadmap.md)

## 前提

- 拿不到 Agent 源码，但能够进入运行环境（控制启动命令、环境变量、容器或宿主）。
- 业务 session 可能无法直接识别，平台必须在没有 session ID 的情况下也能工作。
- 模型推理仍发生在客户环境与原模型服务之间，平台不在推理路径上。
- 平台不在线时，采集端按本地策略继续录制；平台只负责归档、重建和分析。

## 一句话架构

**四个部署单元、七个业务模块、两类核心存储**，采集端与平台之间通过**统一事件协议**（数据面）和**采集管理协议**（控制面）连接。

| 部署单元 | 位置 | 一句话职责 |
|---|---|---|
| `capture-agent` | 客户主机 / 容器附近 | 就是采集端路线图里的 `iorec`：启动或接入 Agent、采集、落盘、上传、能力上报 |
| `platform-api` | 平台服务端 | 接收数据、管理采集端、查询、实时通知、访问控制 |
| `pipeline-worker` | 平台服务端 | 解码、重组、关联、分析、导出；可多副本 |
| `web-console` | 平台前端 | 录制管理、请求检查、时间线、分析与采集状态 |

| 业务模块 | 首版归属 |
|---|---|
| 采集管理 | API |
| 数据接收 | API |
| 录制目录 | API |
| 协议处理 | Worker |
| 行为重建 | Worker |
| 分析与评估 | Worker |
| 查询与展示 | API + Web |

| 核心存储 | 保存什么 |
|---|---|
| 对象存储 | 原始事件批次、大正文、附件、导出文件；永远保留可重新解析的原件 |
| PostgreSQL | 录制目录、批次索引、请求元信息、关系、发现、任务；首版业务事实与查询主库 |

## 实现

平台代码在 [`../iorec-platform/`](../iorec-platform/README.md)：Go 后端（`platform-api`、`pipeline-worker`、`fake-collector`）、React 控制台、共享 schema、Compose 部署。

## 文档索引

| 文件 | 内容 |
|---|---|
| [01-architecture.md](01-architecture.md) | 总体架构、部署单元、采集端内部组件、七个业务模块、设计原则 |
| [02-data-model.md](02-data-model.md) | 核心对象、与采集端 ID 层级的映射、PostgreSQL 表结构草案、对象存储 key 布局 |
| [03-event-and-batch-protocol.md](03-event-and-batch-protocol.md) | 统一事件协议：事件 envelope、批次格式、blob 引用、hash、版本 |
| [04-ingestion-and-commit.md](04-ingestion-and-commit.md) | 接收链路的提交边界、ACK 语义、幂等与冲突、双写失败处理、四个进度指针 |
| [05-processing-pipeline.md](05-processing-pipeline.md) | Worker 任务模型、租约、流式重组检查点、版本化重跑 |
| [06-behavior-reconstruction.md](06-behavior-reconstruction.md) | 行为重建：证据类型、置信度、无 session ID 时的会话推断、晚到证据与修订 |
| [07-analysis-and-findings.md](07-analysis-and-findings.md) | 确定性规则、输入 diff、可选模型评审、Finding 生命周期、coverage 呈现、导出 |
| [08-api-and-realtime.md](08-api-and-realtime.md) | 平台 API 资源、请求/响应示例、SSE 实时通知、认证与错误格式 |
| [09-collector-control.md](09-collector-control.md) | 采集管理协议：注册、能力、健康、版本化配置、补传请求 |
| [10-security-tenancy-retention.md](10-security-tenancy-retention.md) | 租户隔离、数据分级、脱敏、加密、保留与删除传播 |
| [11-deployment-and-scaling.md](11-deployment-and-scaling.md) | 首版 Docker Compose 部署、运维要点、按瓶颈拆分 |
| [12-alignment-with-recorder-roadmap.md](12-alignment-with-recorder-roadmap.md) | 与采集端路线图的对齐、平台侧里程碑、已决配置与后置项 |
| [13-tech-stack-and-middleware.md](13-tech-stack-and-middleware.md) | 技术栈与中间件选型：语言、框架、库、队列、通知、认证、可观测性、明确不选项 |
| [14-kickoff-plan.md](14-kickoff-plan.md) | 启动计划：团队、仓库布局、前六周任务、第一周决策、检查清单 |

## 首版开发边界

**采集端生成可靠文件；API 可靠接收；Worker 重建请求和关系；控制台展示时间线、原始 I/O、输入 diff 与带证据的分析发现。**

首版明确不做：独立消息系统、ClickHouse、用户自定义代码评估器、多区域部署、在线修改模型请求。

开发节奏：平台与采集端并行，以 v0.1 事件 envelope 为契约；平台轨道里程碑 P0～P4 见 12 号文档与采集端路线图 §3.2，启动计划见 14 号文档。

## 术语对照

采集端文档和平台文档各自有命名习惯，下表是唯一权威映射，两边不再互相替代。

| 采集端（iorec / 路线图） | 平台对象 | 说明 |
|---|---|---|
| `run_id` | `CaptureRun` | 一次受控运行或观察范围 |
| `run/` 目录中的一段 `events.jsonl` + 其 blob | `Recording` | 上传、封存、导出的单位；一个 CaptureRun 可滚动出多个 Recording |
| `agent_session_id` / `turn_id` | `Session`（含 `turns`） | 原生或推断的业务会话 |
| `inference_id` | `ModelInference` | 逻辑上的一次模型调用；可能只是推断出来的分组 |
| `attempt_id` | `ModelAttempt` | 一次实际观察到的网络尝试；平台上的一等事实 |
| `connection_id` | `ModelAttempt.connection_id` | 不单独建对象 |
| `parent_span_id` 与各种父子关系 | `Relation` | 统一为带证据和版本的关系对象 |
| `manifest.json` / coverage manifest | `Recording.coverage` | 平台重新计算，不直接信任采集端声明 |
| `client-complete` / `transport-complete` / `server-effective-complete` | `Recording.coverage.claim` | 三个值原样保留，另加 `best-effort` 与 `unknown` |
