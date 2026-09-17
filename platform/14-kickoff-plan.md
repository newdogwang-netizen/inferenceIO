# 14 · 平台启动计划

> **状态（2026-09-16）**：平台仓库已在 [`../iorec-platform/`](../iorec-platform/README.md) 落地，P0～P4 发布路径均已实现；最终 20-collector、18,000 秒故障注入验收正在运行。明确后置项与当前限制见仓库 README。下文的周计划仅保留为历史排期记录。

目标：**2 周内平台仓库可运行，6 周内能接收真实 `iorec` 上传并在控制台看到 attempt 列表。** 对应路线图平台轨道 P0～P1。

## 1. 团队与角色

| 角色 | 人数 | 负责 |
|---|---|---|
| 平台后端 | 1～2 | `platform-api`、`pipeline-worker`、schema、迁移 |
| 前端 | 1（可后置 2 周） | `web-console` |
| 采集端对接人 | 采集端团队指定 1 人 | 共同维护 `schemas/`、提供 fake collector 与真实样例 |

## 2. 仓库布局（monorepo）

```text
iorec-platform/
  schemas/                 # 事件、批次、能力清单 JSON Schema（与采集端共享，见 13 §6）
  api/openapi.yaml         # 平台 API 契约
  cmd/
    platform-api/
    pipeline-worker/
    fake-collector/        # 生成合法批次、模拟断网/乱序/冲突
  internal/
    protocol/              # envelope、批次编解码、校验（采集端可复用）
    ingest/                # 校验、对象写入、事务登记、durable_seq
    catalog/               # recordings、batches、blobs
    jobs/                  # 任务领取、租约、重试
    decode/ assemble/ normalize/ resolve/ coverage/ rules/
    control/               # collectors、config、collector-requests
    query/                 # 时间线、attempt、session、finding 读模型
    notify/                # outbox、LISTEN/NOTIFY、SSE
    auth/                  # OIDC、collector token、租户注入
  migrations/              # goose SQL
  web/                     # Vite + React
  deploy/
    compose.yaml
    compose.dev.yaml
    Caddyfile
  docs/                    # 本目录的文档迁入
  .github/workflows/
```

`internal/protocol` 设计为可被采集端仓库以 Go module 方式引用，避免两份编解码实现。

## 3. 前两周（P0：契约与骨架）

### 第 1 周

- [ ] 建仓库、CI（lint、test、镜像构建）、Compose dev 环境（PostgreSQL、MinIO、Caddy）。
- [ ] 与采集端一起把 03 §1～3 写成 `schemas/*.schema.json`，生成 Go / TS 类型。
- [ ] `api/openapi.yaml` 覆盖 08 §1 全部资源的路径与 schema，先只实现 `recordings`、`batches`、`blobs`。
- [ ] `migrations/0001_init.sql`：02 §3 的全部表。
- [ ] `fake-collector`：从一份录好的 `run/` 目录或内置样例生成批次，支持 `--drop-batch`、`--reorder`、`--corrupt-hash`、`--disconnect-after`。

### 第 2 周

- [ ] `ingest`：校验清单（04 §2）、对象写入、事务登记、`durable_seq` 连续推进、幂等短路、409 冲突。
- [ ] `jobs`：领取 / 续约 / 重试 / dead；Worker 进程骨架。
- [ ] 集成测试：fake collector 全部故障模式 × ingest，断言 ACK 语义与 04 §4 规则。
- [ ] 采集端联调点 1：真实 `iorec` 的 v0.1 输出经 `internal/protocol` 切批后能被接收。

**P0 Gate**：采集端与平台 CI 双向引用同一份 schema；fake collector 全部用例通过。

## 4. 第 3～6 周（P1：可靠接收与最小展示）

| 周 | 后端 | 前端 |
|---|---|---|
| 3 | `decode`：HTTP/1.1、SSE、Hook 结构体；`assemble` 与 `assembly_state` 检查点 | 项目骨架、OIDC 登录、Recording 列表 |
| 4 | `normalize`：api_mode 识别、messages 规范化视图、fingerprint / input_hash；`parsed_seq` 推进 | Recording 详情四态（上传中 / 已归档 / 解析受阻 / 正在分析） |
| 5 | `notify`：outbox、LISTEN/NOTIFY、SSE 端点；`query`：attempt 列表与详情读模型 | attempt 列表、attempt 详情（raw / normalized、SSE 事件到达时间） |
| 6 | `control` 最小版：collector 注册、心跳、能力清单存储；文件导入 `recordings:import` | Collectors 页面（在线状态、能力快照）；SSE 驱动的列表刷新 |

**P1 Gate**：Hermes 一次真实会话经 `iorec` 上传后，控制台能看到每个 attempt 的请求正文、SSE 事件与终态；拔网线 10 分钟再恢复，`durable_seq` 无重复无缺口；解析器故意抛错时页面显示"解析受阻"而不是录制失败。

## 5. 第 7 周起（P2 预告）

`resolve`（06 算法）、coverage 重算、时间线、输入 diff、Finding 骨架。P2 需要采集端 M1 的显式 ID 事件（Hermes plugin、Claude hooks）作为测试输入，在第 6 周前向采集端要一批真实样例。

## 6. 第一周必须定下来的决策

| 决策 | 建议 | 决定人 |
|---|---|---|
| IdP | 接现有公司 SSO（OIDC） | 平台负责人 + IT |
| 生产对象存储 | 现有云的 S3 兼容服务，单区域 | 平台负责人 |
| 可观测性后端 | 现有 Datadog；无则 Compose 内 Grafana 栈 | 平台负责人 |
| Recording 切段 | 512 MB 或 1 小时先到先切 | 采集端 + 平台 |
| 含 PHI project 默认策略 | 默认不录正文，按 Recording 审批开启 | 产品 + 安全 |
| 仓库归属 | 平台独立仓库，`schemas/` 由两队共同 CODEOWNERS | 两队负责人 |

## 7. 每周固定动作

- 采集端 / 平台 30 分钟契约同步会：schema 变更、样例数据、联调问题。
- 每周五把 fake collector 用例和真实样例跑一遍全链路，结果贴到仓库 `STATUS.md`。
- ADR 目录：每个 13 号文档中的选型改动写一条 ADR，不在聊天里决定。

## 8. 启动前检查清单

- [ ] 采集端 v0.1 envelope 定稿日期已确认（P0 依赖）。
- [ ] 平台后端 1 人到位，前端到位时间确认。
- [ ] 云账号、对象存储桶、托管 PostgreSQL 实例申请已提交。
- [ ] SSO 应用注册（redirect URI）已提交。
- [ ] 至少一份真实 Hermes `run/` 样例目录可用于 fake collector。
