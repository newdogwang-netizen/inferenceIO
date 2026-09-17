# 11 · 首版部署与后续扩容

## 1. 首版 Docker Compose

```yaml
# 示意，不是可直接运行的文件
services:
  platform-api:
    image: iorec/platform-api:0.1
    environment:
      DATABASE_URL: postgres://iorec:***@postgres:5432/iorec
      OBJECT_STORE_ENDPOINT: http://minio:9000
      OBJECT_STORE_BUCKET: iorec
      OIDC_ISSUER: https://sso.example.com
    ports: ["8080:8080"]
    depends_on: [postgres, minio]

  pipeline-worker:
    image: iorec/pipeline-worker:0.1
    environment:
      DATABASE_URL: postgres://iorec:***@postgres:5432/iorec
      OBJECT_STORE_ENDPOINT: http://minio:9000
      WORKER_POOLS: "decode=4,assemble=4,normalize=2,resolve=2,transport_audit=1,coverage=1,rules=2,eval=1,export=1"
      IOREC_TSHARK_PATH: /usr/bin/tshark
    deploy: { replicas: 2 }
    depends_on: [postgres, minio]

  web-console:
    image: iorec/web-console:0.1
    environment: { API_BASE_URL: http://platform-api:8080 }
    ports: ["3000:3000"]

  postgres:
    image: postgres:17
    volumes: [pgdata:/var/lib/postgresql/data]

  minio:            # 或直接连接已有 S3 / GCS / 兼容存储
    image: minio/minio
    command: server /data
    volumes: [objdata:/data]

volumes: { pgdata: {}, objdata: {} }
```

客户环境单独安装 `capture-agent`（`iorec`），只需要出方向 HTTPS 到 `platform-api`。平台中断期间，录制仍可独立完成。

## 2. 运维要点

- **迁移**：schema 迁移随 API 镜像发布，启动时执行；Worker 启动前检查 schema 版本匹配。
- **备份**：PostgreSQL 每日快照 + WAL；对象存储开版本控制或跨桶复制。原件在对象存储，数据库可以从原件重建大部分派生数据，反过来不行。
- **平台自身可观测**：API 请求延迟与 4xx/5xx、批次接收速率、每 Recording `durable_seq - parsed_seq`、任务积压与 `dead` 数、SSE 连接数、对象存储写失败。
- **容量估算起点**：一次典型编码 Agent 会话约 50～300 次 inference，每次请求正文 20～200 KB（完整历史重发），响应 2～20 KB。按 blob 去重后，一个活跃开发者每天约 0.5～3 GB 原件。首版按 20 个采集端、90 天正文保留估算对象存储 1～5 TB。
- **单点**：首版 API 单实例可接受（采集端有本地 spool）；Worker 至少 2 副本；数据库单主 + 备份。
- **传输审计隔离**：生产 Worker 镜像固定 TShark 包版本和基础镜像 digest，删除 `dumpcap` 与所有 setuid/setgid 位，以非 root、只读根文件系统、全 capability drop 和 `no-new-privileges` 运行。`/tmp` 必须是 `noexec,nosuid,nodev` 的容器临时文件系统；pcap/key log 只在 mode `0700` 子目录内短暂解密，异常退出后应通过容器重建清除。

## 3. 按瓶颈拆分

| 出现的瓶颈 | 信号 | 拆分方式 |
|---|---|---|
| 上传占满 API 带宽或连接 | API P95 上升、429 增多、`acked_lag_seconds` 增大 | 独立 `ingest-service`，只做校验与落对象，与查询 API 分离 |
| 解码积压 | `durable_seq - parsed_seq` 持续增长 | 扩容 `decode-worker`；按 Recording 哈希分片领取 |
| 会话重建耗时 | `resolve` 任务 P95 超过分钟级 | 独立 `reconstruction-worker`；增量 resolve（只处理新 inference 及其邻接） |
| 模型评估成本 / 耗时高 | `eval` 积压、评审费用 | 独立 `evaluation-runner`，独立配额与预算 |
| 聚合查询拖慢事务库 | 统计页 P95 上升、慢查询 | 增加 ClickHouse 分析投影，由 Worker 双写或 CDC |
| 采集端数量和连接数增加 | 长轮询占满连接、心跳写放大 | 独立 `collector-control-service`；心跳改批量 upsert |
| 任务表锁竞争 | `SKIP LOCKED` 等待、领取延迟 | 引入消息队列（NATS / SQS）做任务分发，PostgreSQL 仍是任务状态的事实源 |

每一步拆分都沿着首版已有的模块边界进行，不需要改事件协议或数据模型。
