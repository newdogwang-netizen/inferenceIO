# 把 Agent 录制带进 Kubernetes

iorec 如何接入 Kubernetes：为什么选择就近采集，注入器改了哪些 YAML，模型流量与录制数据分别走哪里，以及部署时要经过哪些步骤。

2026 年 9 月 23 日 · 约 10 分钟 · 基于 9 月 22 日的实现与验收

## 01 / 先选边界，再选部署方式

Agent 搬进 Kubernetes 后，录制问题没有消失，只是多了 Pod 重建、短任务结束、网络中断和凭据分发。我们仍然需要回答：模型收到什么、返回什么、工具有没有真正执行，以及证据有没有完整保存。

**iorec 的选择是：每个任务附近采集，平台集中接收、解析和查询。** Controller 负责把采集能力装进指定 Pod，不承载模型流量；Platform 可以和 Controller 一起部署，也可以独立部署。

这与链路追踪里的“就近 Collector + 集中后端”思路相近。OpenTelemetry 也区分 [Agent 部署](https://opentelemetry.io/docs/collector/deploy/agent/)和 [Gateway 部署](https://opentelemetry.io/docs/collector/deploy/gateway/)。这里借鉴的是职责拆分，不是声称 iorec 已实现 OTLP 或 OpenTelemetry Collector。

### Sidecar 和代理，不是二选一

**Sidecar 描述进程放在哪里；代理描述数据怎样接入。** 当前实现把录制器和模型代理运行在 Agent 的目标容器中，把上传器放进独立的 native sidecar。不能把它理解成“另起一个 sidecar，就自动看到了所有 HTTPS 和脚本执行”。

| 方式 | 适合解决的问题 | iorec 的选择与限制 |
|---|---|---|
| Pod 内录制 + 上传 sidecar | 关联任务生命周期、本地缓冲、按 Pod 追溯来源 | 当前已实现；每个任务有额外进程和资源开销 |
| 集中式模型网关 | 集中路由、鉴权、限流和观察模型请求 | 可以成为录制代理的上游；只看模型流量，不能证明本地工具如何执行 |
| 节点级 DaemonSet / 旁路观测 | 补充节点网络、进程与流量覆盖证据 | 不是本次 Controller 的交付模式；抓到 TLS 包不等于读到正文 |

对于一次性 Job 和需要工具证据的 Agent，我们优先选择 Pod 内采集。已有模型网关可以保留，两者并不冲突。**这是围绕当前录制目标的取舍，不是所有观测系统的唯一最佳实践。**

## 02 / 创建一个 Pod 时，发生了什么

注入发生在 **Pod 创建时**，不是 Agent 发出模型请求时。Kubernetes API server 把匹配的 Pod 送给 Webhook，接收 JSON Patch 后完成准入、保存 Pod，再交给调度器和 kubelet 启动。

这条控制路径可以理解为：**提交 Pod → API server ⇄ iorec Webhook → 保存并启动修改后的 Pod**。API server 与 Webhook 通过 HTTPS 通信；Controller 之后不参与每次模型调用。

### 只注入明确选择的工作负载

默认要求 Namespace 有 `iorec.io/injection: enabled`，Pod 有 `iorec.io/inject: "true"`。Job 和 Deployment 要把 Pod 标签写在 `spec.template.metadata.labels`，只给 Job 自身打标签无效。标签是自愿接入的开关，不是防止工作负载所有者绕过采集的安全策略。

Webhook 处理新建 Pod 的 AdmissionReview v1，返回确定性的 JSON Patch；不扫描运行中的 Pod，不热修改已有容器，也不查询模型服务或 Platform。重复准入不会重复插入同一组容器。名称虽然叫 Controller，当前核心是准入注入器，不是管理 Agent CRD 的任务调度器。

当前默认 `failurePolicy: Fail`：选中的 Pod 如果无法安全注入，就拒绝创建，避免用户误以为已被录制。代价是 Webhook 不可用时，这些 Pod 的创建会受阻。因此必须限制 Namespace/Pod 范围、排除系统和自身命名空间，并检查 API server 到 Webhook 的连通性。Kubernetes 官方也建议[缩小 Webhook 匹配范围、保持幂等并避免副作用](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)。

### 注入的不是另一个 Agent

1. **`iorec-install` 初始化容器**：把静态 musl 录制二进制复制到共享卷的 `/opt/iorec`，准备目录和权限。Agent 镜像不必预装 iorec。
2. **Agent 启动包装**：将目标命令改为 `/opt/iorec/iorec run … -- 原命令 原参数`，由适配器设置模型 endpoint 和可用 Hook。模型代理也在这个目标容器内运行。
3. **`iorec-uploader` 上传容器**：定义在 `initContainers` 中，设置 `restartPolicy: Always`，持续上传录制，并在结束时做有时限的补传。
4. **来源元数据**：通过 Downward API 等配置记录 cluster、namespace、Pod 名称/UID、node、目标 container 和 injection version。Pod 身份是来源，不替代录制 ID 或 Agent 会话 ID。

native sidecar 的生命周期与普通常驻容器不同：它可以先于应用启动、在应用结束后关闭，也不会因为自身持续运行而阻止 Job 完成。本项目的支持基线因此设为 **Linux / Kubernetes 1.33+**；实际集群验证是 amd64。[生命周期规则见 Kubernetes 文档](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)。

两个接入条件不能省：**显式 `command` 和数字非 root UID**。Webhook 不会拉取镜像去猜 ENTRYPOINT；共享目录也需要录制器、Agent 和上传器能以兼容身份访问。使用 PVC 时还要配置相应 `fsGroup`。原有参数、环境、挂载与镜像拉取凭据会保留。

### Pod YAML 前后对比：到底改了哪些字段

**对比的是同一个 Pod 在准入注入前后的配置，不是 Deployment 的原始 YAML。** 当前 Webhook 只匹配 Pod 的 `CREATE` 请求。Deployment 经 ReplicaSet 创建 Pod 时，注入发生在这个新 Pod 上；Deployment 和 ReplicaSet 的 Pod 模板都不会被 iorec 回写。已有运行中的 Pod 也不会被补改。

下面的接入标签、profile、显式命令和非 root UID 是业务侧预先提供的条件；注入器在此基础上做以下修改。表中的 `containers[agent]` 指选中的目标容器，其他业务容器不做启动包装。

| Pod 字段 | 注入前 | 注入后 |
|---|---|---|
| `containers[agent].command / args` | 原来的 Agent 命令与参数 | **替换入口**为 `/opt/iorec/iorec`；参数组成 `run … -- 原命令 原参数`，原命令仍会执行 |
| `spec.initContainers` | 原有初始化容器，或没有 | **追加** `iorec-install` 和 `iorec-uploader`；后者设置容器级 `restartPolicy: Always`，作为 native sidecar |
| `containers[agent].volumeMounts` | 原有业务挂载 | **追加**只读 `/opt/iorec` 二进制卷和可写 `/var/run/iorec` 录制卷 |
| `spec.volumes` | 原有业务卷 | **追加** `iorec-bin`、`iorec-data`、`iorec-credentials`、`iorec-upload-private`；录制卷默认 `emptyDir`，也可配置 PVC |
| `containers[agent].env` | 原有业务环境变量 | **追加** 7 个 `IOREC_K8S_*` 来源变量：cluster、namespace、Pod 名称/UID、node、目标 container、注入版本 |
| `metadata.annotations` | 容器选择、profile 等原有配置 | **追加** `iorec.io/injected: v1`，标记已经注入 |
| `spec.os / spec.nodeSelector` | 原有系统与调度约束 | **缺少时补充** `os.name: linux` 和 `kubernetes.io/os: linux`；与 Linux 冲突时拒绝，不强行覆盖 |
| `spec.terminationGracePeriodSeconds` | 本例未指定 | **提高下限**到配置的终止宽限期，本例为 120 秒；已有更大值时保留 |
| Agent 镜像、业务凭据、原有环境/挂载及 Pod `restartPolicy` | 业务原始配置 | **保留不变**；非 root UID 必须提前声明，不由注入器猜测或补齐 |

下面两份 YAML 展示这些变化的关键字段；表中列出的凭据卷、来源变量等细节在示例里省略。

### 注入前的 Pod YAML

下面用一个读取 `OPENAI_BASE_URL` 的 Python Agent 举例。`generic` profile 由管理员预先配置为 OpenAI 兼容协议，上游是 `https://model.example/v1`。镜像、域名和任务名均为示例，不是可直接运行的部署清单。

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: agent-tasks
  labels:
    iorec.io/injection: enabled
---
apiVersion: v1
kind: Pod
metadata:
  name: repair-agent
  namespace: agent-tasks
  labels:
    iorec.io/inject: "true"
  annotations:
    iorec.io/container: agent
    iorec.io/profile: generic
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 1000
  containers:
    - name: agent
      image: registry.example/agent:1.0
      command: ["python3", "/app/agent.py"]
      args: ["--task", "repair-tests"]
      # 模型凭据沿用业务自己的 Secret，略。
```

Namespace 标签负责圈定范围；Pod 标签决定这一份任务是否接入；annotation 选择目标容器和已配置的 profile。对于 Job / Deployment，上述 Pod 的 `metadata` 和 `spec` 要放在它们的 `spec.template` 下。

### 注入后的 Pod YAML

以下是**同一个 Pod 的关键字段摘录**。省略了未变化的标签、完整来源环境变量、Secret 卷及配套挂载、探针、资源限制和安全加固字段；`<recorder-image>` 代表管理员固定版本的录制镜像。这里展示结构变化，不代替完整生成清单。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: repair-agent
  namespace: agent-tasks
  annotations:
    iorec.io/container: agent
    iorec.io/profile: generic
    iorec.io/injected: v1          # 新增：已注入标记
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 1000
  terminationGracePeriodSeconds: 120
  initContainers:
    - name: iorec-install         # 先复制二进制、准备本地目录
      image: <recorder-image>
      command: ["/usr/local/bin/iorec-pod"]
      args: [install,
             --bin-dir, /opt/iorec,
             --data-dir, /var/run/iorec,
             --secret-dir, /var/run/iorec-secret]
      # 挂载 iorec-bin、iorec-data 和凭据卷，略。
    - name: iorec-uploader
      image: <recorder-image>
      restartPolicy: Always      # native sidecar，不是一次性 init
      command: ["/usr/local/bin/iorec-pod"]
      args: [upload,
             --data-dir, /var/run/iorec,
             --secret-dir, /var/run/iorec-secret,
             --api, https://iorec.example.com,
             --segment-seconds, "30", --drain-seconds, "45"]
      # 挂载同一份 iorec-data、凭据卷与私有临时卷，略。
  containers:
    - name: agent
      image: registry.example/agent:1.0  # 业务镜像不变
      command: ["/opt/iorec/iorec"]     # 启动入口被包装
      args: [run,
             --runs-dir, /var/run/iorec/runs,
             --key-file, /var/run/iorec/private/key,
             --upstream, https://model.example/v1,
             --provider, openai, --adapter, generic,
             --body, full, "--",
             python3, /app/agent.py, --task, repair-tests]
      # “--” 后面就是原 command + args。
      volumeMounts:
        - name: iorec-bin
          mountPath: /opt/iorec
          readOnly: true
        - name: iorec-data
          mountPath: /var/run/iorec
  volumes:
    - name: iorec-bin
      emptyDir: {sizeLimit: 128Mi}
    - name: iorec-data
      emptyDir: {sizeLimit: 8Gi}  # 默认缓冲；需保留证据时改用 PVC
```

抓住三个变化即可：**原镜像不变、启动入口变成录制包装、上传 sidecar 与 Agent 共享录制卷。** 安装容器先完成准备；上传器达到本地就绪后，Agent 开始执行；Agent 结束后上传器尝试把剩余录制补传完。

这里没有把 `OPENAI_BASE_URL` 写进 Pod YAML：它是在 `iorec run` 启动 Agent **子进程时**设置的。对于其他 Agent，适配器也可能修改其专用配置。不要把“准入时修改 Pod”和“运行时修改子进程环境”混为一件事。

## 03 / 流量究竟经过哪里

![模型通信与录制上传路径：Agent 通过同容器代理请求原模型，响应反向返回；录制写入共享卷，再由 sidecar 上传平台。](assets/iorec-kubernetes-traffic.svg)

[放大查看流量图](assets/iorec-kubernetes-traffic.html)。图中实线是模型请求方向，响应沿同一连接反向返回；虚线是证据交付方向。Webhook 属于上一节的创建路径，不在图中的运行时链路上。

### 模型请求与响应：Agent ⇄ 本地代理 ⇄ 原服务

1. **Agent 连接本地 endpoint。** 以本例为例，子进程的 `OPENAI_BASE_URL` 指向 `http://127.0.0.1:<动态端口>/v1`。代理与 Agent 在同一个容器里；这个地址不是 Platform 地址，也不是上传 sidecar 的服务地址。
2. **代理连接管理员配置的上游。** 它将请求转发到 `https://model.example/v1`，携带调用所需的模型凭据，按协议处理路径和头部。上游也可以是企业已有的模型网关。
3. **响应原路返回。** 普通 JSON 返回正文；SSE 则随上游到达持续转发给 Agent，不等待整段回答生成完，也不等待 Platform 上传完成。录制器同时按策略保留事件和正文。

这里实际上是**两段连接**：Agent 到回环代理的 HTTP，以及代理到模型服务的 HTTPS。模型 TLS 会话由代理作为客户端建立，不是旁听并解密 Agent 已有的 TLS 连接。当前模式不依赖 iptables 重定向，不需要给业务 Pod 抓包特权，也不向集群植入中间人 CA。

### 录制交付：本地目录 → 上传 sidecar → Platform

`spool` 是本地待上传目录。录制器把事件与加密正文写入共享卷，sidecar 从这份卷读取，提交正文对象和事件批次，并根据平台的持久化确认推进续传。它不是拦在 Agent 与模型之间的第二层 HTTP 代理。

上传连接使用**项目上传 token**，不是模型 API Key。跨信任边界使用 HTTPS；tinybox 的模拟验收显式允许了受控集群内的 HTTP，这不代表 ClusterIP 天然具备传输加密。Platform 接收后保存对象和事件，Worker 异步解析；浏览器再带平台用户凭据查询。**模型凭据、上传凭据、用户查询凭据是三种不同的用途。**

因此，平台短暂离线时模型响应不需要等待平台恢复，录制先留在本地；但本地磁盘、写入背压和终止时间仍有限，不能承诺无限离线或零影响。Controller 不承载模型流量，Platform 也不在模型回答的返回路径上。

### 哪些流量不会自动出现

**忽略 endpoint 配置的客户端可能绕过录制。** Agent 发起的网页访问、任意其他 HTTPS 流量，也不会因为 Pod 被注入就全部自动纳入。模型协议中的 tool call 表示调用意图；脚本是否执行、退出码和输出，仍需对应 Agent 的 Hook 或执行后端适配。更细的采集原理见[上一篇文章](how-iorec-records.html)。

## 04 / 可靠交付，不等于“容器都绿了”

### 先留本地证据，再确认平台收到了什么

录制器先保存事件与按策略保留的正文对象，上传器再提交对象和事件批次。平台用序号、身份和哈希确认已持久化边界，上传侧据此续传；不要把重试简化成“再发一次就算成功”。

平台暂时不可用时，Webhook 不会因此依赖失败；上传器的启动检查也只检查本地准备状态。录制可以先写入 spool，随后重试。**这不意味着无限离线或零开销：磁盘容量、代理背压、上传吞吐和终止时限仍然约束录制。**

默认分段间隔是 30 秒；tinybox 验收用了 5 秒，方便观察运行中分段。平台里的 `durable / parsed / final` 是事件序号边界，不是 Token 数量：分别表示已持久化、已解析和封存结束位置。

### Agent 退出后，还要检查上传结果

上传器结束时执行有界的 `collector --once --require-drained` 检查，要求本地录制得到认证过的持久化确认并完成封存。超过 drain 预算会报错并非零退出，不把未完成录制包装成成功。

但 Kubernetes 仍可能在终止宽限期耗尽后强杀 sidecar；**Job 显示 Complete 也不代表每份录制已交付。** 验收应同时检查 Agent 的退出状态、上传器退出/日志，以及平台的 sealed 状态、序号和正文完整性。

### Pod 可以消失，未上传证据不能靠运气保留

默认 `emptyDir` 只能承受容器重启，不能承受 Pod 被删除。需要保留证据时，设置 `controller.spool.existingClaim`，让每个 Pod 使用 PVC 下独立的 Pod-UID 子目录。[Kubernetes 对卷生命周期的说明](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)解释了这一区别。

PVC 也不是自动容灾：tinybox 的本地卷不能抵御节点或磁盘丢失；多个节点并发共享一个 claim 还需要合适的 RWX 存储。旧 Pod 的目录要显式恢复、补传，不能默认新 Pod 已接管。复用 spool 时也不能随意轮换录制密钥。

## 05 / 部署流程：六步完成接入

部署应分成“平台准备、采集接入、结果验收”三个阶段。业务团队不需要手工维护上一节注入后的长清单，只需准备自己的 Agent Pod，并明确选择是否接入。

### 第一步：确定部署边界和保存策略

先决定 Platform 与 Agent 是否在同一个集群、哪些 Namespace 允许录制、保存正文还是仅元数据，以及需要保留多久。再确定本地缓冲用临时卷还是 PVC，平台的数据与对象存储放在哪里。

这一阶段的产出是**清晰的接入范围、数据策略和存储方案**。跨集群访问、敏感正文、Pod 删除后的恢复，不能等录制失败后再补设计。

### 第二步：准备集中平台

部署或复用 Platform，打通 API、Worker、Web、数据库与对象存储，配置访问认证和备份。固定已发布镜像的版本，先验证平台可以接收录制、解析数据和进行已认证查询。

这一阶段的产出是**可访问的平台入口，以及分用途的凭据**。项目上传 token 供采集端使用；用户 token 供界面查询使用；数据库密码与管理员凭据不应分发给 Agent Pod。

### 第三步：安装注入器，限定作用范围

部署 Controller 和准入 Webhook，配置 TLS 证书与 API server 的信任关系。定义 Namespace / Pod 选择器，以及可供业务选择的 profile：上游模型地址、协议、Agent 适配器和正文策略。

这一阶段要确认两件事：**选中的 Pod 会被正确修改；未选中的工作负载不受影响。** 同时明确注入失败时的行为、证书轮换和 Webhook 不可用时的处理方式。

### 第四步：让一个 Agent 工作负载接入

在目标 Namespace 准备录制 key、项目上传 token 和需要的卷。业务 Pod 保留自己的模型凭据，补齐显式启动命令、非 root UID、接入标签和 profile，然后创建一个新 Pod。

检查实际生成的 Pod 是否出现启动包装、安装容器、上传 sidecar 和共享卷。**已有运行中的 Pod 不会自动补注入**；应通过正常发布流程创建新实例。先接一个任务，不直接扩大到所有 Namespace。

### 第五步：用一份录制验收完整链路

先用模拟模型验证 JSON、SSE、封存、上传和正文哈希，再选一个真实 Agent 小任务确认 endpoint 和适配器生效。如果要求工具执行证据，还要检查对应的工具记录，而不只是模型响应中出现了 tool call。

验收看的是**证据完整性**：Pod 来源是否匹配，分段是否 sealed，序号是否连续，正文能否读取且哈希一致，Agent 与上传器是否正常退出。页面能打开、Pod 为 Running 或 Job 为 Complete，都不能单独作为完成标准。

### 第六步：验证恢复，再逐步扩大范围

在受控环境里验证平台暂时离线、上传器重启、Agent 异常退出和 Pod 删除后的恢复。随后设置缓冲占用、上传失败、解析延迟与凭据/证书到期的告警，再按 Namespace 或任务类型灰度扩大。

这一阶段的产出是**可操作的恢复流程和运行边界**。确认尚未交付的录制已经补传，或能从保留的卷恢复后，再清理任务和卷。

以上是部署的步骤与检查点。具体安装参数、完整清单和操作命令由配套运维手册（`docs/kubernetes-controller.md`）维护，将随云原生源码另行发布，不在本文展开。

## 06 / Platform 放在哪里，决定哪些存储约束

Controller 和 Platform 可以一起安装，也可以独立部署；两者之间的联系是上传地址与凭据，不要求它们共处一个集群。已有平台时，Agent 集群只需部署 Controller，并在各接入 Namespace 准备上传凭据和录制 key。

**单节点起步**：PostgreSQL 加持久化文件对象卷。当前文件后端只支持一个 API 副本，Worker 与 API 共用所在节点的 RWO 卷。它适合起步和单节点验收，不是高可用部署。

**多节点扩展**：外部 PostgreSQL 加 S3 对象存储，再扩展 API / Worker。已有两个 API、两个 Worker 对接独立 PostgreSQL / MinIO 夹具的本地验证，但目标托管服务、备份恢复和故障切换仍要单独验收；当前 S3 适配使用静态 V4 凭据，尚不支持 workload identity。

无论放在哪里，公开可拉取的镜像都不意味着录制数据公开。跨信任边界使用 HTTPS，入口保留认证，敏感正文按策略保存；备份必须涵盖数据库、对象数据及对应密钥。

## 07 / tinybox 验收结果

2026 年 9 月 22 日，在 tinybox 的 Kubernetes 1.35.3+k0s / Linux amd64 上完成组合部署与录制验收：**3 次模拟模型调用、2 个封存分段、47 个全局事件，5 份正文对象的下载哈希全部匹配。**

[查看 tinybox 验收结果 →](tinybox-acceptance.html)

独立报告列出环境、准入测试、分段序号、正文完整性、启动重试及网页登录修复后的复验。测试使用真实 Pod 和模拟模型，没有产生付费推理；不把这次通过扩大成所有 Agent、多节点高可用或长期稳态的保证。

## 继续阅读与版本说明

- [采集端工作原理](how-iorec-records.html)：模型代理、流式采集、工具执行和旁路核对分别做什么。
- [tinybox 验收结果](tinybox-acceptance.html)：公开的验证方法、结果与边界，不含凭据或原始录制正文。
- [项目仓库](https://github.com/newdogwang-netizen/inferenceIO)。

版本边界：本文对应 2026-09-22 的工作区实现；五个部署镜像已经公开。本次发布设计说明与验收摘要，云原生源码、Chart 和配套运维手册不包含在这次文档提交中。文中的 YAML 用于说明这版注入器的行为，不把公开仓库旧版本当作本次实现，也不公开原始录制、集群连接信息或 Secret 内容。
