# 下一阶段目标：逐次调用准确还原与可重复验收

最新增量（2026-09-18）：录制开关共用的耗时/CPU/RSS 计量与 off 基线工作流已实现；
125 项 Python 回归及固定 TB2 容器中 on/off 两种无 provider 安装检查通过。
off 不生成采集证明、不导入平台；CPU/RSS 口径和隔离差异明确保留。
这些仍不是两次真实对照实验，M2 全新真实 trial、M3 的 12+2 次真实运行与
当前候选五小时最终验收仍未完成。见[计量检查报告](../benchmarks/2026-09-18-harbor-measured-modes-linux-x86_64.json)。

评估日期：2026-09-18。当前代码基线：`83fffca`。
本文确定下一阶段范围与验收标准，不表示下列工作已经实现。
下文 M1–M3 是本轮增量交付编号，不是原始 roadmap 中同名里程碑的重新验收声明。

## 当前成果与边界

- Recorder、Platform、Web 控制台与 GitHub Pages 已交付；该基线的 CI 与 Pages 部署均成功。
- 加密原始事件、正文、pcap/TLS 证据、导入、派生处理与独立对账链路已跑通。
- Harbor `html-js-filter` 真实 Codex 试验 `run-01a0b3b8-621f-7335-a60b-1c0f2056fa48` 保存 14,093 个事件、13,929 个加密 blob；缺失与损坏为零。
- 独立审计核对 54 条客户端消息与 13,726 条服务端消息，双向载荷一致，内核丢包为零，限定传输边界内 `complete=true`；平台独立证明为 `verified`。
- Harbor reward 为 `0.0`，属于任务正确性结果，单独保留。
- 历史核心与 20-collector 五小时稳态报告绑定各自二进制和镜像，不自动证明后续 WebSocket 变更也通过相同稳态验收。

本次暴露了三个需要优先解决的问题：

1. 一条 WebSocket 连接包含 19 次 `response.create`，平台当前却只有一个 logical inference。规范化器汇总请求输入，不能据此声称每次模型调用均已正确还原。
2. 连接终态为 `error/client_read`，规范化结果却有 `finish_reason=completed`。调用结果、传输结束方式、采集完整性需要各自有证据和展示；一个完成事件不能证明连接中的所有调用成功。
3. 平台 transport proof 为 `verified`，总体 coverage 仍为 `unknown`，存在两个未知 TLS surface 标记和一个未解析服务端状态引用。必须解释各指标的边界和依据，不能直接把总体状态改为 complete。

以上调用粒度与状态问题已在本次评估中通过本机平台 API 和当前规范化代码交叉核对：`websocket_request_messages=19`、`logical_inferences=1`，同时存在 `error_class=client_read` 与 `finish_reason=completed`。这说明当前已经验证的是限定范围内的传输采集，不是逐次调用语义还原的完整性。

## 阶段目标

让使用者打开一次真实 agent 任务后，可以逐次查看模型调用的输入、输出、工具交互、用量、终态及原始证据，并理解哪些信息已经核实、哪些仍无法确定。

## M1：调用粒度与状态语义（优先交付）

交付：

- 将 WebSocket connection 与单次模型调用解耦；以协议显式标识、请求/响应生命周期和可验证关联还原调用，保留重试、重连及 `previous_response_id` 链。
- 每次调用独立保存参数、输入、响应文本、tool call/result、usage、起止时间、终态和证据范围；无法唯一配对时显示未解析及原因。
- 分别表达模型调用结果、传输状态、采集状态和基准判分。保留原始 `client_read`；仅在明确证据支持时将派生关闭诊断分类为非正常关闭。
- 为新录制保存有界、脱敏的底层错误分类，例如 WebSocket 协议错误与 I/O 错误种类。旧证据不能追补不存在的错误细节。
- 版本化重处理既有证据，不修改原始记录；更新详情页及对应导出。

验收：

- 对上述真实录制，19 次 `response.create` 均有独立、可追溯的调用请求记录，每条响应事件有可核实归属或显式未解析状态，不能继续合成一次调用。
- 完成后断连、中途断连、服务端错误、主动取消、多调用复用连接、重连/重试等用例得到正确且独立的状态；一个成功调用不得掩盖同连接中另一调用的失败。
- 各次 usage 依照字段含义计数，不重复累加 delta 与 final；原始事件/blob 哈希保持不变，重复重处理的派生结果一致。

## M2：可解释的证据视图与可复现实验

交付：

- 详情页可在“调用摘要、响应文本、规范化内容、原始协议事件、传输证明”间定位同一调用。
- 同时显示证明范围、decoder/processor 版本、证据引用和未解决缺口；静态 TLS 标记与实际未解密连接分别解释。
- 提供受控 Harbor 工作流：预检、录制、完整性校验、独立审计、平台导入、敏感临时产物清理、输出稳定链接与非敏感报告。每一步可见状态、失败原因且可幂等恢复。
- 固定本机服务入口，启动时检查 API/worker/web 健康；临时浏览器转发地址与实际监听端口应明确区分。
- 同步 README、SUPPORT、PRODUCTION_READINESS 和机器可读资格报告，明确历史报告与当前候选版本的关系。

验收：

- 普通用户能解释为何某次模型调用成功但连接关闭异常，以及为何 transport verified 与整体 unknown 可以同时出现。
- 从全新 trial 开始，一条文档化命令生成可查看的录制和报告；重复执行或中断恢复不重复创建逻辑调用、不丢证据。
- 导入失败路径也清理受控临时明文产物；原始加密证据和所需密钥保持可用于重新审计。
- 不依赖某个历史临时转发端口即可重新进入本机平台。

## M3：真实 agent 矩阵与候选版本冻结

交付：

- Codex、Claude Code、Hermes 各选两类代表任务，每个组合重复两次，共 12 次真实实验；任务类别覆盖多轮工具调用及长响应/重试边界，具体任务在运行前确定。
- 首次执行前确定并记录模型、版本、单次超时、费用上限和停止条件；使用受控故障夹具补齐真实环境不稳定复现的错误路径。
- 对一项代表任务增加录制开启/关闭的配对运行，记录耗时与资源变化、网络依赖受限的影响；模型非确定性下不把单次得分变化归因于 recorder。
- 冻结候选版本后执行已约定的 5 小时相关稳态验证；如影响上传/派生链，则覆盖 collector/API/worker 中断恢复与最终队列排空。

验收：

- 12 次实验均有明确结论及 agent/模型/任务/recorder/decoder 版本与哈希；不支持的组合如实失败，不绕过校验记为通过。
- 正常资格用例无静默截断、事件缺口、缺失/损坏 blob 或载荷差异；故障用例准确降级，不能出现“错误地声称完整”。
- 每次模型请求都可追溯，所有未解析关联可枚举；基准得分与采集验收分别统计。
- 五小时报告绑定最终候选二进制与镜像，保留计数、恢复、队列排空及完整性证据。

## 顺序与本阶段范围

按 M1 → M2 → M3 推进，M1 首先复用已有真实录制验收，避免未修正语义模型就扩大实验数量。

本阶段聚焦现有 Linux x86-64、HTTP/SSE/WebSocket 与三类 agent。HTTP/3 解码、广泛 OS/架构适配、新 eBPF 探针和服务端隐藏上下文还原放到后续阶段。

参考：[原始 roadmap](../agent-inference-flight-recorder-feature-roadmap.md)、[Harbor 方法论](harbor-terminal-bench-audit.md)、[本次资格报告](../benchmarks/2026-09-18-harbor-websocket-transport-linux-x86_64.json)。

## 实施记录：2026-09-18 M1

M1 的调用拆分、状态分离、详情/导出与既有证据重处理已经实现并通过本机验收；M2 与 M3 尚未完成，不能据此宣布最终生产候选版本通过验收。

- 新建独立的 connection / call 投影和逐条消息归属索引，原始记录不变。物理连接仍为 1，逻辑 inference 为 19；每次请求、响应终态、用量及原始消息链接逐项核对。
- 13,780 条消息中，13,710 条归属于调用，70 条是 Ping/Pong 控制消息；未解析消息为 0。
- 真实数据中的 17 个 `custom_tool_call` 和 17 个工具结果完整还原；`additional_tools` 和其他协议状态不再误标为用户消息。
- 19 次模型调用均观察到完成事件；连接的原始 `error/client_read` 保留。旧录制缺乏底层错误详情，关闭诊断继续为未知。新 recorder 已增加有界、无错误原文的类型分类。
- 18 条 `previous_response_id` 链已关联；这不是服务端隐藏上下文完整性的证明。两项静态 TLS 标记仍使总体 coverage 为 unknown，独立传输 proof 继续 verified。
- 当前版本的两次完整重放得到相同的调用投影摘要；原始事件索引、加密事件文件和加密 blob 校验摘要不变，独立 integrity 验证通过。
- Go 全包 PostgreSQL 集成测试、318 项 Rust 测试、Clippy、前端构建通过。真实浏览器 CDP 检查确认 19 条调用列表和调用 → 连接导航；传统 dump-dom 检查超时，不计为成功证据。测试产生的三个临时浏览器 profile 已删除，不可恢复，原始加密录制保留。

机器可读记录：[M1 调用还原资格报告](../benchmarks/2026-09-18-websocket-call-projection-linux-x86_64.json)。只读复核命令：

```bash
node tools/verify_websocket_projection.mjs http://127.0.0.1:18080 \
  'run-01a0b3b8-621f-7335-a60b-1c0f2056fa48~01a0b3b8-6633-771f-8dcc-3f5122b05b62'
```

下一步按 M2 推进：优先限制当前连接详情一次渲染的海量事件，打通逐调用证据导航和证明边界解释，再完成 Harbor 全流程及稳定入口。M3 的 12 次真实实验和最终候选版本五小时稳态尚未启动。

## 实施记录：2026-09-18 M2 增量

以下功能已实现并部署到本机，但 **M2 的全新 trial 验收尚未完成**，不能把既有录制重放等同于新实验。

- 调用详情拆分为摘要、响应文本 / 正文、规范化、原始事件、传输证明；事件 API 默认 200、最多 1000 条，页面每页 100 条，支持游标和未解析 / 控制 / 正文过滤。
- 真实 Chromium 验证 19 条调用导航、两页事件、子调用视图、判分和 TLS / proof 边界。连接摘要初始 DOM 为 13,009 字符；两次早期浏览器探测超时未计为成功，后续 CDP 检查通过，临时浏览器 profile 均已清理。
- Harbor 判分作为有来源的不可变外部注释保存，具有权限、项目隔离、幂等冲突检查和删除清理；不会升级为平台自证的任务正确性。既有 reward 0 已关联，重复流程只产生一次注释审计。
- 增加 worker 心跳与八类处理池健康检查；明确其只证明进程 / 数据库活性，不证明任务处理正确或队列已排空。实际单 worker 停启观察到 2 → 1 → 2，原有凭据未轮换。
- `tools/local_platform.py start --build` / `status` 提供固定本机入口与检查，主机监听 Web 8088 / API 18080。它是回环开发部署，不是生产认证 / 持久性配置。
- `tools/harbor_audit_workflow.py` 串联预检、Harbor、完整性校验、独立审计、导入、判分和报告。原子状态、启动意图和子进程继承锁防止并发恢复或重复付费启动；输入改变会拒绝复用工作目录。
- 新 release 验证二进制上，同一既有 trial / 工作目录连续两次成功，19 次调用、14,093 条事件和原始摘要不变。真实导出后 HTTP 503 故障、SIGKILL 暂存恢复、活跃子进程锁、过期成功报告清除等用例通过。临时明文已删除；加密原件和独立密钥保留，可以重新导出。
- 当前 worker 镜像重新生成独立 proof，仍为 verified，整体 coverage 保持 unknown；队列排空、失败任务为零。Go 全包 PostgreSQL 测试、Vet、Race、前端构建及含真实导出故障夹具的 51 项 Python 测试通过。

机器可读记录：[M2 证据视图与既有 trial 工作流验收](../benchmarks/2026-09-18-m2-evidence-workflow-linux-x86_64.json)。新 Harbor 配置已通过安装版本的 `--print-config` 校验，尚未启动新付费 agent；已向用户询问 M3 新增实验的总费用上限。下一步补全新 trial 和实验预算 / 停止策略，再运行 M3 矩阵、录制开关对照及最终候选版本五小时稳态。

## 实施记录：2026-09-18 M3 稳态准备与缺陷修复

M3 尚未完成。已完成独立 token 认证实例上的 20-collector、120 秒混合 HTTP/SSE/WebSocket 校准；它不是五小时报告，也不替代真实 provider 实验。

- 最新资格二进制 SHA-256：`03e805ee36a1bf20cf7f60d17f94ae02447c35bf98acb2132d804c94d2766da7`。1,200 次客户端调用全部成功，600 次 WebSocket 模型调用对应 60 条物理连接；300 次工具调用 / 结果、用量、请求与最终响应摘要、逐条事件归属全部对账通过。61 个录制分段连续且完成 ACK / seal，22,722 条本地事件完整。
- API 中断期间 20 个本地录制继续推进；collector 重启保留身份，worker 重启后队列排空。每个 WebSocket collector 都覆盖跨录制分段的连接。
- 第一轮校准发现 Close 回复未 flush 就退出，客户端正常关闭因此失败。修复后仅在双向 Close 已观察到时记为完成；缺少回复限时降级。增加客户端发起、服务端发起、未回复和 TCP reset 的真实 socket 回归。这不构成历史 `client_read` 的具体原因证明。
- 第二轮发现 16 条消息的异步采集队列在长响应突发时丢事件；系统正确标为 incomplete，没有伪报通过。改为 256 条消息上限并增加每连接 / 共享字节预算，连空消息的队列元数据也计费；文本转发共享已验证 UTF-8 内存，避免额外正文复制。压力或存储失败仍不阻断模型数据路径，继续记录缺口。
- 第三轮为中间版本通过，第四轮为当前候选版本通过；失败记录保留。三轮执行删除传播检查的校准分别删除了各自新生成的一条合成 HTTP/SSE 录制，均不可恢复；历史真实录制未改动。
- 修复了 bridge 测试中 buffered `readline` 与 `communicate` 混用漏读 evidence 的测试问题；旧代码在延迟读取夹具下可重现，修复后重复 100 次通过。握手修复提交 `35fb6f7` 的 GitHub CI 已全绿。候选版本本机 322 项 Rust 测试、Clippy、含真实导出故障夹具的 61 项 Python 测试通过。
- 浏览平台仍是原 `iorec-local`，未用于故障注入。新准备的五小时实例使用独立数据库 / 对象卷、固定镜像 ID、token 认证和正常 PostgreSQL 持久性配置，匿名访问返回 401。

操作方法：[混合协议资格验收](mixed-protocol-qualification.md)。机器记录：[M3 短时校准](../benchmarks/2026-09-18-m3-mixed-calibration-linux-x86_64.json)。接下来运行冻结候选版本的五小时验收，并在费用上限确认后补全新 Harbor trial、真实三 agent 矩阵和录制开关对照；这些未完成项不能由合成负载替代。

## 实施记录：2026-09-18 真实实验输入预检

- 为新 Harbor trial 补齐实际上传文件的指纹：Codex/helper、recorder、util-linux/helper wrapper 和六个运行库共享同一输入定义，密钥不进入公共输入清单。另记录 Harbor 启动器、解释器、包内容、任务及工作流代码；启动前和录制后复核，变化时拒绝启动或验收，不自动重跑付费任务。
- 增加 `--preflight-only`：检查本机平台和安装的 Harbor 配置，不安装或运行 agent，报告明确为 `qualification_passed=false`。当前候选 recorder 在同一目录连续两次通过真实预检，没有产生 Harbor job 或 launch intent；用于预检的占位模型不是 M3 模型选择。
- 72 项 Python 测试通过且无跳过，包含真实加密录制导出失败夹具。冻结候选提交 `9261b30` 的四个 CI job 已全部成功。五小时负载仍在独立实例运行，本轮仅修改 Harbor 工作流，不改变它锁定的二进制、镜像和负载脚本。
- 这不是完整供应链锁定：传递 Python 依赖、容器内 apt 工具和 Claude/Hermes 的安装适配仍需处理，12 次真实实验及配对运行尚未完成。

机器记录：[Harbor 输入预检](../benchmarks/2026-09-18-harbor-input-preflight-linux-x86_64.json)。

## 实施记录：2026-09-18 原生 Claude 适配与兼容构建

- 增加 Claude Harbor profile，共用固定 CLI 包装器、非 root 目标和输入锁定；Codex 不再依靠搜索替换命令文本来插入 recorder。包装器保留参数、stdin 和退出码，提示词中的命令字符串不会触发替换。
- 真实容器内 Codex 0.154.0、Claude 2.1.274 的安装 / 版本检查已通过；全部采用 `--install-only`、清空 provider 凭据，不算真实模型实验。
- 检查发现显式加载器启动 recorder 会把 `current_exe()` 指向加载器，导致 Claude 生命周期 hook 自执行失败。相同旧二进制在主机上显式加载器启动退出 65、原生启动退出 0。Claude profile 现在要求原生 recorder，并在安装阶段测试 hook，不能通过仅版本检查后冒充适配完成。
- 未修改 Rust 源码，在固定 Bookworm 镜像内离线重建得到兼容二进制 `b54b88d6…e9c05da7`，最高 glibc 依赖 2.34。该二进制通过真实 Debian 12 Harbor 容器内的 synthetic hook 检查，16 个加密事件中包含 `hook:claude / SessionStart`，integrity 通过。78 项 Python 测试在新二进制真实导出夹具下通过，无跳过。
- 新二进制 120 秒校准的 1,200 次调用全部成功，600 次 WebSocket 调用对账、完整性、上传及最终排空均通过，但两路未覆盖跨分段连接，**整体仍记录为失败**。保留报告；追加校准延长连接持有时间、缩短分段周期，保留相同调用数量和所有验收条件。
- 兼容候选的独立五小时测试已启动；旧候选的运行和证据保留，不冒用为新二进制验收。校准删除传播测试仅删除一条新合成录制 `run-01a0b5f6-ac58-748f-af5f-eb9870ce51b8`，不可恢复；历史真实录制未改动。

机器记录：[原生 Harbor 安装与兼容性验证](../benchmarks/2026-09-18-native-harbor-install-linux-x86_64.json)。M3 仍未完成。

## 实施记录：2026-09-18 Hermes 固定运行环境与兼容候选校准

- 核对 Hermes 实际加载的是安装包 0.19.0，而相邻源码目录为 0.16.0。新增已安装运行环境打包与验证工具，固定 Python 3.11.15、204 个 distribution 和 34,812 个文件，不复制个人 Hermes home、配置、会话或凭据。原虚拟环境和源码未修改。
- 包含有界 GNU 长文件名支持、逐文件摘要、源变化检测、路径/链接/特殊文件限制和输出不覆盖保护；106 字节依赖文件名引起的初次 USTAR 失败已保留在记录中，没有通过删依赖来规避。
- 新 Harbor Hermes profile 在容器解包前核对上传文件摘要，以 root-owned 运行环境和 UID 10001 执行 agent；精确本地 session export 不生成第二条录制。显式固定 OpenAI 协议 endpoint，缺少原生 key 时拒绝自动回退 OpenRouter。
- 禁网、无 provider 凭据的 Debian 12 版本检查通过；真实 Harbor `--install-only` 通过并报告 Hermes 0.19.0，无 agent execution 或 verifier 结果。最终预检同一目录连续两次通过，无 launch intent；97 项 Python 测试通过，无跳过。这些不算真实模型实验。
- 兼容候选 `b54b88d6…e9c05da7` 的第七次短时校准通过：20 collectors、180 秒、1,200 次成功调用、600 次 WebSocket 调用、321 个分段、22,719 条事件；十路 WebSocket 均覆盖跨分段连接，共 47 条。全部完整性、上传、平台序列、调用投影、API/collector/worker 恢复和最终排空检查通过。
- 第六次校准的 processing-drain 超时仍记失败。旧 collector 心跳与新启动时间重叠，可能污染 online delta 基线；失败报告未保留精确 overview，不能追补为确定诊断。第七次确认 online/pending 基线为零后，用相同负载参数和未修改的验收脚本通过。已补充复用校准实例前的检查要求。
- 删除传播检查仅不可恢复地删除本轮新合成录制 `run-01a0b60a-e8bf-70bb-9d3e-d3f305f8acbb`，历史真实录制未动。两组五小时进程仍运行，绑定的 recorder、镜像和脚本未改变；不能把短时通过记为五小时通过。

机器记录：[Hermes 运行环境与兼容候选校准](../benchmarks/2026-09-18-hermes-runtime-and-portable-calibration-linux-x86_64.json)。剩余仍是预算/停止策略、全新真实 trial、12 次矩阵、录制开关对照及最终五小时验收。

## 实施记录：2026-09-18 TB2 版本校正与实验声明

- 匿名查询官方 registry，确认历史 `html-js-filter` 与备选 `session-window-debug` 属于当前 66 题 `terminal-bench/terminal-bench`，不属于 89 题 TB2 快照。历史原始证据和得分不改，但不再笼统称其为 TB2 试验。
- 从固定 TB2 数据集摘要选择 `cancel-async-tasks`、`multi-source-data-merger`；下载内容经 Harbor 发布包算法重算，与 registry 的两个 task digest 一致。任务文件原样保留。
- 对两题可变 Docker tag 增加 `--task-image` 固定 digest、同镜像校验、禁止自动 pull 和 overlay 变化拒绝。独立 verifier/多服务任务不允许这种覆盖。增加显式 verifier 超时，当前计划保持两题原有 900 秒上限。
- 两题新预检通过，Claude 在异步题容器中完成安装与 synthetic hook 完整性检查；Hermes 在数据题容器中完成安装与版本检查。Codex 另完成兼容 recorder 的安装检查。全部无 provider 凭据、无 agent execution，不计入真实矩阵。
- [实验清单与说明](m3-experiment-plan.md) 包含完整 12 次矩阵和额外 2 次对照，固定候选 recorder、agent 文件、任务树与镜像摘要。模型和费用/审批证据保留空值，`--require-approved` 按预期返回 2。该工具仅检查声明，不伪装成 provider 的财务限额执行器。
- 110 项 Python 测试在真实加密导出夹具下通过，无跳过。旧候选五小时实例的首次 API 中断后已恢复，所有本地日志仍推进；新兼容候选五小时实例仍运行。两者均未完成最终验收，绑定文件未修改。

机器记录：[TB2 清单与预检](../benchmarks/2026-09-18-tb2-plan-preflight-linux-x86_64.json)。M3 仍未完成，真实矩阵与对照尚未启动。
