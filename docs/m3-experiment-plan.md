# M3 真实实验清单与启动前检查

状态：**尚无本轮真实实验结果**。仓库机器清单示例位于
[`examples/m3-experiment-plan.json`](../examples/m3-experiment-plan.json)。模型和预算
故意保留 `null`；操作员实际授权、模型选择、凭据来源及费用限制检查保留在本机
私有计划中，不公开提交预算或凭据。不能把占位模型、安装检查或合成负载计入
12 次实验。冻结兼容候选的[五小时稳态](../benchmarks/2026-09-19-m3-portable-connected-5h-linux-x86_64.json)
已通过，但不替代这 12 次及额外 2 次真实对照。

## 数据集与题目

2026-09-18 对 Harbor 公共 registry 做匿名只读查询，并按 registry task digest
下载、重新计算发布包摘要，确认以下两题属于明确的
[Terminal-Bench 2 数据集](https://hub.harborframework.com/datasets/terminal-bench/terminal-bench-2)：

| 题目 | 代表工作 | 任务包摘要（前 12 位） |
|---|---|---|
| `cancel-async-tasks` | Python 异步并发、实现与调试、工具交互 | `7c230a29f27c` |
| `multi-source-data-merger` | JSON/CSV/Parquet 检查、转换与结果核对 | `3f7ecbb6adc0` |

数据集共有 89 题，本次固定数据集摘要 `c6fc2e2382c1…e99d078b`，完整摘要见清单。
`cancel-async-tasks` 描述的是题目代码的取消语义，不等于模型 API 的取消覆盖。
必须记录实际出现的多轮工具交互、最长响应、重试和关闭状态；未出现的边界明确记为
未覆盖，不能仅凭题名或任务得分通过。故障夹具独立补充长响应/重试/取消验证；若真实
环境覆盖仍不足，先声明追加实验和预算，不偷偷替换既定的 12 次。

此前真实录制使用的 `html-js-filter` 和备选 `session-window-debug` 属于当前
66 题的 `terminal-bench/terminal-bench` 快照 `39d9f44b4042…35e27732`，**不在这个
TB2 快照里**。历史录制、reward 和传输证明保留，但不得改称 TB2 结果。Harbor
是运行框架，不是数据集版本；题目的 `schema_version` 也不是基准版本。

## 完整矩阵与约束

- Codex 0.154.0、Claude Code 2.1.274、Hermes 0.19.0，各两题、各重复两次：12 次。
- 额外以 Codex / `cancel-async-tasks` 做一次关闭录制、一次开启录制，共 2 次，
  不占用上面的 12 次。顺序预先固定为 off → on，记录顺序偏差和模型非确定性。
- 录制开关对照分别报告 agent 执行耗时、CPU/内存、网络限制与外部依赖失败；安装
  时间单列，不把单次 reward 或耗时变化解释为 recorder 的因果效应。
  工作流的 `--recording-mode on|off` 已实现同一计量器；off 只生成基线报告，
  不冒充采集验收。计量口径和隔离差异见[对照运行说明](harbor-terminal-bench-audit.md#measured-recorder-offon-comparison)。
- 单 agent 900 秒、verifier 900 秒，保持两题发布的时间上限；安装 600 秒。
  串行、无自动重试。发生录制缺口、未分类失败、费用未知/超限时停止后续启动。
  保留失败试验和证据，不重复启动状态不明的付费进程。
- 固定 recorder、agent 二进制/Hermes 运行包、任务包及独立本地树摘要。
  现有五小时候选的绑定文件不得在运行中变更。

## 镜像不能只固定 tag

这两个 TB2 任务的发布配置包含可变镜像 tag。先获取原 tag 当前解析的镜像，随后
使用其 `repository@sha256:...`，并通过 `--task-image` 固定最后一层 Compose 配置。
该选项检查本机 Linux amd64 镜像、registry digest 及原任务 tag 是否指向相同 image ID；
设置 `pull_policy: never`。不修改任务指令、测试、Dockerfile 或 task.toml。

覆盖仅适用于单主服务、共享 verifier 的任务；独立 verifier 或多服务 Compose
会拒绝，防止把另一套判分环境也替换掉。生成的 overlay 纳入工作目录输入锁定，
启动前和录制后改变均使验收失败。这不是对 Docker daemon 本身的远程证明。

## 不付费的检查命令

```bash
python3 tools/m3_experiment_plan.py \
  --plan examples/m3-experiment-plan.json --verify-local

python3 tools/m3_experiment_plan.py \
  --plan examples/m3-experiment-plan.json --require-approved
```

第二条当前应返回 **2**：本机输入匹配，但三个模型、总预算、单次预算、审批引用和
provider spending-cap 证据未填写。检查器不会运行或安装 agent，也没有付费启动器。
`--require-approved` 是声明检查，不是所有 Harbor 调用的全局授权拦截器；不得绕过
实际用户批准，直接把下面的预检命令改成付费执行。

预算金额使用十进制字符串，至少覆盖 12 次矩阵加 2 次对照的单次预留上限。
provider cap 的摘要只是操作员证据引用；脚本不证明账单服务真的实施了该上限。
超时和轮次上限也不是财务硬上限。Harbor 未报告成本时不能当成零，须补充可核实
的 provider 账单/usage 成本证据，或停止后续付费启动。

每个 case 还要跑独立的原生工作流预检，例如（仍不付费）：

```bash
python3 tools/harbor_audit_workflow.py --preflight-only \
  --work-dir /private/new-tb2-case \
  --task /var/tmp/iorec-m3-tb2-tasks-20260918/cancel-async-tasks \
  --task-image alexgshaw/cancel-async-tasks@sha256:84c7fae6b256dcc56a350790e2a9715eefc7dad662a9d8e8a472363aa71ef18d \
  --agent claude --model anthropic/preflight-placeholder \
  --iorec /path/to/qualified/iorec --key-file /private/recorder.key \
  --agent-timeout 900 --verifier-timeout 900
```

使用真实模型前必须替换占位值、冻结经批准的清单及摘要，并绑定每次结果。
“12 个 case 已生成”只代表计划，不能代表 12 次运行，更不能代表 M3 完成。

## 启动前绑定计划与 case

M3 的每个真实工作流都必须同时传入 `--experiment-plan /private/approved-m3-plan.json`
和 `--experiment-case CASE_ID`。矩阵 case ID 由上面的清单检查器列出；额外对照是
`paired-off` 和 `paired-on`，分别使用 `--recording-mode off` / `on`。

控制器先检查完整声明、case 成员关系、模型、任务、录制模式、镜像、时间限制和
实际输入摘要，再将计划 SHA-256 / case ID 锁进配置及 launch intent；启动前和
录制后重查，改变会拒绝启动或验收，不能自动重试。实际返回的 agent、版本、
模型和任务也必须匹配。计划验证代码本身进入输入摘要。未填写的仓库清单应以
`experiment_declaration_incomplete_no_launch` 拒绝，不能拿预检占位模型来过关。

这是输入绑定，**不是实际用户批准或 provider 账单证明**。绑定的真实工作流还会
经过下面的共享账本。不带计划选项的普通 Harbor 工作流仍然存在，不能计作已绑定的
M3 case。操作员必须先获得实际预算批准并设置有效的 provider 侧费用限制。

## 共享执行账本与停止策略

绑定 M3 的真实执行使用 `--experiment-ledger /private/m3-ledger`；省略时默认为
计划文件同目录的 `PLAN_FILE.ledger`。所有 14 个 case 必须使用同一私有目录，按
清单检查器给出的 case 顺序串行执行。预检模式不创建账本，也不预留费用。

- 在调用 Harbor 前落盘单次费用预留和一次性启动标记；模型启动前还要写入工作流
  launch intent，二者通过随机 reservation ID 关联。
- 工作流与账本锁一起由 Harbor 子进程继承；控制器中断不会释放仍在运行的实验。
  观察超时不重启。标记存在而工作流 intent / 终结结果缺失时拒绝重跑。
- case 不能换目录或输入再次启动；不能跳过前一项未结算的 case，也不能把已有
  的非账本启动事后注册进去。
- 费用未知保留 `null`，并继续按单次上限预留；超限、工作流未完成、benchmark
  未正常终结均停止后续启动。正常终结但 reward 为 0 不等于录制或财务控制失败。
- 同一份证据可恢复校验与导入，不启动第二次模型任务。恢复期间先撤销旧的 ready
  状态；保存最多 32 份旧结算记录，不抹掉曾观察到的较高费用。达到历史上限会明确
  停止，不能静默截断。
- 下一项准入还会以非阻塞共享锁锁住前序工作目录，核对当前最终报告摘要与结算
  记录。即使旧任务在进入账本之前就预检失败、报告被撤销，也不能凭旧的 ready
  记录继续启动；前序任务仍在恢复、报告变化或缺失时都停止。

账本位于 `ledger.json`，原子落盘、owner-only；保留完整私有工作目录和原始结果。
正常工作流结束后的 CLI JSON 包含 `experiment_control`。若仍须停止后续实验，
退出码为 **2**；执行/验收错误为 **1**。录制报告可能已经通过采集验收，但账本仍因
费用未知而停止，两种结论不能混为一谈。

费用是 Harbor 报告值，不是经 provider 账单核实的金额；`billing_verified=false`。
账本控制同目录协调的**后续启动**，不能撤销已经产生的费用，也不能替代 provider
实时硬上限。另一个账本目录、复制计划、直接调用普通 Harbor 都不受这把锁控制；
不能据此声称机器级/账户级强制执行。不要用换账本绕过停止状态。未知费用需要补充
可核实证据和操作员处理，当前没有“强制通过”或自动清除失败的选项。

## 完成后汇总额外对照

仅在两个绑定 case 均结束后运行只读汇总；保留完整私有工作目录，不只保留 report：

```bash
python3 tools/m3_pair_comparison.py \
  --plan /private/approved-m3-plan.json \
  --off-work-dir /private/paired-off \
  --on-work-dir /private/paired-on \
  --output /private/reports/pair-comparison.json
```

输出文件必须是私有目录中的新文件，不能位于两个证据工作目录内。工具持共享锁，
拒绝仍在运行的工作流；核对启动绑定、单一终结 trial、Harbor 启动配置、报告与
原件、录制索引摘要、已完成的 proof 阶段和安装依赖清单。它不会重新解密/审计
全部 blob，也不会发起模型调用。输入、版本或系统依赖不同则不给出可比结论。

报告分别列出 CLI wall / user CPU / system CPU / RSS 的 off、on、差值及比值；
分母为零时比值为 `null`。Harbor 的安装、执行和 verifier 耗时单列。未知费用
保留 `null`；未知或超过单次声明上限时 `stop_further_paid_trials=true`，退出码 2。
这不是总预算执行器，也不能替代 provider 费用证据。

`paired_metrics_compared=true` 只表示这些观察已可比对，`qualification_passed`
和 `m3_complete` 仍为 false。网络依赖影响默认 `not_determined_from_summary`，
须结合真实任务日志和录制另行分析；单次对照不能证明因果性能回退。
