# M3 真实实验清单与启动前检查

状态：**尚未批准付费执行，尚无本轮真实实验结果**。机器清单位于
[`examples/m3-experiment-plan.json`](../examples/m3-experiment-plan.json)。模型和预算
故意保留 `null`；不能把占位模型、安装检查或短时合成负载计入 12 次实验。

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
