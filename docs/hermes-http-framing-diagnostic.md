# Hermes：有响应正文但传输核验不通过

2026-09-19 对已有两份失败录制做离线诊断，没有重新调用收费模型，也没有改写原件或旧账本。

| 录制 | 严格核验 | 离线补充发现 |
| --- | --- | --- |
| `run-01a0b8ab-9610-71ff-be3e-7dd1f125cdee` | 10/13 模型调用匹配 | 另两条完整 SSE 正文与 proxy 相同，但缺 HTTP 结束块；一条真实取消只送达正文前缀 |
| `run-01a0b8c5-5cdb-77e6-a570-ca4329c8ac93` | 5/6 模型调用匹配 | 第六条有 894,919 字节正文，与 proxy 完全相同，但缺 HTTP 结束块 |

## 三种不同的“结束”

1. SSE 的 `data: [DONE]` 是应用协议结束标记。
2. HTTP/1.1 chunked 响应还需要零长度结束块。上述三条完整 SSE 正文之后，抓包未观察到这个块；客户端先发出了 FIN。
3. Recorder 的 proxy 终态描述它读到上游 EOF、完成采集及向下游转发的状态，不等于客户端一侧已观察到完整 HTTP 封装。平台独立传输证明仍须单独检查。

因此“正文存在”“模型输出完成”“HTTP 传输完整”不能互相替代。默认 TShark HTTP 重组未交出这些未完成的响应，严格审计显示 `stream_status_missing` / `proxy_attempt_missing_from_wire`，并拒绝 `complete=true`。这不是响应正文为零的证据。

真实取消的那一条不同：proxy 保存 8,496 字节，任务侧线上只有 7,931 字节的相同前缀，相差 565 字节，且没有 `[DONE]`。仍保留 `cancelled/downstream_cancelled`，不将其算作正常成功。

## 离线复核方法

在仅所有者可访问的临时目录中，使用本机密钥显式导出 pcap、TLS key log 及 platform bundle；不上传这些明文文件。对指定 TCP stream 执行 TShark 的 TLS-follow 重组，将 HTTP chunk 数据拼接后，与经过摘要校验的 proxy 原始 blob 逐字节比较。另检查 FIN 方向和 TCP 丢失段/重传指示，不把 manifest drops=0 单独当成“绝无丢包”的证明。

TLS-follow 原始输出包含敏感请求和响应，只能由诊断程序在私有环境内消费；公共报告只保留字节数、摘要、终态和布尔核对结果。本次补充诊断不代替生产审计器，不提升失败样本资格。客户端为什么决定关闭，仍不能仅从 FIN 推断。

同时修正 CLI 审计报告中的一个展示错误：HTTP/1 未解码出响应时，`response_end_observed` 不再默认 `true`。原失败结论保持不变；新增回归测试及真实证据重审均确认其为 `false`。

完整非敏感证据见 [诊断报告](../benchmarks/2026-09-19-hermes-http-framing-diagnostic-linux-x86_64.json)。
