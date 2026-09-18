import { Claim, Json } from "./components";

export default function EvidenceContext({ coverage, proof, processor }: { coverage: any; proof: any; processor?: string }) {
  const markers = (coverage?.tls_surfaces ?? []).filter((s: any) => String(s.kind ?? "").includes("marker"));
  return <div className="panel">
    <h3>证据范围与未解决缺口</h3>
    <p>模型结果、连接关闭、采集完整性、基准得分是四个独立结论。某次响应 completed 不会证明同连接的所有请求成功，也不会把 client_read 改写为正常关闭。</p>
    <div className="kv">
      <span className="k">整体 coverage</span><span><Claim c={coverage?.claim} /> · 采集端原声明 {coverage?.collector_claim ?? "未知"}</span>
      <span className="k">独立传输证明</span><span className={`tag ${proof?.verified ? "ok" : "warn"}`}>{proof?.status ?? "未生成"}</span>
      <span className="k">证明边界</span><code>{proof?.completeness_boundary ?? "未声明"}</code>
      <span className="k">解析器</span><span>{proof?.decoder?.kind ?? "–"} {proof?.decoder?.version ?? ""}<div className="mono small">{proof?.decoder?.sha256 ?? ""}</div></span>
      <span className="k">处理器版本</span><span>{processor ?? "–"} · {proof?.processor_version ?? "–"} · {coverage?.processor_version ?? "–"}</span>
      <span className="k">消息 / 状态关联</span><span>{coverage?.unresolved_websocket_messages ?? "–"} 条 WS 消息未解析；{coverage?.calls_without_model_terminal ?? "–"} 次调用缺少明确模型终态；{coverage?.unresolved_server_state ?? "–"} 个服务端状态引用未解析</span>
      <span className="k">正文 / 丢失</span><span>{coverage?.missing_blobs ?? "–"} 个缺失 blob；{coverage?.body_unavailable ?? "–"} 次正文不可用；{coverage?.capture_drops ?? "–"} 个采集丢失</span>
    </div>
    {proof?.completeness_boundary === "target-network-namespace-ip-transport" ? <p className="small">本证明只核对隔离目标网络命名空间中的 IP 传输及载荷一致性；不涵盖宿主机全部流量、Unix IPC、代理到厂商的全部链路或服务端隐藏上下文。</p> : null}
    <h3>TLS：静态标记与实际连接分开看</h3>
    <p className="small">静态二进制标记只说明某种 TLS 实现可能存在，不等于实际发现了未解密连接。当前总体覆盖策略仍保守保留这些未知项；不能因为传输 proof verified 就自动升级总体结论。</p>
    <div className="kv"><span className="k">静态实现线索</span><span>{markers.length ? markers.map((s: any) => `${s.kind} × ${s.count}`).join("；") : "无已索引标记"}</span>
      <span className="k">未知 TLS 指标</span><span>{coverage?.unknown_tls_surfaces ?? "–"}（可能包含上述线索，不作为未解密连接数）</span>
      <span className="k">证明中已解密流</span><span>{proof?.tls_decrypted_streams ?? "–"}</span>
      <span className="k">未解析连接指标</span><span>{coverage?.unparsed_connections ?? "–"}（也可能来自协议/采集缺口，并非专指 TLS 解密失败）</span></div>
    <details><summary>传输证明原文与已知缺口</summary><Json v={{ proof, known_gaps: coverage?.known_gaps }} max={420} /></details>
  </div>;
}
