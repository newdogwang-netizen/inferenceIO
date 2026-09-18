import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, enc, fmtDur, fmtTime } from "../api";
import { EvidenceLinks, Json, Loading, RecLink, Terminal } from "../components";
import AttemptEvents from "../AttemptEvents";
import EvidenceContext from "../EvidenceContext";
import BenchmarkResult from "../BenchmarkResult";

const tabs = { summary: "调用摘要", text: "响应文本 / 正文", normalized: "规范化内容", events: "原始协议事件", proof: "传输证明" } as const;
type Tab = keyof typeof tabs;

export default function AttemptDetail() {
  const { id = "" } = useParams();
  const [search, setSearch] = useSearchParams();
  const requested = search.get("view") ?? "summary";
  const tab: Tab = Object.prototype.hasOwnProperty.call(tabs, requested) ? requested as Tab : "summary";
  const q = useQuery({ queryKey: ["attempt", id], queryFn: () => api(`/v1/attempts/${enc(id)}?view=normalized`) });
  const a = q.data;
  const connection = a?.entity_kind === "websocket_connection";
  const context = a?.evidence_context;
  return <>
    <h2 className="mono">{id}</h2><Loading q={q} />
    {a ? <>
      <div className="panel">
        <div className="row"><span className="tag">{connection ? "WebSocket 连接" : a.entity_kind === "websocket_call" ? "WebSocket 模型调用" : "模型调用尝试"}</span><Terminal s={a.terminal_state} /><span>{a.status_code ?? ""} {a.error_class ?? ""}</span><span className="tag">{a.api_mode}</span></div>
        <div className="row small" style={{ marginTop: 8 }}><RecLink id={a.recording_id} />
          {a.inference_id ? <Link to={`/inferences/${enc(a.inference_id)}`}>逻辑 inference</Link> : null}
          {a.parent_connection ? <Link to={`/attempts/${enc(a.parent_connection.id)}`}>查看连接</Link> : null}
          <span className="muted">{a.processor_version}</span></div>
      </div>
      <nav className="row" aria-label="调用证据视图" style={{ marginBottom: 12 }}>{(Object.keys(tabs) as Tab[]).map(t => <button key={t} className={tab === t ? "primary" : ""} aria-current={tab === t ? "page" : undefined} onClick={() => setSearch({ view: t })}>{tabs[t]}</button>)}</nav>
      {tab === "summary" ? <>
        <div className="panel">
          {connection ? <p>这是承载多次模型请求的连接。连接关闭状态不代表其中每次调用的结果，请从下方逐次调用进入详情。</p> : null}
          <div className="kv">
            <span className="k">模型结果</span><span>{connection ? "见逐次调用列表" : a.projection?.outcome ?? a.normalized?.finish_reason ?? "尚未确定"}</span>
            <span className="k">传输状态</span><span>{a.parent_connection?.terminal_state ?? a.terminal_state} · {a.parent_connection?.error_class ?? a.error_class ?? "无已记录错误分类"}</span>
            <span className="k">关闭诊断</span><span>{a.parent_connection?.projection?.close_diagnosis ?? a.projection?.close_diagnosis ?? "未提供"}（原始错误缺少底层详情时不能推断正常或异常握手）</span>
            <span className="k">采集状态</span><span>{a.projection?.capture_state ?? "见录制 coverage"} · <Link to="?view=proof">查看独立证明及范围</Link></span>
            <span className="k">基准判分</span><BenchmarkResult value={context?.benchmark_result} />
            <span className="k">关联依据</span><span>{a.projection?.association ?? "见关系与原始事件"}</span>
            <span className="k">模型 / 用量</span><span>{a.model ?? "–"} <code>{a.usage ? JSON.stringify(a.usage) : ""}</code></span>
            <span className="k">时间</span><span>{fmtTime(a.started_at)} · 首响应 {fmtDur(a.started_at, a.first_byte_at)} · 总 {fmtDur(a.started_at, a.ended_at)}</span>
            <span className="k">连接 / PID</span><span className="mono">{a.connection_id ?? "–"} / {a.pid ?? "–"}</span>
            <span className="k">证据</span><EvidenceLinks refs={a.evidence_refs?.length ? a.evidence_refs : [{ recording_id: a.recording_id, first_seq: a.first_seq, last_seq: a.last_seq }]} />
          </div>
          <details><summary>派生诊断及关系</summary><Json v={{ projection: a.projection, relations: a.relations }} max={300} /></details>
        </div>
        {a.calls ? <div className="panel"><h3>逐次模型调用（{a.calls.length}）</h3>
          <p className="muted small">未解析消息：{a.projection?.unresolved_messages ?? "–"}。<Link to="?view=events">逐条查看归属与控制消息</Link></p>
          <table><thead><tr><th>调用</th><th>时间</th><th>模型结果</th><th>归属依据</th><th>用量</th></tr></thead><tbody>{a.calls.map((c: any, i: number) => <tr key={c.id}><td><Link to={`/attempts/${enc(c.id)}`}>调用 {i + 1}</Link></td><td>{fmtTime(c.started_at)}</td><td>{c.projection?.outcome}</td><td>{c.projection?.association}</td><td><code>{JSON.stringify(c.usage)}</code></td></tr>)}</tbody></table>
        </div> : null}
      </> : null}
      {tab === "text" ? <div className="panel">
        <h3>响应文本</h3><p className="small muted">从属于本次调用的协议事件提取 / 重组的人类可读文本，不是全部响应正文。工具调用、usage、状态与协议元数据请看规范化或原始事件。</p>
        <pre className="json" style={{ maxHeight: 400 }}>{a.response_text || (connection ? "连接不合并多次调用的响应文本，请进入具体调用。" : "（无文本；可能只有工具调用或未收到正文）")}</pre>
        <h3>协议正文快照</h3><p className="small muted">以下为请求对象与结束响应的结构化快照；不是逐字节线上消息。原始消息 / HTTP chunks 保存在各事件的 blob 中。</p>
        <details><summary>请求正文</summary><Json v={a.request_body} max={450} />{a.request_body_ref ? <a href={`/v1/blobs/${a.request_body_ref}`} target="_blank" rel="noreferrer">请求原始 blob</a> : null}</details>
        <details><summary>结束响应正文</summary><Json v={a.response_body} max={450} />{a.response_body_ref ? <a href={`/v1/blobs/${a.response_body_ref}`} target="_blank" rel="noreferrer">响应原始 blob</a> : null}</details>
        <details><summary>HTTP headers（采集白名单）</summary><Json v={{ request: a.request_headers, response: a.response_headers }} max={250} /></details>
        <Link to="?view=events">打开原始正文事件与 blob</Link>
      </div> : null}
      {tab === "normalized" ? <div className="panel"><h3>规范化视图</h3><p className="small muted">按协议整理的消息、工具调用 / 结果、参数、用量和状态引用。它是可重建的派生视图，不替代原始证据，也不代表厂商内部实际上下文。</p><Json v={a.normalized} max={700} /></div> : null}
      {tab === "events" ? <AttemptEvents key={id} id={id} /> : null}
      {tab === "proof" ? <EvidenceContext coverage={context?.coverage} proof={context?.transport_proof} processor={a.processor_version} /> : null}
    </> : null}
  </>;
}
