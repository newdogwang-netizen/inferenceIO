import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc, fmtDur, fmtTime } from "../api";
import { EvidenceLinks, Json, Loading, RecLink, Terminal } from "../components";

function BodyEvidence({ inline, bodyRef, parts }: { inline: any; bodyRef?: string; parts?: any[] }) {
  const allParts = parts ?? [];
  const availableParts = allParts.filter((part: any) => part.sha256);
  if (allParts.length) {
    const bytes = allParts.reduce((sum: number, part: any) => sum + Number(part.size ?? 0), 0);
    return (
      <div>
        {inline ? <><div className="muted small">协议内容视图；下方链接保留原始消息</div><Json v={inline} max={500} /></> : null}
        <div className="muted small">{allParts.length} 消息 / chunks · {bytes} B（采集顺序）</div>
        {availableParts.map((part: any) => (
          <div key={`${part.seq}-${part.sha256}`}>
            <a href={`/v1/blobs/${part.sha256}`} target="_blank" rel="noreferrer" className="mono small">
              seq {part.seq} blob {String(part.sha256).slice(0, 16)}… ({part.size} B)
            </a>
            {part.raw_truncated ? <span className="tag warn">截断</span> : null}
          </div>
        ))}
        {allParts.filter((part: any) => !part.sha256).map((part: any) => (
          <div key={`${part.seq}-empty`} className="mono small muted">
            #{part.chunk_sequence} 空块（0 B，无 Blob）
          </div>
        ))}
      </div>
    );
  }
  if (inline) return <Json v={inline} max={500} />;
  if (bodyRef) return <a href={`/v1/blobs/${bodyRef}`} target="_blank" rel="noreferrer">blob {bodyRef}</a>;
  return <span className="muted">不可用</span>;
}

export default function AttemptDetail() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["attempt", id], queryFn: () => api(`/v1/attempts/${enc(id)}`) });
  const a = q.data;
  return (
    <>
      <h2 className="mono">{id}</h2>
      <Loading q={q} />
      {a ? (
        <>
          <div className="panel">
            {a.entity_kind === "websocket_connection" ? <p>WebSocket 连接：传输终态不代表其中每次模型调用的结果。请从下方逐次调用进入详情。</p> : null}
            <div className="row">
              <Terminal s={a.terminal_state} /> <span>{a.status_code ?? ""} {a.error_class ?? ""}</span>
              <span className="tag">{a.api_mode}</span><span className="tag">{a.source}</span>
              <span className="muted">{a.method} {a.url}</span>
            </div>
            <div className="kv" style={{ marginTop: 8 }}>
              <span className="k">录制</span><RecLink id={a.recording_id} />
              <span className="k">逻辑调用</span><span>{a.inference_id ? <Link to={`/inferences/${enc(a.inference_id)}`} className="mono">{a.inference_id}</Link> : a.entity_kind === "websocket_connection" ? "见逐次调用列表" : <span className="tag warn">未归属</span>}</span>
              {a.parent_connection ? <><span className="k">所属连接</span><span><Link to={`/attempts/${enc(a.parent_connection.id)}`}>查看连接</Link> · <Terminal s={a.parent_connection.terminal_state} /> {a.parent_connection.error_class}</span></> : null}
              {a.projection ? <><span className="k">模型结果 / 关联</span><span>{a.projection.outcome ?? "连接不计模型结果"} · {a.projection.association ?? "–"}</span><span className="k">消息采集</span><span>{a.projection.capture_state}（仅已观测消息；独立传输证明见录制页）</span></> : null}
              <span className="k">连接 / pid</span><span className="mono">{a.connection_id ?? "–"} / {a.pid ?? "–"}</span>
              <span className="k">时间</span><span>{fmtTime(a.started_at)} · TTFB {fmtDur(a.started_at, a.first_byte_at)} · 总 {fmtDur(a.started_at, a.ended_at)}</span>
              <span className="k">模型 / usage</span><span>{a.model ?? "–"} <code>{a.usage ? JSON.stringify(a.usage) : ""}</code></span>
              <span className="k">SSE 事件</span><span>{a.sse_event_count}</span>
              <span className="k">证据</span><span><EvidenceLinks refs={a.evidence_refs?.length ? a.evidence_refs : [{ recording_id: a.recording_id, first_seq: a.first_seq, last_seq: a.last_seq }]} /></span>
              <span className="k">处理器</span><span className="mono">{a.processor_version}</span>
            </div>
          </div>
          {a.calls ? <div className="panel"><h3>逐次模型调用（{a.calls.length}）</h3>
            <p className="muted small">未解析消息：{a.projection?.unresolved_messages ?? "–"}。Ping/Pong/Close 单独保留为连接控制消息。</p>
            <table><thead><tr><th>调用</th><th>时间</th><th>模型结果</th><th>归属依据</th><th>用量</th></tr></thead><tbody>{a.calls.map((c: any, i: number) => <tr key={c.id}><td><Link to={`/attempts/${enc(c.id)}`}>调用 {i + 1}</Link></td><td>{fmtTime(c.started_at)}</td><td>{c.projection?.outcome}</td><td>{c.projection?.association}</td><td><code>{JSON.stringify(c.usage)}</code></td></tr>)}</tbody></table>
          </div> : null}
          <div className="grid cols-2">
            <div className="panel">
              <h3>请求 header（白名单）</h3><Json v={a.request_headers} max={140} />
              <h3>请求正文（raw）</h3>
              <BodyEvidence inline={a.request_body} bodyRef={a.request_body_ref} parts={a.request_body_parts} />
            </div>
            <div className="panel">
              <h3>响应 header</h3><Json v={a.response_headers} max={140} />
              <h3>响应文本（重组）</h3>
              <pre className="json" style={{ maxHeight: 200 }}>{a.response_text || <span className="muted">（无）</span>}</pre>
              <h3>响应正文（raw）</h3>
              <BodyEvidence inline={a.response_body} bodyRef={a.response_body_ref} parts={a.response_body_parts} />
            </div>
          </div>
          <div className="panel">
            <h3>规范化视图</h3><Json v={a.normalized} max={400} />
            {a.projection ? <><h3>派生状态与局限</h3><Json v={a.projection} max={200} /></> : null}
          </div>
          <div className="panel">
            <h3>原始事件（{a.events?.length ?? 0}）</h3>
            <table>
              <thead><tr><th>seq</th><th>时间</th><th>event / 归属</th><th>payload</th></tr></thead>
              <tbody>{(a.events ?? []).map((e: any) => (
                <tr key={`${e.recording_id}-${e.seq}`}><td className="mono">{e.seq}</td><td className="muted small">{fmtTime(e.wall_time)}</td><td className="mono">{e.event}<div className="small">{e.assignment_reason} {e.call_attempt_id ? <Link to={`/attempts/${enc(e.call_attempt_id)}`}>所属调用</Link> : null}</div></td>
                  <td><code className="small">{e.payload ? JSON.stringify(e.payload).slice(0, 300) : ""}</code>{e.payload_sha256 ? <> <a href={`/v1/blobs/${e.payload_sha256}`} target="_blank" rel="noreferrer" className="mono small">blob {String(e.payload_sha256).slice(0, 16)}… ({e.payload_size} B)</a></> : null}</td></tr>
              ))}</tbody>
            </table>
          </div>
          <div className="panel"><h3>关系</h3><Json v={a.relations} max={200} /></div>
        </>
      ) : null}
    </>
  );
}
