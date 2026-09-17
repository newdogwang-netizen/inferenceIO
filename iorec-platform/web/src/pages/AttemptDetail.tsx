import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc, fmtDur, fmtTime } from "../api";
import { EvidenceLinks, Json, Loading, RecLink, Terminal } from "../components";

function BodyEvidence({ inline, bodyRef, parts }: { inline: any; bodyRef?: string; parts?: any[] }) {
  if (inline) return <Json v={inline} max={500} />;
  const allParts = parts ?? [];
  const availableParts = allParts.filter((part: any) => part.sha256);
  if (allParts.length) {
    const bytes = allParts.reduce((sum: number, part: any) => sum + Number(part.size ?? 0), 0);
    return (
      <div>
        <div className="muted small">{allParts.length} chunks · {bytes} B（wire 顺序）</div>
        {availableParts.map((part: any) => (
          <div key={`${part.seq}-${part.sha256}`}>
            <a href={`/v1/blobs/${part.sha256}`} target="_blank" rel="noreferrer" className="mono small">
              #{part.chunk_sequence} blob {String(part.sha256).slice(0, 16)}… ({part.size} B)
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
            <div className="row">
              <Terminal s={a.terminal_state} /> <span>{a.status_code ?? ""} {a.error_class ?? ""}</span>
              <span className="tag">{a.api_mode}</span><span className="tag">{a.source}</span>
              <span className="muted">{a.method} {a.url}</span>
            </div>
            <div className="kv" style={{ marginTop: 8 }}>
              <span className="k">录制</span><RecLink id={a.recording_id} />
              <span className="k">逻辑调用</span><span>{a.inference_id ? <Link to={`/inferences/${enc(a.inference_id)}`} className="mono">{a.inference_id}</Link> : <span className="tag warn">未归属</span>}</span>
              <span className="k">连接 / pid</span><span className="mono">{a.connection_id ?? "–"} / {a.pid ?? "–"}</span>
              <span className="k">时间</span><span>{fmtTime(a.started_at)} · TTFB {fmtDur(a.started_at, a.first_byte_at)} · 总 {fmtDur(a.started_at, a.ended_at)}</span>
              <span className="k">模型 / usage</span><span>{a.model ?? "–"} <code>{a.usage ? JSON.stringify(a.usage) : ""}</code></span>
              <span className="k">SSE 事件</span><span>{a.sse_event_count}</span>
              <span className="k">证据</span><span><EvidenceLinks refs={[{ recording_id: a.recording_id, first_seq: a.first_seq, last_seq: a.last_seq }]} /></span>
              <span className="k">处理器</span><span className="mono">{a.processor_version}</span>
            </div>
          </div>
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
          </div>
          <div className="panel">
            <h3>原始事件（{a.events?.length ?? 0}）</h3>
            <table>
              <thead><tr><th>seq</th><th>时间</th><th>event</th><th>payload</th></tr></thead>
              <tbody>{(a.events ?? []).map((e: any) => (
                <tr key={e.seq}><td className="mono">{e.seq}</td><td className="muted small">{fmtTime(e.wall_time)}</td><td className="mono">{e.event}</td>
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
