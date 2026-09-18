import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc, fmtDur, fmtTime } from "../api";
import { EvidenceLinks, Json, Loading, RecLink, Terminal } from "../components";

export default function InferenceDetail() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["inference", id], queryFn: () => api(`/v1/inferences/${enc(id)}`) });
  const i = q.data;
  const n = i?.normalized ?? {};
  const diff = i?.input_diff;
  const added = new Set<number>(diff?.added_indices ?? []);
  const modified = new Set<number>(diff?.modified_indices ?? []);
  return (
    <>
      <h2 className="mono">{id}</h2>
      <Loading q={q} />
      {i ? (
        <>
          <div className="panel">
            <div className="row">
              <span className={`tag ${i.status === "observed" ? "ok" : "info"}`}>{i.status}</span>
              <span className="tag">{i.api_mode}</span>
              <span>{i.model}</span>
              <span className="muted">{i.attempt_count} attempts · {fmtTime(i.first_attempt_at)}</span>
              {i.server_state !== "none" ? <span className={`tag ${i.server_state === "resolved" ? "ok" : "warn"}`}>server_state {i.server_state}</span> : null}
            </div>
            <div className="kv" style={{ marginTop: 8 }}>
              <span className="k">录制</span><RecLink id={i.recording_id} />
              <span className="k">任务</span><span className="mono">{i.task_id ?? "–"}</span>
              <span className="k">会话 / 轮次</span><span>{i.session_id ? <Link to={`/sessions/${enc(i.session_id)}`} className="mono">{i.session_id}</Link> : "–"} <span className="muted">/ {i.turn_id ?? "–"}</span></span>
              <span className="k">usage</span><code>{i.usage ? JSON.stringify(i.usage) : "–"}</code>
              <span className="k">指纹 / 输入 hash</span><span className="mono small">{String(i.request_fingerprint ?? "").slice(0, 16)}… / {String(i.input_hash ?? "").slice(0, 16)}…</span>
              <span className="k">证据</span><span><EvidenceLinks refs={i.evidence_refs} /></span>
            </div>
          </div>
          <div className="panel">
            <h3>调用尝试</h3>
            <table><tbody>{(i.attempts ?? []).map((a: any) => (
              <tr key={a.id}><td><Link to={`/attempts/${enc(a.id)}`} className="mono">{a.id}</Link>{a.parent_attempt_id ? <div><Link to={`/attempts/${enc(a.parent_attempt_id)}`}>所属 WebSocket 连接</Link></div> : null}</td><td><Terminal s={a.terminal_state} /></td><td>{a.status_code ?? ""} {a.error_class ?? ""}</td><td>{a.provider_host}</td><td>{a.entity_kind === "websocket_call" ? `${a.projection?.message_count ?? 0} WS 消息` : `${a.sse_event_count} SSE`}</td><td className="muted">{fmtDur(a.started_at, a.ended_at)}</td></tr>
            ))}</tbody></table>
          </div>
          <div className="grid cols-2">
            <div className="panel">
              <h3>输入 diff（相对上一次调用）</h3>
              {diff ? (
                <>
                  <div className="row small">
                    <span className="tag ok">+{diff.messages.added}</span><span className="tag bad">−{diff.messages.removed}</span><span className="tag warn">~{diff.messages.modified}</span><span className="tag">={diff.messages.unchanged}</span>
                    {diff.system_prompt_changed ? <span className="tag warn">system prompt 变化</span> : null}
                    {diff.model_changed ? <span className="tag warn">模型变化</span> : null}
                    {diff.token_delta != null ? <span className="tag">Δ prompt tokens {diff.token_delta}</span> : null}
                    {diff.tools.added.length || diff.tools.removed.length ? <span className="tag warn">tools +{diff.tools.added.join(",")} −{diff.tools.removed.join(",")}</span> : null}
                  </div>
                  <div className="muted small" style={{ marginTop: 6 }}>基于 <Link to={`/inferences/${enc(diff.from)}`} className="mono">{diff.from}</Link>{diff.server_state_note ? ` · ${diff.server_state_note}` : ""}</div>
                </>
              ) : <span className="muted">链中的第一次调用，或尚未关联。</span>}
              <h3>消息（{n.messages?.length ?? 0}）</h3>
              {n.body_unavailable ? <span className="tag warn">正文不可用</span> : null}
              <div style={{ maxHeight: 600, overflow: "auto" }}>
                {(n.messages ?? []).map((m: any, idx: number) => (
                  <div key={idx} className={`msg ${m.role} ${added.has(idx) ? "added" : modified.has(idx) ? "modified" : ""}`}>
                    <div className="role">#{idx} {m.role}{m.tool_call_id ? ` · tool_call_id ${m.tool_call_id}` : ""}{added.has(idx) ? " · 新增" : modified.has(idx) ? " · 修改" : ""}</div>
                    <div className="small" style={{ whiteSpace: "pre-wrap" }}>{(m.text ?? "").slice(0, 1200)}{(m.text?.length ?? 0) > 1200 ? " …" : ""}</div>
                    {m.tool_calls?.length ? <div className="small muted">tool_calls: {m.tool_calls.map((t: any) => `${t.name}(${t.id ?? ""})`).join(", ")}</div> : null}
                  </div>
                ))}
              </div>
            </div>
            <div className="panel">
              <h3>响应</h3>
              <div className="row small"><span className="tag">{n.finish_reason ?? "–"}</span>{n.stream_terminated === false ? <span className="tag warn">流未终止</span> : null}</div>
              <pre className="json" style={{ maxHeight: 260 }}>{n.response_text || "（无文本）"}</pre>
              {n.response_tool_calls?.length ? (<><h3>响应中的工具调用</h3><Json v={n.response_tool_calls} max={160} /></>) : null}
              <h3>system prompt</h3>
              <pre className="json" style={{ maxHeight: 160 }}>{n.system || "（无）"}</pre>
              <h3>tools / 参数</h3>
              <div className="small">{(n.tools ?? []).map((t: string) => <span key={t} className="tag">{t}</span>)}</div>
              <Json v={n.params} max={120} />
              {n.protocol_inputs?.length ? <><h3>原生协议输入（非用户消息）</h3><Json v={n.protocol_inputs} max={160} /></> : null}
              <h3>关系</h3><Json v={i.relations} max={220} />
            </div>
          </div>
        </>
      ) : null}
    </>
  );
}
