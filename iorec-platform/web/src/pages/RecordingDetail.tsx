import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, enc, fmtDur, fmtTime, short } from "../api";
import { Claim, Json, Loading, RelStatus, Terminal, TokenUsageStat, UiState } from "../components";
import DeletionAction from "../DeletionAction";
import EvidenceContext from "../EvidenceContext";
import TaskProgress from "../TaskProgress";

export default function RecordingDetail() {
  const { id = "" } = useParams();
  const [sp] = useSearchParams();
  const [tab, setTab] = useState<"progress" | "timeline" | "attempts" | "coverage" | "lifecycle" | "batches">("progress");
  const rec = useQuery({ queryKey: ["recording", id], queryFn: () => api(`/v1/recordings/${enc(id)}`) });
  const needsTimeline = tab === "timeline" || tab === "lifecycle";
  const tl = useQuery({ queryKey: ["timeline", id], queryFn: () => api(`/v1/recordings/${enc(id)}/timeline`), enabled: needsTimeline });
  const from = sp.get("from"), to = sp.get("to");
  const ev = useQuery({ queryKey: ["events", id, from, to], queryFn: () => api(`/v1/recordings/${enc(id)}/events?from_seq=${from}&to_seq=${to}`), enabled: !!from });
  const r = rec.data;
  const cov = r?.coverage;
  return (
    <>
      <h2 className="recording-title">{r?.benchmark_result?.result?.task ?? "录制详情"}</h2>
      <Loading q={rec} />
      {r ? (
        <div className="panel">
          <div className="row">
            <UiState s={r.ui_state} />
            <Claim c={cov?.claim} />
            <span className="muted">state={r.state}</span>
            <span className="mono">durable {r.durable_seq} · parsed {r.parsed_seq} · final {r.final_seq ?? "–"}</span>
            <TokenUsageStat value={r.input_token_count} observedCalls={r.input_token_call_count} modelCalls={r.model_call_count} label="输入 Token" />
            <TokenUsageStat value={r.output_token_count} observedCalls={r.output_token_call_count} modelCalls={r.model_call_count} label="输出 Token" />
            <span className="muted">rev {r.relation_revision}/{r.analysis_revision}</span>
          </div>
          <p className="small muted">{r.benchmark_result?.result?.agent ?? r.agent_kind ?? "Agent 未标注"} · {fmtTime(r.run_started_at)} → {fmtTime(r.run_ended_at)} · exit {r.exit_code ?? "–"}</p>
          <details><summary>录制标识、启动命令与处理信息</summary>
          <div className="kv" style={{ marginTop: 10 }}>
            <span className="k">运行</span><span className="mono">{r.capture_run_id}</span>
            <span className="k">Agent</span><span>{r.agent_kind} {r.agent_version} <code>{r.command}</code> <span className="muted">{r.cwd}</span></span>
            <span className="k">时间</span><span>{fmtTime(r.run_started_at)} → {fmtTime(r.run_ended_at)} <span className="muted">exit {r.exit_code ?? "–"}</span></span>
            <span className="k">处理状态</span><span>{r.failed_jobs} 个失败处理作业 · {r.active_jobs} 个进行中作业；活动计数见下方任务进度，不按混合 attempt 行计轮数。</span>
            {Array.isArray(r.integrity_alerts) && r.integrity_alerts.length ? (<><span className="k error">完整性告警</span><span><Json v={r.integrity_alerts} max={120} /></span></>) : null}
          </div>
          </details>
        </div>
      ) : null}
      {from ? (
        <div className="panel">
          <h3>原始事件 seq {from}–{to} <Link to={`/recordings/${enc(id)}`} className="small">关闭</Link></h3>
          <Loading q={ev} />
          <Json v={ev.data?.items ?? []} />
        </div>
      ) : null}
      <div className="row" style={{ marginBottom: 10 }}>
        {(["progress", "timeline", "attempts", "coverage", "lifecycle", "batches"] as const).map((t) => (
          <button key={t} className={tab === t ? "primary" : ""} onClick={() => setTab(t)}>{{ progress: "任务进度", timeline: "会话归属", attempts: "底层观测记录", coverage: "coverage", lifecycle: "生命周期事件", batches: "批次" }[t]}</button>
        ))}
      </div>
      {needsTimeline ? <Loading q={tl} /> : null}
      {tab === "progress" ? <TaskProgress key={id} recordingID={id} /> : null}
      {tab === "timeline" && tl.data ? <Timeline d={tl.data} /> : null}
      {tab === "attempts" ? <Attempts recId={id} /> : null}
      {tab === "coverage" ? <><EvidenceContext coverage={cov} proof={r?.transport_proof} /><CoveragePanel cov={cov} manifest={r?.manifest} /></> : null}
      {tab === "lifecycle" && tl.data ? <Json v={tl.data.lifecycle} max={700} /> : null}
      {tab === "batches" && r ? <Json v={r.batches} max={700} /> : null}
      <DeletionAction entity="recording" id={id} />
    </>
  );
}

function Timeline({ d }: { d: any }) {
  const tasks: any[] = d.tasks ?? [];
  const bySession: Record<string, any[]> = {};
  for (const i of d.inferences ?? []) (bySession[i.session_id ?? "?"] ??= []).push(i);
  const sessions: any[] = d.sessions ?? [];
  const roots = sessions.filter((s) => !s.parent_session_id);
  const children = (pid: string) => sessions.filter((s) => s.parent_session_id === pid);
  const renderSession = (s: any, depth: number) => (
    <div key={s.id} style={{ marginLeft: depth * 24 }}>
      <div className="row" style={{ margin: "10px 0 4px" }}>
        <Link to={`/sessions/${enc(s.id)}`} className="mono">{short(s.id, 44)}</Link>
        <span className={`tag ${s.kind === "native" ? "ok" : "info"}`}>{s.kind}</span>
        <span className="tag">{s.role}</span>
        <span className="muted small">{s.turns?.length ?? 0} turns · {s.inference_count} inferences · {fmtTime(s.first_seen_at)}</span>
      </div>
      <div className="tl">
        {(s.turns ?? []).map((t: any) => (
          <div key={t.turn_id}>
            <div className="item turn"><span className="tag ok">turn</span> <span className="mono small">{t.turn_id}</span> <span className="muted small">{fmtTime(t.started_at)}</span></div>
            {(bySession[s.id] ?? []).filter((i) => i.turn_id === t.turn_id).map((i) => <InfRow key={i.id} i={i} />)}
          </div>
        ))}
        {(bySession[s.id] ?? []).filter((i) => !(s.turns ?? []).some((t: any) => t.turn_id === i.turn_id)).map((i) => <InfRow key={i.id} i={i} />)}
      </div>
      {children(s.id).map((c) => renderSession(c, depth + 1))}
    </div>
  );
  return (
    <>
      {tasks.length ? (
        <div className="panel" style={{ marginBottom: 14 }}>
          <h3>逻辑任务（{tasks.length}）</h3>
          <div className="muted small" style={{ marginBottom: 8 }}>切分策略：{tasks[0]?.split_policy}</div>
          <table><tbody>{tasks.map((t) => (
            <tr key={t.id}>
              <td><span className="mono">{short(t.native_id, 40)}</span></td>
              <td><span className="tag info">{t.boundary_kind}</span></td>
              <td>{t.event_count} events</td>
              <td className="muted">seq {t.first_seq}–{t.last_seq} · {(t.session_ids ?? []).length} sessions</td>
            </tr>
          ))}</tbody></table>
        </div>
      ) : null}
      {roots.length === 0 ? <div className="muted">尚无会话（等待 resolve）。</div> : roots.map((s) => renderSession(s, 0))}
      {d.unattributed_attempts?.length ? (
        <div className="panel" style={{ marginTop: 14 }}>
          <h3>未归属 attempt（{d.unattributed_attempts.length}）</h3>
          <table><tbody>{d.unattributed_attempts.map((a: any) => (
            <tr key={a.id}><td><Link to={`/attempts/${enc(a.id)}`} className="mono">{short(a.id, 40)}</Link></td><td>{a.provider_host}</td><td><Terminal s={a.terminal_state} /></td><td className="muted">{fmtTime(a.started_at)}</td></tr>
          ))}</tbody></table>
        </div>
      ) : null}
    </>
  );
}

function InfRow({ i }: { i: any }) {
  return (
    <div className="item inf">
      <div className="row">
        <Link to={`/inferences/${enc(i.id)}`} className="mono">{short(i.id, 36)}</Link>
        {i.task_id ? <span className="tag info">task {short(i.task_id, 24)}</span> : null}
        <RelStatus s={i.relation_status} c={i.confidence} />
        <span className="muted small">{i.model ?? ""} · {i.message_count} msgs · {i.finish_reason ?? "–"}</span>
        {i.server_state !== "none" ? <span className={`tag ${i.server_state === "resolved" ? "ok" : "warn"}`}>server_state {i.server_state}</span> : null}
      </div>
      <div className="row small" style={{ marginTop: 4 }}>
        {(i.attempts ?? []).map((a: any) => (
          <Link key={a.id} to={`/attempts/${enc(a.id)}`}><Terminal s={a.terminal_state} /> <span className="muted">{a.status_code ?? ""} {a.provider_host} {fmtDur(a.started_at, a.ended_at)}</span></Link>
        ))}
      </div>
      {i.response_preview ? <div className="muted small" style={{ marginTop: 4 }}>{i.response_preview}</div> : null}
    </div>
  );
}

function Attempts({ recId }: { recId: string }) {
  const q = useQuery({ queryKey: ["attempts", recId], queryFn: () => api(`/v1/attempts?recording_id=${enc(recId)}&limit=500`) });
  return (
    <>
      <Loading q={q} />
      <p className="muted small">此表混合模型请求、WebSocket 连接和 Hook 等原始观测，不代表任务轮数。模型调用与工具执行请看“任务进度”。</p>
      <table>
        <thead><tr><th>attempt</th><th>inference</th><th>api</th><th>host</th><th>状态</th><th>HTTP</th><th>SSE</th><th>TTFB / 总时长</th><th>开始</th></tr></thead>
        <tbody>{(q.data?.items ?? []).map((a: any) => (
          <tr key={a.id}>
            <td><Link to={`/attempts/${enc(a.id)}`} className="mono">{short(a.id, 30)}</Link></td>
            <td>{a.inference_id ? <Link to={`/inferences/${enc(a.inference_id)}`} className="mono small">{short(a.inference_id, 26)}</Link> : <span className="tag warn">未归属</span>}</td>
            <td>{a.api_mode}</td><td>{a.provider_host}</td><td><Terminal s={a.terminal_state} /> {a.error_class ? <span className="muted small">{a.error_class}</span> : null}</td>
            <td>{a.status_code ?? "–"}</td><td>{a.sse_event_count}</td><td className="small">{fmtDur(a.started_at, a.first_byte_at)} / {fmtDur(a.started_at, a.ended_at)}</td><td className="muted small">{fmtTime(a.started_at)}</td>
          </tr>
        ))}</tbody>
      </table>
    </>
  );
}

function CoveragePanel({ cov, manifest }: { cov: any; manifest: any }) {
  if (!cov) return <div className="muted">coverage 尚未计算。</div>;
  const gates: [string, boolean, any][] = [
    ["capabilities_known", cov.capabilities_known, cov.capabilities_known],
    ["platform_transport_proof_verified", cov.platform_transport_proof_verified === true, cov.platform_transport_proof_verified ?? false],
    ["unknown_tls_surfaces == 0", cov.unknown_tls_surfaces === 0, cov.unknown_tls_surfaces],
    ["unparsed_connections == 0", cov.unparsed_connections === 0, cov.unparsed_connections],
    ["capture_drops == 0", cov.capture_drops === 0, cov.capture_drops],
    ["unknown_egress == 0", cov.unknown_egress === 0, cov.unknown_egress],
    ["model_bypass_connections == 0", cov.model_bypass_connections === 0, cov.model_bypass_connections],
    ["all_attempts_have_terminal_state", cov.all_attempts_have_terminal_state, cov.all_attempts_have_terminal_state],
    ["missing_blobs == 0", cov.missing_blobs === 0, cov.missing_blobs],
    ["unresolved_server_state == 0", cov.unresolved_server_state === 0, cov.unresolved_server_state],
    ["body_unavailable == 0", cov.body_unavailable === 0, cov.body_unavailable],
  ];
  return (
    <div className="grid cols-2">
      <div className="panel">
        <h3>三类结论</h3>
        <div className="kv">
          <span className="k">Observed</span><span>{cov.logical_inferences} 次逻辑调用，{cov.transport_attempts} 次 attempt，来源 {cov.capture_sources?.join(", ")}</span>
          <span className="k">Egress classes</span><span className="mono small">{JSON.stringify(cov.observed_egress_classes ?? {})}</span>
          <span className="k">Verified complete</span><span><Claim c={cov.claim} /> {cov.collector_claim ? <span className="muted small">采集端声明 {cov.collector_claim}</span> : null}</span>
          <span className="k">Unknown / unresolved</span><span>{cov.unattributed_attempts} 未归属 · {cov.unresolved_server_state} 服务端状态未解析 · {cov.unknown_tls_surfaces} 未知 TLS · {cov.known_gaps?.length ? cov.known_gaps.join("; ") : "无已知缺口"}</span>
        </div>
        <h3>Gate</h3>
        <table><tbody>{gates.map(([k, ok, v]) => (<tr key={k}><td className="mono">{k}</td><td><span className={`tag ${ok ? "ok" : "bad"}`}>{ok ? "pass" : "fail"}</span></td><td className="muted">{String(v)}</td></tr>))}</tbody></table>
      </div>
      <div className="panel">
        <h3>平台重算</h3><Json v={cov} max={360} />
        <h3>采集端 manifest</h3><Json v={manifest ?? null} max={200} />
      </div>
    </div>
  );
}
