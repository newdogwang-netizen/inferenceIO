import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, ApiError, enc, fmtDur, fmtTime } from "./api";
import { Loading, Terminal } from "./components";
import BenchmarkResult from "./BenchmarkResult";

type Evidence = { attempt_id: string; recording_id: string; first_seq: number; last_seq: number };
type Tool = {
  id: string; name: string; state: string; arguments_available: boolean; arguments_preview: string;
  arguments_characters: number; evidence: Evidence; result_variants: number; observation_count: number;
  result?: { evidence: Evidence; call_ordinal: number; preview: string; characters: number; sha256: string };
};
type Call = {
  ordinal: number; evidence: Evidence; inference_id?: string; model: string; api_mode: string;
  terminal_state: string; started_at?: string; ended_at?: string; input_preview: string;
  response_preview: string; response_characters: number; tools: Tool[]; body_unavailable: boolean;
  unmatched_tool_results: number; parent_connection_id?: string;
  predecessors: { attempt_id?: string; ordinal?: number; kind: string; status: string }[];
};
type Progress = {
  capture_run_id: string; snapshot: string; total: number; next_offset: number | null;
  summary: {
    model_calls: number; websocket_connections: number; hook_observations: number; hook_events: number;
    other_http_requests: number; all_attempt_rows: number; raw_events: number; sse_events: number;
    websocket_messages: number; stream_events: number; normalization_pending: number;
    tools: { requested: number; results_observed: number; awaiting_result_evidence: number; ambiguous: number;
      conflicting: number; unmatched_result_observations: number };
  };
  items: Call[]; benchmark_result: any;
};

const toolStates: Record<string, string> = {
  result_observed: "已见执行结果", requested_only: "仅见调用请求", missing_call_id: "缺少工具 ID",
  ambiguous_call_id: "归属有歧义", conflicting_results: "结果有冲突",
};
const number = (v: number) => v.toLocaleString();

function EvidenceLink({ value, children }: { value: Evidence; children: React.ReactNode }) {
  return <Link to={`/attempts/${enc(value.attempt_id)}`}>{children}</Link>;
}

export default function TaskProgress({ recordingID }: { recordingID: string }) {
  const section = useRef<HTMLElement>(null);
  const shownOffset = useRef(0);
  const [page, setPage] = useState<{ offset: number; snapshot?: string }>({ offset: 0 });
  const [history, setHistory] = useState<typeof page[]>([]);
  const q = useQuery({
    queryKey: ["task-progress", recordingID, page],
    queryFn: () => api<Progress>(`/v1/recordings/${enc(recordingID)}/progress?limit=25&offset=${page.offset}${page.snapshot ? `&snapshot=${page.snapshot}` : ""}`),
    retry: false,
    // First page can track newly uploaded evidence; later pages deliberately
    // stay bound to their snapshot. A changed snapshot requires explicit reset.
    refetchInterval: page.offset === 0 ? 10000 : false,
  });
  useEffect(() => {
    if (q.isSuccess && shownOffset.current !== page.offset) {
      section.current?.scrollIntoView({ block: "start" });
      shownOffset.current = page.offset;
    }
  }, [page.offset, q.isSuccess]);
  const reset = () => {
    setPage({ offset: 0 });
    setHistory([]);
    // Changing the key fetches page one. Do not also refetch the old page with
    // its stale snapshot, which would generate another avoidable 409.
    if (page.offset === 0) void q.refetch();
  };
  const changed = q.error instanceof ApiError && q.error.code === "progress_snapshot_changed";
  const d = q.data;
  const s = d?.summary;
  return <section ref={section} aria-label="任务进度链" aria-busy={q.isFetching} className="task-progress">
    <div className="row progress-heading">
      <div><h3>任务进度链</h3><p className="muted small">跨本次运行的全部可用录制分段。按证据顺序排列，不把时间先后当作因果关系。</p></div>
      <button onClick={reset}>刷新进度</button>
    </div>
    {changed ? <div role="status" className="panel">
      <p>模型调用记录已更新，本页已过期。已有记录没有丢失，请返回第一页重新浏览。</p>
      <button onClick={reset}>返回第一页并刷新</button>
    </div> : <Loading q={q} />}
    {s ? <>
      <dl className="activity-metrics" aria-label="独立活动统计">
        <div><dt>模型调用</dt><dd>{number(s.model_calls)}</dd><p>实际请求；不是对话轮数，包含重试</p></div>
        <div><dt>工具执行</dt><dd>{number(s.tools.results_observed)}<small> / {number(s.tools.requested)} 发起</small></dd><p>按唯一工具 ID 观察返回结果；不等于成功</p></div>
        <div><dt>连接</dt><dd>{number(s.websocket_connections)}</dd><p>已观测 WebSocket 父连接，不推算 HTTP 连接</p></div>
        <div><dt>Hook 观测</dt><dd>{number(s.hook_observations)}</dd><p>单独计数，不叠加成模型调用</p></div>
        <div><dt>流式事件</dt><dd>{number(s.stream_events)}</dd><p>SSE {number(s.sse_events)} · WebSocket 消息 {number(s.websocket_messages)}</p></div>
      </dl>
      <p className="muted small">原始事件 {number(s.raw_events)} · 其他 HTTP 请求 {number(s.other_http_requests)} · 底层 attempt 行 {number(s.all_attempt_rows)}。这些单位不能相加作为对话轮数。</p>
      {s.normalization_pending || s.tools.awaiting_result_evidence || s.tools.ambiguous || s.tools.conflicting || s.tools.unmatched_result_observations ?
        <div className="progress-notice" role="status">
          证据边界：{s.normalization_pending} 次调用缺少规范化视图；{s.tools.awaiting_result_evidence} 个工具未见结果；
          {s.tools.ambiguous} 个 ID 缺失或有歧义；{s.tools.conflicting} 个结果冲突；{s.tools.unmatched_result_observations} 条上下文结果未能归属。
          缺证据不自动判为工具失败或执行成功。
        </div> : null}
    </> : null}
    {d && !q.error ? <>
      {d.items.length === 0 ? <div className="panel">尚无已解析的代理模型调用。Hook、连接和原始事件会单独统计；等待上传或解析后刷新，不据此断言没有模型活动。</div> : null}
      <ol className="progress-chain" start={page.offset + 1}>
        {d.items.map(c => <li key={c.evidence.attempt_id} className="progress-step">
          <div className="row progress-step-title"><strong>调用 {c.ordinal}</strong><span>{c.model || "模型未知"}</span><Terminal s={c.terminal_state} /><span className="muted small">{fmtDur(c.started_at, c.ended_at)}</span></div>
          <div className="row small muted"><span>{fmtTime(c.started_at)}</span><span>{c.api_mode}</span>
            <EvidenceLink value={c.evidence}>调用详情</EvidenceLink>
            {c.evidence.first_seq > 0 ? <Link to={`/recordings/${enc(c.evidence.recording_id)}?from=${c.evidence.first_seq}&to=${c.evidence.last_seq}`}>原始 seq {c.evidence.first_seq}–{c.evidence.last_seq}</Link> : <span>事件序号未知</span>}
            {c.parent_connection_id ? <Link to={`/attempts/${enc(c.parent_connection_id)}`}>所属连接</Link> : null}
          </div>
          <div className="progress-links small">
            {c.predecessors.length ? c.predecessors.map((p, i) => <span key={i}>
              {p.kind === "tool_call_id" ? "新返回的工具结果来自" : "previous_response 承接"}：{p.status === "explicit_id" && p.attempt_id ? <Link to={`/attempts/${enc(p.attempt_id)}`}>调用 {p.ordinal}（显式 ID）</Link> : "关联未解析"}
            </span>) : <span className="muted">{c.ordinal === 1 ? "首条已观测调用" : "与前一行仅表示先后顺序；没有确定的承接证据"}</span>}
          </div>
          {c.input_preview ? <details className="progress-input"><summary>本次输入中的用户任务 / 消息</summary><pre>{c.input_preview}</pre></details> : null}
          {c.body_unavailable ? <p className="error">正文或规范化证据不可用，请检查原始事件；下方不补造内容。</p> : null}
          {c.response_preview ? <p className="progress-response">{c.response_preview}{c.response_characters > 1200 ? <span className="muted">（共 {number(c.response_characters)} 字符，完整内容见调用详情）</span> : null}</p> : null}
          <div className="progress-tools">
            {c.tools.map((t, i) => <details key={`${t.id}/${i}`} className="progress-tool">
              <summary><strong>{t.name || "未命名工具"}</strong><span className={`tag ${t.state === "result_observed" ? "info" : "warn"}`}>{toolStates[t.state] ?? t.state}</span></summary>
              <div className="small muted mono">{t.id}</div>
              <h4>请求的操作</h4>
              {t.arguments_available ? <pre>{t.arguments_preview}</pre> : <p className="muted">当前规范化视图未保留参数；请通过原始请求 / 响应事件核查，不能据哈希恢复内容。</p>}
              {t.arguments_characters > 1200 ? <p className="muted small">参数共 {number(t.arguments_characters)} 字符，此处仅预览。</p> : null}
              <EvidenceLink value={t.evidence}>工具请求证据</EvidenceLink>
              <h4>执行结果证据</h4>
              {t.result ? <><pre>{t.result.preview || "（已观察到空结果）"}</pre><div className="row small"><EvidenceLink value={t.result.evidence}>首次观察到结果的调用 {t.result.call_ordinal}</EvidenceLink><span className="muted">结果进入该次模型输入；上下文观测 {t.observation_count} 次 · {t.result_variants} 种内容</span></div></> : <p className="muted">尚无可唯一归属的返回结果；这条记录仅证明模型提出了工具请求。</p>}
              {t.result_variants > 1 ? <p className="error">同一工具 ID 出现不同结果，保留冲突；以上仅显示首次结果。</p> : null}
            </details>)}
            {!c.tools.length ? <p className="muted small">本次响应未解析出工具请求。</p> : null}
          </div>
        </li>)}
      </ol>
      {d.next_offset === null ? <div className="progress-outcome"><strong>任务最终判分</strong><BenchmarkResult value={d.benchmark_result} /></div> : <p className="muted small">继续翻页查看后续调用与最终判分；当前并非任务的全部步骤。</p>}
      <div className="row progress-pager"><span className="muted">{d.total ? `${page.offset + 1}–${page.offset + d.items.length}` : "0"} / {number(d.total)} 次模型调用</span>
        <button disabled={!history.length || q.isFetching} onClick={() => { const h = [...history]; const prev = h.pop(); if (prev) setPage(prev); setHistory(h); }}>上一页</button>
        <button disabled={d.next_offset === null || q.isFetching} onClick={() => { if (d.next_offset !== null) { setHistory([...history, page]); setPage({ offset: d.next_offset, snapshot: d.snapshot }); } }}>下一页</button>
      </div>
    </> : null}
  </section>;
}
