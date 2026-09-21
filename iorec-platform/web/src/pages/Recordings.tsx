import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, fmtTime } from "../api";
import { Claim, Loading, RecLink, TokenUsageStat, UiState } from "../components";
import { Link } from "react-router-dom";
import { enc } from "../api";

export default function Recordings() {
  const [cursor, setCursor] = useState("");
  const [stack, setStack] = useState<string[]>([]);
  const q = useQuery({ queryKey: ["recordings", cursor], queryFn: () => api(`/v1/recordings?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`) });
  const recordings = q.data?.items ?? [];
  const page = stack.length + 1;
  return (
    <>
      <header className="page-header recordings-header">
        <div>
          <p className="page-eyebrow">证据目录</p>
          <h2>录制</h2>
          <p className="page-description">逐分段核对模型调用、Token 用量、传输观测和证据完整性。</p>
        </div>
        <div className="page-meta" aria-live="polite">
          <strong>{recordings.length}</strong>
          <span>本页录制</span>
        </div>
      </header>
      <div className="context-note">
        <strong>统计口径</strong>
        <p>模型请求、Provider 上报 Token、WebSocket、Hook 与流式事件分别计数，不混算对话轮数。Token 未上报的调用不按零计算；跨分段工具执行请进入任务进度。</p>
      </div>
      <div className="data-surface recordings-surface">
        <div className="table-scroll recordings-scroll" role="region" aria-label="录制数据表，可横向滚动" tabIndex={0}>
          <table className="data-table recordings-table">
            <caption className="sr-only">录制分段及各类采集指标</caption>
            <thead><tr>
              <th scope="col">录制</th>
              <th scope="col">运行 / Agent</th>
              <th scope="col">状态</th>
              <th scope="col">覆盖结论</th>
              <th scope="col" className="numeric">模型调用</th>
              <th scope="col" className="numeric">输入 Token</th>
              <th scope="col" className="numeric">输出 Token</th>
              <th scope="col">工具执行</th>
              <th scope="col" className="numeric">连接（WS）</th>
              <th scope="col" className="numeric">Hook 观测</th>
              <th scope="col" className="numeric">流式事件</th>
              <th scope="col" className="numeric">证据序号<span className="th-detail">durable / parsed / final</span></th>
              <th scope="col" className="numeric">缺失 blob</th>
              <th scope="col" className="numeric">告警</th>
              <th scope="col">创建时间</th>
            </tr></thead>
            <tbody>
              {recordings.map((r: any) => {
                const missing = Array.isArray(r.missing_blobs) ? r.missing_blobs.length : 0;
                const alerts = Array.isArray(r.integrity_alerts) ? r.integrity_alerts.length : 0;
                return (
                  <tr key={r.id} className={missing || alerts ? "row-attention" : undefined}>
                    <td className="recording-id-cell"><RecLink id={r.id} /></td>
                    <td className="run-cell">
                      <div className="mono small">{r.capture_run_id}</div>
                      <div className="muted small run-agent">{r.agent_kind ?? "Agent 未标注"} {r.agent_version ?? ""}</div>
                      {r.command ? <code className="command-preview" title={r.command}>{r.command}</code> : null}
                    </td>
                    <td><div className="cell-stack"><UiState s={r.ui_state} /><span className="muted small">{r.state}</span></div></td>
                    <td><Claim c={r.coverage_claim} /></td>
                    <td className="numeric metric-cell">{r.model_call_count?.toLocaleString?.() ?? r.model_call_count ?? "–"}</td>
                    <td className="numeric"><TokenUsageStat value={r.input_token_count} observedCalls={r.input_token_call_count} modelCalls={r.model_call_count} label="输入 Token" /></td>
                    <td className="numeric"><TokenUsageStat value={r.output_token_count} observedCalls={r.output_token_call_count} modelCalls={r.model_call_count} label="输出 Token" /></td>
                    <td><Link to={`/recordings/${enc(r.id)}`} className="text-action">查看进度</Link></td>
                    <td className="numeric metric-cell">{r.websocket_connection_count ?? "–"}</td>
                    <td className="numeric metric-cell">{r.hook_observation_count ?? "–"}</td>
                    <td className="numeric metric-cell">{r.stream_event_count ?? "–"}</td>
                    <td className="mono numeric sequence-cell">{r.durable_seq} / {r.parsed_seq} / {r.final_seq ?? "–"}</td>
                    <td className="numeric">{missing ? <span className="tag warn">{missing}</span> : <span className="muted">–</span>}</td>
                    <td className="numeric">{alerts ? <span className="tag bad">{alerts}</span> : <span className="muted">–</span>}</td>
                    <td className="muted time-cell">{fmtTime(r.created_at)}</td>
                  </tr>
                );
              })}
              {!q.isLoading && !q.error && !recordings.length ? (
                <tr><td colSpan={15}><div className="empty-state">当前页没有录制数据。</div></td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <Loading q={q} />
        <div className="table-footer">
          <span className="muted small">第 {page} 页，每页最多 50 条</span>
          <nav className="pagination" aria-label="录制分页">
            <button disabled={!stack.length || q.isFetching} onClick={() => { const s = [...stack]; const prev = s.pop() ?? ""; setStack(s); setCursor(prev); }}>上一页</button>
            <span aria-current="page">{page}</span>
            <button disabled={!q.data?.next_cursor || q.isFetching} onClick={() => { setStack([...stack, cursor]); setCursor(q.data.next_cursor); }}>下一页</button>
          </nav>
        </div>
      </div>
    </>
  );
}
