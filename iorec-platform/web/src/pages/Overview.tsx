import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../api";
import { Claim, Loading, RecLink, UiState } from "../components";

export default function Overview() {
  const ov = useQuery({ queryKey: ["overview"], queryFn: () => api("/v1/overview"), refetchInterval: 10000 });
  const recs = useQuery({ queryKey: ["recordings", "recent"], queryFn: () => api("/v1/recordings?limit=8") });
  const d = ov.data ?? {};
  const stats = [
    { label: "录制", value: d.recordings, detail: "可检索的录制分段" },
    { label: "逻辑调用", value: d.inferences, detail: "已规范化模型调用" },
    { label: "待处理发现", value: d.open_findings, detail: "等待人工复核", tone: d.open_findings > 0 ? "warn" : "ok" },
    { label: "解析积压", value: d.parse_lag_events, detail: "尚未解析的事件", tone: d.parse_lag_events > 0 ? "bad" : "ok" },
    { label: "采集运行", value: d.capture_runs, detail: "已登记 CaptureRun" },
    { label: "底层 attempt", value: d.attempts, detail: "传输尝试与连接" },
    { label: "进行中录制", value: d.open_recordings, detail: "正在接收证据", tone: d.open_recordings > 0 ? "info" : undefined },
    { label: "在线采集端", value: d.online_collectors, detail: "当前心跳在线", tone: d.online_collectors > 0 ? "ok" : undefined },
  ];
  return (
    <>
      <header className="page-header">
        <div>
          <p className="page-eyebrow">运行状态</p>
          <h2>总览</h2>
          <p className="page-description">从采集、解析到审计发现，快速确认当前证据链是否完整可用。</p>
        </div>
        <span className="refresh-note">每 10 秒自动刷新</span>
      </header>
      <Loading q={ov} />
      <section className="metrics-grid" aria-label="平台关键指标">
        {stats.map((stat) => (
          <div className={`stat${stat.tone ? ` stat-${stat.tone}` : ""}`} key={stat.label}>
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value">{typeof stat.value === "number" ? stat.value.toLocaleString() : "–"}</div>
            <div className="stat-detail">{stat.detail}</div>
          </div>
        ))}
      </section>
      {d.dead_jobs > 0 ? (
        <div className="notice notice-danger" role="alert">
          <div><strong>解析受阻</strong><span>{d.dead_jobs} 个任务已放弃重试。</span></div>
          <Link to="/jobs?status=dead">查看任务</Link>
        </div>
      ) : null}
      <section className="data-section" aria-labelledby="recent-recordings-heading">
        <div className="section-heading">
          <div>
            <h3 id="recent-recordings-heading">最近录制</h3>
            <p>按更新时间排列的最近 8 个录制分段。</p>
          </div>
          <Link to="/recordings" className="text-action">查看全部录制</Link>
        </div>
        <div className="data-surface">
          <div className="table-scroll">
            <table className="data-table overview-table">
              <caption className="sr-only">最近更新的录制列表</caption>
              <thead><tr><th scope="col">录制</th><th scope="col">Agent</th><th scope="col">状态</th><th scope="col">覆盖结论</th><th scope="col">attempt</th><th scope="col">证据序号<span className="th-detail">durable / parsed</span></th><th scope="col">更新时间</th></tr></thead>
              <tbody>
                {(recs.data?.items ?? []).map((r: any) => (
                  <tr key={r.id}>
                    <td><RecLink id={r.id} /></td>
                    <td>{r.agent_kind ?? "未标注"} <span className="muted">{r.agent_version}</span></td>
                    <td><UiState s={r.ui_state} /></td>
                    <td><Claim c={r.coverage_claim} /></td>
                    <td className="numeric">{r.attempt_count?.toLocaleString?.() ?? r.attempt_count ?? "–"}</td>
                    <td className="mono numeric">{r.durable_seq} / {r.parsed_seq}</td>
                    <td className="muted time-cell">{fmtTime(r.updated_at)}</td>
                  </tr>
                ))}
                {!recs.isLoading && !recs.error && !(recs.data?.items ?? []).length ? (
                  <tr><td colSpan={7}><div className="empty-state">尚无录制。采集端上传首个分段后会显示在这里。</div></td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <Loading q={recs} />
        </div>
      </section>
    </>
  );
}
