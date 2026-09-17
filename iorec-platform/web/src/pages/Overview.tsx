import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../api";
import { Claim, Loading, RecLink, UiState } from "../components";

export default function Overview() {
  const ov = useQuery({ queryKey: ["overview"], queryFn: () => api("/v1/overview"), refetchInterval: 10000 });
  const recs = useQuery({ queryKey: ["recordings", "recent"], queryFn: () => api("/v1/recordings?limit=8") });
  const d = ov.data ?? {};
  const stats: [string, any][] = [
    ["录制", d.recordings], ["进行中", d.open_recordings], ["运行", d.capture_runs], ["attempt", d.attempts],
    ["逻辑调用", d.inferences], ["待处理发现", d.open_findings], ["在线采集端", d.online_collectors], ["解析积压事件", d.parse_lag_events],
  ];
  return (
    <>
      <h2>总览</h2>
      <Loading q={ov} />
      <div className="grid cols-4">
        {stats.map(([k, v]) => (
          <div className="stat" key={k}>
            <div className="v">{v ?? "–"}</div>
            <div className="k">{k}</div>
          </div>
        ))}
      </div>
      {d.dead_jobs > 0 ? (
        <div className="panel" style={{ marginTop: 16 }}>
          <span className="tag bad">解析受阻</span> {d.dead_jobs} 个任务已放弃重试。<Link to="/jobs?status=dead">查看任务</Link>
        </div>
      ) : null}
      <h3>最近录制</h3>
      <table>
        <thead><tr><th>录制</th><th>Agent</th><th>状态</th><th>coverage</th><th>attempt</th><th>durable / parsed</th><th>更新</th></tr></thead>
        <tbody>
          {(recs.data?.items ?? []).map((r: any) => (
            <tr key={r.id}>
              <td><RecLink id={r.id} /></td>
              <td>{r.agent_kind ?? "–"} <span className="muted">{r.agent_version}</span></td>
              <td><UiState s={r.ui_state} /></td>
              <td><Claim c={r.coverage_claim} /></td>
              <td>{r.attempt_count}</td>
              <td className="mono">{r.durable_seq} / {r.parsed_seq}</td>
              <td className="muted">{fmtTime(r.updated_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
