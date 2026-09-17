import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, fmtTime } from "../api";
import { Claim, Loading, RecLink, UiState } from "../components";

export default function Recordings() {
  const [cursor, setCursor] = useState("");
  const [stack, setStack] = useState<string[]>([]);
  const q = useQuery({ queryKey: ["recordings", cursor], queryFn: () => api(`/v1/recordings?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`) });
  return (
    <>
      <h2>录制</h2>
      <Loading q={q} />
      <table>
        <thead><tr><th>录制</th><th>运行 / Agent</th><th>状态</th><th>coverage</th><th>attempt</th><th>durable / parsed / final</th><th>缺失 blob</th><th>告警</th><th>创建</th></tr></thead>
        <tbody>
          {(q.data?.items ?? []).map((r: any) => (
            <tr key={r.id}>
              <td><RecLink id={r.id} /></td>
              <td>
                <div className="mono small">{r.capture_run_id}</div>
                <div className="muted small">{r.agent_kind} {r.agent_version} · <code>{r.command}</code></div>
              </td>
              <td><UiState s={r.ui_state} /> <span className="muted small">{r.state}</span></td>
              <td><Claim c={r.coverage_claim} /></td>
              <td>{r.attempt_count}</td>
              <td className="mono">{r.durable_seq} / {r.parsed_seq} / {r.final_seq ?? "–"}</td>
              <td>{Array.isArray(r.missing_blobs) && r.missing_blobs.length ? <span className="tag warn">{r.missing_blobs.length}</span> : "–"}</td>
              <td>{Array.isArray(r.integrity_alerts) && r.integrity_alerts.length ? <span className="tag bad">{r.integrity_alerts.length}</span> : "–"}</td>
              <td className="muted">{fmtTime(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row" style={{ marginTop: 12 }}>
        <button disabled={!stack.length} onClick={() => { const s = [...stack]; const prev = s.pop() ?? ""; setStack(s); setCursor(prev); }}>上一页</button>
        <button disabled={!q.data?.next_cursor} onClick={() => { setStack([...stack, cursor]); setCursor(q.data.next_cursor); }}>下一页</button>
      </div>
    </>
  );
}
