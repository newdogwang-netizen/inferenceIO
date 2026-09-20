import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, fmtTime } from "../api";
import { Claim, Loading, RecLink, UiState } from "../components";
import { Link } from "react-router-dom";
import { enc } from "../api";

export default function Recordings() {
  const [cursor, setCursor] = useState("");
  const [stack, setStack] = useState<string[]>([]);
  const q = useQuery({ queryKey: ["recordings", cursor], queryFn: () => api(`/v1/recordings?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`) });
  return (
    <>
      <h2>录制</h2>
      <p className="muted small">下表按录制分段分别统计模型请求、WebSocket 连接、Hook 观测与流式事件，不混算对话轮数。跨分段的工具执行与完整任务链请打开“任务进度”。</p>
      <Loading q={q} />
      <div className="recordings-scroll">
      <table>
        <thead><tr><th>录制</th><th>运行 / Agent</th><th>状态</th><th>coverage</th><th>模型调用</th><th>工具执行</th><th>连接（WS）</th><th>Hook 观测</th><th>流式事件</th><th>durable / parsed / final</th><th>缺失 blob</th><th>告警</th><th>创建</th></tr></thead>
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
              <td>{r.model_call_count ?? "–"}</td>
              <td><Link to={`/recordings/${enc(r.id)}`}>任务进度</Link></td>
              <td>{r.websocket_connection_count ?? "–"}</td>
              <td>{r.hook_observation_count ?? "–"}</td>
              <td>{r.stream_event_count ?? "–"}</td>
              <td className="mono">{r.durable_seq} / {r.parsed_seq} / {r.final_seq ?? "–"}</td>
              <td>{Array.isArray(r.missing_blobs) && r.missing_blobs.length ? <span className="tag warn">{r.missing_blobs.length}</span> : "–"}</td>
              <td>{Array.isArray(r.integrity_alerts) && r.integrity_alerts.length ? <span className="tag bad">{r.integrity_alerts.length}</span> : "–"}</td>
              <td className="muted">{fmtTime(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <button disabled={!stack.length} onClick={() => { const s = [...stack]; const prev = s.pop() ?? ""; setStack(s); setCursor(prev); }}>上一页</button>
        <button disabled={!q.data?.next_cursor} onClick={() => { setStack([...stack, cursor]); setCursor(q.data.next_cursor); }}>下一页</button>
      </div>
    </>
  );
}
