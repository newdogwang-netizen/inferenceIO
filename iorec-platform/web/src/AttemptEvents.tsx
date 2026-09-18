import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, enc, fmtTime } from "./api";
import { Loading } from "./components";

export default function AttemptEvents({ id, initialFilter = "all" }: { id: string; initialFilter?: string }) {
  const [filter, setFilter] = useState(initialFilter);
  const [cursors, setCursors] = useState<number[]>([0]);
  const after = cursors[cursors.length - 1];
  const q = useQuery({ queryKey: ["attempt-events", id, after, filter], queryFn: () => api(`/v1/attempts/${enc(id)}/events?after_seq=${after}&limit=100&filter=${filter}`) });
  return <div className="panel">
    <h3>原始协议事件</h3>
    <p className="small muted">WebSocket 事件保留重组后的消息；SSE 事件是协议流事件，不等于 TCP 包或一次模型调用。每页最多 100 条；原始内容通过 blob 链接读取。</p>
    <div className="row"><label>显示 <select value={filter} onChange={e => { setFilter(e.target.value); setCursors([0]); }}><option value="all">全部事件</option><option value="body">正文消息 / chunks</option><option value="unresolved">未解析的 WS 消息</option><option value="control">连接控制消息</option></select></label>
      <span className="muted">共 {q.data?.total ?? "–"} 条 · 第 {cursors.length} 页</span>
      <button disabled={cursors.length === 1 || q.isFetching} onClick={() => setCursors(cursors.slice(0, -1))}>上一页</button>
      <button disabled={!q.data?.has_more || q.isFetching} onClick={() => setCursors([...cursors, q.data.next_after_seq])}>下一页</button>
    </div>
    <Loading q={q} />
    <table><thead><tr><th>seq / 时间</th><th>协议事件 / 方向</th><th>归属与证据</th></tr></thead><tbody>{(q.data?.items ?? []).map((e: any) => <tr key={`${e.recording_id}-${e.seq}`}>
      <td><Link to={`/recordings/${enc(e.recording_id)}?from=${e.seq}&to=${e.seq}`}>{e.seq}</Link><div className="muted small">{fmtTime(e.wall_time)}</div></td>
      <td><code>{e.event}</code><div className="small">{e.direction ?? ""} {e.payload?.opcode ?? ""}</div></td>
      <td><div className="small">{e.assignment_reason ?? "原始 attempt 关联"} {e.call_attempt_id ? <Link to={`/attempts/${enc(e.call_attempt_id)}?view=events`}>所属调用</Link> : null}</div>
        {e.payload_sha256 ? <a href={`/v1/blobs/${e.payload_sha256}`} target="_blank" rel="noreferrer" className="mono small">blob {String(e.payload_sha256).slice(0, 16)}… ({e.payload_size} B)</a> : null}
        {e.raw_truncated ? <span className="tag warn">原始正文已截断</span> : null}
        <details><summary className="small">事件元数据</summary><pre className="json">{JSON.stringify(e.payload, null, 2)}</pre></details>
      </td></tr>)}</tbody></table>
  </div>;
}
