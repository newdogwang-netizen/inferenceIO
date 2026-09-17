import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, enc, fmtTime } from "../api";
import { EvidenceLinks, Loading, RecLink, Sev } from "../components";

export default function Findings() {
  const [status, setStatus] = useState("open");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["findings", status], queryFn: () => api(`/v1/findings?status=${status}&limit=500`) });
  const review = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) => api(`/v1/findings/${id}:review`, { method: "POST", body: JSON.stringify({ status: s, note: "" }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
  return (
    <>
      <h2>分析发现</h2>
      <div className="row" style={{ marginBottom: 10 }}>
        {["open", "confirmed", "dismissed", ""].map((s) => <button key={s} className={status === s ? "primary" : ""} onClick={() => setStatus(s)}>{s || "全部"}</button>)}
      </div>
      <Loading q={q} />
      {review.error ? <div className="error">{String((review.error as any).message)}</div> : null}
      <table>
        <thead><tr><th>级别</th><th>规则</th><th>标题</th><th>详情</th><th>录制</th><th>证据</th><th>状态</th><th>时间</th><th></th></tr></thead>
        <tbody>{(q.data?.items ?? []).map((f: any) => (
          <tr key={f.id}>
            <td><Sev s={f.severity} /></td><td className="mono">{f.rule_id}</td><td>{f.title}</td>
            <td><code className="small">{JSON.stringify(f.detail).slice(0, 160)}</code>{f.detail?.inference_id ? <> <Link to={`/inferences/${enc(f.detail.inference_id)}`}>→ 调用</Link></> : null}{f.detail?.attempt_id ? <> <Link to={`/attempts/${enc(f.detail.attempt_id)}`}>→ attempt</Link></> : null}</td>
            <td>{f.recording_id ? <RecLink id={f.recording_id} /> : "–"}</td>
            <td><EvidenceLinks refs={f.evidence_refs} /></td>
            <td><span className="tag">{f.status}</span>{f.reviewed_by ? <div className="muted small">{f.reviewed_by} {f.review_note}</div> : null}</td>
            <td className="muted small">{fmtTime(f.created_at)}</td>
            <td className="row">{f.status !== "confirmed" ? <button onClick={() => review.mutate({ id: f.id, s: "confirmed" })}>确认</button> : null}{f.status !== "dismissed" ? <button onClick={() => review.mutate({ id: f.id, s: "dismissed" })}>驳回</button> : null}</td>
          </tr>
        ))}</tbody>
      </table>
    </>
  );
}
