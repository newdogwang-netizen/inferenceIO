import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtTime, short } from "../api";
import { Loading } from "../components";

export default function Deletions() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["deletions"], queryFn: () => api("/v1/deletions") });
  const policy = useQuery({ queryKey: ["retention-policy"], queryFn: () => api("/v1/projects/current/retention") });
  const [rawDays, setRawDays] = useState(90);
  const [metaDays, setMetaDays] = useState(365);
  useEffect(() => {
    if (policy.data) {
      setRawDays(policy.data.raw_evidence_days);
      setMetaDays(policy.data.metadata_days);
    }
  }, [policy.data]);
  const save = useMutation({
    mutationFn: () => api("/v1/projects/current/retention", { method: "PUT", body: JSON.stringify({ raw_evidence_days: rawDays, metadata_days: metaDays }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["retention-policy"] }),
  });
  const retry = useMutation({
    mutationFn: (id: string) => api(`/v1/deletions/${id}:retry-local`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["deletions"] }),
  });
  return (
    <>
      <h2>保留与删除</h2>
      <div className="panel">
        <h3>项目保留策略</h3>
        <div className="row">
          <label>原始证据 / 正文（天） <input type="number" min={1} max={3650} value={rawDays} onChange={(e) => setRawDays(Number(e.target.value))} /></label>
          <label>元数据（天） <input type="number" min={rawDays} max={3650} value={metaDays} onChange={(e) => setMetaDays(Number(e.target.value))} /></label>
          <button onClick={() => save.mutate()} disabled={save.isPending}>保存</button>
          {save.error ? <span className="error">{String(save.error.message)}</span> : null}
        </div>
        <p className="muted small">新 Recording / CaptureRun 使用新 TTL；缩短策略会立即收紧现存期限，延长仅适用于新数据，避免意外扩大既有 PHI 保留承诺。审计日志独立保留，删除任务与本地传播结果均写入 append-only 审计。</p>
      </div>
      <Loading q={q} />
      <table>
        <thead><tr><th>请求</th><th>原始目标</th><th>有效范围</th><th>模式</th><th>状态</th><th>本地请求</th><th>时间</th><th></th></tr></thead>
        <tbody>{(q.data?.items ?? []).map((d: any) => (
          <tr key={d.id}>
            <td className="mono small">{short(d.id, 18)}</td>
            <td>{d.requested_entity_type} <span className="mono small">{short(d.requested_entity_id, 28)}</span></td>
            <td className="mono small">{short(d.capture_run_id, 32)}</td>
            <td><span className="tag">{d.mode}</span></td>
            <td><span className={`tag ${d.state === "done" ? "ok" : d.state === "local_failed" ? "bad" : "warn"}`}>{d.state}</span><div className="muted small">objects {d.objects_deleted}/{d.object_total}</div>{d.last_error ? <div className="error small">{d.last_error}</div> : null}</td>
            <td className="mono small">{short(d.collector_request_id, 18) || "–"}<br /><span className="muted">{d.collector_status ?? ""}</span></td>
            <td className="muted small">{fmtTime(d.requested_at)}<br />{fmtTime(d.completed_at)}</td>
            <td>{d.state === "local_failed" ? <button onClick={() => retry.mutate(d.id)}>重试本地删除</button> : null}</td>
          </tr>
        ))}</tbody>
      </table>
    </>
  );
}
