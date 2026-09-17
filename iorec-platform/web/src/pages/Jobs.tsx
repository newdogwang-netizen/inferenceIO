import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, fmtTime } from "../api";
import { Loading, RecLink } from "../components";

export default function Jobs() {
  const [sp, setSp] = useSearchParams();
  const status = sp.get("status") ?? "";
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["jobs", status], queryFn: () => api(`/v1/processing-jobs?limit=200${status ? `&status=${status}` : ""}`), refetchInterval: 5000 });
  const retry = useMutation({ mutationFn: (id: string) => api(`/v1/processing-jobs/${id}:retry`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }) });
  const stats: any[] = q.data?.stats ?? [];
  return (
    <>
      <h2>处理任务</h2>
      <div className="row" style={{ marginBottom: 10 }}>
        {["", "pending", "leased", "done", "failed", "dead"].map((s) => <button key={s} className={status === s ? "primary" : ""} onClick={() => setSp(s ? { status: s } : {})}>{s || "全部"}</button>)}
        <span className="muted small">{stats.map((s) => `${s.type}/${s.status}=${s.n}`).join("  ")}</span>
      </div>
      <Loading q={q} />
      <table>
        <thead><tr><th>类型</th><th>录制 / 运行</th><th>input</th><th>版本</th><th>状态</th><th>尝试</th><th>错误</th><th>创建 / 完成</th><th></th></tr></thead>
        <tbody>{(q.data?.items ?? []).map((j: any) => (
          <tr key={j.id}>
            <td className="mono">{j.type}</td>
            <td className="small">{j.recording_id ? <RecLink id={j.recording_id} /> : <span className="mono">{j.capture_run_id}</span>}</td>
            <td><code className="small">{JSON.stringify(j.input_ref).slice(0, 100)}</code></td>
            <td className="mono small">{j.processor_version}</td>
            <td><span className={`tag ${j.status === "done" ? "ok" : j.status === "dead" ? "bad" : j.status === "failed" ? "warn" : "info"}`}>{j.status}</span></td>
            <td>{j.attempts}</td>
            <td className="error small">{j.last_error?.slice(0, 160)}</td>
            <td className="muted small">{fmtTime(j.created_at)}<br />{fmtTime(j.finished_at)}</td>
            <td>{j.status === "dead" || j.status === "failed" ? <button onClick={() => retry.mutate(j.id)}>重试</button> : null}</td>
          </tr>
        ))}</tbody>
      </table>
    </>
  );
}
