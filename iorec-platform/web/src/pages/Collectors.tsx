import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtTime } from "../api";
import { Json, Loading } from "../components";

export default function Collectors() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["collectors"], queryFn: () => api("/v1/collectors"), refetchInterval: 15000 });
  const reqs = useQuery({ queryKey: ["collectors", "requests"], queryFn: () => api("/v1/collector-requests?limit=50"), refetchInterval: 15000 });
  const [type, setType] = useState("flush");
  const [payload, setPayload] = useState("{}");
  const create = useMutation({
    mutationFn: (collector_id: string) => api("/v1/collector-requests", { method: "POST", body: JSON.stringify({ collector_id, type, payload: JSON.parse(payload || "{}") }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["collectors"] }),
  });
  return (
    <>
      <h2>采集端</h2>
      <Loading q={q} />
      <div className="row panel">
        <span className="muted">下发请求：</span>
        <select value={type} onChange={(e) => setType(e.target.value)}>{["flush", "seal", "pause", "resume", "apply_config", "backfill", "upload_sensitive", "delete_local"].map((t) => <option key={t}>{t}</option>)}</select>
        <input value={payload} onChange={(e) => setPayload(e.target.value)} style={{ width: 360 }} className="mono" placeholder='{"recording_id":"…","first_seq":1,"last_seq":100}' />
        {create.error ? <span className="error">{String((create.error as any).message)}</span> : null}
      </div>
      {(q.data?.items ?? []).map((c: any) => (
        <div className="panel" key={c.id}>
          <div className="row">
            <span className={`tag ${c.status === "online" ? "ok" : c.status === "stale" ? "warn" : "bad"}`}>{c.status}</span>
            <b>{c.name}</b> <span className="muted">{c.version} · {c.hostname} · {c.os}</span>
            <span className="mono small muted">{c.id}</span>
            <span className="muted small">心跳 {fmtTime(c.last_heartbeat_at)} · 配置 v{c.config_version} · 待执行 {c.pending_requests}</span>
            <button onClick={() => create.mutate(c.id)}>下发 {type}</button>
          </div>
          <div className="grid cols-3" style={{ marginTop: 8 }}>
            <div><h3>能力清单</h3><Json v={c.capabilities} max={260} /></div>
            <div><h3>健康</h3><Json v={c.health} max={260} /></div>
            <div><h3>生效配置</h3><Json v={c.effective_config ?? "（未上报，使用项目默认）"} max={260} /></div>
          </div>
        </div>
      ))}
      <h3>请求记录</h3>
      <table>
        <thead><tr><th>时间</th><th>collector</th><th>类型</th><th>payload</th><th>状态</th><th>结果</th><th>发起人</th></tr></thead>
        <tbody>{(reqs.data?.items ?? []).map((r: any) => (
          <tr key={r.id}><td className="muted small">{fmtTime(r.created_at)}</td><td className="mono small">{String(r.collector_id).slice(0, 8)}</td><td>{r.type}</td><td><code className="small">{JSON.stringify(r.payload)}</code></td><td><span className="tag">{r.status}</span></td><td><code className="small">{r.result ? JSON.stringify(r.result) : ""}</code></td><td className="muted small">{r.created_by}</td></tr>
        ))}</tbody>
      </table>
    </>
  );
}
