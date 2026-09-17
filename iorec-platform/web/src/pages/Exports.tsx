import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, enc, fmtTime, token } from "../api";
import { Loading } from "../components";

async function downloadExport(item: any) {
  const headers: Record<string, string> = {};
  const bearer = token();
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  const response = await fetch(`/v1/exports/${enc(item.id)}/download`, { headers });
  if (!response.ok) throw new Error(`download failed (${response.status})`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = item.filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function Exports() {
  const [captureRunID, setCaptureRunID] = useState("");
  const [downloadError, setDownloadError] = useState("");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["exports"], queryFn: () => api("/v1/exports"), refetchInterval: 3000 });
  const create = useMutation({
    mutationFn: () => api("/v1/exports", { method: "POST", body: JSON.stringify({ capture_run_id: captureRunID, format: "normalized-jsonl" }) }),
    onSuccess: () => { setCaptureRunID(""); qc.invalidateQueries({ queryKey: ["exports"] }); },
  });
  return (
    <>
      <h2>导出</h2>
      <div className="panel">
        <div className="row">
          <input style={{ minWidth: 360 }} value={captureRunID} onChange={(event) => setCaptureRunID(event.target.value)} placeholder="已完成的 CaptureRun ID" />
          <select disabled><option>normalized-jsonl</option></select>
          <button className="primary" disabled={!captureRunID || create.isPending} onClick={() => create.mutate()}>创建导出</button>
        </div>
        {create.error ? <div className="error small">{String(create.error)}</div> : null}
        <p className="muted small">仅 admin 可用；导出包含规范化正文，7 天后自动删除并保留审计元数据。</p>
      </div>
      <Loading q={q} />
      {downloadError ? <div className="error small">{downloadError}</div> : null}
      <table>
        <thead><tr><th>CaptureRun</th><th>格式</th><th>状态</th><th>大小 / SHA-256</th><th>创建 / 过期</th><th></th></tr></thead>
        <tbody>{(q.data?.items ?? []).map((item: any) => (
          <tr key={item.id}>
            <td className="mono">{item.capture_run_id}</td>
            <td>{item.format}</td>
            <td><span className={`tag ${item.state === "ready" ? "ok" : item.state === "failed" ? "bad" : item.state === "expired" ? "warn" : "info"}`}>{item.state}</span><div className="error small">{item.last_error}</div></td>
            <td className="mono small">{item.byte_length ?? "–"}<br />{item.sha256 ?? ""}</td>
            <td className="muted small">{fmtTime(item.created_at)}<br />{fmtTime(item.expires_at)}</td>
            <td>{item.state === "ready" ? <button onClick={() => { setDownloadError(""); downloadExport(item).catch((error) => setDownloadError(String(error))); }}>下载</button> : null}</td>
          </tr>
        ))}</tbody>
      </table>
    </>
  );
}
