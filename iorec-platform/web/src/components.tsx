import { Link } from "react-router-dom";
import { enc } from "./api";

export function Json({ v, max }: { v: any; max?: number }) {
  return <pre className="json" style={max ? { maxHeight: max } : undefined}>{JSON.stringify(v, null, 2)}</pre>;
}

export function Claim({ c }: { c?: string | null }) {
  const cls = c === "client-complete" || c === "transport-complete" || c === "server-effective-complete" ? "ok" : c === "unknown" ? "bad" : "warn";
  return <span className={`tag ${cls}`}>{c ?? "pending"}</span>;
}

export function Terminal({ s }: { s?: string | null }) {
  const cls = s === "completed" ? "ok" : s === "error" ? "bad" : s === "cancelled" || s === "truncated" ? "warn" : "";
  return <span className={`tag ${cls}`}>{s ?? "unknown"}</span>;
}

export function UiState({ s }: { s?: string }) {
  const label: Record<string, string> = { uploading: "上传中", archived: "已归档", parse_blocked: "解析受阻", analyzing: "正在分析", deleting: "删除中", deleted: "已删除", expiring: "过期清理中", evidence_expired: "原始证据已过期" };
  const cls = s === "archived" ? "ok" : s === "parse_blocked" ? "bad" : s === "analyzing" ? "info" : s === "deleted" || s === "evidence_expired" ? "" : "warn";
  return <span className={`tag ${cls}`}>{label[s ?? ""] ?? s}</span>;
}

export function RelStatus({ s, c }: { s?: string | null; c?: number | null }) {
  const cls = s === "observed" ? "ok" : s === "conflict" ? "bad" : s === "inferred" ? "info" : "";
  return (
    <span className={`tag ${cls}`}>
      {s ?? "unknown"}
      {c != null ? ` ${Number(c).toFixed(2)}` : ""}
    </span>
  );
}

export function Sev({ s }: { s: string }) {
  return <span className={`tag ${s === "high" ? "bad" : s === "warn" ? "warn" : "info"}`}>{s}</span>;
}

export function RecLink({ id }: { id: string }) {
  return (
    <Link to={`/recordings/${enc(id)}`} className="mono recording-link" title={id}>
      {id}
    </Link>
  );
}

export function EvidenceLinks({ refs }: { refs?: any[] }) {
  if (!refs?.length) return <span className="muted">–</span>;
  return (
    <span>
      {refs.slice(0, 6).map((r, i) => (
        <Link key={i} to={`/recordings/${enc(r.recording_id)}?from=${r.first_seq}&to=${r.last_seq}`} className="tag mono">
          seq {r.first_seq}–{r.last_seq}
        </Link>
      ))}
      {refs.length > 6 ? <span className="muted"> +{refs.length - 6}</span> : null}
    </span>
  );
}

export function TokenUsageStat({ value, observedCalls, modelCalls, label }: {
  value?: number | null;
  observedCalls?: number | null;
  modelCalls?: number | null;
  label: string;
}) {
  const hasValue = typeof value === "number" && Number.isFinite(value);
  const observed = typeof observedCalls === "number" ? observedCalls : null;
  const total = typeof modelCalls === "number" ? modelCalls : null;
  const coverage = observed == null || total == null ? "覆盖未知" : `${observed}/${total} 调用上报`;
  return (
    <span className="token-stat" title={`${label}为模型提供方上报值之和；${coverage}，未上报的调用不按零计算。`}>
      <strong className="mono">{hasValue ? value.toLocaleString() : "–"}</strong>
      <small className="muted">{coverage}</small>
    </span>
  );
}

export function Loading({ q }: { q: { isLoading: boolean; error: any } }) {
  if (q.isLoading) return <div className="loading-state" role="status"><span className="loading-indicator" aria-hidden="true" />正在载入数据…</div>;
  if (q.error) return <div className="feedback error-feedback" role="alert"><strong>数据载入失败</strong><span>{String((q.error as any).message ?? q.error)}</span></div>;
  return null;
}
