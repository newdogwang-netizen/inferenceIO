import { useMutation, useQuery } from "@tanstack/react-query";
import { api, enc } from "./api";

type Entity = "recording" | "capture_run" | "session";

const paths: Record<Entity, string> = {
  recording: "recordings",
  capture_run: "capture-runs",
  session: "sessions",
};

export default function DeletionAction({ entity, id }: { entity: Entity; id: string }) {
  const me = useQuery({ queryKey: ["me"], queryFn: () => api("/v1/me") });
  const deletion = useMutation({
    mutationFn: (reason: string) => api(`/v1/${paths[entity]}/${enc(id)}`, {
      method: "DELETE",
      body: JSON.stringify({ confirmation: id, reason }),
    }),
  });
  if (me.data?.role !== "admin") return null;
  const start = () => {
    const confirmation = window.prompt(`此操作不可逆，并会删除整个 CaptureRun。请输入完整 ID 以确认：\n${id}`);
    if (confirmation !== id) return;
    const reason = window.prompt("删除原因（可选，进入审计日志）：") ?? "";
    deletion.mutate(reason);
  };
  return (
    <div className="panel" style={{ borderColor: "var(--bad)", marginTop: 16 }}>
      <h3 className="error">不可逆删除</h3>
      <p className="muted small">原始批次可能包含多个逻辑范围，因此 Recording / Session 删除会保守升级为整个 CaptureRun 删除；平台对象与事实表清理后，离线 Collector 上线时仍会收到 delete_local。</p>
      <button disabled={deletion.isPending} onClick={start} style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
        {deletion.isPending ? "提交中…" : "删除整个 CaptureRun"}
      </button>
      {deletion.error ? <span className="error" style={{ marginLeft: 10 }}>{String(deletion.error.message)}</span> : null}
      {deletion.data ? <span className="muted small" style={{ marginLeft: 10 }}>任务 {deletion.data.id} · {deletion.data.state}</span> : null}
    </div>
  );
}

