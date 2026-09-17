import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { token } from "./api";

// Subscribes to /v1/notifications/stream and invalidates queries by entity type.
// Notifications carry only ids and versions; the page re-fetches (platform/08 §3).
export function useNotifications() {
  const qc = useQueryClient();
  useEffect(() => {
    // EventSource cannot set headers; token mode appends it as a query param handled by a small
    // shim on the server side is out of scope, so SSE is used in dev/OIDC-cookie deployments.
    if (token()) return;
    let es: EventSource | null = null;
    let cursor = localStorage.getItem("iorec.sse.cursor") ?? "";
    let stopped = false;
    const connect = () => {
      es = new EventSource(`/v1/notifications/stream${cursor ? `?cursor=${cursor}` : ""}`);
      es.addEventListener("entity.updated", (ev: MessageEvent) => {
        cursor = ev.lastEventId;
        localStorage.setItem("iorec.sse.cursor", cursor);
        let n: any = {};
        try {
          n = JSON.parse(ev.data);
        } catch {}
        const t = n.entity_type as string;
        qc.invalidateQueries({ queryKey: ["overview"] });
        if (t === "recording") {
          qc.invalidateQueries({ queryKey: ["recordings"] });
          qc.invalidateQueries({ queryKey: ["recording", n.entity_id] });
          qc.invalidateQueries({ queryKey: ["timeline", n.entity_id] });
        } else if (t === "capture_run") {
          qc.invalidateQueries({ queryKey: ["timeline"] });
          qc.invalidateQueries({ queryKey: ["findings"] });
          qc.invalidateQueries({ queryKey: ["recordings"] });
        } else if (t === "finding") {
          qc.invalidateQueries({ queryKey: ["findings"] });
        } else if (t === "collector" || t === "collector_request") {
          qc.invalidateQueries({ queryKey: ["collectors"] });
        }
        qc.invalidateQueries({ queryKey: ["jobs"] });
      });
      es.onerror = () => {
        es?.close();
        if (!stopped) setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      stopped = true;
      es?.close();
    };
  }, [qc]);
}
