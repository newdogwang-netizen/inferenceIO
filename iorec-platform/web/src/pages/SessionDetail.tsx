import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, enc, fmtTime } from "../api";
import { Json, Loading } from "../components";
import DeletionAction from "../DeletionAction";

export default function SessionDetail() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["session", id], queryFn: () => api(`/v1/sessions/${enc(id)}`) });
  const s = q.data;
  return (
    <>
      <h2 className="mono">{id}</h2>
      <Loading q={q} />
      {s ? (
        <>
          <div className="panel">
            <div className="row">
              <span className={`tag ${s.kind === "native" ? "ok" : "info"}`}>{s.kind}</span><span className="tag">{s.role}</span>
              <span className="muted">native_id {s.native_id ?? "–"} · {s.inference_count} inferences · {fmtTime(s.first_seen_at)} → {fmtTime(s.last_seen_at)} · rev {s.relation_revision}</span>
            </div>
            {s.parent_session_id ? <div style={{ marginTop: 6 }}>父会话：<Link to={`/sessions/${enc(s.parent_session_id)}`} className="mono">{s.parent_session_id}</Link></div> : null}
            {s.children?.length ? <div style={{ marginTop: 6 }}>子会话：{s.children.map((c: any) => <Link key={c.id} to={`/sessions/${enc(c.id)}`} className="tag mono">{c.id}</Link>)}</div> : null}
          </div>
          <div className="panel">
            <h3>轮次与调用</h3>
            {(s.turns ?? []).map((t: any) => (
              <div key={t.turn_id} style={{ marginBottom: 10 }}>
                <div className="row"><span className="tag ok">turn {t.index}</span><span className="mono small">{t.turn_id}</span><span className="muted small">{fmtTime(t.started_at)}</span></div>
                <table><tbody>{(s.inferences ?? []).filter((i: any) => i.turn_id === t.turn_id).map((i: any) => (
                  <tr key={i.id}><td><Link to={`/inferences/${enc(i.id)}`} className="mono">{i.id}</Link></td><td><span className={`tag ${i.status === "observed" ? "ok" : "info"}`}>{i.status}</span></td><td>{i.attempt_count} att</td><td className="muted small">{i.response_preview}</td></tr>
                ))}</tbody></table>
              </div>
            ))}
          </div>
          <div className="panel"><h3>关系（证据）</h3><Json v={s.relations} max={400} /></div>
          <DeletionAction entity="session" id={id} />
        </>
      ) : null}
    </>
  );
}
