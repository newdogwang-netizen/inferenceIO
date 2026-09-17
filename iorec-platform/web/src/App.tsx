import { NavLink, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { useNotifications } from "./sse";
import Overview from "./pages/Overview";
import Recordings from "./pages/Recordings";
import RecordingDetail from "./pages/RecordingDetail";
import AttemptDetail from "./pages/AttemptDetail";
import InferenceDetail from "./pages/InferenceDetail";
import SessionDetail from "./pages/SessionDetail";
import Findings from "./pages/Findings";
import Collectors from "./pages/Collectors";
import Jobs from "./pages/Jobs";
import Exports from "./pages/Exports";
import Deletions from "./pages/Deletions";

export default function App() {
  useNotifications();
  const me = useQuery({ queryKey: ["me"], queryFn: () => api("/v1/me") });
  return (
    <div className="layout">
      <nav className="side">
        <h1>iorec console</h1>
        <NavLink to="/" end>总览</NavLink>
        <NavLink to="/recordings">录制</NavLink>
        <NavLink to="/findings">分析发现</NavLink>
        <NavLink to="/collectors">采集端</NavLink>
        <NavLink to="/jobs">处理任务</NavLink>
        <NavLink to="/exports">导出</NavLink>
        {me.data?.role === "admin" ? <NavLink to="/deletions">保留与删除</NavLink> : null}
        <div className="muted small" style={{ marginTop: 24 }}>
          {me.data ? (
            <>
              {me.data.subject}
              <br />
              <span className="tag">{me.data.role}</span>
            </>
          ) : me.error ? (
            <span className="error">未登录：请在 localStorage 设置 iorec.token</span>
          ) : (
            "…"
          )}
        </div>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/recordings" element={<Recordings />} />
          <Route path="/recordings/:id" element={<RecordingDetail />} />
          <Route path="/attempts/:id" element={<AttemptDetail />} />
          <Route path="/inferences/:id" element={<InferenceDetail />} />
          <Route path="/sessions/:id" element={<SessionDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/collectors" element={<Collectors />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/exports" element={<Exports />} />
          <Route path="/deletions" element={<Deletions />} />
        </Routes>
      </main>
    </div>
  );
}
