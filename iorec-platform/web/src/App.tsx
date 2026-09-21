import { useEffect, useRef, useState } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
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
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const me = useQuery({ queryKey: ["me"], queryFn: () => api("/v1/me") });
  const navItem = ({ isActive }: { isActive: boolean }) => isActive ? "nav-link active" : "nav-link";
  const closeNav = () => setNavOpen(false);
  useEffect(() => {
    setNavOpen(false);
    mainRef.current?.focus();
  }, [location.pathname]);
  return (
    <>
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <h1 className="sr-only">iorec console</h1>
      <div className="layout">
        <aside className={`side${navOpen ? " nav-open" : ""}`}>
        <div className="side-header">
          <NavLink to="/" end className="brand" onClick={closeNav} aria-label="iorec console 总览">
            <span className="brand-mark" aria-hidden="true">io</span>
            <span className="brand-copy">
              <strong>iorec</strong>
              <small>inference flight recorder</small>
            </span>
          </NavLink>
          <button
            type="button"
            className="nav-toggle"
            aria-expanded={navOpen}
            aria-controls="primary-navigation"
            onClick={() => setNavOpen(open => !open)}
          >
            {navOpen ? "关闭" : "菜单"}
          </button>
        </div>
        <nav id="primary-navigation" className="primary-nav" aria-label="主要导航">
          <span className="nav-section-label">观测</span>
          <NavLink to="/" end className={navItem} onClick={closeNav}>总览</NavLink>
          <NavLink to="/recordings" className={navItem} onClick={closeNav}>录制</NavLink>
          <NavLink to="/findings" className={navItem} onClick={closeNav}>分析发现</NavLink>
          <span className="nav-section-label">运行</span>
          <NavLink to="/collectors" className={navItem} onClick={closeNav}>采集端</NavLink>
          <NavLink to="/jobs" className={navItem} onClick={closeNav}>处理任务</NavLink>
          <NavLink to="/exports" className={navItem} onClick={closeNav}>导出</NavLink>
          {me.data?.role === "admin" ? <NavLink to="/deletions" className={navItem} onClick={closeNav}>保留与删除</NavLink> : null}
        </nav>
        <div className="side-session" aria-live="polite">
          {me.data ? (
            <>
              <span className="session-subject">{me.data.subject}</span>
              <span className="tag">{me.data.role}</span>
            </>
          ) : me.error ? (
            <span className="error small">未登录：请在 localStorage 设置 iorec.token</span>
          ) : (
            <span className="muted small">正在确认会话…</span>
          )}
        </div>
        </aside>
        <main id="main-content" ref={mainRef} tabIndex={-1}>
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
    </>
  );
}
