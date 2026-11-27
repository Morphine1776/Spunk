import { NavLink, Route, Routes } from "react-router-dom";
import { AlertsPage } from "./pages/AlertsPage";
import { DashboardPage, DashboardsPage } from "./pages/DashboardsPage";
import { SearchPage } from "./pages/SearchPage";
import { StatusPage } from "./pages/StatusPage";

export function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="6" fill="#121a22" />
            <path d="M6 22h4V10H6zm8 0h4V6h-4zm8 0h4v-7h-4z" fill="#3dcc9a" />
          </svg>
          <div>SPUNK<small>log search</small></div>
        </div>
        <nav className="nav">
          <NavLink to="/" end>Search</NavLink>
          <NavLink to="/dashboards">Dashboards</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/status">Status</NavLink>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<SearchPage />} />
        <Route path="/dashboards" element={<DashboardsPage />} />
        <Route path="/dashboards/:slug" element={<DashboardPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/status" element={<StatusPage />} />
      </Routes>
    </div>
  );
}
