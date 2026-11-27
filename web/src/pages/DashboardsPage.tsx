import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getDashboard, listDashboards, runSearch, type DashboardDetail, type DashboardSummary, type SearchResponse } from "../api";
import { Viz } from "../components/Charts";

export function DashboardsPage() {
  const [items, setItems] = useState<DashboardSummary[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    listDashboards().then(setItems).catch((err: Error) => setError(err.message));
  }, []);
  return (
    <div className="page">
      <h1>Dashboards</h1>
      {error && <div className="error">{error}</div>}
      <div className="cards">
        {items.map((item) => (
          <Link key={item.slug} className="card" to={`/dashboards/${item.slug}`}>
            <h2>{item.name}</h2>
            <p>{item.description}</p>
            <span className="meta">{item.panels} panels</span>
          </Link>
        ))}
      </div>
    </div>
  );
}

export function DashboardPage() {
  const { slug = "" } = useParams();
  const [dashboard, setDashboard] = useState<DashboardDetail | null>(null);
  const [results, setResults] = useState<Record<number, SearchResponse>>({});
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setDashboard(null);
    setResults({});
    getDashboard(slug)
      .then(async (detail) => {
        if (cancelled) return;
        setDashboard(detail);
        const pairs = await Promise.all(detail.panels.map(async (panel) => {
          try {
            const result = await runSearch(panel.query, panel.earliest, panel.latest, 200);
            return [panel.id, result] as const;
          } catch (err) {
            return [panel.id, { rows: [], resultType: "table", measures: [], columns: [], timeline: [], query: panel.query, from: "", to: "", total: 0, truncated: false, elapsedMs: 0, sql: err instanceof Error ? err.message : "failed" }] as const;
          }
        }));
        if (!cancelled) setResults(Object.fromEntries(pairs));
      })
      .catch((err: Error) => setError(err.message));
    return () => { cancelled = true; };
  }, [slug]);

  return (
    <div className="page">
      <h1>{dashboard?.name ?? "Dashboard"}</h1>
      {dashboard?.description && <p style={{ margin: "4px 16px 0", color: "var(--muted)" }}>{dashboard.description}</p>}
      {error && <div className="error">{error}</div>}
      <div className="grid">
        {dashboard?.panels.map((panel) => (
          <section key={panel.id} className="panel" style={{ gridColumn: `span ${Math.min(12, panel.colSpan)}` }}>
            <h2>{panel.title}</h2>
            {results[panel.id] ? <Viz result={results[panel.id]} kind={panel.viz} /> : <div className="empty">Loading…</div>}
          </section>
        ))}
      </div>
    </div>
  );
}
