import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { loadFields, runSearch, saveSearch, type FieldSummary, type SearchResponse } from "../api";
import { DataTable, Viz } from "../components/Charts";

const presets = [
  { id: "-15m", label: "15m" },
  { id: "-60m", label: "60m" },
  { id: "-4h", label: "4h" },
  { id: "-24h", label: "24h" },
  { id: "-7d", label: "7d" },
  { id: "-30d", label: "30d" },
];

const examples = [
  "sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10",
  "sourcetype=cisco:ios | timechart count by host",
  "sourcetype=pan:threat | stats count by severity | sort -count",
  "sourcetype=pan:traffic",
];

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10");
  const [earliest, setEarliest] = useState(params.get("earliest") ?? "-24h");
  const [result, setResult] = useState<SearchResponse | null>(null);
  const [fields, setFields] = useState<FieldSummary[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const [showSql, setShowSql] = useState(false);

  async function execute(nextQuery = query, nextEarliest = earliest) {
    setBusy(true);
    setError("");
    setParams({ q: nextQuery, earliest: nextEarliest });
    try {
      const [search, sidebar] = await Promise.all([
        runSearch(nextQuery, nextEarliest),
        loadFields(nextQuery, nextEarliest).catch(() => ({ fields: [] })),
      ]);
      setResult(search);
      setFields(sidebar.fields);
      setOpen(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void execute(query, earliest);
    // Initial load only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const maxBucket = useMemo(() => Math.max(1, ...(result?.timeline.map((b) => b.count) ?? [1])), [result]);

  function addTerm(field: string, value: string) {
    const term = /[\s"=]/.test(value) ? `${field}="${value.replaceAll('"', '\\"')}"` : `${field}=${value}`;
    const next = query.trim().length === 0 ? term : `${query.trim()} ${term}`;
    setQuery(next);
    void execute(next, earliest);
  }

  async function onSave() {
    const name = window.prompt("Name this search");
    if (!name) return;
    await saveSearch({ name, query, earliest, latest: "now" });
  }

  return (
    <div className="page search-page">
      <form className="querybar" onSubmit={(e) => { e.preventDefault(); void execute(); }}>
        <textarea
          aria-label="Search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void execute();
            }
          }}
          spellCheck={false}
        />
        <button className="run" disabled={busy} type="submit">{busy ? "…" : "Search"}</button>
      </form>
      <div className="times">
        {presets.map((preset) => (
          <button key={preset.id} className={earliest === preset.id ? "on" : ""} type="button" onClick={() => { setEarliest(preset.id); void execute(query, preset.id); }}>
            {preset.label}
          </button>
        ))}
        {examples.map((example) => (
          <button key={example} className="chip" type="button" onClick={() => { setQuery(example); void execute(example, earliest); }}>
            {example.length > 42 ? example.slice(0, 42) + "…" : example}
          </button>
        ))}
        <button type="button" onClick={() => void onSave()}>Save</button>
        {result && <span className="meta">{(result.total ?? result.rows.length).toLocaleString()} {result.resultType === "events" ? "events" : "results"} · {result.elapsedMs} ms{result.truncated ? " · truncated" : ""}</span>}
      </div>
      {error && <div className="error">{error}</div>}
      {result && result.timeline.length > 0 && (
        <div className="histogram" aria-label="Event timeline">
          {result.timeline.map((bucket) => (
            <button key={bucket.time} title={`${bucket.time}: ${bucket.count}`} style={{ height: `${Math.max(4, (bucket.count / maxBucket) * 100)}%` }} />
          ))}
        </div>
      )}
      <div className="workspace">
        <aside className="sidebar">
          {fields.length === 0 && <div className="empty">No field values yet.</div>}
          {fields.map((field) => {
            const max = field.top[0]?.count ?? 1;
            return (
              <section className="field" key={field.name}>
                <h3>{field.name}</h3>
                {field.top.map((item) => (
                  <button key={item.value} className="val" type="button" onClick={() => addTerm(field.name, item.value)}>
                    <span>{item.value}</span>
                    <em>{item.count.toLocaleString()}</em>
                    <div className="bar"><i style={{ width: `${(item.count / max) * 100}%` }} /></div>
                  </button>
                ))}
              </section>
            );
          })}
        </aside>
        <section className="results">
          {!result && <div className="empty">Run a search.</div>}
          {result && result.resultType === "events" && (
            result.rows.length === 0 ? <div className="empty">No events in this window.</div> : result.rows.map((row, index) => (
              <article className="event" key={index}>
                <button className="head" type="button" onClick={() => setOpen(open === index ? null : index)}>
                  <span className="time">{formatTime(row._time)}</span>
                  <span className="host">{String(row.host ?? "")}</span>
                  <span className="badge">{String(row.sourcetype ?? "")}</span>
                  <span className="preview">{String(row.message ?? row._raw ?? "")}</span>
                </button>
                {open === index && (
                  <div className="detail">
                    <dl>
                      {Object.entries(row).filter(([k]) => k !== "_raw").map(([k, v]) => (
                        <span key={k} style={{ display: "contents" }}>
                          <dt>{k}</dt>
                          <dd>{String(v ?? "")}</dd>
                        </span>
                      ))}
                    </dl>
                    {row._raw != null && <div className="raw">{String(row._raw)}</div>}
                  </div>
                )}
              </article>
            ))
          )}
          {result && result.resultType !== "events" && (
            <>
              <Viz result={result} />
              <DataTable rows={result.rows} />
            </>
          )}
          {result && (
            <details className="sql" open={showSql} onToggle={(e) => setShowSql((e.target as HTMLDetailsElement).open)}>
              <summary>Job inspector</summary>
              <pre>{result.sql}</pre>
            </details>
          )}
        </section>
      </div>
    </div>
  );
}

function formatTime(value: unknown) {
  if (value == null) return "";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toISOString().replace("T", " ").slice(0, 19) + "Z";
}
