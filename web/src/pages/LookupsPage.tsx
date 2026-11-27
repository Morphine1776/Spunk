import { useEffect, useState } from "react";
import { getLookup, listLookups, saveLookup } from "../api";

export function LookupsPage() {
  const [names, setNames] = useState<string[]>([]);
  const [name, setName] = useState("app_categories");
  const [csv, setCsv] = useState("app,category\nssh,remote-access\n");
  const [error, setError] = useState("");

  async function refresh() {
    const files = await listLookups();
    setNames(files.map((file) => file.name));
  }

  useEffect(() => { refresh().catch((err: Error) => setError(err.message)); }, []);

  return (
    <div className="page">
      <h1>Lookups</h1>
      <p style={{ margin: "4px 16px 0", color: "var(--muted)" }}>
        CSV files used by lookup, inputlookup, and outputlookup. Reference them as <span className="badge">app_categories</span> or <span className="badge">app_categories.csv</span>.
      </p>
      {error && <div className="error">{error}</div>}
      <div className="cards">
        {names.map((item) => (
          <button key={item} className="card" type="button" onClick={() => getLookup(item).then((text) => { setName(item); setCsv(text); })}>
            <h2>{item}</h2>
          </button>
        ))}
      </div>
      <form className="form" onSubmit={(event) => { event.preventDefault(); saveLookup(name, csv).then(refresh).catch((err: Error) => setError(err.message)); }}>
        <input value={name} onChange={(event) => setName(event.target.value)} aria-label="Lookup name" />
        <textarea rows={12} value={csv} onChange={(event) => setCsv(event.target.value)} spellCheck={false} />
        <button className="run" type="submit">Save lookup</button>
      </form>
    </div>
  );
}
