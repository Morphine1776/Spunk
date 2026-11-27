import { useEffect, useState } from "react";
import { setRetention, status, type Status } from "../api";

export function StatusPage() {
  const [data, setData] = useState<Status | null>(null);
  const [error, setError] = useState("");
  const [days, setDays] = useState(90);

  async function load() {
    const next = await status();
    setData(next);
    setDays(next.retentionDays);
  }

  useEffect(() => { load().catch((err: Error) => setError(err.message)); }, []);

  return (
    <div className="page">
      <h1>Status</h1>
      {error && <div className="error">{error}</div>}
      {data && (
        <>
          <div className="status-grid">
            <div className="card stat">Database <b className={data.database ? "ok" : "bad"}>{data.database ? "connected" : "down"}</b></div>
            <div className="card stat">Events <b>{data.events.toLocaleString()}</b></div>
            <div className="card stat">Inserted this process <b>{data.ingest.inserted.toLocaleString()}</b></div>
            <div className="card stat">Queued <b>{data.ingest.queued.toLocaleString()}</b></div>
            <div className="card stat">UDP {data.ingest.udpPort} <b className={data.ingest.udpListening ? "ok" : "bad"}>{data.ingest.udpListening ? "listening" : "down"}</b></div>
            <div className="card stat">TCP {data.ingest.tcpPort} <b className={data.ingest.tcpListening ? "ok" : "bad"}>{data.ingest.tcpListening ? "listening" : "down"}</b></div>
          </div>
          <p style={{ margin: "0 16px", color: "var(--muted)" }}>
            {data.minTime ? `Oldest event ${data.minTime}` : "No events stored."}
            {data.maxTime ? ` · newest ${data.maxTime}` : ""}
            {data.ingest.udpError ? ` · UDP: ${data.ingest.udpError}` : ""}
            {data.ingest.tcpError ? ` · TCP: ${data.ingest.tcpError}` : ""}
            {data.databaseError ? ` · ${data.databaseError}` : ""}
          </p>
          <form className="form" onSubmit={(e) => { e.preventDefault(); setRetention(days).then(load); }}>
            <label>Retention days
              <input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} />
            </label>
            <button className="run" type="submit">Save retention</button>
          </form>
        </>
      )}
    </div>
  );
}
