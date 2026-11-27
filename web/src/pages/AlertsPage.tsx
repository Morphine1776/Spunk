import { useEffect, useState, type FormEvent } from "react";
import { alertHistory, createAlert, deleteAlert, listAlerts, runAlert, updateAlert, type AlertHistory, type AlertRecord } from "../api";

const empty = {
  name: "",
  query: "sourcetype=pan:threat severity=critical | stats count",
  earliest: "-15m",
  condition: "count > 0",
  cron: "*/5 * * * *",
  action: "log",
  webhookUrl: "",
  emailTo: "",
  enabled: true,
  suppressMinutes: 15,
};

export function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [history, setHistory] = useState<AlertHistory[]>([]);
  const [form, setForm] = useState(empty);
  const [error, setError] = useState("");

  async function refresh() {
    const [nextAlerts, nextHistory] = await Promise.all([listAlerts(), alertHistory()]);
    setAlerts(nextAlerts);
    setHistory(nextHistory);
  }

  useEffect(() => { refresh().catch((err: Error) => setError(err.message)); }, []);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await createAlert(form);
      setForm(empty);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save alert");
    }
  }

  return (
    <div className="page">
      <h1>Alerts</h1>
      {error && <div className="error">{error}</div>}
      <form className="form" onSubmit={onCreate}>
        <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        <textarea rows={3} value={form.query} onChange={(e) => setForm({ ...form, query: e.target.value })} />
        <div className="row2">
          <input value={form.condition} onChange={(e) => setForm({ ...form, condition: e.target.value })} aria-label="Condition" />
          <select value={form.cron} onChange={(e) => setForm({ ...form, cron: e.target.value })}>
            <option value="*/1 * * * *">Every minute</option>
            <option value="*/5 * * * *">Every 5 minutes</option>
            <option value="*/15 * * * *">Every 15 minutes</option>
            <option value="0 * * * *">Hourly</option>
            <option value="0 0 * * *">Daily</option>
          </select>
        </div>
        <div className="row2">
          <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
            <option value="log">Log</option>
            <option value="webhook">Webhook</option>
            <option value="email">Email</option>
          </select>
          <input value={form.earliest} onChange={(e) => setForm({ ...form, earliest: e.target.value })} aria-label="Earliest" />
        </div>
        {form.action === "webhook" && <input placeholder="https://hooks.example/spunk" value={form.webhookUrl} onChange={(e) => setForm({ ...form, webhookUrl: e.target.value })} />}
        {form.action === "email" && <input placeholder="oncall@example.com" value={form.emailTo} onChange={(e) => setForm({ ...form, emailTo: e.target.value })} />}
        <button className="run" type="submit">Create alert</button>
      </form>
      <div className="alert-list">
        {alerts.map((alert) => (
          <article key={alert.id} className="card alert">
            <div>
              <strong>{alert.name}</strong>
              <div className="meta">{alert.cron} · {alert.condition} · {alert.action}{alert.lastFiredUtc ? ` · fired ${alert.lastFiredUtc}` : ""}</div>
              <div className="preview">{alert.query}</div>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <button type="button" onClick={() => runAlert(alert.id).then(refresh)}>Run</button>
              <button type="button" onClick={() => updateAlert(alert.id, { ...alert, enabled: !alert.enabled }).then(refresh)}>{alert.enabled ? "Disable" : "Enable"}</button>
              <button type="button" onClick={() => deleteAlert(alert.id).then(refresh)}>Delete</button>
            </div>
          </article>
        ))}
      </div>
      <h1>Recent runs</h1>
      <div className="alert-list">
        {history.map((item) => (
          <article key={item.id} className="card">
            <strong className={item.matched ? "warn" : "ok"}>{item.alertName}</strong>
            <div className="meta">{item.firedUtc} · {item.summary} · {item.success ? "ok" : item.detail}</div>
          </article>
        ))}
        {history.length === 0 && <div className="empty">No alert runs yet.</div>}
      </div>
    </div>
  );
}
