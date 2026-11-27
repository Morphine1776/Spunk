import type { Row, SearchResponse } from "../api";

const palette = ["#3dcc9a", "#f0b429", "#8eb7ff", "#ff6b6b", "#c084fc", "#5eead4", "#fb923c", "#94a3b8"];

export function num(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : 0;
}

export function pivot(result: SearchResponse) {
  const measure = result.measures[0] ?? "count";
  const rows = result.rows;
  if (result.resultType === "timechart" || result.categoryField === "_time") {
    const split = result.splitBy;
    const categories = [...new Set(rows.map((r) => String(r._time ?? "")))].sort();
    if (!split) {
      return {
        categories,
        series: [{ name: measure, data: categories.map((t) => num(rows.find((r) => String(r._time) === t)?.[measure])) }],
      };
    }
    const names = [...new Set(rows.map((r) => String(r[split] ?? "—")))].slice(0, 8);
    return {
      categories,
      series: names.map((name) => ({
        name,
        data: categories.map((t) => num(rows.find((r) => String(r._time) === t && String(r[split]) === name)?.[measure])),
      })),
    };
  }
  const cat = result.categoryField;
  if (!cat) return { categories: [] as string[], series: [] as { name: string; data: number[] }[] };
  return {
    categories: rows.map((r) => String(r[cat] ?? "")),
    series: [{ name: measure, data: rows.map((r) => num(r[measure])) }],
  };
}

export function Viz({ result, kind }: { result: SearchResponse; kind?: string }) {
  const viz = kind ?? (result.resultType === "timechart" ? "line" : result.resultType === "single" ? "single" : "bar");
  if (viz === "table") return <DataTable rows={result.rows} />;
  if (viz === "single" || result.resultType === "single") {
    const measure = result.measures[0] ?? "count";
    const value = result.rows[0]?.[measure] ?? 0;
    return (
      <div className="single">
        {typeof value === "number" ? value.toLocaleString() : String(value)}
        <small>{measure}</small>
      </div>
    );
  }
  if (result.rows.length === 0) return <div className="empty">No results in this window.</div>;
  if (viz === "pie") return <Pie rows={result.rows} label={result.categoryField ?? ""} value={result.measures[0] ?? "count"} />;
  if (viz === "line") return <LineChart data={pivot(result)} />;
  return <BarChart data={pivot(result)} />;
}

export function DataTable({ rows }: { rows: Row[] }) {
  if (rows.length === 0) return <div className="empty">No rows.</div>;
  const columns = Object.keys(rows[0]).filter((c) => c !== "_extra");
  return (
    <table className="data">
      <thead>
        <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>{columns.map((c) => <td key={c}>{formatCell(row[c])}</td>)}</tr>
        ))}
      </tbody>
    </table>
  );
}

function formatCell(value: unknown) {
  if (value == null) return "";
  if (typeof value === "number") return value.toLocaleString();
  const text = String(value);
  return text.length > 180 ? text.slice(0, 180) + "…" : text;
}

function BarChart({ data }: { data: ReturnType<typeof pivot> }) {
  const series = data.series[0];
  if (!series || data.categories.length === 0) return <div className="empty">Nothing to chart.</div>;
  const max = Math.max(...series.data, 1);
  return (
    <div className="chart">
      {data.categories.map((label, i) => (
        <div key={label + i} style={{ display: "grid", gridTemplateColumns: "160px 1fr 70px", gap: 8, alignItems: "center", marginBottom: 6 }}>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12 }}>{label}</div>
          <div style={{ background: "#203028", borderRadius: 99, height: 8 }}>
            <div style={{ width: `${(series.data[i] / max) * 100}%`, background: palette[0], height: 8, borderRadius: 99 }} />
          </div>
          <div style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 12, color: "var(--muted)" }}>{series.data[i].toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

function LineChart({ data }: { data: ReturnType<typeof pivot> }) {
  if (data.categories.length === 0) return <div className="empty">Nothing to chart.</div>;
  const w = 640;
  const h = 180;
  const pad = 16;
  const max = Math.max(1, ...data.series.flatMap((s) => s.data));
  const step = data.categories.length === 1 ? 0 : (w - pad * 2) / (data.categories.length - 1);
  const y = (v: number) => h - pad - (v / max) * (h - pad * 2);
  return (
    <div className="chart">
      <div className="legend">
        {data.series.map((s, i) => (
          <span key={s.name}><i className="swatch" style={{ background: palette[i % palette.length] }} />{s.name}</span>
        ))}
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height="180" role="img">
        {data.series.map((s, i) => {
          const d = s.data.map((v, idx) => `${idx === 0 ? "M" : "L"} ${pad + idx * step} ${y(v)}`).join(" ");
          return <path key={s.name} d={d} fill="none" stroke={palette[i % palette.length]} strokeWidth="2" />;
        })}
      </svg>
    </div>
  );
}

function Pie({ rows, label, value }: { rows: Row[]; label: string; value: string }) {
  const total = rows.reduce((sum, row) => sum + num(row[value]), 0) || 1;
  let angle = -Math.PI / 2;
  const slices = rows.slice(0, 8).map((row, i) => {
    const portion = num(row[value]) / total;
    const start = angle;
    angle += portion * Math.PI * 2;
    return { row, start, end: angle, color: palette[i % palette.length] };
  });
  return (
    <div className="chart" style={{ display: "flex", gap: 16, alignItems: "center" }}>
      <svg viewBox="0 0 120 120" width="140" height="140">
        {slices.map((slice, i) => (
          <path key={i} d={arc(60, 60, 54, slice.start, slice.end)} fill={slice.color} />
        ))}
      </svg>
      <div>
        {slices.map((slice) => (
          <div key={String(slice.row[label])} style={{ fontSize: 13, marginBottom: 4 }}>
            <i className="swatch" style={{ background: slice.color }} />
            {String(slice.row[label] ?? "—")} · {num(slice.row[value]).toLocaleString()}
          </div>
        ))}
      </div>
    </div>
  );
}

function arc(cx: number, cy: number, r: number, start: number, end: number) {
  const large = end - start > Math.PI ? 1 : 0;
  const x1 = cx + r * Math.cos(start);
  const y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end);
  const y2 = cy + r * Math.sin(end);
  return `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`;
}
