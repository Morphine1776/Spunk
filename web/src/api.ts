export type Row = Record<string, string | number | boolean | null>;

export interface SearchResponse {
  query: string;
  resultType: string;
  from: string;
  to: string;
  total: number | null;
  truncated: boolean;
  elapsedMs: number;
  columns: string[];
  rows: Row[];
  timeline: { time: string; count: number }[];
  categoryField?: string | null;
  splitBy?: string | null;
  measures: string[];
  sql: string;
}

export interface FieldSummary {
  name: string;
  top: { value: string; count: number }[];
}

export interface SavedSearch {
  id: number;
  name: string;
  query: string;
  earliest: string;
  latest: string;
  description?: string | null;
}

export interface DashboardSummary {
  id: number;
  name: string;
  slug: string;
  description?: string | null;
  panels: number;
}

export interface DashboardPanel {
  id: number;
  title: string;
  viz: string;
  colSpan: number;
  savedSearchId: number;
  searchName: string;
  query: string;
  earliest: string;
  latest: string;
}

export interface DashboardDetail {
  id: number;
  name: string;
  slug: string;
  description?: string | null;
  panels: DashboardPanel[];
}

export interface AlertRecord {
  id: number;
  name: string;
  query: string;
  earliest: string;
  condition: string;
  cron: string;
  action: string;
  webhookUrl?: string | null;
  emailTo?: string | null;
  enabled: boolean;
  suppressMinutes: number;
  lastRunUtc?: string | null;
  lastFiredUtc?: string | null;
}

export interface AlertHistory {
  id: number;
  alertId: number;
  alertName: string;
  firedUtc: string;
  matched: boolean;
  rowCount: number;
  summary?: string | null;
  success: boolean;
  detail?: string | null;
}

export interface Status {
  database: boolean;
  databaseError?: string | null;
  events: number;
  minTime?: string | null;
  maxTime?: string | null;
  retentionDays: number;
  ingest: {
    accepted: number;
    inserted: number;
    dropped: number;
    queued: number;
    udpListening: boolean;
    tcpListening: boolean;
    udpPort: number;
    tcpPort: number;
    udpError?: string | null;
    tcpError?: string | null;
    hecEnabled: boolean;
  };
}

async function send<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text;
    try {
      message = JSON.parse(text).error ?? text;
    } catch {
      /* plain text */
    }
    throw new Error(message || response.statusText);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function runSearch(query: string, earliest: string, latest = "now", limit = 500) {
  return send<SearchResponse>("/api/search", {
    method: "POST",
    body: JSON.stringify({ query, earliest, latest, limit }),
  });
}

export function loadFields(query: string, earliest: string, latest = "now") {
  return send<{ fields: FieldSummary[] }>("/api/fields", {
    method: "POST",
    body: JSON.stringify({ query, earliest, latest }),
  });
}

export const listSearches = () => send<SavedSearch[]>("/api/saved-searches");
export const saveSearch = (body: Partial<SavedSearch>) =>
  send<SavedSearch>("/api/saved-searches", { method: "POST", body: JSON.stringify(body) });
export const listDashboards = () => send<DashboardSummary[]>("/api/dashboards");
export const getDashboard = (slug: string) => send<DashboardDetail>(`/api/dashboards/${slug}`);
export const listAlerts = () => send<AlertRecord[]>("/api/alerts");
export const createAlert = (body: Partial<AlertRecord>) =>
  send<AlertRecord>("/api/alerts", { method: "POST", body: JSON.stringify(body) });
export const updateAlert = (id: number, body: Partial<AlertRecord>) =>
  send<AlertRecord>(`/api/alerts/${id}`, { method: "PUT", body: JSON.stringify(body) });
export const deleteAlert = (id: number) => send<void>(`/api/alerts/${id}`, { method: "DELETE" });
export const runAlert = (id: number) => send<AlertHistory[]>(`/api/alerts/${id}/run`, { method: "POST" });
export const alertHistory = () => send<AlertHistory[]>("/api/alerts/history");
export const status = () => send<Status>("/api/status");
export const setRetention = (days: number) =>
  send<{ retentionDays: number }>("/api/settings/retention", { method: "PUT", body: JSON.stringify({ days }) });
