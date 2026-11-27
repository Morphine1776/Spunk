# Spunk

Spunk is a self-hosted log search and analytics service for two sources: Palo Alto Networks firewalls (PAN-OS syslog) and Cisco switches (IOS, IOS-XE, and NX-OS syslog). It listens for syslog, extracts the fields you actually filter on, stores the raw event plus those fields in Microsoft SQL Server, and answers a Splunk-like search language from a web UI.

## Architecture

```
PAN-OS / Cisco syslog          HTTP (HEC-style)
        \                         /
         UDP/TCP 514        POST /services/collector/event
                    \      /
                  Spunk API (.NET 8)
                  parse → batch → SqlBulkCopy
                         |
                  SQL Server 2022
                  monthly partitions, clustered columnstore ordered by time
                         |
                  SPL subset → parameterized T-SQL
                         |
                  React UI: search, dashboards, alerts
```

Ingest accepts RFC 3164 and RFC 5424 on UDP and TCP (octet-counted or newline-framed) and an HTTP collector compatible with a Splunk HTTP Event Collector client (`Authorization: Splunk <token>`). Events are parsed, queued, and written with `SqlBulkCopy` in batches.

PAN-OS `TRAFFIC`, `THREAT`, `SYSTEM`, `CONFIG`, and `GLOBALPROTECT` CSV logs are mapped with the field order used by the Palo Alto Splunk add-on (the same order documented for current PAN-OS syslog). Cisco messages are split on `%FACILITY-SEVERITY-MNEMONIC`, with interface, state, VLAN, MAC, user, and source IP pulled out when present. Anything unrecognized is still stored as `sourcetype=syslog` with the raw text.

The `Events` table is partitioned by month and has a clustered columnstore index ordered on `EventTime`. Common filters (addresses, zones, action, app, user, bytes, threat, interface, mnemonic) are real columns. Less common fields are in `ExtraJson`. A background job deletes events older than the configured retention (default 90 days) and splits the next monthly partition when needed.

Search accepts the field names used by the Splunk Add-on for Palo Alto Networks and the Splunk Add-on for Cisco IOS, plus the CIM aliases those apps add. A pipeline that is only filtering, `stats`, `timechart`, `top`/`rare`, `table`, `fields`, `sort`, `head`/`tail`, `rename`, `dedup`, and basic `eval` is translated to parameterized T-SQL. Anything else runs in the API after a parameterized event fetch (capped at 20,000 events in the selected time range). An unknown command fails with `Search command 'tstats' is not supported` rather than being treated as search text.

`index=` is accepted and does not filter. Spunk keeps one store, so a copied `index=pan_logs` still returns the matching sourcetype. `earliest=` and `latest=` work inline (`-15m`, `-24h@h`, `now`) or from the time picker.

### Commands

| Command | What works |
| --- | --- |
| search | `field=value`, `!=`, `<`, `>`, `<=`, `>=`, `AND` / `OR` / `NOT`, parentheses, `*` and `?`, `field IN (...)`, bare subsearches `[search ...]` |
| where | comparisons, `isnull`, `isnotnull`, `like`, `cidrmatch`, `match` |
| stats | `count`, `dc` / `distinct_count`, `sum`, `avg`, `min`, `max`, `values`, `list`, `earliest`, `latest`, `first`, `last`, `median`, `stdev`, `stdevp`, `perc95`, `perc99` … `by` |
| eventstats, streamstats | same aggregations; `streamstats` accepts `window=` |
| timechart | `span=` and `by` |
| chart | `chart count over field by field` |
| bin / bucket | `span=` on `_time` or a number |
| top / rare | `limit=`, a bare number, `by`, `showperc=t|f` |
| rex | named groups `(?<field>...)`, `field=`, `mode=sed` with `s/pattern/replacement/flags` |
| transaction | `maxspan=`, `maxpause=`, producing `eventcount` and `duration` |
| join | `type=inner|left`, field list, `[subsearch]`. One match per key, matching Splunk's default |
| append | `[subsearch]` concatenated onto the current results |
| lookup | `lookup name field OUTPUT other as alias`. CSV files are managed under Lookups |
| inputlookup / outputlookup | read or replace a named CSV |
| iplocation | sets `Country`, `City`, `Region`, `lat`, `lon`. A small built-in table covers the sample generator's public addresses. Point `GeoIp:CsvPath` at a GeoLite2-style CSV (`network,country,city,region,lat,lon`) for everything else. Private addresses stay empty |
| fillnull | `value=` and an optional field list |
| makemv / mvexpand | `delim=` |
| spath | `input=`, `path=`, `output=` for JSON |
| table, fields, sort, head, tail, rename, dedup | |
| eval | `+ - * /`, `if`, `case`, `coalesce`, `round`, `len`, `lower`, `upper`, `substr`, `replace`, `strftime`, `strptime`, `relative_time`, `now`, `cidrmatch`, `match`, `split`, `mvcount`, `tostring`, `tonumber`, `true` |

Not implemented, and rejected by name: `tstats`, `datamodel`, `from`, `mstats`, `appendcols`, `union`, `map`, `metadata`, `geostats`, `timewrap`, `predict`, `xmlkv`. `transaction` does not support `startswith` / `endswith`. Lookup matching is exact, not CIDR or wildcard.

### Fields

Palo Alto sourcetypes are `pan:traffic`, `pan:threat`, `pan:system`, `pan:config`, and `pan:globalprotect`. Cisco IOS / IOS-XE is `cisco:ios`. NX-OS facilities such as `ETHPORT` and `VSHD` are `cisco:nxos`.

| Copied name | Also accepted | Meaning |
| --- | --- | --- |
| src, src_ip | | client address |
| dest, dest_ip | dst, dst_ip | server address |
| src_port, dest_port | dst_port | ports |
| src_zone, dest_zone | dst_zone | zones |
| src_interface | interface | ingress interface, and the Cisco interface |
| dest_interface | | egress interface |
| user, src_user | | user |
| app, rule, protocol | transport | application, rule, IP protocol |
| bytes, bytes_in, bytes_out | bytes_sent, bytes_received | totals and directions, matching the Palo Alto add-on (`bytes_in` is bytes received) |
| action | vendor_action | original value: `allow`, `deny`, `drop`, `alert`, … |
| cim_action | `action=allowed` or `action=blocked` also match | CIM: allow/alert/success → `allowed`; deny/drop/reset/block → `blocked` |
| severity | severity_description | Palo Alto word (`critical`, `high`, `informational`) or Cisco word (`error`, `warning`, `notification`) |
| severity_id | `severity<=3` | numeric syslog / mnemonic severity |
| threat_name, category | http_category | threat and URL category |
| facility, mnemonic, message_text | message | Cisco `%FACILITY-SEVERITY-MNEMONIC` body |
| host, dvc, sourcetype, source, _time, _raw | index (accepted, not filtered) | the usual Splunk metadata. `index` does not select a different store |

`_time`, `_raw`, `host`, `source`, and `sourcetype` are on every event. `source` is the sender address when syslog provided one.

The UI is search (query bar, time range, timeline, field sidebar, event list or stats chart), saved searches, dashboards built from those searches, and scheduled alerts. Alert actions are a history log, an HTTP webhook, or email when SMTP is configured.

## Run with Docker Compose

Docker Compose starts SQL Server 2022 Developer and Spunk. The default SQL password is for local development only. Change `MSSQL_SA_PASSWORD` and `Ingest__HecToken` before exposing the stack.

```bash
docker compose up --build
```

- UI: http://localhost:8080
- Syslog: UDP and TCP port 514
- HTTP collector token: `spunk-hec-token`

Load demo data from another shell once the UI responds:

```bash
dotnet run --project tools/Spunk.Generator -- --count 6000 --url http://localhost:8080
```

SQL Server needs about 2 GB of RAM. The first start can take a minute while the database finishes recovery.

## Run against an existing SQL Server

Prerequisites: .NET 8 SDK, Node.js 22, and a SQL Server login that can create a database (or a pre-created empty database).

```bash
cd web && npm ci && npm run build && cd ..
```

Set the connection string and start the API. Ports below 1024 need an elevated process on Windows and `CAP_NET_BIND_SERVICE` or root on Linux. If you cannot bind 514, point devices at another port and set `Ingest__UdpPort` / `Ingest__TcpPort`.

```bash
# Linux / macOS
export ConnectionStrings__SqlServer="Server=sql.example,1433;Database=Spunk;User Id=spunk;Password=...;TrustServerCertificate=True;Encrypt=True"
export Ingest__UdpPort=514
export Ingest__TcpPort=514
export Ingest__HecToken="replace-me"
dotnet run --project src/Spunk.Api
```

```powershell
$env:ConnectionStrings__SqlServer = "Server=sql.example;Database=Spunk;Integrated Security=True;TrustServerCertificate=True"
dotnet run --project src/Spunk.Api
```

Spunk creates the database, the monthly partition function, and the columnstore index on startup.

### Windows service

From an elevated PowerShell session, after the web assets have been built (the script builds them if `npm` is on `PATH`):

```powershell
.\scripts\install-windows-service.ps1 -ConnectionString "Server=sql.example;Database=Spunk;Integrated Security=True;TrustServerCertificate=True"
```

That publishes `Spunk.Api.exe` and registers a service named `Spunk`. The host calls `UseWindowsService`, so the same binary runs in a console or as a service.

### SMTP

Alerts with action `email` use `Smtp` in `appsettings.json` (`Host`, `Port`, `User`, `Password`, `From`, `EnableSsl`). Leave `Host` empty until you want mail; webhook and log actions do not need it.

## Point devices at Spunk

Send logs in the default syslog CSV format, not CEF or LEEF. Timestamps are read as UTC. Set the firewall and the switches to UTC so the time picker lines up with the device clock.

### PAN-OS

1. Device → Server Profiles → Syslog → Add. Name it `Spunk`, server address is the Spunk host, port `514`, transport UDP or TCP.
2. For each log type you care about (Traffic, Threat, System, Config, GlobalProtect), use the default syslog format. The payload must be the comma-separated log, which is the stock PAN-OS syslog custom format.
3. Objects → Log Forwarding. Add a profile that sends Traffic, Threat, URL, WildFire, System, and Config to the `Spunk` syslog profile. Attach that profile to the security rules you want, or set it as the default log forwarding profile.
4. Commit. `sourcetype` becomes `pan:traffic`, `pan:threat`, `pan:system`, `pan:config`, or `pan:globalprotect`.

### Cisco IOS / IOS-XE

```
configure terminal
logging host <spunk-ip> transport udp port 514
logging trap informational
logging source-interface Loopback0
logging on
end
```

Use `transport tcp port 514` instead if you want reliable delivery. Interface up/down, port security, spanning tree, authentication, and configuration messages are parsed from the `%FACILITY-SEVERITY-MNEMONIC` body. `sourcetype` is `cisco:ios`.

### Cisco NX-OS

```
configure terminal
logging server <spunk-ip> 6 use-vrf management
logging timestamp seconds
end
```

NX-OS facilities such as `ETHPORT` and `VSHD` are stored as `cisco:nxos`.

### HTTP collector

```bash
curl -H "Authorization: Splunk spunk-hec-token" \
  -H "Content-Type: application/json" \
  http://localhost:8080/services/collector/event \
  -d '{"host":"pa-edge-1","sourcetype":"pan:traffic","event":"<14>Nov 27 12:00:00 pa-edge-1 1,2026/11/27 12:00:00,..."}'
```

`POST /services/collector/raw` accepts newline-delimited syslog. The token is `Ingest:HecToken`.

## Search examples

```
sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10
sourcetype=cisco:ios | timechart count by host
sourcetype=pan:threat | stats count by severity
(sourcetype=cisco:ios OR sourcetype=cisco:nxos) severity=error | stats count by host
```

The field sidebar lists the common fields for the current search. Click a value to append it. Dashboards named **Palo Alto** and **Cisco switching** are created on first startup. Alerts run on a five-field cron schedule; `count > 0` sums a `count` column when the search is a `stats` command, and `results > 0` triggers whenever the search returns rows.

## Develop

```bash
dotnet test
cd web && npm run dev
```

The Vite dev server proxies `/api` to `http://localhost:8080`.

`dotnet test` covers the parsers, the SPL translator (including parameterization), schedules, and, when SQL Server is reachable, a round trip that writes sample lines and runs the two searches above. Set `SPUNK_SQL` to point the integration test at a different instance. The default is `localhost` with the Compose password and database `SpunkIt`.

## Project layout

| Path | Role |
| --- | --- |
| `src/Spunk.Core` | Parsers, SPL parser, T-SQL translator |
| `src/Spunk.Infrastructure` | Schema, bulk writer, search, saved objects |
| `src/Spunk.Api` | HTTP API, syslog listeners, retention, alerts, static UI |
| `web` | React search, dashboards, alerts |
| `tools/Spunk.Generator` | PAN-OS and Cisco sample generator |
| `tests` | Unit tests and a SQL Server round-trip test |
