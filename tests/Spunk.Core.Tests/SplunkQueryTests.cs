using Spunk.Core.Query;

namespace Spunk.Core.Tests;

/// <summary>
/// Queries shaped like the ones in Splunk docs and Palo Alto / Cisco community answers.
/// They run against a fixed in-memory sample through the same engine the API uses
/// when a command cannot be pushed into SQL.
/// </summary>
public class SplunkQueryTests
{
    private static readonly DateTime Now = new(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Index_and_vendor_action_still_group_denied_sources()
    {
        var rows = Run("index=pan_logs sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count");
        Assert.Equal("10.20.4.15", Text(rows[0], "src_ip"));
        Assert.Equal(2, Num(rows[0], "count"));
        Assert.Equal("10.20.8.5", Text(rows[1], "src_ip"));
        Assert.Equal(1, Num(rows[1], "count"));
    }

    [Fact]
    public void Cim_blocked_includes_deny_and_drop()
    {
        var rows = Run("sourcetype=pan:traffic action=blocked | stats count by src | sort -count");
        Assert.Equal("10.20.4.15", Text(rows[0], "src"));
        Assert.Equal(3, Num(rows[0], "count"));
        Assert.Equal(1, Num(rows[1], "count"));
    }

    [Fact]
    public void Threats_by_name_and_severity_words()
    {
        var rows = Run("sourcetype=pan:threat severity=critical | stats count by threat_name | sort threat_name");
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, row => Text(row, "threat_name") == "Scan: TCP Port Scan" && Num(row, "count") == 1);
        Assert.Contains(rows, row => Text(row, "threat_name") == "Virus" && Num(row, "count") == 1);
    }

    [Fact]
    public void Cisco_severity_number_and_interface()
    {
        var rows = Run("sourcetype=cisco:ios severity<=3 | stats count by host | sort -count");
        Assert.Equal("sw-access-1", Text(rows[0], "host"));
        Assert.Equal(2, Num(rows[0], "count"));
        Assert.Equal(1, Num(rows[1], "count"));
    }

    [Fact]
    public void Rex_extracts_interface_state()
    {
        var rows = Run("sourcetype=cisco:ios facility=LINK | rex field=message_text \"changed state to (?<state>\\w+)\" | stats count by state | sort state");
        Assert.Equal("down", Text(rows[0], "state"));
        Assert.Equal(2, Num(rows[0], "count"));
        Assert.Equal("up", Text(rows[1], "state"));
        Assert.Equal(1, Num(rows[1], "count"));
    }

    [Fact]
    public void Cidrmatch_limits_sources()
    {
        var rows = Run("sourcetype=pan:traffic | where cidrmatch(\"10.20.0.0/16\", src_ip) | stats count by src_ip | sort -count");
        Assert.Equal("10.20.4.15", Text(rows[0], "src_ip"));
        Assert.Equal(4, Num(rows[0], "count"));
        Assert.Equal("10.20.8.5", Text(rows[1], "src_ip"));
        Assert.DoesNotContain(rows, row => Text(row, "src_ip") == "10.30.1.4");
    }

    [Fact]
    public void Iplocation_counts_countries()
    {
        var rows = Run("sourcetype=pan:traffic | iplocation dest_ip | stats count by Country | sort -count");
        Assert.Equal("United States", Text(rows[0], "Country"));
        Assert.Equal(5, Num(rows[0], "count"));
        Assert.Equal("Australia", Text(rows[1], "Country"));
        Assert.Equal(1, Num(rows[1], "count"));
    }

    [Fact]
    public void Transaction_groups_interface_flaps()
    {
        var rows = Run("sourcetype=cisco:ios mnemonic=UPDOWN | transaction host maxspan=5m | stats sum(eventcount) as events, count as groups");
        Assert.Equal(3, Num(rows[0], "events"));
        Assert.Equal(2, Num(rows[0], "groups"));
    }

    [Fact]
    public void Subsearch_keeps_sources_that_had_critical_threats()
    {
        var rows = Run("sourcetype=pan:traffic [search sourcetype=pan:threat severity=critical | fields src_ip] | stats count by src_ip");
        Assert.Single(rows);
        Assert.Equal("10.20.4.15", Text(rows[0], "src_ip"));
        Assert.Equal(4, Num(rows[0], "count"));
    }

    [Fact]
    public void Chart_over_app_by_action()
    {
        var rows = Run("sourcetype=pan:traffic | chart count over app by action");
        var ssh = rows.Single(row => Text(row, "app") == "ssh");
        Assert.Equal(2, Num(ssh, "deny"));
    }

    [Fact]
    public void Bin_preserves_the_event_total()
    {
        var rows = Run("sourcetype=pan:traffic | bin _time span=1h | stats count by _time");
        Assert.Equal(6, rows.Sum(row => Num(row, "count")));
    }

    [Fact]
    public void Fillnull_replaces_missing_users()
    {
        var rows = Run("sourcetype=cisco:ios | fillnull value=\"none\" user | stats count by user | sort user");
        Assert.Equal("admin", Text(rows[0], "user"));
        Assert.Equal(1, Num(rows[0], "count"));
        Assert.Equal("none", Text(rows[1], "user"));
        Assert.Equal(3, Num(rows[1], "count"));
    }

    [Fact]
    public void Lookup_maps_apps_to_categories()
    {
        var rows = Run("sourcetype=pan:traffic | lookup app_categories app OUTPUT category as app_category | stats count by app_category | sort app_category");
        Assert.Equal(1, Num(rows.Single(row => Text(row, "app_category") == "encrypted"), "count"));
        Assert.Equal(2, Num(rows.Single(row => Text(row, "app_category") == "remote-access"), "count"));
        Assert.Equal(2, Num(rows.Single(row => Text(row, "app_category") == "web"), "count"));
    }

    [Fact]
    public void Eval_round_and_bytes()
    {
        var rows = Run("sourcetype=pan:traffic | eval mb=round(bytes/1048576,2) | stats max(mb) as mb");
        Assert.Equal(4.77, Num(rows[0], "mb"), 2);
    }

    [Fact]
    public void Eventstats_percentage_of_severity()
    {
        var rows = Run("sourcetype=pan:threat | stats count by severity | eventstats sum(count) as total | eval pct=round(100*count/total,1) | sort -count");
        Assert.Equal(66.7, Num(rows[0], "pct"), 1);
        Assert.Equal(3, Num(rows[0], "total"));
        Assert.Equal(33.3, Num(rows[1], "pct"), 1);
    }

    [Fact]
    public void Top_limit_returns_the_noisiest_source()
    {
        var rows = Run("sourcetype=pan:traffic | top limit=2 src_ip showperc=false");
        Assert.Equal(2, rows.Count);
        Assert.Equal("10.20.4.15", Text(rows[0], "src_ip"));
        Assert.Equal(4, Num(rows[0], "count"));
        Assert.False(rows[0].ContainsKey("percent"));
    }

    [Fact]
    public void System_log_rex_finds_the_client_ip()
    {
        var rows = Run("sourcetype=pan:system | rex field=message_text \"from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\" | stats count by src_ip");
        Assert.Equal("10.0.0.20", Text(rows[0], "src_ip"));
        Assert.Equal(1, Num(rows[0], "count"));
    }

    [Fact]
    public void Config_table_and_latest_message()
    {
        var config = Run("sourcetype=pan:config | table user, command");
        Assert.Equal("admin", Text(config[0], "user"));
        Assert.Equal("commit", Text(config[0], "command"));

        var latest = Run("sourcetype=cisco:ios | stats latest(message_text) as msg by host");
        var access = latest.Single(row => Text(row, "host") == "sw-access-1");
        Assert.Contains("up", Text(access, "msg"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Median_and_time_modifier()
    {
        var median = Run("sourcetype=pan:traffic | stats median(bytes) as med");
        Assert.Equal(1500, Num(median[0], "med"), 0);

        var recent = Run("sourcetype=pan:traffic earliest=-1h | stats count");
        Assert.Equal(1, Num(recent[0], "count"));
    }

    [Fact]
    public void Join_adds_deny_counts_onto_threats()
    {
        var rows = Run("sourcetype=pan:threat | join type=left src_ip [search sourcetype=pan:traffic action=deny | stats count as denies by src_ip]");
        Assert.All(rows.Where(row => Text(row, "src_ip") == "10.20.4.15"), row => Assert.Equal(2, Num(row, "denies")));
        Assert.Equal(1, Num(rows.Single(row => Text(row, "src_ip") == "10.20.8.5"), "denies"));
    }

    [Fact]
    public void Streamstats_inputlookup_and_spath()
    {
        var running = Run("sourcetype=pan:traffic src_ip=10.20.4.15 | sort _time | streamstats count as n | stats max(n) as n");
        Assert.Equal(4, Num(running[0], "n"));

        var lookup = Run("| inputlookup app_categories | search category=remote-access");
        Assert.Equal("ssh", Text(lookup[0], "app"));

        var path = Run("sourcetype=hec | spath input=_raw path=threat.name output=threat_name | table threat_name");
        Assert.Equal("SQL injection", Text(path[0], "threat_name"));
    }

    [Fact]
    public void Unsupported_command_names_itself()
    {
        var error = Assert.Throws<QueryException>(() => SplParser.Parse("sourcetype=pan:traffic | tstats count where sourcetype=pan:traffic"));
        Assert.Contains("tstats", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not supported", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sql_accepts_blocked_and_numeric_severity()
    {
        var from = Now.AddDays(-1);
        var blocked = TsqlTranslator.Compile(SplParser.Parse("sourcetype=pan:traffic action=blocked | stats count by dest"), from, Now, 100);
        Assert.Contains("blocked", blocked.Parameters.Select(p => p.Value?.ToString()));
        Assert.Contains("DstIp", blocked.Sql, StringComparison.Ordinal);
        Assert.Contains("THEN N'allowed'", blocked.Sql, StringComparison.Ordinal);

        var severity = TsqlTranslator.Compile(SplParser.Parse("sourcetype=cisco:ios severity<=3"), from, Now, 100);
        Assert.Contains("Severity <=", severity.Sql, StringComparison.Ordinal);
    }

    private static List<Dictionary<string, object?>> Run(string spl)
    {
        var parsed = SplParser.Parse(spl);
        var ctx = Context();
        RowEngine.ExpandSubsearches(parsed, query => RowEngine.Execute(query, Sample(), ctx).Rows);
        return RowEngine.Execute(parsed, Sample(), ctx).Rows;
    }

    private static EngineContext Context() => new()
    {
        Now = Now,
        Lookup = name => name.StartsWith("app_cat", StringComparison.OrdinalIgnoreCase)
            ? [
                new(StringComparer.OrdinalIgnoreCase) { ["app"] = "ssh", ["category"] = "remote-access" },
                new(StringComparer.OrdinalIgnoreCase) { ["app"] = "ssl", ["category"] = "encrypted" },
                new(StringComparer.OrdinalIgnoreCase) { ["app"] = "web-browsing", ["category"] = "web" },
                new(StringComparer.OrdinalIgnoreCase) { ["app"] = "unknown", ["category"] = "other" },
            ]
            : [],
        Subsearch = query => RowEngine.Execute(query, Sample(), Context()).Rows,
        Geo = GeoIp.Builtin,
    };

    private static List<Dictionary<string, object?>> Sample() =>
    [
        Event(Now.AddHours(-4), "pan:traffic", "pa-edge-1", src: "10.20.4.15", dest: "8.8.8.8", action: "deny", app: "ssh", bytes: 1000),
        Event(Now.AddHours(-3.5), "pan:traffic", "pa-edge-1", src: "10.20.4.15", dest: "1.1.1.1", action: "deny", app: "ssh", bytes: 2000),
        Event(Now.AddHours(-3), "pan:traffic", "pa-edge-1", src: "10.20.8.5", dest: "8.8.8.8", action: "deny", app: "web-browsing", bytes: 500),
        Event(Now.AddMinutes(-30), "pan:traffic", "pa-edge-1", src: "10.20.4.15", dest: "8.8.8.8", action: "allow", app: "ssl", bytes: 5_000_000),
        Event(Now.AddHours(-3.2), "pan:traffic", "pa-dc-1", src: "10.30.1.4", dest: "93.184.216.34", action: "allow", app: "web-browsing", bytes: 8000),
        Event(Now.AddHours(-2.5), "pan:traffic", "pa-edge-1", src: "10.20.4.15", dest: "8.8.4.4", action: "drop", app: "unknown", bytes: 100),
        Event(Now.AddHours(-4), "pan:threat", "pa-edge-1", src: "10.20.4.15", severity: "critical", threat: "Scan: TCP Port Scan"),
        Event(Now.AddHours(-4), "pan:threat", "pa-edge-1", src: "10.20.8.5", severity: "high", threat: "Phishing"),
        Event(Now.AddHours(-3), "pan:threat", "pa-edge-1", src: "10.20.4.15", severity: "critical", threat: "Virus"),
        Cisco(Now.AddHours(-2), "sw-access-1", "LINK", "UPDOWN", 3, "error", "Interface Gi1/0/1, changed state to down", "Gi1/0/1"),
        Cisco(Now.AddHours(-2).AddSeconds(30), "sw-access-1", "LINK", "UPDOWN", 3, "error", "Interface Gi1/0/1, changed state to up", "Gi1/0/1"),
        Cisco(Now.AddHours(-3), "sw-access-2", "SYS", "CONFIG_I", 5, "notice", "Configured from console by admin", "Gi1/0/1", "admin"),
        Cisco(Now.AddMinutes(-15), "sw-core-1", "LINK", "UPDOWN", 3, "error", "Interface Gi1/0/2, changed state to down", "Gi1/0/2"),
        Event(Now.AddMinutes(-10), "pan:system", "pa-edge-1", message: "User admin logged in via Web from 10.0.0.20 using https"),
        Event(Now.AddHours(-3), "pan:config", "pa-edge-1", user: "admin", command: "commit"),
        Event(Now.AddHours(-1), "hec", "collector", raw: "{\"threat\":{\"name\":\"SQL injection\"}}"),
    ];

    private static Dictionary<string, object?> Event(DateTime time, string sourcetype, string host, string? src = null, string? dest = null, string? action = null, string? app = null, long? bytes = null, string? severity = null, string? threat = null, string? message = null, string? user = null, string? command = null, string? raw = null) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["_time"] = time,
            ["_raw"] = raw ?? message ?? $"{action} {app} {src} {dest}",
            ["host"] = host,
            ["sourcetype"] = sourcetype,
            ["src_ip"] = src,
            ["src"] = src,
            ["dest_ip"] = dest,
            ["dest"] = dest,
            ["action"] = action,
            ["app"] = app,
            ["bytes"] = bytes,
            ["severity"] = severity,
            ["threat_name"] = threat,
            ["message"] = message,
            ["message_text"] = message,
            ["user"] = user,
            ["command"] = command,
        };

    private static Dictionary<string, object?> Cisco(DateTime time, string host, string facility, string mnemonic, int severityId, string severity, string message, string iface, string? user = null)
    {
        var row = Event(time, "cisco:ios", host, message: message, user: user);
        row["facility"] = facility;
        row["mnemonic"] = mnemonic;
        row["severity"] = severity;
        row["severity_id"] = severityId;
        row["severity_description"] = severity;
        row["message_text"] = message;
        row["src_interface"] = iface;
        row["interface"] = iface;
        row["_raw"] = $"%{facility}-{severityId}-{mnemonic}: {message}";
        return row;
    }

    private static string Text(Dictionary<string, object?> row, string field) => row[field]?.ToString() ?? "";

    private static double Num(Dictionary<string, object?> row, string field) => Convert.ToDouble(row[field], System.Globalization.CultureInfo.InvariantCulture);
}
