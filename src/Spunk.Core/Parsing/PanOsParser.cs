using System.Globalization;
using System.Text.RegularExpressions;
using Spunk.Core.Models;

namespace Spunk.Core.Parsing;

/// <summary>
/// PAN-OS CSV syslog, using the field order from the Palo Alto Splunk add-on
/// (TRAFFIC, THREAT, SYSTEM, CONFIG, GLOBALPROTECT). Shorter legacy rows still map;
/// columns past the known list are kept as field_N.
/// </summary>
public static partial class PanOsParser
{
    private static readonly string[] Traffic =
    [
        "future_use1", "receive_time", "serial", "type", "subtype", "version", "generated_time",
        "src_ip", "dest_ip", "natsrc", "natdst", "rule", "src_user", "dest_user", "app", "vsys",
        "src_zone", "dest_zone", "inbound_if", "outbound_if", "logset", "future_use3", "session_id",
        "repeat_count", "src_port", "dest_port", "natsport", "natdport", "flags", "protocol", "action",
        "bytes", "bytes_out", "bytes_in", "packets", "start_time", "elapsed", "category", "future_use4",
        "seqno", "action_flags", "src_location", "dest_location", "future_use5", "packets_out", "packets_in",
        "session_end_reason", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
        "vsys_name", "device_name", "action_source", "src_vm", "dest_vm", "tunnel_id", "monitor_tag",
        "parent_session_id", "parent_start_time", "tunnel",
    ];

    private static readonly string[] Threat =
    [
        "future_use1", "receive_time", "serial", "type", "subtype", "version", "generated_time",
        "src_ip", "dest_ip", "natsrc", "natdst", "rule", "src_user", "dest_user", "app", "vsys",
        "src_zone", "dest_zone", "inbound_if", "outbound_if", "logset", "future_use3", "session_id",
        "repeat_count", "src_port", "dest_port", "natsport", "natdport", "flags", "protocol", "action",
        "misc", "threat_name", "category", "severity", "direction", "seqno", "action_flags",
        "src_location", "dest_location", "future_use4", "content_type", "pcap_id", "file_hash", "cloud",
        "url_index", "user_agent", "file_type", "xff", "referer", "sender", "subject", "recipient",
        "report_id", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
        "vsys_name", "device_name", "future_use5", "src_vm", "dest_vm", "http_method", "tunnel_id",
        "monitor_tag", "parent_session_id", "parent_start_time", "tunnel", "threat_category", "content_version",
    ];

    private static readonly string[] SystemLog =
    [
        "future_use1", "receive_time", "serial", "type", "subtype", "version", "generated_time",
        "vsys", "event_id", "object", "future_use3", "future_use4", "module", "severity", "description",
        "seqno", "action_flags", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
        "vsys_name", "device_name",
    ];

    private static readonly string[] Config =
    [
        "future_use1", "receive_time", "serial", "type", "subtype", "version", "generated_time",
        "host", "vsys", "command", "admin", "client", "result", "path", "seqno", "action_flags",
        "before_change", "after_change", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3",
        "dg_hier_level_4", "vsys_name", "device_name",
    ];

    private static readonly string[] GlobalProtect =
    [
        "future_use1", "receive_time", "serial", "type", "subtype", "version", "generated_time",
        "vsys", "event_id", "stage", "auth_method", "tunnel_type", "src_user", "src_region", "machine_name",
        "public_ip", "public_ipv6", "private_ip", "private_ipv6", "host_id", "client_serial", "client_ver",
        "client_os", "client_os_ver", "repeat_count", "reason", "error", "description", "status", "location",
        "login_duration", "connect_method", "error_code", "portal", "seqno", "action_flags",
    ];

    private static readonly HashSet<string> Promoted = new(StringComparer.OrdinalIgnoreCase)
    {
        "future_use1", "future_use3", "future_use4", "future_use5", "receive_time", "generated_time",
        "type", "src_ip", "dest_ip", "src_port", "dest_port", "src_zone", "dest_zone", "protocol",
        "action", "rule", "app", "src_user", "bytes", "bytes_in", "bytes_out", "packets", "threat_name",
        "category", "severity", "device_name", "session_id", "repeat_count", "inbound_if", "description",
        "admin",
    };

    public static bool TryApply(string body, LogEvent ev)
    {
        var match = PanStartRegex().Match(body.Trim());
        if (!match.Success)
        {
            return false;
        }

        var fields = CsvSplitter.Split(match.Groups["csv"].Value.Trim());
        if (fields.Count < 4)
        {
            return false;
        }

        var type = Field(fields, 3)?.ToUpperInvariant();
        var names = type switch
        {
            "TRAFFIC" => Traffic,
            "THREAT" => Threat,
            "SYSTEM" => SystemLog,
            "CONFIG" => Config,
            "GLOBALPROTECT" => GlobalProtect,
            _ => null,
        };
        if (names == null)
        {
            return false;
        }

        ev.Vendor = "paloalto";
        ev.Sourcetype = "pan:" + type!.ToLowerInvariant();
        var map = Map(names, fields);

        var when = ParsePanTime(Get(map, "generated_time")) ?? ParsePanTime(Get(map, "receive_time"));
        if (when != null)
        {
            ev.EventTime = when.Value;
        }

        ev.SrcIp = CleanIp(Get(map, "src_ip"));
        ev.DstIp = CleanIp(Get(map, "dest_ip"));
        ev.SrcPort = Int(Get(map, "src_port"));
        ev.DstPort = Int(Get(map, "dest_port"));
        ev.SrcZone = Get(map, "src_zone");
        ev.DstZone = Get(map, "dest_zone");
        ev.Protocol = Get(map, "protocol");
        ev.Action = Get(map, "action");
        ev.RuleName = Get(map, "rule");
        ev.Application = Get(map, "app");
        ev.UserName = Get(map, "src_user") ?? Get(map, "admin");
        ev.BytesTotal = Long(Get(map, "bytes"));
        ev.BytesOut = Long(Get(map, "bytes_out"));
        ev.BytesIn = Long(Get(map, "bytes_in"));
        ev.Packets = Long(Get(map, "packets"));
        ev.ThreatName = Get(map, "threat_name");
        ev.ThreatCategory = Get(map, "threat_category") ?? Get(map, "category");
        ev.DeviceName = Get(map, "device_name");
        ev.SessionId = Get(map, "session_id");
        ev.RepeatCount = Int(Get(map, "repeat_count"));
        ev.Interface = Get(map, "inbound_if");
        if (Get(map, "severity") is { } sev)
        {
            ev.SeverityName = sev.ToLowerInvariant();
        }

        if (string.IsNullOrWhiteSpace(ev.Host) && ev.DeviceName != null)
        {
            ev.Host = ev.DeviceName;
        }

        switch (type)
        {
            case "TRAFFIC":
                ev.Message = Join(" ", ev.Action, ev.Application, Endpoint(ev.SrcIp, ev.SrcPort), "->", Endpoint(ev.DstIp, ev.DstPort), ev.RuleName);
                break;
            case "THREAT":
                ev.Message = Join(" ", ev.SeverityName, ev.ThreatName, ev.Action, Endpoint(ev.SrcIp, ev.SrcPort), "->", Endpoint(ev.DstIp, ev.DstPort));
                if (Get(map, "misc") is { } misc)
                {
                    ev.Extra["url"] = misc;
                }
                break;
            case "SYSTEM":
                ev.Message = Get(map, "description");
                ApplySystemExtras(ev);
                ev.Action ??= Get(map, "event_id");
                break;
            case "CONFIG":
                ev.Message = Join(" ", Get(map, "admin"), Get(map, "command"), Get(map, "path"), Get(map, "result"));
                ev.Action ??= Get(map, "result") ?? "config";
                if (LooksLikeIp(Get(map, "host")))
                {
                    ev.SrcIp ??= Get(map, "host");
                }
                break;
            case "GLOBALPROTECT":
                var privateIp = CleanIp(Get(map, "private_ip"));
                var publicIp = CleanIp(Get(map, "public_ip"));
                ev.SrcIp = privateIp ?? publicIp;
                ev.UserName ??= Get(map, "src_user");
                ev.Action ??= Get(map, "status") ?? Get(map, "event_id");
                ev.Message = Join(" ", Get(map, "event_id"), Get(map, "stage"), Get(map, "src_user"), Get(map, "status"), Get(map, "description"));
                ev.SeverityName ??= Get(map, "status");
                break;
        }

        foreach (var (key, value) in map)
        {
            if (value == null || Promoted.Contains(key) || key.StartsWith("future_use", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            ev.Extra[key] = value;
        }

        if (ev.ThreatName is { } threat)
        {
            var id = ThreatIdRegex().Match(threat);
            if (id.Success)
            {
                ev.Extra["threat_id"] = id.Groups[1].Value;
            }
        }

        return true;
    }

    private static void ApplySystemExtras(LogEvent ev)
    {
        var desc = ev.Message;
        if (string.IsNullOrEmpty(desc))
        {
            return;
        }

        var user = SystemUserRegex().Match(desc);
        if (user.Success)
        {
            ev.UserName ??= user.Groups[1].Value;
        }

        var ip = SystemIpRegex().Match(desc);
        if (ip.Success)
        {
            ev.SrcIp ??= ip.Groups[1].Value;
        }
    }

    private static Dictionary<string, string?> Map(string[] names, List<string> fields)
    {
        var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var n = Math.Max(names.Length, fields.Count);
        for (var i = 0; i < n; i++)
        {
            var value = Field(fields, i);
            var name = i < names.Length ? names[i] : "field_" + i;
            if (name.StartsWith("future_use", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            map[name] = value;
        }

        return map;
    }

    private static string? Field(IReadOnlyList<string> fields, int index)
    {
        if ((uint)index >= (uint)fields.Count)
        {
            return null;
        }

        var value = fields[index].Trim();
        return value.Length == 0 ? null : value;
    }

    private static string? Get(Dictionary<string, string?> map, string key) =>
        map.TryGetValue(key, out var value) ? value : null;

    private static int? Int(string? value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;

    private static long? Long(string? value) => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;

    private static string? CleanIp(string? value) =>
        string.IsNullOrWhiteSpace(value) || value == "0.0.0.0" || value == "::" ? null : value;

    private static bool LooksLikeIp(string? value) =>
        value != null && IpRegex().IsMatch(value);

    private static DateTime? ParsePanTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string[] formats = ["yyyy/MM/dd HH:mm:ss", "yyyy/MM/dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss"];
        if (DateTime.TryParseExact(value, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            return dt;
        }

        return null;
    }

    private static string? Endpoint(string? ip, int? port) =>
        ip == null ? null : port is > 0 ? ip + ":" + port.Value.ToString(CultureInfo.InvariantCulture) : ip;

    private static string? Join(string sep, params string?[] parts)
    {
        var kept = parts.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
        return kept.Length == 0 ? null : string.Join(sep, kept);
    }

    [GeneratedRegex(@"(?<csv>\d+\s*,[^,\r\n]*,[^,\r\n]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT),[\s\S]*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PanStartRegex();

    [GeneratedRegex(@"\((\d+)\)\s*$")]
    private static partial Regex ThreatIdRegex();

    [GeneratedRegex(@"\b(?:by user|User|user)\s+([A-Za-z0-9._\\-]+)", RegexOptions.CultureInvariant)]
    private static partial Regex SystemUserRegex();

    [GeneratedRegex(@"\b(?:from|IP:)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", RegexOptions.CultureInvariant)]
    private static partial Regex SystemIpRegex();

    [GeneratedRegex(@"^(?:\d{1,3}\.){3}\d{1,3}$")]
    private static partial Regex IpRegex();
}
