using System.Globalization;
using System.Text.RegularExpressions;

namespace Spunk.Core.Parsing;

public sealed class SyslogHeader
{
    public int? Pri { get; init; }
    public byte? Facility { get; init; }
    public byte? Severity { get; init; }
    public DateTime? Timestamp { get; init; }
    public string? Host { get; init; }
    public string? AppName { get; init; }
    public string Message { get; init; } = "";
}

/// <summary>RFC 3164 and RFC 5424 header parser. The body is returned untouched for vendor parsers.</summary>
public static partial class SyslogParser
{
    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    public static readonly string[] SeverityWords =
        ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];

    public static string SeverityWord(int severity) =>
        severity >= 0 && severity < SeverityWords.Length ? SeverityWords[severity] : "info";

    public static SyslogHeader? TryParse(string raw, DateTime receivedUtc)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var text = raw.Trim();
        int? pri = null;
        if (text.Length > 3 && text[0] == '<')
        {
            var close = text.IndexOf('>');
            if (close > 1 && close <= 4 && int.TryParse(text.AsSpan(1, close - 1), out var priValue))
            {
                pri = priValue;
                text = text[(close + 1)..];
            }
        }

        if (TryRfc5424(text, out var header))
        {
            return WithPri(header, pri);
        }

        if (TryRfc3164(text, receivedUtc, out header))
        {
            return WithPri(header, pri);
        }

        if (pri == null)
        {
            return null;
        }

        return WithPri(new SyslogHeader { Message = text.Trim() }, pri);
    }

    private static SyslogHeader WithPri(SyslogHeader header, int? pri)
    {
        if (pri is null)
        {
            return header;
        }

        return new SyslogHeader
        {
            Pri = pri,
            Facility = (byte)(pri.Value / 8),
            Severity = (byte)(pri.Value % 8),
            Timestamp = header.Timestamp,
            Host = header.Host,
            AppName = header.AppName,
            Message = header.Message,
        };
    }

    private static bool TryRfc5424(string text, out SyslogHeader header)
    {
        header = new SyslogHeader();
        var match = Rfc5424Regex().Match(text);
        if (!match.Success)
        {
            return false;
        }

        DateTime? ts = null;
        var tsText = match.Groups["ts"].Value;
        if (tsText != "-" && DateTimeOffset.TryParse(tsText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
        {
            ts = dto.UtcDateTime;
        }

        var host = Nil(match.Groups["host"].Value);
        var app = Nil(match.Groups["app"].Value);
        header = new SyslogHeader
        {
            Timestamp = ts,
            Host = host,
            AppName = app,
            Message = match.Groups["msg"].Value,
        };
        return true;
    }

    private static bool TryRfc3164(string text, DateTime receivedUtc, out SyslogHeader header)
    {
        header = new SyslogHeader();
        var match = Rfc3164Regex().Match(text);
        if (!match.Success)
        {
            return false;
        }

        var month = Array.FindIndex(Months, m => m.Equals(match.Groups["mon"].Value, StringComparison.OrdinalIgnoreCase));
        if (month < 0 || !int.TryParse(match.Groups["day"].Value, out var day))
        {
            return false;
        }

        var clock = match.Groups["time"].Value.Split(':');
        if (clock.Length != 3
            || !int.TryParse(clock[0], out var hour)
            || !int.TryParse(clock[1], out var minute)
            || !int.TryParse(clock[2], out var second))
        {
            return false;
        }

        var year = receivedUtc.Year;
        DateTime ts;
        try
        {
            ts = new DateTime(year, month + 1, day, hour, minute, second, DateTimeKind.Utc);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        if (ts > receivedUtc.AddDays(2))
        {
            ts = ts.AddYears(-1);
        }

        header = new SyslogHeader
        {
            Timestamp = ts,
            Host = match.Groups["host"].Value,
            Message = match.Groups["msg"].Value,
        };
        return true;
    }

    private static string? Nil(string value) => value == "-" || value.Length == 0 ? null : value;

    [GeneratedRegex(@"^(?<ver>\d{1,3})\s+(?<ts>\S+)\s+(?<host>\S+)\s+(?<app>\S+)\s+(?<proc>\S+)\s+(?<msgid>\S+)\s+(?<sd>-|\[[\s\S]*?\])\s*(?<msg>[\s\S]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex Rfc5424Regex();

    [GeneratedRegex(@"^(?<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<msg>[\s\S]*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Rfc3164Regex();
}
