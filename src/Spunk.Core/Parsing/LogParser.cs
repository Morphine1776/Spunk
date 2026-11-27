using Spunk.Core.Models;

namespace Spunk.Core.Parsing;

public static class LogParser
{
    public static LogEvent Parse(string raw, DateTime receivedUtc, ParseHint? hint = null)
    {
        var ev = new LogEvent
        {
            Raw = raw ?? "",
            ReceivedTime = DateTime.SpecifyKind(receivedUtc, DateTimeKind.Utc),
            EventTime = hint?.Time ?? receivedUtc,
            Host = hint?.Host,
            SourceIp = hint?.SourceIp,
            Sourcetype = string.IsNullOrWhiteSpace(hint?.Sourcetype) ? "syslog" : hint!.Sourcetype!,
        };

        if (string.IsNullOrWhiteSpace(raw))
        {
            ev.Message = "";
            return ev;
        }

        var header = SyslogParser.TryParse(raw, receivedUtc);
        var body = raw.Trim();
        if (header != null)
        {
            ev.Host ??= header.Host;
            ev.AppName ??= header.AppName;
            if (header.Facility != null)
            {
                ev.Facility = header.Facility;
            }

            if (header.Severity != null)
            {
                ev.Severity = header.Severity;
                ev.SeverityName = SyslogParser.SeverityWord(header.Severity.Value);
            }

            if (header.Timestamp != null)
            {
                ev.EventTime = header.Timestamp.Value;
            }

            if (!string.IsNullOrWhiteSpace(header.Message))
            {
                body = header.Message;
            }
        }

        if (hint?.Time != null && header?.Timestamp == null)
        {
            ev.EventTime = hint.Time.Value;
        }

        if (PanOsParser.TryApply(body, ev) || CiscoParser.TryApply(body, ev))
        {
            ev.EventTime = DateTime.SpecifyKind(ev.EventTime, DateTimeKind.Utc);
            return ev;
        }

        ev.Vendor = "generic";
        if (!string.IsNullOrWhiteSpace(hint?.Sourcetype))
        {
            ev.Sourcetype = hint!.Sourcetype!;
        }
        else
        {
            ev.Sourcetype = "syslog";
        }

        ev.Message = body.Trim();
        ev.EventTime = DateTime.SpecifyKind(ev.EventTime, DateTimeKind.Utc);
        return ev;
    }
}
