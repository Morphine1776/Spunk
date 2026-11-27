namespace Spunk.Core.Models;

/// <summary>
/// One normalized log event. Promoted columns are the fields we filter and aggregate on;
/// everything else lives in <see cref="Extra"/> and is stored as JSON.
/// </summary>
public sealed class LogEvent
{
    public long EventId { get; set; }
    public DateTime EventTime { get; set; }
    public DateTime ReceivedTime { get; set; }
    public string? Host { get; set; }
    public string? SourceIp { get; set; }
    public string Sourcetype { get; set; } = "syslog";
    public string Vendor { get; set; } = "generic";
    public byte? Severity { get; set; }
    public string? SeverityName { get; set; }
    public byte? Facility { get; set; }
    public string? FacilityName { get; set; }
    public string? AppName { get; set; }
    public string? Mnemonic { get; set; }
    public string? Message { get; set; }
    public string Raw { get; set; } = "";
    public string? SrcIp { get; set; }
    public string? DstIp { get; set; }
    public int? SrcPort { get; set; }
    public int? DstPort { get; set; }
    public string? SrcZone { get; set; }
    public string? DstZone { get; set; }
    public string? Protocol { get; set; }
    public string? Action { get; set; }
    public string? RuleName { get; set; }
    public string? Application { get; set; }
    public string? UserName { get; set; }
    public long? BytesTotal { get; set; }
    public long? BytesIn { get; set; }
    public long? BytesOut { get; set; }
    public long? Packets { get; set; }
    public string? ThreatName { get; set; }
    public string? ThreatCategory { get; set; }
    public string? Interface { get; set; }
    public string? DeviceName { get; set; }
    public string? SessionId { get; set; }
    public int? RepeatCount { get; set; }
    public Dictionary<string, string?> Extra { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class ParseHint
{
    public DateTime? Time { get; init; }
    public string? Host { get; init; }
    public string? SourceIp { get; init; }
    public string? Sourcetype { get; init; }
}
