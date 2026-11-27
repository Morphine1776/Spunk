using System.Data;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Spunk.Core.Models;

namespace Spunk.Infrastructure.Data;

public sealed class EventWriter
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };
    private long _nextId = DateTime.UtcNow.Ticks;

    public EventWriter(string connectionString) => ConnectionString = connectionString;

    public string ConnectionString { get; }

    public async Task WriteAsync(IReadOnlyList<LogEvent> events, CancellationToken ct = default)
    {
        if (events.Count == 0)
        {
            return;
        }

        var ordered = events.OrderBy(e => e.EventTime).ToList();
        foreach (var ev in ordered)
        {
            if (ev.EventId == 0)
            {
                ev.EventId = Interlocked.Increment(ref _nextId);
            }
        }

        var table = BuildTable(ordered);
        await using var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync(ct);
        using var bulk = new SqlBulkCopy(conn, SqlBulkCopyOptions.TableLock, null)
        {
            DestinationTableName = "dbo.Events",
            BatchSize = ordered.Count,
            BulkCopyTimeout = 120,
        };
        foreach (DataColumn column in table.Columns)
        {
            bulk.ColumnMappings.Add(column.ColumnName, column.ColumnName);
        }

        await bulk.WriteToServerAsync(table, ct);
    }

    private static DataTable BuildTable(IReadOnlyList<LogEvent> events)
    {
        var table = new DataTable();
        table.Columns.Add("EventId", typeof(long));
        table.Columns.Add("EventTime", typeof(DateTime));
        table.Columns.Add("ReceivedTime", typeof(DateTime));
        table.Columns.Add("Host", typeof(string));
        table.Columns.Add("SourceIp", typeof(string));
        table.Columns.Add("Sourcetype", typeof(string));
        table.Columns.Add("Vendor", typeof(string));
        table.Columns.Add("Severity", typeof(byte));
        table.Columns.Add("SeverityName", typeof(string));
        table.Columns.Add("Facility", typeof(byte));
        table.Columns.Add("FacilityName", typeof(string));
        table.Columns.Add("AppName", typeof(string));
        table.Columns.Add("Mnemonic", typeof(string));
        table.Columns.Add("Message", typeof(string));
        table.Columns.Add("Raw", typeof(string));
        table.Columns.Add("SrcIp", typeof(string));
        table.Columns.Add("DstIp", typeof(string));
        table.Columns.Add("SrcPort", typeof(int));
        table.Columns.Add("DstPort", typeof(int));
        table.Columns.Add("SrcZone", typeof(string));
        table.Columns.Add("DstZone", typeof(string));
        table.Columns.Add("Protocol", typeof(string));
        table.Columns.Add("Action", typeof(string));
        table.Columns.Add("RuleName", typeof(string));
        table.Columns.Add("Application", typeof(string));
        table.Columns.Add("UserName", typeof(string));
        table.Columns.Add("BytesTotal", typeof(long));
        table.Columns.Add("BytesIn", typeof(long));
        table.Columns.Add("BytesOut", typeof(long));
        table.Columns.Add("Packets", typeof(long));
        table.Columns.Add("ThreatName", typeof(string));
        table.Columns.Add("ThreatCategory", typeof(string));
        table.Columns.Add("Interface", typeof(string));
        table.Columns.Add("DeviceName", typeof(string));
        table.Columns.Add("SessionId", typeof(string));
        table.Columns.Add("RepeatCount", typeof(int));
        table.Columns.Add("ExtraJson", typeof(string));

        foreach (var ev in events)
        {
            table.Rows.Add(
                ev.EventId,
                Utc(ev.EventTime),
                Utc(ev.ReceivedTime),
                Cut(ev.Host, 255),
                Cut(ev.SourceIp, 45),
                Cut(string.IsNullOrWhiteSpace(ev.Sourcetype) ? "syslog" : ev.Sourcetype, 64),
                Cut(string.IsNullOrWhiteSpace(ev.Vendor) ? "generic" : ev.Vendor, 32),
                (object?)ev.Severity ?? DBNull.Value,
                Cut(ev.SeverityName, 32),
                (object?)ev.Facility ?? DBNull.Value,
                Cut(ev.FacilityName, 64),
                Cut(ev.AppName, 128),
                Cut(ev.Mnemonic, 64),
                (object?)ev.Message ?? DBNull.Value,
                ev.Raw ?? "",
                Cut(ev.SrcIp, 45),
                Cut(ev.DstIp, 45),
                (object?)ev.SrcPort ?? DBNull.Value,
                (object?)ev.DstPort ?? DBNull.Value,
                Cut(ev.SrcZone, 64),
                Cut(ev.DstZone, 64),
                Cut(ev.Protocol, 32),
                Cut(ev.Action, 64),
                Cut(ev.RuleName, 256),
                Cut(ev.Application, 128),
                Cut(ev.UserName, 256),
                (object?)ev.BytesTotal ?? DBNull.Value,
                (object?)ev.BytesIn ?? DBNull.Value,
                (object?)ev.BytesOut ?? DBNull.Value,
                (object?)ev.Packets ?? DBNull.Value,
                Cut(ev.ThreatName, 512),
                Cut(ev.ThreatCategory, 128),
                Cut(ev.Interface, 128),
                Cut(ev.DeviceName, 255),
                Cut(ev.SessionId, 64),
                (object?)ev.RepeatCount ?? DBNull.Value,
                Extra(ev));
        }

        return table;
    }

    private static object Extra(LogEvent ev)
    {
        if (ev.Extra.Count == 0)
        {
            return DBNull.Value;
        }

        var cleaned = ev.Extra.Where(p => !string.IsNullOrWhiteSpace(p.Value)).ToDictionary(p => p.Key, p => p.Value);
        return cleaned.Count == 0 ? DBNull.Value : JsonSerializer.Serialize(cleaned, Json);
    }

    private static object Cut(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return DBNull.Value;
        }

        return value.Length <= max ? value : value[..max];
    }

    private static DateTime Utc(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : value;
        return DateTime.SpecifyKind(utc, DateTimeKind.Utc);
    }
}
