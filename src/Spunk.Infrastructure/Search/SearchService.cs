using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Spunk.Core.Query;
using Spunk.Infrastructure.Data;

namespace Spunk.Infrastructure.Search;

public sealed class SearchService
{
    private static readonly (string Name, string Column)[] Sidebar =
    [
        ("sourcetype", "Sourcetype"),
        ("host", "Host"),
        ("action", "Action"),
        ("app", "Application"),
        ("src_ip", "SrcIp"),
        ("dst_ip", "DstIp"),
        ("src_zone", "SrcZone"),
        ("dst_zone", "DstZone"),
        ("protocol", "Protocol"),
        ("severity", "SeverityName"),
        ("rule", "RuleName"),
        ("user", "UserName"),
        ("threat_name", "ThreatName"),
        ("mnemonic", "Mnemonic"),
        ("interface", "Interface"),
        ("device", "DeviceName"),
    ];

    public SearchService(string connectionString) => ConnectionString = connectionString;

    public string ConnectionString { get; }

    public async Task<SearchResponse> SearchAsync(string query, string? earliest, string? latest, int limit, CancellationToken ct = default)
    {
        var parsed = SplParser.Parse(string.IsNullOrWhiteSpace(query) ? "*" : query);
        var now = DateTime.UtcNow;
        var from = RelativeTime.Resolve(parsed.Earliest ?? earliest ?? "-24h", now);
        var to = RelativeTime.Resolve(parsed.Latest ?? latest ?? "now", now);
        if (to <= from)
        {
            to = from.AddMinutes(1);
        }

        var compiled = TsqlTranslator.Compile(parsed, from, to, limit <= 0 ? 500 : limit);
        var response = new SearchResponse
        {
            Query = query,
            ResultType = compiled.ResultType,
            From = from,
            To = to,
            CategoryField = compiled.CategoryField,
            SplitBy = compiled.SplitBy,
            Measures = compiled.Measures.ToList(),
            Sql = compiled.Sql,
        };

        var clock = Stopwatch.StartNew();
        await using var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync(ct);
        response.Rows = await ReadRowsAsync(conn, compiled.Sql, compiled.Parameters, ct);
        response.Columns = response.Rows.Count == 0
            ? []
            : response.Rows.SelectMany(r => r.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (compiled.CountSql != null)
        {
            response.Total = await ScalarAsync(conn, compiled.CountSql, compiled.Parameters, ct);
            response.Truncated = response.Total > response.Rows.Count;
        }
        else
        {
            response.Total = response.Rows.Count;
            response.Truncated = response.Rows.Count >= compiled.RowLimit;
        }

        response.Timeline = await ReadTimelineAsync(conn, compiled, ct);
        response.ElapsedMs = (int)clock.ElapsedMilliseconds;
        return response;
    }

    public async Task<List<FieldSummary>> FieldsAsync(string query, string? earliest, string? latest, CancellationToken ct = default)
    {
        var parsed = SplParser.Parse(string.IsNullOrWhiteSpace(query) ? "*" : StripAfterFirstPipe(query));
        // Sidebar follows the base search, not the reporting commands.
        var searchOnly = new SplQuery();
        foreach (var stage in parsed.Stages)
        {
            if (stage is SearchStage or WhereStage)
            {
                searchOnly.Stages.Add(stage);
            }
            else
            {
                break;
            }
        }

        if (searchOnly.Stages.Count == 0)
        {
            searchOnly.Stages.Add(new SearchStage(new SxTrue()));
        }

        searchOnly.Earliest = parsed.Earliest;
        searchOnly.Latest = parsed.Latest;
        var now = DateTime.UtcNow;
        var from = RelativeTime.Resolve(searchOnly.Earliest ?? earliest ?? "-24h", now);
        var to = RelativeTime.Resolve(searchOnly.Latest ?? latest ?? "now", now);
        var compiled = TsqlTranslator.Compile(searchOnly, from, to, 1);

        var sql = string.Join(";\n", Sidebar.Select(field => $@"
SELECT TOP (8) {field.Column} AS value, COUNT_BIG(*) AS cnt
FROM dbo.Events
WHERE {compiled.FilterSql} AND {field.Column} IS NOT NULL AND {field.Column} <> N''
GROUP BY {field.Column}
ORDER BY cnt DESC"));

        var result = Sidebar.Select(f => new FieldSummary { Name = f.Name }).ToList();
        await using var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandTimeout = 30;
        cmd.CommandText = sql;
        Database.AddParameters(cmd, compiled.Parameters);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        for (var i = 0; i < result.Count; i++)
        {
            while (await reader.ReadAsync(ct))
            {
                result[i].Top.Add(new FieldValue
                {
                    Value = reader.IsDBNull(0) ? "" : Convert.ToString(reader.GetValue(0), CultureInfo.InvariantCulture) ?? "",
                    Count = reader.GetInt64(1),
                });
            }

            if (i < result.Count - 1)
            {
                await reader.NextResultAsync(ct);
            }
        }

        return result.Where(f => f.Top.Count > 0).ToList();
    }

    private static string StripAfterFirstPipe(string query)
    {
        var pipe = query.IndexOf('|');
        return pipe < 0 ? query : query[..pipe];
    }

    private static async Task<List<Dictionary<string, object?>>> ReadRowsAsync(SqlConnection conn, string sql, IReadOnlyList<QueryParameter> parameters, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandTimeout = 60;
        cmd.CommandText = sql;
        Database.AddParameters(cmd, parameters);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string?>? extra = null;
            for (var i = 0; i < reader.FieldCount; i++)
            {
                var name = reader.GetName(i);
                if (name.Equals("__rn", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (reader.IsDBNull(i))
                {
                    continue;
                }

                var value = reader.GetValue(i);
                if (name.Equals("_extra", StringComparison.OrdinalIgnoreCase) && value is string json)
                {
                    extra = ParseExtra(json);
                    continue;
                }

                row[name] = Normalize(value);
            }

            if (extra != null)
            {
                foreach (var pair in extra)
                {
                    if (!row.ContainsKey(pair.Key) && pair.Value != null)
                    {
                        row[pair.Key] = pair.Value;
                    }
                }
            }

            rows.Add(row);
        }

        return rows;
    }

    private static async Task<List<TimelineBucket>> ReadTimelineAsync(SqlConnection conn, CompiledQuery compiled, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandTimeout = 60;
        cmd.CommandText = compiled.TimelineSql;
        Database.AddParameters(cmd, compiled.Parameters);
        var buckets = new List<TimelineBucket>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            buckets.Add(new TimelineBucket
            {
                Time = DateTime.SpecifyKind(reader.GetDateTime(0), DateTimeKind.Utc),
                Count = reader.GetInt64(1),
            });
        }

        return buckets;
    }

    private static async Task<long> ScalarAsync(SqlConnection conn, string sql, IReadOnlyList<QueryParameter> parameters, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandTimeout = 60;
        cmd.CommandText = sql;
        Database.AddParameters(cmd, parameters);
        var value = await cmd.ExecuteScalarAsync(ct);
        return value == null || value is DBNull ? 0 : Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    private static object Normalize(object value) => value switch
    {
        DateTime dt => DateTime.SpecifyKind(dt, DateTimeKind.Utc),
        decimal d => (double)d,
        byte or short or int or long or float or double or bool or string => value,
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
    };

    private static Dictionary<string, string?>? ParseExtra(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string?>>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

public sealed class SearchResponse
{
    public string Query { get; set; } = "";
    public string ResultType { get; set; } = "events";
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public long? Total { get; set; }
    public bool Truncated { get; set; }
    public int ElapsedMs { get; set; }
    public List<string> Columns { get; set; } = [];
    public List<Dictionary<string, object?>> Rows { get; set; } = [];
    public List<TimelineBucket> Timeline { get; set; } = [];
    public string? CategoryField { get; set; }
    public string? SplitBy { get; set; }
    public List<string> Measures { get; set; } = [];
    public string Sql { get; set; } = "";
}

public sealed class TimelineBucket
{
    public DateTime Time { get; set; }
    public long Count { get; set; }
}

public sealed class FieldSummary
{
    public string Name { get; set; } = "";
    public List<FieldValue> Top { get; set; } = [];
}

public sealed class FieldValue
{
    public string Value { get; set; } = "";
    public long Count { get; set; }
}
