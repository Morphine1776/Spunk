using Microsoft.Data.SqlClient;

namespace Spunk.Infrastructure.Data;

public sealed class MetadataStore
{
    public MetadataStore(string connectionString) => ConnectionString = connectionString;

    public string ConnectionString { get; }

    public async Task<List<SavedSearch>> ListSearchesAsync(CancellationToken ct = default)
    {
        const string sql = "SELECT Id, Name, SearchQuery, Earliest, Latest, Description, CreatedUtc FROM dbo.SavedSearches ORDER BY Name";
        return await QueryAsync(sql, null, r => new SavedSearch
        {
            Id = r.GetInt32(0),
            Name = r.GetString(1),
            Query = r.GetString(2),
            Earliest = r.GetString(3),
            Latest = r.GetString(4),
            Description = r.IsDBNull(5) ? null : r.GetString(5),
            CreatedUtc = r.GetDateTime(6),
        }, ct);
    }

    public async Task<SavedSearch> CreateSearchAsync(SavedSearch search, CancellationToken ct = default)
    {
        const string sql = """
            INSERT INTO dbo.SavedSearches (Name, SearchQuery, Earliest, Latest, Description)
            OUTPUT INSERTED.Id, INSERTED.CreatedUtc
            VALUES (@name, @query, @earliest, @latest, @description)
            """;
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@name", search.Name.Trim());
        cmd.Parameters.AddWithValue("@query", search.Query);
        cmd.Parameters.AddWithValue("@earliest", string.IsNullOrWhiteSpace(search.Earliest) ? "-24h" : search.Earliest);
        cmd.Parameters.AddWithValue("@latest", string.IsNullOrWhiteSpace(search.Latest) ? "now" : search.Latest);
        cmd.Parameters.AddWithValue("@description", (object?)search.Description ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        await reader.ReadAsync(ct);
        search.Id = reader.GetInt32(0);
        search.CreatedUtc = reader.GetDateTime(1);
        return search;
    }

    public async Task DeleteSearchAsync(int id, CancellationToken ct = default)
    {
        await ExecAsync("DELETE FROM dbo.SavedSearches WHERE Id = @id", cmd => cmd.Parameters.AddWithValue("@id", id), ct);
    }

    public async Task<List<DashboardSummary>> ListDashboardsAsync(CancellationToken ct = default)
    {
        const string sql = """
            SELECT d.Id, d.Name, d.Slug, d.Description, COUNT(p.Id)
            FROM dbo.Dashboards d
            LEFT JOIN dbo.DashboardPanels p ON p.DashboardId = d.Id
            GROUP BY d.Id, d.Name, d.Slug, d.Description
            ORDER BY d.Name
            """;
        return await QueryAsync(sql, null, r => new DashboardSummary
        {
            Id = r.GetInt32(0),
            Name = r.GetString(1),
            Slug = r.GetString(2),
            Description = r.IsDBNull(3) ? null : r.GetString(3),
            Panels = r.GetInt32(4),
        }, ct);
    }

    public async Task<DashboardDetail?> GetDashboardAsync(string slug, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, Name, Slug, Description FROM dbo.Dashboards WHERE Slug = @slug";
        cmd.Parameters.AddWithValue("@slug", slug);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            return null;
        }

        var dashboard = new DashboardDetail
        {
            Id = reader.GetInt32(0),
            Name = reader.GetString(1),
            Slug = reader.GetString(2),
            Description = reader.IsDBNull(3) ? null : reader.GetString(3),
        };
        await reader.CloseAsync();
        await using var panels = conn.CreateCommand();
        panels.CommandText = """
            SELECT p.Id, p.Title, p.Viz, p.ColSpan, p.SortOrder, s.Id, s.Name, s.SearchQuery, s.Earliest, s.Latest
            FROM dbo.DashboardPanels p
            JOIN dbo.SavedSearches s ON s.Id = p.SavedSearchId
            WHERE p.DashboardId = @id
            ORDER BY p.SortOrder, p.Id
            """;
        panels.Parameters.AddWithValue("@id", dashboard.Id);
        await using var panelReader = await panels.ExecuteReaderAsync(ct);
        while (await panelReader.ReadAsync(ct))
        {
            dashboard.Panels.Add(new DashboardPanel
            {
                Id = panelReader.GetInt32(0),
                Title = panelReader.GetString(1),
                Viz = panelReader.GetString(2),
                ColSpan = panelReader.GetInt32(3),
                SortOrder = panelReader.GetInt32(4),
                SavedSearchId = panelReader.GetInt32(5),
                SearchName = panelReader.GetString(6),
                Query = panelReader.GetString(7),
                Earliest = panelReader.GetString(8),
                Latest = panelReader.GetString(9),
            });
        }

        return dashboard;
    }

    public async Task<int> AddPanelAsync(int dashboardId, int savedSearchId, string title, string viz, int colSpan, CancellationToken ct = default)
    {
        const string sql = """
            INSERT INTO dbo.DashboardPanels (DashboardId, SavedSearchId, Title, Viz, ColSpan, SortOrder)
            OUTPUT INSERTED.Id
            VALUES (@dash, @search, @title, @viz, @span, (SELECT ISNULL(MAX(SortOrder), 0) + 1 FROM dbo.DashboardPanels WHERE DashboardId = @dash))
            """;
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@dash", dashboardId);
        cmd.Parameters.AddWithValue("@search", savedSearchId);
        cmd.Parameters.AddWithValue("@title", title);
        cmd.Parameters.AddWithValue("@viz", viz);
        cmd.Parameters.AddWithValue("@span", Math.Clamp(colSpan, 3, 12));
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
    }

    public async Task DeletePanelAsync(int id, CancellationToken ct = default)
    {
        await ExecAsync("DELETE FROM dbo.DashboardPanels WHERE Id = @id", cmd => cmd.Parameters.AddWithValue("@id", id), ct);
    }

    public async Task<List<AlertRecord>> ListAlertsAsync(CancellationToken ct = default)
    {
        const string sql = """
            SELECT Id, Name, SearchQuery, Earliest, Condition, Cron, Action, WebhookUrl, EmailTo, Enabled, SuppressMinutes, LastRunUtc, LastFiredUtc
            FROM dbo.Alerts ORDER BY Name
            """;
        return await QueryAsync(sql, null, ReadAlert, ct);
    }

    public async Task<AlertRecord?> GetAlertAsync(int id, CancellationToken ct = default)
    {
        var rows = await QueryAsync(
            "SELECT Id, Name, SearchQuery, Earliest, Condition, Cron, Action, WebhookUrl, EmailTo, Enabled, SuppressMinutes, LastRunUtc, LastFiredUtc FROM dbo.Alerts WHERE Id = @id",
            cmd => cmd.Parameters.AddWithValue("@id", id),
            ReadAlert,
            ct);
        return rows.FirstOrDefault();
    }

    public async Task<AlertRecord> CreateAlertAsync(AlertRecord alert, CancellationToken ct = default)
    {
        const string sql = """
            INSERT INTO dbo.Alerts (Name, SearchQuery, Earliest, Condition, Cron, Action, WebhookUrl, EmailTo, Enabled, SuppressMinutes)
            OUTPUT INSERTED.Id
            VALUES (@name, @query, @earliest, @condition, @cron, @action, @webhook, @email, @enabled, @suppress)
            """;
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        BindAlert(cmd, alert);
        alert.Id = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
        return alert;
    }

    public async Task UpdateAlertAsync(AlertRecord alert, CancellationToken ct = default)
    {
        const string sql = """
            UPDATE dbo.Alerts
            SET Name=@name, SearchQuery=@query, Earliest=@earliest, Condition=@condition, Cron=@cron,
                Action=@action, WebhookUrl=@webhook, EmailTo=@email, Enabled=@enabled, SuppressMinutes=@suppress
            WHERE Id=@id
            """;
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        BindAlert(cmd, alert);
        cmd.Parameters.AddWithValue("@id", alert.Id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task DeleteAlertAsync(int id, CancellationToken ct = default)
    {
        await ExecAsync("DELETE FROM dbo.AlertHistory WHERE AlertId=@id; DELETE FROM dbo.Alerts WHERE Id=@id", cmd => cmd.Parameters.AddWithValue("@id", id), ct);
    }

    public async Task TouchAlertAsync(int id, DateTime ranUtc, bool fired, CancellationToken ct = default)
    {
        const string sql = """
            UPDATE dbo.Alerts
            SET LastRunUtc = @ran, LastFiredUtc = CASE WHEN @fired = 1 THEN @ran ELSE LastFiredUtc END
            WHERE Id = @id
            """;
        await ExecAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@ran", ranUtc);
            cmd.Parameters.AddWithValue("@fired", fired);
        }, ct);
    }

    public async Task AddHistoryAsync(int alertId, bool matched, int rows, string? summary, bool success, string? detail, CancellationToken ct = default)
    {
        const string sql = """
            INSERT INTO dbo.AlertHistory (AlertId, FiredUtc, Matched, [RowCount], Summary, Success, Detail)
            VALUES (@id, SYSUTCDATETIME(), @matched, @rows, @summary, @success, @detail)
            """;
        await ExecAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("@id", alertId);
            cmd.Parameters.AddWithValue("@matched", matched);
            cmd.Parameters.AddWithValue("@rows", rows);
            cmd.Parameters.AddWithValue("@summary", (object?)summary ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@success", success);
            cmd.Parameters.AddWithValue("@detail", (object?)detail ?? DBNull.Value);
        }, ct);
    }

    public async Task<List<AlertHistoryRecord>> HistoryAsync(int? alertId, int take, CancellationToken ct = default)
    {
        var sql = alertId == null
            ? "SELECT TOP (@take) h.Id, h.AlertId, a.Name, h.FiredUtc, h.Matched, h.[RowCount], h.Summary, h.Success, h.Detail FROM dbo.AlertHistory h JOIN dbo.Alerts a ON a.Id = h.AlertId ORDER BY h.FiredUtc DESC"
            : "SELECT TOP (@take) h.Id, h.AlertId, a.Name, h.FiredUtc, h.Matched, h.[RowCount], h.Summary, h.Success, h.Detail FROM dbo.AlertHistory h JOIN dbo.Alerts a ON a.Id = h.AlertId WHERE h.AlertId = @id ORDER BY h.FiredUtc DESC";
        return await QueryAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("@take", take);
            if (alertId != null)
            {
                cmd.Parameters.AddWithValue("@id", alertId.Value);
            }
        }, r => new AlertHistoryRecord
        {
            Id = r.GetInt64(0),
            AlertId = r.GetInt32(1),
            AlertName = r.GetString(2),
            FiredUtc = DateTime.SpecifyKind(r.GetDateTime(3), DateTimeKind.Utc),
            Matched = r.GetBoolean(4),
            RowCount = r.GetInt32(5),
            Summary = r.IsDBNull(6) ? null : r.GetString(6),
            Success = r.GetBoolean(7),
            Detail = r.IsDBNull(8) ? null : r.GetString(8),
        }, ct);
    }

    public async Task<int> GetRetentionDaysAsync(int fallback, CancellationToken ct = default)
    {
        var rows = await QueryAsync("SELECT [Value] FROM dbo.Settings WHERE [Key] = N'retentionDays'", null, r => r.GetString(0), ct);
        return rows.Count > 0 && int.TryParse(rows[0], out var days) ? days : fallback;
    }

    public async Task SetRetentionDaysAsync(int days, CancellationToken ct = default)
    {
        const string sql = """
            MERGE dbo.Settings AS t
            USING (SELECT N'retentionDays' AS [Key]) AS s ON t.[Key] = s.[Key]
            WHEN MATCHED THEN UPDATE SET [Value] = @value
            WHEN NOT MATCHED THEN INSERT ([Key], [Value]) VALUES (N'retentionDays', @value);
            """;
        await ExecAsync(sql, cmd => cmd.Parameters.AddWithValue("@value", days.ToString()), ct);
    }

    public async Task<long> CountEventsAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT_BIG(*) FROM dbo.Events";
        cmd.CommandTimeout = 60;
        var value = await cmd.ExecuteScalarAsync(ct);
        return value == null || value is DBNull ? 0 : Convert.ToInt64(value);
    }

    public async Task<(DateTime? Min, DateTime? Max)> EventRangeAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT MIN(EventTime), MAX(EventTime) FROM dbo.Events";
        cmd.CommandTimeout = 60;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        await reader.ReadAsync(ct);
        DateTime? min = reader.IsDBNull(0) ? null : DateTime.SpecifyKind(reader.GetDateTime(0), DateTimeKind.Utc);
        DateTime? max = reader.IsDBNull(1) ? null : DateTime.SpecifyKind(reader.GetDateTime(1), DateTimeKind.Utc);
        return (min, max);
    }

    public async Task<int> PurgeBeforeAsync(DateTime cutoffUtc, CancellationToken ct = default)
    {
        var total = 0;
        await using var conn = await OpenAsync(ct);
        while (!ct.IsCancellationRequested)
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandTimeout = 120;
            cmd.CommandText = "DELETE TOP (5000) FROM dbo.Events WHERE EventTime < @cutoff";
            cmd.Parameters.AddWithValue("@cutoff", cutoffUtc);
            var n = await cmd.ExecuteNonQueryAsync(ct);
            total += n;
            if (n < 5000)
            {
                break;
            }
        }

        return total;
    }

    public async Task EnsureFuturePartitionAsync(CancellationToken ct = default)
    {
        const string sql = """
            DECLARE @boundary datetime2(3) = DATEADD(month, DATEDIFF(month, '20000101', SYSUTCDATETIME()) + 2, CONVERT(datetime2(3), '20000101'));
            IF NOT EXISTS (
                SELECT 1
                FROM sys.partition_range_values v
                JOIN sys.partition_functions f ON f.function_id = v.function_id
                WHERE f.name = N'pf_events' AND CONVERT(datetime2(3), v.value) = @boundary)
            BEGIN
                ALTER PARTITION SCHEME ps_events NEXT USED [PRIMARY];
                ALTER PARTITION FUNCTION pf_events() SPLIT RANGE (@boundary);
            END
            """;
        await ExecAsync(sql, null, ct);
    }

    private static AlertRecord ReadAlert(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        Name = r.GetString(1),
        Query = r.GetString(2),
        Earliest = r.GetString(3),
        Condition = r.GetString(4),
        Cron = r.GetString(5),
        Action = r.GetString(6),
        WebhookUrl = r.IsDBNull(7) ? null : r.GetString(7),
        EmailTo = r.IsDBNull(8) ? null : r.GetString(8),
        Enabled = r.GetBoolean(9),
        SuppressMinutes = r.GetInt32(10),
        LastRunUtc = r.IsDBNull(11) ? null : DateTime.SpecifyKind(r.GetDateTime(11), DateTimeKind.Utc),
        LastFiredUtc = r.IsDBNull(12) ? null : DateTime.SpecifyKind(r.GetDateTime(12), DateTimeKind.Utc),
    };

    private static void BindAlert(SqlCommand cmd, AlertRecord alert)
    {
        cmd.Parameters.AddWithValue("@name", alert.Name.Trim());
        cmd.Parameters.AddWithValue("@query", alert.Query);
        cmd.Parameters.AddWithValue("@earliest", string.IsNullOrWhiteSpace(alert.Earliest) ? "-15m" : alert.Earliest);
        cmd.Parameters.AddWithValue("@condition", alert.Condition);
        cmd.Parameters.AddWithValue("@cron", alert.Cron);
        cmd.Parameters.AddWithValue("@action", alert.Action);
        cmd.Parameters.AddWithValue("@webhook", (object?)alert.WebhookUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@email", (object?)alert.EmailTo ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@enabled", alert.Enabled);
        cmd.Parameters.AddWithValue("@suppress", alert.SuppressMinutes);
    }

    private async Task<List<T>> QueryAsync<T>(string sql, Action<SqlCommand>? bind, Func<SqlDataReader, T> map, CancellationToken ct)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        bind?.Invoke(cmd);
        var list = new List<T>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(map(reader));
        }

        return list;
    }

    private async Task ExecAsync(string sql, Action<SqlCommand>? bind, CancellationToken ct)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.CommandTimeout = 120;
        bind?.Invoke(cmd);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<SqlConnection> OpenAsync(CancellationToken ct)
    {
        var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}

public sealed class SavedSearch
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Query { get; set; } = "";
    public string Earliest { get; set; } = "-24h";
    public string Latest { get; set; } = "now";
    public string? Description { get; set; }
    public DateTime CreatedUtc { get; set; }
}

public sealed class DashboardSummary
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public string? Description { get; set; }
    public int Panels { get; set; }
}

public sealed class DashboardDetail
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public string? Description { get; set; }
    public List<DashboardPanel> Panels { get; set; } = [];
}

public sealed class DashboardPanel
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Viz { get; set; } = "table";
    public int ColSpan { get; set; } = 6;
    public int SortOrder { get; set; }
    public int SavedSearchId { get; set; }
    public string SearchName { get; set; } = "";
    public string Query { get; set; } = "";
    public string Earliest { get; set; } = "-24h";
    public string Latest { get; set; } = "now";
}

public sealed class AlertRecord
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Query { get; set; } = "";
    public string Earliest { get; set; } = "-15m";
    public string Condition { get; set; } = "count > 0";
    public string Cron { get; set; } = "*/5 * * * *";
    public string Action { get; set; } = "log";
    public string? WebhookUrl { get; set; }
    public string? EmailTo { get; set; }
    public bool Enabled { get; set; } = true;
    public int SuppressMinutes { get; set; } = 15;
    public DateTime? LastRunUtc { get; set; }
    public DateTime? LastFiredUtc { get; set; }
}

public sealed class AlertHistoryRecord
{
    public long Id { get; set; }
    public int AlertId { get; set; }
    public string AlertName { get; set; } = "";
    public DateTime FiredUtc { get; set; }
    public bool Matched { get; set; }
    public int RowCount { get; set; }
    public string? Summary { get; set; }
    public bool Success { get; set; }
    public string? Detail { get; set; }
}
