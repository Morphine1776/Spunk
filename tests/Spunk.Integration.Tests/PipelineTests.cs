using System.Globalization;
using Microsoft.Data.SqlClient;
using Spunk.Core.Parsing;
using Spunk.Infrastructure.Data;
using Spunk.Infrastructure.Search;

namespace Spunk.Integration.Tests;

public class PipelineTests : IAsyncLifetime
{
    private static readonly string ConnectionString = Environment.GetEnvironmentVariable("SPUNK_SQL")
        ?? "Server=localhost,1433;Database=SpunkIt;User Id=sa;Password=Spunk_Dev_Passw0rd!;TrustServerCertificate=True;Encrypt=True";

    private readonly EventWriter _writer = new(ConnectionString);
    private readonly SearchService _search = new(ConnectionString);

    public async Task InitializeAsync()
    {
        await Database.MigrateAsync(ConnectionString);
        await DeleteProbeAsync();
    }

    public async Task DisposeAsync() => await DeleteProbeAsync();

    [Fact]
    public async Task Sample_lines_round_trip_through_sql()
    {
        var now = DateTime.UtcNow;
        var events = new[]
        {
            Line(now.AddHours(-3), "10.9.9.9"),
            Line(now.AddHours(-2), "10.9.9.9"),
            Line(now.AddHours(-1), "10.9.9.9"),
            Line(now.AddMinutes(-30), "10.9.9.8"),
            Cisco(now.AddHours(-2)),
            Cisco(now.AddMinutes(-20)),
        }.Select(raw => LogParser.Parse(raw, now)).ToList();

        Assert.All(events.Take(4), ev => Assert.Equal("pan:traffic", ev.Sourcetype));
        Assert.Equal("cisco:ios", events[4].Sourcetype);
        await _writer.WriteAsync(events);

        var denied = await _search.SearchAsync(
            "host=it-pa sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10",
            "-24h", "now", 100);
        Assert.Equal("10.9.9.9", denied.Rows[0]["src_ip"]?.ToString());
        Assert.Equal(3L, Convert.ToInt64(denied.Rows[0]["count"], CultureInfo.InvariantCulture));
        Assert.Equal("10.9.9.8", denied.Rows[1]["src_ip"]?.ToString());
        Assert.Equal(1L, Convert.ToInt64(denied.Rows[1]["count"], CultureInfo.InvariantCulture));

        var chart = await _search.SearchAsync("host=it-sw sourcetype=cisco:ios | timechart span=1h count by host", "-24h", "now", 100);
        Assert.Equal("timechart", chart.ResultType);
        Assert.Equal(2L, chart.Rows.Sum(r => Convert.ToInt64(r["count"], CultureInfo.InvariantCulture)));
        Assert.All(chart.Rows, row => Assert.Equal("it-sw", row["host"]?.ToString()));
    }

    private static string Line(DateTime time, string src)
    {
        var stamp = time.ToString("yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
        var header = time.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        var csv = $"1,{stamp},012345000099,TRAFFIC,deny,2305,{stamp},{src},192.168.1.50,{src},192.168.1.50,Deny-Outbound,,,unknown,vsys1,trust,untrust,ethernet1/2,ethernet1/1,To-Spunk,{stamp},33915,1,51002,443,0,0,0x400000,tcp,deny,94,80,14,1,{stamp},1,any,0,665538,0x0,10.0.0.0-10.255.255.255,United States,,1,1,policy-deny,0,0,0,0,,it-pa,from-policy";
        return $"<14>{header} it-pa {csv}";
    }

    private static string Cisco(DateTime time)
    {
        var header = time.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        return $"<187>{header} it-sw %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down";
    }

    private static async Task DeleteProbeAsync()
    {
        await using var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM dbo.Events WHERE Host IN (N'it-pa', N'it-sw')";
        await cmd.ExecuteNonQueryAsync();
    }
}
