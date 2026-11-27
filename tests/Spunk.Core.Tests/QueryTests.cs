using Spunk.Core.Alerts;
using Spunk.Core.Query;

namespace Spunk.Core.Tests;

public class QueryTests
{
    private static readonly DateTime From = new(2026, 11, 26, 22, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime To = new(2026, 11, 27, 22, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Denied_traffic_stats_becomes_parameterized_sql()
    {
        var query = SplParser.Parse("sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10");
        var sql = TsqlTranslator.Compile(query, From, To, 500);

        Assert.Contains("COUNT_BIG(*)", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("GROUP BY", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("[src_ip]", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("TOP (10)", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY [count] DESC", sql.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("pan:traffic", sql.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("deny", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(sql.Parameters, p => Equals(p.Value, "pan:traffic"));
        Assert.Contains(sql.Parameters, p => Equals(p.Value, "deny"));
        Assert.Equal("table", sql.ResultType);
    }

    [Fact]
    public void Timechart_buckets_by_host()
    {
        var query = SplParser.Parse("sourcetype=cisco:ios | timechart count by host");
        var sql = TsqlTranslator.Compile(query, From, To, 500);

        Assert.Contains("DATEADD", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("DATEDIFF_BIG", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("[host]", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("COUNT_BIG(*)", sql.Sql, StringComparison.Ordinal);
        Assert.Contains("GROUP BY", sql.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("cisco:ios", sql.Sql, StringComparison.Ordinal);
        Assert.Contains(sql.Parameters, p => Equals(p.Value, "cisco:ios"));
        Assert.Equal("timechart", sql.ResultType);
        Assert.Equal("host", sql.SplitBy);
        Assert.Equal("_time", sql.CategoryField);
    }

    [Fact]
    public void Quoted_injection_stays_a_parameter()
    {
        var query = SplParser.Parse("src_ip=\"1'; DROP TABLE dbo.Events; --\"");
        var sql = TsqlTranslator.Compile(query, From, To, 500);
        Assert.DoesNotContain("DROP", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(sql.Parameters, p => Equals(p.Value, "1'; DROP TABLE dbo.Events; --"));
    }

    [Fact]
    public void Unquoted_injection_is_not_executable_sql()
    {
        var query = SplParser.Parse("src_ip=1;DROP");
        var sql = TsqlTranslator.Compile(query, From, To, 500);
        Assert.DoesNotContain("DROP", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(sql.Parameters, p => Equals(p.Value, "1;DROP"));
    }

    [Fact]
    public void And_binds_tighter_than_or_and_parentheses_work()
    {
        var loose = TsqlTranslator.Compile(SplParser.Parse("sourcetype=cisco:ios OR sourcetype=cisco:nxos severity=error"), From, To, 100);
        Assert.Contains("(Sourcetype = @p0) OR ((Sourcetype = @p1) AND (SeverityName = @p2))", loose.Sql, StringComparison.Ordinal);

        var grouped = TsqlTranslator.Compile(SplParser.Parse("(sourcetype=cisco:ios OR sourcetype=cisco:nxos) severity=error"), From, To, 100);
        Assert.Contains("((Sourcetype = @p0) OR (Sourcetype = @p1)) AND (SeverityName = @p2)", grouped.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Wildcard_not_and_eval_translate()
    {
        var like = TsqlTranslator.Compile(SplParser.Parse("src_ip=10.20.* NOT action=allow"), From, To, 100);
        Assert.Contains("LIKE", like.Sql, StringComparison.Ordinal);
        Assert.Contains("ESCAPE '\\'", like.Sql, StringComparison.Ordinal);
        Assert.Contains("NOT (", like.Sql, StringComparison.Ordinal);
        Assert.Contains(like.Parameters, p => Equals(p.Value, "10.20.%"));

        var eval = TsqlTranslator.Compile(SplParser.Parse("sourcetype=pan:traffic | eval mb=bytes/1048576, label=if(action=\"deny\",\"blocked\",\"ok\") | where mb>1"), From, To, 100);
        Assert.Contains("NULLIF", eval.Sql, StringComparison.Ordinal);
        Assert.Contains("CASE WHEN", eval.Sql, StringComparison.Ordinal);
        Assert.Contains(eval.Parameters, p => Equals(p.Value, "blocked"));
        Assert.Contains(">", eval.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Stats_functions_and_top()
    {
        var stats = TsqlTranslator.Compile(
            SplParser.Parse("sourcetype=pan:traffic | stats count, dc(user) as users, sum(bytes) as total, avg(bytes), min(bytes), max(bytes), values(app) by app"),
            From, To, 500);
        Assert.Contains("COUNT(DISTINCT", stats.Sql, StringComparison.Ordinal);
        Assert.Contains("SUM(TRY_CONVERT(bigint,", stats.Sql, StringComparison.Ordinal);
        Assert.Contains("AVG(TRY_CONVERT(float,", stats.Sql, StringComparison.Ordinal);
        Assert.Contains("STRING_AGG", stats.Sql, StringComparison.Ordinal);
        Assert.Contains("[users]", stats.Sql, StringComparison.Ordinal);

        var rare = TsqlTranslator.Compile(SplParser.Parse("sourcetype=cisco:ios | rare 5 mnemonic"), From, To, 500);
        Assert.Contains("TOP (5)", rare.Sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY [count] ASC", rare.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Relative_time_and_cron_and_condition()
    {
        var now = new DateTime(2026, 11, 27, 15, 40, 33, DateTimeKind.Utc);
        Assert.Equal(now.AddHours(-24), RelativeTime.Resolve("-24h", now));
        Assert.Equal(new DateTime(2026, 11, 27, 0, 0, 0, DateTimeKind.Utc), RelativeTime.Resolve("-0d@d", now));
        Assert.Equal(new DateTime(2026, 11, 27, 15, 0, 0, DateTimeKind.Utc), RelativeTime.Resolve("now@h", now));
        Assert.Equal(300, RelativeTime.ParseSpan("5m"));

        Assert.True(AlertRules.Matches("*/5 * * * *", new DateTime(2026, 11, 27, 15, 40, 0, DateTimeKind.Utc)));
        Assert.False(AlertRules.Matches("*/5 * * * *", new DateTime(2026, 11, 27, 15, 41, 0, DateTimeKind.Utc)));
        Assert.True(AlertRules.IsDue("*/5 * * * *", new DateTime(2026, 11, 27, 15, 35, 0, DateTimeKind.Utc), new DateTime(2026, 11, 27, 15, 40, 10, DateTimeKind.Utc)));

        var rows = new List<IReadOnlyDictionary<string, object?>>
        {
            new Dictionary<string, object?> { ["count"] = 4L },
            new Dictionary<string, object?> { ["count"] = 6L },
        };
        Assert.True(AlertRules.ConditionMet("count > 9", 2, rows));
        Assert.False(AlertRules.ConditionMet("count > 10", 2, rows));
        Assert.True(AlertRules.ConditionMet("results >= 1", 2, rows));
    }

    [Fact]
    public void Rejects_bad_field_names()
    {
        Assert.Throws<QueryException>(() => SplParser.Parse("src-ip=1 | stats count"));
    }
}
