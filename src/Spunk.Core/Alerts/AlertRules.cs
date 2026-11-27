using System.Globalization;

namespace Spunk.Core.Alerts;

public static class AlertRules
{
    public static bool IsDue(string cron, DateTime? lastRunUtc, DateTime nowUtc)
    {
        nowUtc = new DateTime(nowUtc.Year, nowUtc.Month, nowUtc.Day, nowUtc.Hour, nowUtc.Minute, 0, DateTimeKind.Utc);
        if (lastRunUtc == null)
        {
            return true;
        }

        var cursor = new DateTime(lastRunUtc.Value.Year, lastRunUtc.Value.Month, lastRunUtc.Value.Day, lastRunUtc.Value.Hour, lastRunUtc.Value.Minute, 0, DateTimeKind.Utc);
        if (nowUtc <= cursor)
        {
            return false;
        }

        if (nowUtc - cursor > TimeSpan.FromDays(2))
        {
            cursor = nowUtc.AddDays(-2);
        }

        for (var minute = cursor.AddMinutes(1); minute <= nowUtc; minute = minute.AddMinutes(1))
        {
            if (Matches(cron, minute))
            {
                return true;
            }
        }

        return false;
    }

    public static bool Matches(string cron, DateTime utc)
    {
        var parts = cron.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 5)
        {
            throw new ArgumentException($"Cron '{cron}' must have 5 fields.");
        }

        return Field(parts[0], utc.Minute)
               && Field(parts[1], utc.Hour)
               && Field(parts[2], utc.Day)
               && Field(parts[3], utc.Month)
               && Field(parts[4], (int)utc.DayOfWeek);
    }

    public static bool ConditionMet(string condition, int rowCount, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        var text = condition.Trim();
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 3)
        {
            throw new ArgumentException($"Condition '{condition}' must look like 'count > 0' or 'results >= 1'.");
        }

        var metric = parts[0].ToLowerInvariant();
        var op = parts[1];
        if (!double.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var threshold))
        {
            throw new ArgumentException($"Condition threshold '{parts[2]}' is not a number.");
        }

        double actual = metric switch
        {
            "results" or "rows" => rowCount,
            "count" => SumColumn(rows, "count") ?? rowCount,
            _ => SumColumn(rows, metric) ?? throw new ArgumentException($"Unknown condition metric '{parts[0]}'."),
        };

        return op switch
        {
            ">" => actual > threshold,
            ">=" => actual >= threshold,
            "<" => actual < threshold,
            "<=" => actual <= threshold,
            "=" or "==" => Math.Abs(actual - threshold) < 0.0000001,
            "!=" => Math.Abs(actual - threshold) >= 0.0000001,
            _ => throw new ArgumentException($"Unknown operator '{op}'."),
        };
    }

    private static double? SumColumn(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, string name)
    {
        double sum = 0;
        var found = false;
        foreach (var row in rows)
        {
            if (!row.TryGetValue(name, out var value) || value is null)
            {
                continue;
            }

            if (value is IConvertible convertible)
            {
                try
                {
                    sum += convertible.ToDouble(CultureInfo.InvariantCulture);
                    found = true;
                }
                catch (FormatException)
                {
                }
                catch (InvalidCastException)
                {
                }
            }
        }

        return found ? sum : null;
    }

    private static bool Field(string expr, int value)
    {
        foreach (var part in expr.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part == "*")
            {
                return true;
            }

            if (part.StartsWith("*/", StringComparison.Ordinal))
            {
                if (int.TryParse(part.AsSpan(2), out var step) && step > 0 && value % step == 0)
                {
                    return true;
                }

                continue;
            }

            var dash = part.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(part.AsSpan(0, dash), out var lo) && int.TryParse(part.AsSpan(dash + 1), out var hi) && value >= lo && value <= hi)
                {
                    return true;
                }

                continue;
            }

            if (int.TryParse(part, out var exact) && exact == value)
            {
                return true;
            }
        }

        return false;
    }
}
