using System.Globalization;
using System.Text.RegularExpressions;

namespace Spunk.Core.Query;

public static partial class RelativeTime
{
    public static DateTime Resolve(string expression, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(expression))
        {
            throw new QueryException("Empty time expression.");
        }

        nowUtc = DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc);
        var text = expression.Trim();
        if (text.StartsWith("now", StringComparison.OrdinalIgnoreCase))
        {
            var rest = text[3..];
            if (rest.Length == 0)
            {
                return nowUtc;
            }

            if (rest.StartsWith('@'))
            {
                return Snap(nowUtc, rest[1..]);
            }

            throw new QueryException($"Cannot parse time '{expression}'.");
        }

        var match = ExprRegex().Match(text);
        if (!match.Success)
        {
            if (DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var absolute))
            {
                return absolute.ToUniversalTime();
            }

            throw new QueryException($"Cannot parse time '{expression}'.");
        }

        var amount = int.Parse(match.Groups["n"].Value, CultureInfo.InvariantCulture);
        if (match.Groups["sign"].Value == "-")
        {
            amount = -amount;
        }

        var unit = match.Groups["unit"].Success ? match.Groups["unit"].Value.ToLowerInvariant() : "s";
        var when = unit switch
        {
            "s" => nowUtc.AddSeconds(amount),
            "m" => nowUtc.AddMinutes(amount),
            "h" => nowUtc.AddHours(amount),
            "d" => nowUtc.AddDays(amount),
            "w" => nowUtc.AddDays(amount * 7),
            "mon" => nowUtc.AddMonths(amount),
            "y" => nowUtc.AddYears(amount),
            _ => throw new QueryException($"Unknown time unit '{unit}'."),
        };

        var snap = match.Groups["snap"].Success ? match.Groups["snap"].Value : null;
        return Snap(when, snap);
    }

    public static int ParseSpan(string text)
    {
        var match = SpanRegex().Match(text.Trim());
        if (!match.Success)
        {
            throw new QueryException($"Invalid span '{text}'. Use a number plus s, m, h, or d.");
        }

        var n = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
        var mul = match.Groups[2].Value.ToLowerInvariant() switch
        {
            "" or "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => 1,
        };
        var seconds = n * mul;
        if (seconds <= 0 || seconds > 86400 * 31)
        {
            throw new QueryException($"Span '{text}' is out of range.");
        }

        return seconds;
    }

    public static int DefaultSpan(DateTime fromUtc, DateTime toUtc)
    {
        var range = Math.Max(1, (toUtc - fromUtc).TotalSeconds);
        var target = range / 180.0;
        int[] nice = [1, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400];
        foreach (var n in nice)
        {
            if (n >= target * 0.6)
            {
                return n;
            }
        }

        return 86400;
    }

    private static DateTime Snap(DateTime value, string? unit)
    {
        if (string.IsNullOrEmpty(unit))
        {
            return value;
        }

        return unit.ToLowerInvariant() switch
        {
            "s" => new DateTime(value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, DateTimeKind.Utc),
            "m" => new DateTime(value.Year, value.Month, value.Day, value.Hour, value.Minute, 0, DateTimeKind.Utc),
            "h" => new DateTime(value.Year, value.Month, value.Day, value.Hour, 0, 0, DateTimeKind.Utc),
            "d" => new DateTime(value.Year, value.Month, value.Day, 0, 0, 0, DateTimeKind.Utc),
            "w" => StartOfWeek(value),
            "mon" => new DateTime(value.Year, value.Month, 1, 0, 0, 0, DateTimeKind.Utc),
            "y" => new DateTime(value.Year, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            _ => throw new QueryException($"Unknown snap '{unit}'."),
        };
    }

    private static DateTime StartOfWeek(DateTime value)
    {
        var delta = ((int)value.DayOfWeek + 6) % 7;
        var day = value.Date.AddDays(-delta);
        return DateTime.SpecifyKind(day, DateTimeKind.Utc);
    }

    [GeneratedRegex(@"^(?<sign>[-+])(?<n>\d+)(?<unit>mon|s|m|h|d|w|y)?(?:@(?<snap>mon|s|m|h|d|w|y))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExprRegex();

    [GeneratedRegex(@"^(\d+)(s|m|h|d)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SpanRegex();
}
