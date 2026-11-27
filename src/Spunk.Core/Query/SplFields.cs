using System.Globalization;
using System.Net;

namespace Spunk.Core.Query;

public static class SplFields
{
    public const string CimActionSql =
        "CASE WHEN LOWER(ISNULL(Action, N'')) IN (N'allow', N'alert', N'success', N'up', N'accept', N'pass', N'permitted') THEN N'allowed' " +
        "WHEN LOWER(ISNULL(Action, N'')) IN (N'deny', N'drop', N'block', N'block-url', N'block-ip', N'reset-both', N'reset-client', N'reset-server', N'failure', N'violation', N'down', N'reject') THEN N'blocked' " +
        "WHEN Action IS NULL THEN NULL ELSE LOWER(Action) END";

    public static string? CimAction(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor))
        {
            return null;
        }

        return vendor.ToLowerInvariant() switch
        {
            "allow" or "alert" or "success" or "up" or "accept" or "pass" or "permitted" => "allowed",
            "deny" or "drop" or "block" or "block-url" or "block-ip" or "reset-both" or "reset-client" or "reset-server" or "failure" or "violation" or "down" or "reject" => "blocked",
            _ => vendor.ToLowerInvariant(),
        };
    }

    public static bool ActionEquals(string? vendor, string expected)
    {
        if (vendor != null && vendor.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var cim = CimAction(vendor);
        return cim != null && cim.Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    public static string CanonSeverity(string value) => value.ToLowerInvariant() switch
    {
        "notice" or "notification" => "notice",
        "info" or "informational" => "info",
        "debug" or "debugging" => "debug",
        _ => value.ToLowerInvariant(),
    };

    public static string[] SeverityWords(string value) => CanonSeverity(value) switch
    {
        "notice" => ["notice", "notification"],
        "info" => ["info", "informational"],
        "debug" => ["debug", "debugging"],
        _ => [value],
    };

    public static bool SeverityEquals(string? name, int? id, string expected)
    {
        if (int.TryParse(expected, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
        {
            if (id == number)
            {
                return true;
            }
        }

        return name != null && CanonSeverity(name) == CanonSeverity(expected);
    }

    public static bool SeverityCompare(string? name, int? id, string op, string expected)
    {
        if (op is "=" or "!=")
        {
            var equal = SeverityEquals(name, id, expected);
            return op == "=" ? equal : !equal;
        }

        if (!int.TryParse(expected, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) || id == null)
        {
            return false;
        }

        return op switch
        {
            "<" => id < number,
            ">" => id > number,
            "<=" => id <= number,
            ">=" => id >= number,
            _ => false,
        };
    }

    public static bool CidrMatch(string cidr, string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var bits) || bits is < 0 or > 32)
        {
            return false;
        }

        var ipBytes = address.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(ipBytes);
            Array.Reverse(netBytes);
        }

        var ipValue = BitConverter.ToUInt32(ipBytes, 0);
        var netValue = BitConverter.ToUInt32(netBytes, 0);
        var mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
        return (ipValue & mask) == (netValue & mask);
    }
}
