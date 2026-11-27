namespace Spunk.Core.Query;

public static class GeoIp
{
    public readonly record struct Place(string Country, string? City, string? Region, double Lat, double Lon);

    public static readonly (string Cidr, Place Place)[] Builtin =
    [
        ("8.8.8.8/32", new("United States", "Mountain View", "California", 37.386, -122.084)),
        ("8.8.4.4/32", new("United States", "Mountain View", "California", 37.386, -122.084)),
        ("1.1.1.1/32", new("Australia", "Sydney", "New South Wales", -33.868, 151.209)),
        ("93.184.216.34/32", new("United States", null, null, 0, 0)),
        ("151.101.0.0/16", new("United States", null, null, 0, 0)),
    ];

    public static Place? Locate(string? ip, IEnumerable<(string Cidr, Place Place)>? extra = null)
    {
        if (string.IsNullOrWhiteSpace(ip) || IsPrivate(ip))
        {
            return null;
        }

        if (extra != null)
        {
            foreach (var row in extra)
            {
                if (SplFields.CidrMatch(row.Cidr, ip))
                {
                    return row.Place;
                }
            }
        }

        foreach (var row in Builtin)
        {
            if (SplFields.CidrMatch(row.Cidr, ip))
            {
                return row.Place;
            }
        }

        return null;
    }

    public static List<(string Cidr, Place Place)> LoadCsv(string path)
    {
        var rows = new List<(string, Place)>();
        if (!File.Exists(path))
        {
            return rows;
        }

        foreach (var line in File.ReadLines(path).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            {
                continue;
            }

            var cells = line.Split(',');
            if (cells.Length < 2)
            {
                continue;
            }

            var cidr = cells[0].Trim();
            if (!cidr.Contains('/'))
            {
                cidr += "/32";
            }

            _ = double.TryParse(cells.ElementAtOrDefault(4), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var lat);
            _ = double.TryParse(cells.ElementAtOrDefault(5), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var lon);
            rows.Add((cidr, new Place(cells[1].Trim(), NullIfEmpty(cells.ElementAtOrDefault(2)), NullIfEmpty(cells.ElementAtOrDefault(3)), lat, lon)));
        }

        return rows;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool IsPrivate(string ip) =>
        SplFields.CidrMatch("10.0.0.0/8", ip)
        || SplFields.CidrMatch("172.16.0.0/12", ip)
        || SplFields.CidrMatch("192.168.0.0/16", ip)
        || SplFields.CidrMatch("127.0.0.0/8", ip);
}
