using System.Text.RegularExpressions;
using Spunk.Core.Models;

namespace Spunk.Core.Parsing;

public static partial class CiscoParser
{
    private static readonly HashSet<string> NxosFacilities = new(StringComparer.OrdinalIgnoreCase)
    {
        "ETHPORT", "ETH_PORT_CHANNEL", "ETHPM", "VSHD", "SYSMGR", "MODULE", "PFMA", "VLAN_MGR",
        "LIBIFMGR", "IFTMC", "ELTMC", "L3VM", "IPQOSMGR", "VPC", "FEX", "PIXM", "ACLQOS",
        "PORT-CHANNEL", "PORT_CHANNEL", "RPM", "IM", "BOOTVAR", "CARDCLIENT", "PLTFM_CONFIG",
        "KERNEL", "USER", "DAEMON",
    };

    public static bool TryApply(string body, LogEvent ev)
    {
        var match = MnemonicRegex().Match(body);
        if (!match.Success)
        {
            return false;
        }

        var facility = match.Groups["fac"].Value;
        var mnemonic = match.Groups["mnem"].Value;
        var message = match.Groups["msg"].Value.Trim();
        var sevDigit = int.Parse(match.Groups["sev"].Value);

        ev.Vendor = "cisco";
        ev.FacilityName = facility;
        ev.Mnemonic = mnemonic;
        ev.Severity = (byte)sevDigit;
        ev.SeverityName = SyslogParser.SeverityWord(sevDigit);
        ev.Message = message;
        ev.Sourcetype = NxosFacilities.Contains(facility) || LooksLikeNxos(facility, message)
            ? "cisco:nxos"
            : "cisco:ios";

        var iface = InterfaceRegex().Match(message);
        if (iface.Success)
        {
            ev.Interface = iface.Groups[1].Value.Replace(" ", "", StringComparison.Ordinal);
            ev.Extra["interface"] = ev.Interface;
        }

        var state = StateRegex().Match(message);
        if (state.Success)
        {
            ev.Action = state.Groups[1].Value.ToLowerInvariant();
            ev.Extra["state"] = ev.Action;
        }

        var mac = MacRegex().Match(message);
        if (mac.Success)
        {
            ev.Extra["mac"] = mac.Groups[1].Value.ToLowerInvariant();
        }

        var vlan = VlanRegex().Match(message);
        if (vlan.Success)
        {
            ev.Extra["vlan"] = vlan.Groups[1].Value.TrimStart('0') is { Length: > 0 } trimmed ? trimmed : "0";
        }

        var user = UserRegex().Match(message);
        if (user.Success && FirstGroup(user) is { } userName)
        {
            ev.UserName = userName;
        }

        var src = SourceIpRegex().Match(message);
        if (src.Success && FirstGroup(src) is { } srcIp)
        {
            ev.SrcIp = srcIp;
        }
        else
        {
            var any = IpRegex().Match(message);
            if (any.Success && (ev.UserName != null || mnemonic.Contains("LOGIN", StringComparison.OrdinalIgnoreCase) || mnemonic.Contains("CONFIG", StringComparison.OrdinalIgnoreCase)))
            {
                ev.SrcIp = any.Groups[1].Value;
            }
        }

        ev.Action ??= mnemonic.ToUpperInvariant() switch
        {
            "LOGIN_SUCCESS" => "success",
            "LOGIN_FAILED" or "FAIL" or "AUTH_FAILED" => "failure",
            "PSECURE_VIOLATION" => "violation",
            "CONFIG_I" or "VSHD_SYSLOG_CONFIG_I" => "config",
            _ when mnemonic.Contains("FAIL", StringComparison.OrdinalIgnoreCase) => "failure",
            _ when mnemonic.Contains("UP", StringComparison.OrdinalIgnoreCase) && ev.Action == null && message.Contains(" up", StringComparison.OrdinalIgnoreCase) => "up",
            _ => null,
        };

        return true;
    }

    private static string? FirstGroup(Match match)
    {
        for (var i = 1; i < match.Groups.Count; i++)
        {
            if (match.Groups[i].Success && match.Groups[i].Length > 0)
            {
                return match.Groups[i].Value;
            }
        }

        return null;
    }

    private static bool LooksLikeNxos(string facility, string message) =>
        facility.Equals("ETHPORT", StringComparison.OrdinalIgnoreCase)
        || message.Contains("vsh", StringComparison.OrdinalIgnoreCase)
        || NxInterfaceRegex().IsMatch(message);

    [GeneratedRegex(@"%(?<fac>[A-Za-z][A-Za-z0-9_]*)-(?<sev>[0-7])-(?<mnem>[A-Za-z0-9_]+)\s*:\s*(?<msg>[\s\S]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex MnemonicRegex();

    [GeneratedRegex(@"\b((?:GigabitEthernet|FastEthernet|TenGigabitEthernet|FortyGigabitEthernet|HundredGigE|TwentyFiveGigE|TwoGigabitEthernet|FiveGigabitEthernet|Port-channel|Loopback|Ethernet|Tunnel|Vlan|Gi|Fa|Te|Fo|Hu|Twe|Eth|Po|Lo|Tu|Vl)\s?\d[\d/\.]*)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InterfaceRegex();

    [GeneratedRegex(@"\bEthernet\d+/\d+\b", RegexOptions.CultureInvariant)]
    private static partial Regex NxInterfaceRegex();

    [GeneratedRegex(@"\b(?:changed state to|is)\s+(up|down)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StateRegex();

    [GeneratedRegex(@"\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\b")]
    private static partial Regex MacRegex();

    [GeneratedRegex(@"\bVLAN\s*0*(\d+)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VlanRegex();

    [GeneratedRegex(@"\[user:\s*([^\]]+)\]|\bby\s+user\s+([A-Za-z0-9._\\-]+)|\bconfigured\b[\s\S]*?\bby\s+([A-Za-z0-9._\\-]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserRegex();

    [GeneratedRegex(@"\[Source:\s*([0-9.]+)\]|\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SourceIpRegex();

    [GeneratedRegex(@"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b")]
    private static partial Regex IpRegex();
}
