using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

var count = ArgInt("--count", 6000);
var hours = ArgInt("--hours", 24);
var url = Arg("--url", "http://localhost:8080");
var token = Arg("--token", "spunk-hec-token");
var batchSize = ArgInt("--batch", 300);
var seed = ArgInt("--seed", 42);
var udp = Arg("--udp", "");

var rng = new Random(seed);
var end = DateTime.UtcNow;
var start = end.AddHours(-hours);
var events = new List<(DateTime Time, string Line, string Host, string Sourcetype)>(count);

for (var i = 0; i < count; i++)
{
    var roll = rng.NextDouble();
    var time = When(rng, start, end);
    if (roll < 0.62) events.Add(Traffic(rng, time));
    else if (roll < 0.74) events.Add(Threat(rng, time));
    else if (roll < 0.80) events.Add(SystemLog(rng, time));
    else if (roll < 0.84) events.Add(Config(rng, time));
    else if (roll < 0.88) events.Add(GlobalProtect(rng, time));
    else if (roll < 0.96) events.Add(CiscoIos(rng, time));
    else events.Add(CiscoNxos(rng, time));
}

events.Sort((a, b) => a.Time.CompareTo(b.Time));
Console.WriteLine($"Generated {events.Count} events from {start:u} to {end:u}");

if (!string.IsNullOrWhiteSpace(udp))
{
    await SendUdp(udp, events);
    return;
}

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Splunk", token);
var sent = 0;
for (var i = 0; i < events.Count; i += batchSize)
{
    var slice = events.Skip(i).Take(batchSize).Select(e => new
    {
        time = new DateTimeOffset(DateTime.SpecifyKind(e.Time, DateTimeKind.Utc)).ToUnixTimeSeconds(),
        host = e.Host,
        sourcetype = e.Sourcetype,
        @event = e.Line,
    });
    var body = JsonSerializer.Serialize(slice);
    var response = await http.PostAsync(url.TrimEnd('/') + "/services/collector/event", new StringContent(body, Encoding.UTF8, "application/json"));
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
    {
        Console.Error.WriteLine($"Ingest failed ({(int)response.StatusCode}): {text}");
        Environment.Exit(1);
    }

    sent += Math.Min(batchSize, events.Count - i);
    Console.WriteLine($"queued {sent}/{events.Count}");
}

var deadline = DateTime.UtcNow.AddMinutes(3);
while (DateTime.UtcNow < deadline)
{
    try
    {
        var status = await http.GetStringAsync(url.TrimEnd('/') + "/api/status");
        using var doc = JsonDocument.Parse(status);
        var inserted = doc.RootElement.GetProperty("ingest").GetProperty("inserted").GetInt64();
        var accepted = doc.RootElement.GetProperty("ingest").GetProperty("accepted").GetInt64();
        Console.WriteLine($"stored {inserted}/{accepted}");
        if (accepted >= sent && inserted >= sent)
        {
            Console.WriteLine("Done.");
            return;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("waiting for API: " + ex.Message);
    }

    await Task.Delay(500);
}

Console.Error.WriteLine("Timed out waiting for inserts to finish.");
Environment.Exit(2);

static async Task SendUdp(string target, List<(DateTime Time, string Line, string Host, string Sourcetype)> events)
{
    var parts = target.Split(':');
    using var udp = new System.Net.Sockets.UdpClient();
    var endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(parts[0]), int.Parse(parts[1]));
    foreach (var ev in events)
    {
        var bytes = Encoding.UTF8.GetBytes(ev.Line);
        await udp.SendAsync(bytes, endpoint);
    }

    Console.WriteLine($"Sent {events.Count} UDP datagrams to {target}");
}

static (DateTime Time, string Line, string Host, string Sourcetype) Traffic(Random rng, DateTime time)
{
    var noisy = rng.NextDouble() < 0.22;
    var src = noisy ? "10.20.4.15" : Pick(rng, "10.20.4.22", "10.20.8.5", "10.20.8.9", "10.30.1.4", "10.30.1.18", "172.16.4.10", "10.30.2.40");
    var deny = src == "10.20.4.15" ? rng.NextDouble() < 0.72 : rng.NextDouble() < 0.08;
    var action = deny ? "deny" : rng.NextDouble() < 0.03 ? "drop" : "allow";
    var app = deny ? Pick(rng, "unknown", "ssh", "web-browsing", "ssl") : Pick(rng, "ssl", "web-browsing", "dns", "ms-office365", "quic", "zoom", "ssh");
    var rule = action == "allow" ? Pick(rng, "Allow-Web", "Allow-Dns", "Allow-Apps", "Allow-Internal") : "Deny-Outbound";
    var dst = app == "dns" ? "8.8.8.8" : Pick(rng, "192.168.1.50", "192.168.1.80", "172.16.8.12", "93.184.216.34", "151.101.1.67");
    var dport = app switch { "dns" => 53, "ssh" => 22, "quic" => 443, _ => rng.NextDouble() < 0.7 ? 443 : 80 };
    var proto = app == "dns" ? "udp" : "tcp";
    var bytes = action == "allow" ? rng.Next(200, 2_000_000) : rng.Next(60, 800);
    var host = rng.NextDouble() < 0.75 ? "pa-edge-1" : "pa-dc-1";
    var user = Pick(rng, @"corp\jsmith", @"corp\ajones", @"corp\mchen", "");
    var zoneIn = "trust";
    var zoneOut = rule == "Allow-Internal" ? "dmz" : "untrust";
    var fields = new string?[56];
    var ts = Stamp(time);
    fields[0] = "1";
    fields[1] = ts;
    fields[2] = host == "pa-edge-1" ? "012345000001" : "012345000002";
    fields[3] = "TRAFFIC";
    fields[4] = action == "allow" ? "end" : action;
    fields[5] = "2305";
    fields[6] = ts;
    fields[7] = src;
    fields[8] = dst;
    fields[9] = src;
    fields[10] = dst;
    fields[11] = rule;
    fields[12] = user;
    fields[14] = app;
    fields[15] = "vsys1";
    fields[16] = zoneIn;
    fields[17] = zoneOut;
    fields[18] = "ethernet1/2";
    fields[19] = "ethernet1/1";
    fields[20] = "To-Spunk";
    fields[21] = ts;
    fields[22] = rng.Next(10000, 99999).ToString(CultureInfo.InvariantCulture);
    fields[23] = "1";
    fields[24] = rng.Next(12000, 64000).ToString(CultureInfo.InvariantCulture);
    fields[25] = dport.ToString(CultureInfo.InvariantCulture);
    fields[26] = "0";
    fields[27] = "0";
    fields[28] = "0x400000";
    fields[29] = proto;
    fields[30] = action;
    fields[31] = bytes.ToString(CultureInfo.InvariantCulture);
    fields[32] = (bytes * 2 / 3).ToString(CultureInfo.InvariantCulture);
    fields[33] = (bytes / 3).ToString(CultureInfo.InvariantCulture);
    fields[34] = "4";
    fields[35] = ts;
    fields[36] = "2";
    fields[37] = "any";
    fields[39] = "1000";
    fields[40] = "0x0";
    fields[41] = "10.0.0.0-10.255.255.255";
    fields[42] = "United States";
    fields[44] = "2";
    fields[45] = "2";
    fields[46] = action == "allow" ? "tcp-fin" : "policy-deny";
    fields[52] = host;
    fields[53] = "from-policy";
    return (time, Syslog(time, host, Csv(fields)), host, "pan:traffic");
}

static (DateTime Time, string Line, string Host, string Sourcetype) Threat(Random rng, DateTime time)
{
    (string Name, string Severity, string Subtype, string Action)[] threats =
    [
        ("HTTP SQL Injection Attempt(40030)", "high", "vulnerability", "alert"),
        ("Virus/Win32.WGeneric(123456)", "critical", "virus", "drop"),
        ("Scan: TCP Port Scan(8001)", "medium", "scan", "alert"),
        ("Microsoft Windows RPC Vulnerability(30105)", "critical", "vulnerability", "reset-both"),
        ("Phishing URL(12300)", "medium", "url", "block-url"),
        ("WildFire Malware(52000)", "high", "wildfire", "drop"),
        ("Info: Benign File(60001)", "informational", "file", "alert"),
        ("Spyware.PhoneHome(14000)", "low", "spyware", "alert"),
    ];
    var threat = threats[rng.Next(threats.Length)];
    var src = Pick(rng, "10.20.4.15", "10.20.8.5", "10.30.1.18", "172.16.4.10");
    var host = rng.NextDouble() < 0.8 ? "pa-edge-1" : "pa-dc-1";
    var fields = new string?[40];
    var ts = Stamp(time);
    fields[0] = "1";
    fields[1] = ts;
    fields[2] = "012345000001";
    fields[3] = "THREAT";
    fields[4] = threat.Subtype;
    fields[5] = "2561";
    fields[6] = ts;
    fields[7] = src;
    fields[8] = Pick(rng, "93.184.216.34", "198.51.100.40", "203.0.113.10");
    fields[9] = "0.0.0.0";
    fields[10] = "0.0.0.0";
    fields[11] = "Allow-Web";
    fields[12] = Pick(rng, @"corp\ajones", @"corp\jsmith", @"corp\mchen");
    fields[14] = "web-browsing";
    fields[15] = "vsys1";
    fields[16] = "trust";
    fields[17] = "untrust";
    fields[18] = "ethernet1/2";
    fields[19] = "ethernet1/1";
    fields[20] = "Log-Forward";
    fields[22] = rng.Next(10000, 99999).ToString(CultureInfo.InvariantCulture);
    fields[23] = "1";
    fields[24] = rng.Next(12000, 64000).ToString(CultureInfo.InvariantCulture);
    fields[25] = "80";
    fields[29] = "tcp";
    fields[30] = threat.Action;
    fields[31] = "http://evil.example/payload";
    fields[32] = threat.Name;
    fields[33] = "web-browsing";
    fields[34] = threat.Severity;
    fields[35] = "client-to-server";
    return (time, Syslog(time, host, Csv(fields), 13), host, "pan:threat");
}

static (DateTime Time, string Line, string Host, string Sourcetype) SystemLog(Random rng, DateTime time)
{
    var host = Pick(rng, "pa-edge-1", "pa-dc-1");
    var admin = Pick(rng, "admin", "soc-ops");
    var ip = Pick(rng, "10.0.0.20", "10.0.0.21");
    var desc = rng.NextDouble() < 0.5
        ? $"User {admin} logged in via Web from {ip} using https"
        : $"Failed password for {admin} from {ip}";
    var fields = new string?[24];
    var ts = Stamp(time);
    fields[0] = "1";
    fields[1] = ts;
    fields[2] = "012345000001";
    fields[3] = "SYSTEM";
    fields[4] = "auth";
    fields[6] = ts;
    fields[8] = desc.StartsWith("Failed", StringComparison.Ordinal) ? "auth-fail" : "auth-success";
    fields[12] = "general";
    fields[13] = desc.StartsWith("Failed", StringComparison.Ordinal) ? "medium" : "informational";
    fields[14] = desc;
    fields[15] = "445566";
    fields[22] = host;
    return (time, Syslog(time, host, Csv(fields)), host, "pan:system");
}

static (DateTime Time, string Line, string Host, string Sourcetype) Config(Random rng, DateTime time)
{
    var host = Pick(rng, "pa-edge-1", "pa-dc-1");
    var admin = Pick(rng, "admin", "netops");
    var fields = new string?[25];
    var ts = Stamp(time);
    fields[0] = "1";
    fields[1] = ts;
    fields[2] = "012345000001";
    fields[3] = "CONFIG";
    fields[4] = "0";
    fields[6] = ts;
    fields[7] = "10.0.0.5";
    fields[8] = "vsys1";
    fields[9] = Pick(rng, "set", "commit", "edit");
    fields[10] = admin;
    fields[11] = "Web";
    fields[12] = "Submitted";
    fields[13] = "rulebase/security/rules/Deny-Outbound";
    fields[22] = "vsys1";
    fields[23] = host;
    return (time, Syslog(time, host, Csv(fields)), host, "pan:config");
}

static (DateTime Time, string Line, string Host, string Sourcetype) GlobalProtect(Random rng, DateTime time)
{
    var user = Pick(rng, @"corp\jsmith", @"corp\ajones", @"corp\mchen");
    var ok = rng.NextDouble() < 0.85;
    var fields = new string?[36];
    var ts = Stamp(time);
    fields[0] = "1";
    fields[1] = ts;
    fields[2] = "012345000001";
    fields[3] = "GLOBALPROTECT";
    fields[4] = "globalprotect";
    fields[6] = ts;
    fields[7] = "vsys1";
    fields[8] = ok ? "gateway-auth" : "gateway-auth-fail";
    fields[9] = ok ? "login" : "login-fail";
    fields[10] = "SAML";
    fields[11] = "ipsec";
    fields[12] = user;
    fields[13] = "US";
    fields[14] = user.Split('\\')[1].ToUpperInvariant() + "-LAPTOP";
    fields[15] = $"203.0.113.{rng.Next(10, 200)}";
    fields[17] = $"10.50.{rng.Next(0, 4)}.{rng.Next(2, 250)}";
    fields[22] = Pick(rng, "Windows", "macOS");
    fields[27] = ok ? "User authenticated" : "Authentication failed";
    fields[28] = ok ? "success" : "failure";
    fields[33] = "gp.example.com";
    return (time, Syslog(time, "pa-edge-1", Csv(fields)), "pa-edge-1", "pan:globalprotect");
}

static (DateTime Time, string Line, string Host, string Sourcetype) CiscoIos(Random rng, DateTime time)
{
    var host = Pick(rng, "sw-access-1", "sw-access-2", "sw-core-1");
    var iface = $"GigabitEthernet1/0/{rng.Next(1, 24)}";
    var kind = rng.Next(8);
    var body = kind switch
    {
        0 => $"%LINK-3-UPDOWN: Interface {iface}, changed state to down",
        1 => $"%LINEPROTO-5-UPDOWN: Line protocol on Interface {iface}, changed state to up",
        2 => $"%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address {Mac(rng)} on port {iface}.",
        3 => $"%SPANTREE-2-BLOCK_PVID_PEER: Blocking {iface} on VLAN00{rng.Next(1, 40)}. Inconsistent peer vlan.",
        4 => $"%SYS-5-CONFIG_I: Configured from console by {Pick(rng, "admin", "netops")} on vty0 (10.0.0.{rng.Next(5, 20)})",
        5 => $"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: {Pick(rng, "admin", "netops")}] [Source: 10.1.1.{rng.Next(10, 80)}] [localport: 22]",
        6 => $"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 10.9.9.{rng.Next(1, 40)}] [localport: 22] [Reason: Login Authentication Failed]",
        _ => $"%ILPOWER-5-IEEE_DISCONNECT: Interface {iface}: PD removed",
    };
    var pri = body.Contains("-2-", StringComparison.Ordinal) ? 186 : body.Contains("-3-", StringComparison.Ordinal) ? 187 : body.Contains("-4-", StringComparison.Ordinal) ? 188 : 189;
    return (time, $"<{pri}>{SyslogTime(time)} {host} {body}", host, "cisco:ios");
}

static (DateTime Time, string Line, string Host, string Sourcetype) CiscoNxos(Random rng, DateTime time)
{
    var iface = $"Ethernet1/{rng.Next(1, 16)}";
    var kind = rng.Next(4);
    var body = kind switch
    {
        0 => $"%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface {iface} is down (Link failure)",
        1 => $"%ETHPORT-5-IF_UP: Interface {iface} is up in mode access",
        2 => $"%ETHPORT-5-IF_DOWN_ADMIN_DOWN: Interface {iface} is down (Administratively down)",
        _ => $"%VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vsh by {Pick(rng, "admin", "netops")} on vty0 (10.0.0.8)",
    };
    return (time, $"<189>{SyslogTime(time)} nx-dc-1 {body}", "nx-dc-1", "cisco:nxos");
}

static DateTime When(Random rng, DateTime start, DateTime end)
{
    var span = end - start;
    var biased = Math.Pow(rng.NextDouble(), 1.55);
    return start.AddTicks((long)((1 - biased) * span.Ticks));
}

static string Syslog(DateTime time, string host, string message, int pri = 14) =>
    $"<{pri}>{SyslogTime(time)} {host} {message}";

static string SyslogTime(DateTime time) => time.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
static string Stamp(DateTime time) => time.ToString("yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);

static string Csv(string?[] fields)
{
    var sb = new StringBuilder();
    for (var i = 0; i < fields.Length; i++)
    {
        if (i > 0) sb.Append(',');
        var value = fields[i] ?? "";
        if (value.Contains(',') || value.Contains('"'))
        {
            sb.Append('"').Append(value.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
        }
        else
        {
            sb.Append(value);
        }
    }

    return sb.ToString();
}

static string Mac(Random rng) =>
    $"{rng.Next(65536):x4}.{rng.Next(65536):x4}.{rng.Next(65536):x4}";

static string Pick(Random rng, params string[] values) => values[rng.Next(values.Length)];

static string Arg(string name, string fallback)
{
    var args = Environment.GetCommandLineArgs();
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
}

static int ArgInt(string name, int fallback) => int.TryParse(Arg(name, ""), out var value) ? value : fallback;
