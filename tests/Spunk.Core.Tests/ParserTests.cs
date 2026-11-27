using Spunk.Core.Parsing;

namespace Spunk.Core.Tests;

public class ParserTests
{
    private static readonly DateTime Received = new(2026, 11, 27, 18, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Rfc3164_extracts_pri_host_and_infers_year()
    {
        var header = SyslogParser.TryParse("<14>Nov 27 14:53:27 pa-edge-1 1,2026/11/27 14:53:27,TRAFFIC", Received);
        Assert.NotNull(header);
        Assert.Equal((byte)1, header!.Facility);
        Assert.Equal((byte)6, header.Severity);
        Assert.Equal("pa-edge-1", header.Host);
        Assert.Equal(new DateTime(2026, 11, 27, 14, 53, 27, DateTimeKind.Utc), header.Timestamp);
        Assert.StartsWith("1,2026/11/27", header.Message);
    }

    [Fact]
    public void Rfc5424_honors_offset()
    {
        var raw = "<134>1 2026-11-27T14:53:27.000Z sw-core-1 ios - ID47 - %SYS-5-CONFIG_I: Configured from console by admin";
        var header = SyslogParser.TryParse(raw, Received);
        Assert.NotNull(header);
        Assert.Equal("sw-core-1", header!.Host);
        Assert.Equal("ios", header.AppName);
        Assert.Equal(new DateTime(2026, 11, 27, 14, 53, 27, DateTimeKind.Utc), header.Timestamp);
        Assert.Contains("%SYS-5-CONFIG_I", header.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PanTraffic_maps_named_fields()
    {
        const string raw = "<14>Nov 27 14:53:27 pa-edge-1 1,2026/11/27 14:53:27,012345000001,TRAFFIC,end,2305,2026/11/27 14:53:27,10.20.4.15,192.168.1.50,10.20.4.15,192.168.1.50,Deny-Outbound,corp\\jsmith,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,To-Syslog,2026/11/27 14:53:27,33915,1,51002,443,0,0,0x400000,tcp,deny,94,80,14,1,2026/11/27 14:53:26,1,any,0,665538,0x0,10.0.0.0-10.255.255.255,United States,,1,1,policy-deny,12,0,0,0,,pa-edge-1,from-policy";
        var ev = LogParser.Parse(raw, Received);
        Assert.Equal("pan:traffic", ev.Sourcetype);
        Assert.Equal("paloalto", ev.Vendor);
        Assert.Equal("pa-edge-1", ev.Host);
        Assert.Equal("10.20.4.15", ev.SrcIp);
        Assert.Equal("192.168.1.50", ev.DstIp);
        Assert.Equal(51002, ev.SrcPort);
        Assert.Equal(443, ev.DstPort);
        Assert.Equal("trust", ev.SrcZone);
        Assert.Equal("untrust", ev.DstZone);
        Assert.Equal("tcp", ev.Protocol);
        Assert.Equal("deny", ev.Action);
        Assert.Equal("Deny-Outbound", ev.RuleName);
        Assert.Equal("web-browsing", ev.Application);
        Assert.Equal("corp\\jsmith", ev.UserName);
        Assert.Equal(94, ev.BytesTotal);
        Assert.Equal(80, ev.BytesOut);
        Assert.Equal(14, ev.BytesIn);
        Assert.Equal(1, ev.Packets);
        Assert.Equal("33915", ev.SessionId);
        Assert.Equal("ethernet1/2", ev.Interface);
        Assert.Equal("policy-deny", ev.Extra["session_end_reason"]);
        Assert.Equal(new DateTime(2026, 11, 27, 14, 53, 27, DateTimeKind.Utc), ev.EventTime);
    }

    [Fact]
    public void PanThreat_maps_threat_and_severity()
    {
        const string raw = "1,2026/11/27 15:01:02,012345000001,THREAT,vulnerability,2561,2026/11/27 15:01:02,10.20.8.5,93.184.216.34,0.0.0.0,0.0.0.0,Allow-Web,corp\\ajones,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Log-Forward,2026/11/27 15:01:02,88421,1,51500,80,51500,80,0x80000000,tcp,alert,\"example.com/search?q=1\",HTTP SQL Injection Attempt(40030),web-browsing,high,client-to-server,998877,0x0,10.0.0.0-10.255.255.255,United States";
        var ev = LogParser.Parse(raw, Received);
        Assert.Equal("pan:threat", ev.Sourcetype);
        Assert.Equal("10.20.8.5", ev.SrcIp);
        Assert.Equal("93.184.216.34", ev.DstIp);
        Assert.Equal("alert", ev.Action);
        Assert.Equal("HTTP SQL Injection Attempt(40030)", ev.ThreatName);
        Assert.Equal("high", ev.SeverityName);
        Assert.Equal("web-browsing", ev.ThreatCategory);
        Assert.Equal("40030", ev.Extra["threat_id"]);
        Assert.Equal("example.com/search?q=1", ev.Extra["url"]);
        Assert.Equal("client-to-server", ev.Extra["direction"]);
    }

    [Fact]
    public void PanSystem_and_config_and_globalprotect()
    {
        var system = LogParser.Parse("1,2026/11/27 15:10:00,012345000001,SYSTEM,auth,0,2026/11/27 15:10:00,,auth-success,,0,0,general,informational,\"User admin logged in via Web from 10.0.0.20 using https\",445566,0x0,0,0,0,0,,pa-edge-1", Received);
        Assert.Equal("pan:system", system.Sourcetype);
        Assert.Equal("informational", system.SeverityName);
        Assert.Equal("admin", system.UserName);
        Assert.Equal("10.0.0.20", system.SrcIp);
        Assert.Contains("logged in", system.Message, StringComparison.Ordinal);

        var config = LogParser.Parse("1,2026/11/27 16:00:00,012345000001,CONFIG,0,0,2026/11/27 16:00:00,10.0.0.5,vsys1,set,admin,Web,Submitted,rulebase/security/rules/Allow-Web,778899,0x0,\"action=allow\",\"action=deny\",0,0,0,0,vsys1,pa-edge-1", Received);
        Assert.Equal("pan:config", config.Sourcetype);
        Assert.Equal("admin", config.UserName);
        Assert.Equal("10.0.0.5", config.SrcIp);
        Assert.Equal("Submitted", config.Action);
        Assert.Equal("set", config.Extra["command"]);
        Assert.Equal("rulebase/security/rules/Allow-Web", config.Extra["path"]);

        var gp = LogParser.Parse("1,2026/11/27 17:00:00,012345000001,GLOBALPROTECT,0,0,2026/11/27 17:00:00,vsys1,gateway-auth,login,SAML,ipsec,corp\\jsmith,US,JSMITH-LAPTOP,203.0.113.10,0.0.0.0,10.50.0.15,0.0.0.0,host-123,SN123,6.2.0,Windows,11,1,Success,,User authenticated,success,US-West,3600,on-demand,0,gp.example.com,556677,0x0", Received);
        Assert.Equal("pan:globalprotect", gp.Sourcetype);
        Assert.Equal("corp\\jsmith", gp.UserName);
        Assert.Equal("10.50.0.15", gp.SrcIp);
        Assert.Equal("success", gp.Action);
        Assert.Equal("JSMITH-LAPTOP", gp.Extra["machine_name"]);
        Assert.Equal("Windows", gp.Extra["client_os"]);
        Assert.Equal("gateway-auth", gp.Extra["event_id"]);
    }

    [Fact]
    public void CiscoIos_extracts_interface_auth_and_config()
    {
        var down = LogParser.Parse("<187>Nov 27 14:22:01 sw-access-1 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down", Received);
        Assert.Equal("cisco:ios", down.Sourcetype);
        Assert.Equal("LINK", down.FacilityName);
        Assert.Equal("UPDOWN", down.Mnemonic);
        Assert.Equal("error", down.SeverityName);
        Assert.Equal("GigabitEthernet1/0/1", down.Interface);
        Assert.Equal("down", down.Action);
        Assert.Equal("sw-access-1", down.Host);

        var violation = LogParser.Parse("<188>Nov 27 14:22:10 sw-access-1 %PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0011.2233.4455 on port GigabitEthernet1/0/24.", Received);
        Assert.Equal("critical", violation.SeverityName);
        Assert.Equal("violation", violation.Action);
        Assert.Equal("0011.2233.4455", violation.Extra["mac"]);
        Assert.Equal("GigabitEthernet1/0/24", violation.Interface);
        Assert.Null(violation.UserName);

        var stp = LogParser.Parse("<187>Nov 27 14:23:00 sw-access-1 %SPANTREE-2-BLOCK_PVID_PEER: Blocking GigabitEthernet1/0/5 on VLAN0001. Inconsistent peer vlan.", Received);
        Assert.Equal("1", stp.Extra["vlan"]);
        Assert.Equal("GigabitEthernet1/0/5", stp.Interface);

        var login = LogParser.Parse("<189>Nov 27 14:26:00 sw-access-1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.50] [localport: 22]", Received);
        Assert.Equal("admin", login.UserName);
        Assert.Equal("10.1.1.50", login.SrcIp);
        Assert.Equal("success", login.Action);
        Assert.Equal("notice", login.SeverityName);

        var cfg = LogParser.Parse("<189>Nov 27 14:24:00 sw-access-1 %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)", Received);
        Assert.Equal("admin", cfg.UserName);
        Assert.Equal("10.0.0.5", cfg.SrcIp);
        Assert.Equal("config", cfg.Action);
    }

    [Fact]
    public void CiscoNxos_is_its_own_sourcetype()
    {
        var down = LogParser.Parse("<189>Nov 27 14:22:01 nx-dc-1 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down (Link failure)", Received);
        Assert.Equal("cisco:nxos", down.Sourcetype);
        Assert.Equal("IF_DOWN_LINK_FAILURE", down.Mnemonic);
        Assert.Equal("Ethernet1/1", down.Interface);
        Assert.Equal("down", down.Action);

        var cfg = LogParser.Parse("<189>Nov 27 14:40:00 nx-dc-1 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vsh by netops on vty0 (10.0.0.8)", Received);
        Assert.Equal("cisco:nxos", cfg.Sourcetype);
        Assert.Equal("netops", cfg.UserName);
        Assert.Equal("10.0.0.8", cfg.SrcIp);
        Assert.Equal("config", cfg.Action);
    }

    [Fact]
    public void Unknown_event_keeps_raw_text()
    {
        var ev = LogParser.Parse("<134>Nov 27 12:00:00 app-1 something happened without a mnemonic", Received);
        Assert.Equal("syslog", ev.Sourcetype);
        Assert.Equal("something happened without a mnemonic", ev.Message);
        Assert.Contains("something happened", ev.Raw, StringComparison.Ordinal);
        Assert.Equal("app-1", ev.Host);
    }
}
