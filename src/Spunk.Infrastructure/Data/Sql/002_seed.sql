INSERT INTO dbo.SavedSearches (Name, SearchQuery, Earliest, Latest, Description) VALUES
(N'Denied connections', N'sourcetype=pan:traffic action=deny | stats count', N'-24h', N'now', N'How many sessions Palo Alto denied'),
(N'Denied by source', N'sourcetype=pan:traffic action=deny | stats count by src_ip | sort -count | head 10', N'-24h', N'now', N'Top sources hitting a deny rule'),
(N'Threats by severity', N'sourcetype=pan:threat | stats count by severity | sort -count', N'-24h', N'now', N'Threat log volume by severity'),
(N'Top applications', N'sourcetype=pan:traffic | stats count by app | sort -count | head 10', N'-24h', N'now', N'Most seen applications'),
(N'Traffic by action', N'sourcetype=pan:traffic | timechart span=15m count by action', N'-24h', N'now', N'Allow, deny, and drop over time'),
(N'Top talkers by bytes', N'sourcetype=pan:traffic | stats sum(bytes) as bytes, count by src_ip | sort -bytes | head 10', N'-24h', N'now', N'Sources that moved the most data'),
(N'Threat count', N'sourcetype=pan:threat | stats count', N'-24h', N'now', N'Threat events in the window'),
(N'Interface flaps', N'(mnemonic=UPDOWN OR mnemonic=IF_UP OR mnemonic=IF_DOWN_LINK_FAILURE OR mnemonic=IF_DOWN_ADMIN_DOWN) | stats count', N'-24h', N'now', N'IOS link up/down and NX-OS interface state changes'),
(N'Errors by device', N'(sourcetype=cisco:ios OR sourcetype=cisco:nxos) (severity=error OR severity=critical OR severity=alert OR severity=emergency) | stats count by host | sort -count | head 10', N'-24h', N'now', N'Devices logging error-or-worse messages'),
(N'Interface state over time', N'(sourcetype=cisco:ios OR sourcetype=cisco:nxos) (mnemonic=UPDOWN OR mnemonic=IF_UP OR mnemonic=IF_DOWN_LINK_FAILURE) | timechart span=30m count by host', N'-24h', N'now', N'Flaps per switch'),
(N'Config changes', N'(mnemonic=CONFIG_I OR mnemonic=VSHD_SYSLOG_CONFIG_I) | table _time, host, user, src_ip, message | head 25', N'-7d', N'now', N'IOS and NX-OS configuration commits'),
(N'Top Cisco mnemonics', N'(sourcetype=cisco:ios OR sourcetype=cisco:nxos) | stats count by mnemonic | sort -count | head 10', N'-24h', N'now', N'What the switches are saying most often'),
(N'Cisco events over time', N'(sourcetype=cisco:ios OR sourcetype=cisco:nxos) | timechart span=15m count by host', N'-24h', N'now', N'Syslog volume per device');
GO

DECLARE @denied int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Denied connections');
DECLARE @deniedBy int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Denied by source');
DECLARE @sev int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Threats by severity');
DECLARE @apps int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Top applications');
DECLARE @byAction int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Traffic by action');
DECLARE @talkers int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Top talkers by bytes');
DECLARE @threats int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Threat count');
DECLARE @flaps int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Interface flaps');
DECLARE @errors int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Errors by device');
DECLARE @flapTime int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Interface state over time');
DECLARE @config int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Config changes');
DECLARE @mnem int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Top Cisco mnemonics');
DECLARE @ciscoTime int = (SELECT Id FROM dbo.SavedSearches WHERE Name = N'Cisco events over time');

INSERT INTO dbo.Dashboards (Name, Slug, Description) VALUES
(N'Palo Alto', N'palo-alto', N'Traffic, denies, applications, and threats from PAN-OS firewalls'),
(N'Cisco switching', N'cisco', N'Interface flaps, errors, and configuration changes from IOS and NX-OS');

DECLARE @pa int = (SELECT Id FROM dbo.Dashboards WHERE Slug = N'palo-alto');
DECLARE @cisco int = (SELECT Id FROM dbo.Dashboards WHERE Slug = N'cisco');

INSERT INTO dbo.DashboardPanels (DashboardId, SavedSearchId, Title, Viz, ColSpan, SortOrder) VALUES
(@pa, @denied, N'Denied connections', N'single', 3, 1),
(@pa, @threats, N'Threats', N'single', 3, 2),
(@pa, @byAction, N'Traffic by action', N'line', 6, 3),
(@pa, @deniedBy, N'Top denied sources', N'bar', 6, 4),
(@pa, @apps, N'Top applications', N'bar', 6, 5),
(@pa, @sev, N'Threats by severity', N'pie', 4, 6),
(@pa, @talkers, N'Top talkers by bytes', N'table', 8, 7),
(@cisco, @flaps, N'Interface flaps', N'single', 4, 1),
(@cisco, @errors, N'Errors by device', N'bar', 8, 2),
(@cisco, @flapTime, N'Flaps over time', N'line', 12, 3),
(@cisco, @mnem, N'Top mnemonics', N'bar', 6, 4),
(@cisco, @ciscoTime, N'Events by device', N'line', 6, 5),
(@cisco, @config, N'Configuration changes', N'table', 12, 6);
GO

INSERT INTO dbo.Alerts (Name, SearchQuery, Earliest, Condition, Cron, Action, Enabled, SuppressMinutes)
VALUES (N'Critical threats', N'sourcetype=pan:threat severity=critical | stats count', N'-15m', N'count > 0', N'*/5 * * * *', N'log', 1, 15);
GO
