IF OBJECT_ID(N'dbo.Lookups', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Lookups
    (
        Name nvarchar(128) NOT NULL CONSTRAINT PK_Lookups PRIMARY KEY,
        Csv nvarchar(max) NOT NULL,
        UpdatedUtc datetime2(3) NOT NULL CONSTRAINT DF_Lookups_Updated DEFAULT SYSUTCDATETIME()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM dbo.Lookups WHERE Name = N'app_categories')
INSERT INTO dbo.Lookups (Name, Csv) VALUES (N'app_categories', N'app,category
ssh,remote-access
ssl,encrypted
web-browsing,web
dns,infrastructure
quic,web
ms-office365,business
zoom,collaboration
unknown,uncategorized');
GO

IF NOT EXISTS (SELECT 1 FROM dbo.SavedSearches WHERE Name = N'Blocked by destination')
INSERT INTO dbo.SavedSearches (Name, SearchQuery, Earliest, Latest, Description)
VALUES (N'Blocked by destination', N'sourcetype=pan:traffic action=blocked | stats count by dest | sort -count | head 10', N'-24h', N'now', N'CIM action=blocked, grouped by the Splunk dest field');
GO

IF NOT EXISTS (SELECT 1 FROM dbo.DashboardPanels WHERE Title = N'Blocked destinations')
INSERT INTO dbo.DashboardPanels (DashboardId, SavedSearchId, Title, Viz, ColSpan, SortOrder)
SELECT d.Id, s.Id, N'Blocked destinations', N'bar', 6, 8
FROM dbo.Dashboards d
JOIN dbo.SavedSearches s ON s.Name = N'Blocked by destination'
WHERE d.Slug = N'palo-alto';
GO
