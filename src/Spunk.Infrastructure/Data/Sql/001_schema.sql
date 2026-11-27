IF OBJECT_ID(N'dbo.SchemaMigrations', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SchemaMigrations
    (
        Name nvarchar(200) NOT NULL CONSTRAINT PK_SchemaMigrations PRIMARY KEY,
        AppliedUtc datetime2(3) NOT NULL CONSTRAINT DF_SchemaMigrations_Applied DEFAULT SYSUTCDATETIME()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = N'pf_events')
BEGIN
    DECLARE @sql nvarchar(max) = N'CREATE PARTITION FUNCTION pf_events (datetime2(3)) AS RANGE RIGHT FOR VALUES (';
    DECLARE @d date = '20240101';
    DECLARE @first bit = 1;
    WHILE @d < '20290101'
    BEGIN
        IF @first = 0 SET @sql += N',';
        SET @first = 0;
        SET @sql += N'''' + CONVERT(char(10), @d, 23) + N'''';
        SET @d = DATEADD(month, 1, @d);
    END
    SET @sql += N')';
    EXEC sys.sp_executesql @sql;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.partition_schemes WHERE name = N'ps_events')
    CREATE PARTITION SCHEME ps_events AS PARTITION pf_events ALL TO ([PRIMARY]);
GO

IF OBJECT_ID(N'dbo.Events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Events
    (
        EventId bigint NOT NULL,
        EventTime datetime2(3) NOT NULL,
        ReceivedTime datetime2(3) NOT NULL,
        Host nvarchar(255) NULL,
        SourceIp varchar(45) NULL,
        Sourcetype nvarchar(64) NOT NULL,
        Vendor nvarchar(32) NOT NULL,
        Severity tinyint NULL,
        SeverityName nvarchar(32) NULL,
        Facility tinyint NULL,
        FacilityName nvarchar(64) NULL,
        AppName nvarchar(128) NULL,
        Mnemonic nvarchar(64) NULL,
        Message nvarchar(max) NULL,
        Raw nvarchar(max) NOT NULL,
        SrcIp varchar(45) NULL,
        DstIp varchar(45) NULL,
        SrcPort int NULL,
        DstPort int NULL,
        SrcZone nvarchar(64) NULL,
        DstZone nvarchar(64) NULL,
        Protocol nvarchar(32) NULL,
        Action nvarchar(64) NULL,
        RuleName nvarchar(256) NULL,
        Application nvarchar(128) NULL,
        UserName nvarchar(256) NULL,
        BytesTotal bigint NULL,
        BytesIn bigint NULL,
        BytesOut bigint NULL,
        Packets bigint NULL,
        ThreatName nvarchar(512) NULL,
        ThreatCategory nvarchar(128) NULL,
        Interface nvarchar(128) NULL,
        DeviceName nvarchar(255) NULL,
        SessionId nvarchar(64) NULL,
        RepeatCount int NULL,
        ExtraJson nvarchar(max) NULL
    ) ON ps_events(EventTime);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'CCI_Events' AND object_id = OBJECT_ID(N'dbo.Events'))
    CREATE CLUSTERED COLUMNSTORE INDEX CCI_Events ON dbo.Events ORDER (EventTime);
GO

IF OBJECT_ID(N'dbo.SavedSearches', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SavedSearches
    (
        Id int IDENTITY(1,1) NOT NULL CONSTRAINT PK_SavedSearches PRIMARY KEY,
        Name nvarchar(200) NOT NULL,
        SearchQuery nvarchar(max) NOT NULL,
        Earliest nvarchar(40) NOT NULL CONSTRAINT DF_Saved_Earliest DEFAULT N'-24h',
        Latest nvarchar(40) NOT NULL CONSTRAINT DF_Saved_Latest DEFAULT N'now',
        Description nvarchar(500) NULL,
        CreatedUtc datetime2(3) NOT NULL CONSTRAINT DF_Saved_Created DEFAULT SYSUTCDATETIME(),
        CONSTRAINT UQ_SavedSearches_Name UNIQUE (Name)
    );
END
GO

IF OBJECT_ID(N'dbo.Dashboards', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Dashboards
    (
        Id int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Dashboards PRIMARY KEY,
        Name nvarchar(200) NOT NULL,
        Slug nvarchar(80) NOT NULL,
        Description nvarchar(500) NULL,
        CreatedUtc datetime2(3) NOT NULL CONSTRAINT DF_Dash_Created DEFAULT SYSUTCDATETIME(),
        CONSTRAINT UQ_Dashboards_Slug UNIQUE (Slug)
    );
END
GO

IF OBJECT_ID(N'dbo.DashboardPanels', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.DashboardPanels
    (
        Id int IDENTITY(1,1) NOT NULL CONSTRAINT PK_DashboardPanels PRIMARY KEY,
        DashboardId int NOT NULL,
        SavedSearchId int NOT NULL,
        Title nvarchar(200) NOT NULL,
        Viz nvarchar(20) NOT NULL,
        ColSpan int NOT NULL CONSTRAINT DF_Panel_Span DEFAULT 6,
        SortOrder int NOT NULL CONSTRAINT DF_Panel_Sort DEFAULT 0,
        CONSTRAINT FK_Panels_Dashboard FOREIGN KEY (DashboardId) REFERENCES dbo.Dashboards(Id) ON DELETE CASCADE,
        CONSTRAINT FK_Panels_Search FOREIGN KEY (SavedSearchId) REFERENCES dbo.SavedSearches(Id)
    );
END
GO

IF OBJECT_ID(N'dbo.Alerts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Alerts
    (
        Id int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Alerts PRIMARY KEY,
        Name nvarchar(200) NOT NULL,
        SearchQuery nvarchar(max) NOT NULL,
        Earliest nvarchar(40) NOT NULL CONSTRAINT DF_Alert_Earliest DEFAULT N'-15m',
        Condition nvarchar(200) NOT NULL,
        Cron nvarchar(80) NOT NULL,
        Action nvarchar(20) NOT NULL,
        WebhookUrl nvarchar(1000) NULL,
        EmailTo nvarchar(400) NULL,
        Enabled bit NOT NULL CONSTRAINT DF_Alert_Enabled DEFAULT 1,
        SuppressMinutes int NOT NULL CONSTRAINT DF_Alert_Suppress DEFAULT 15,
        LastRunUtc datetime2(3) NULL,
        LastFiredUtc datetime2(3) NULL,
        CreatedUtc datetime2(3) NOT NULL CONSTRAINT DF_Alert_Created DEFAULT SYSUTCDATETIME()
    );
END
GO

IF OBJECT_ID(N'dbo.AlertHistory', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.AlertHistory
    (
        Id bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_AlertHistory PRIMARY KEY,
        AlertId int NOT NULL,
        FiredUtc datetime2(3) NOT NULL,
        Matched bit NOT NULL,
        [RowCount] int NOT NULL,
        Summary nvarchar(max) NULL,
        Success bit NOT NULL,
        Detail nvarchar(max) NULL
    );
    CREATE INDEX IX_AlertHistory_Alert ON dbo.AlertHistory(AlertId, FiredUtc DESC);
END
GO

IF OBJECT_ID(N'dbo.Settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Settings
    (
        [Key] nvarchar(100) NOT NULL CONSTRAINT PK_Settings PRIMARY KEY,
        [Value] nvarchar(max) NOT NULL
    );
    INSERT INTO dbo.Settings ([Key], [Value]) VALUES (N'retentionDays', N'90');
END
GO
