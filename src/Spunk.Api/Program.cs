using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Spunk.Api.Ingest;
using Spunk.Api.Workers;
using Spunk.Core.Alerts;
using Spunk.Core.Query;
using Spunk.Infrastructure.Data;
using Spunk.Infrastructure.Search;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(options => options.ServiceName = "Spunk");

var connectionString = builder.Configuration.GetConnectionString("SqlServer")
    ?? throw new InvalidOperationException("ConnectionStrings:SqlServer is required.");
var ingestOptions = builder.Configuration.GetSection("Ingest").Get<IngestOptions>() ?? new IngestOptions();
var smtpOptions = builder.Configuration.GetSection("Smtp").Get<SmtpOptions>() ?? new SmtpOptions();
var retentionOptions = builder.Configuration.GetSection("Retention").Get<RetentionOptions>() ?? new RetentionOptions();

builder.Services.AddSingleton(ingestOptions);
builder.Services.AddSingleton(smtpOptions);
builder.Services.AddSingleton(retentionOptions);
builder.Services.AddSingleton<IngestStats>();
builder.Services.AddSingleton(new EventWriter(connectionString));
builder.Services.AddSingleton(new SearchService(connectionString));
builder.Services.AddSingleton(new MetadataStore(connectionString));
builder.Services.AddHttpClient("alerts", client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddSingleton<AlertRunner>();
builder.Services.AddSingleton<IngestHost>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IngestHost>());
builder.Services.AddHostedService<MaintenanceWorker>();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
});
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("http://localhost:5173", "http://127.0.0.1:5173").AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
await MigrateWithRetry(app, connectionString);

app.UseExceptionHandler(handler => handler.Run(async context =>
{
    var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
    var code = error is QueryException or ArgumentException or FormatException ? HttpStatusCode.BadRequest : HttpStatusCode.InternalServerError;
    context.Response.StatusCode = (int)code;
    await context.Response.WriteAsJsonAsync(new { error = error?.Message ?? "Request failed." });
}));
app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/status", async (MetadataStore store, IngestStats stats, IngestOptions ingest, CancellationToken ct) =>
{
    var db = true;
    long events = 0;
    DateTime? min = null;
    DateTime? max = null;
    string? dbError = null;
    try
    {
        events = await store.CountEventsAsync(ct);
        (min, max) = await store.EventRangeAsync(ct);
    }
    catch (Exception ex)
    {
        db = false;
        dbError = ex.Message;
    }

    var retention = db ? await store.GetRetentionDaysAsync(retentionOptions.Days, ct) : retentionOptions.Days;
    return Results.Ok(new
    {
        database = db,
        databaseError = dbError,
        events,
        minTime = min,
        maxTime = max,
        retentionDays = retention,
        ingest = new
        {
            accepted = stats.Accepted,
            inserted = stats.Inserted,
            dropped = stats.Dropped,
            queued = stats.Queued,
            udpListening = stats.UdpListening,
            tcpListening = stats.TcpListening,
            udpPort = ingest.UdpPort,
            tcpPort = ingest.TcpPort,
            udpError = stats.UdpError,
            tcpError = stats.TcpError,
            hecEnabled = ingest.HecEnabled,
        },
    });
});

app.MapPut("/api/settings/retention", async (RetentionBody body, MetadataStore store, CancellationToken ct) =>
{
    var days = Math.Clamp(body.Days, 1, 3650);
    await store.SetRetentionDaysAsync(days, ct);
    return Results.Ok(new { retentionDays = days });
});

app.MapPost("/api/search", async (SearchBody body, SearchService search, IConfiguration config, CancellationToken ct) =>
{
    var limit = body.Limit ?? config.GetValue("Search:DefaultLimit", 500);
    return Results.Ok(await search.SearchAsync(body.Query ?? "", body.Earliest, body.Latest, limit, ct));
});

app.MapPost("/api/fields", async (SearchBody body, SearchService search, CancellationToken ct) =>
    Results.Ok(new { fields = await search.FieldsAsync(body.Query ?? "", body.Earliest, body.Latest, ct) }));

app.MapGet("/api/saved-searches", async (MetadataStore store, CancellationToken ct) => Results.Ok(await store.ListSearchesAsync(ct)));
app.MapPost("/api/saved-searches", async (SavedSearch body, MetadataStore store, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(body.Name) || string.IsNullOrWhiteSpace(body.Query))
    {
        return Results.BadRequest(new { error = "Name and query are required." });
    }

    SplParser.Parse(body.Query);
    return Results.Ok(await store.CreateSearchAsync(body, ct));
});
app.MapDelete("/api/saved-searches/{id:int}", async (int id, MetadataStore store, CancellationToken ct) =>
{
    await store.DeleteSearchAsync(id, ct);
    return Results.NoContent();
});

app.MapGet("/api/dashboards", async (MetadataStore store, CancellationToken ct) => Results.Ok(await store.ListDashboardsAsync(ct)));
app.MapGet("/api/dashboards/{slug}", async (string slug, MetadataStore store, CancellationToken ct) =>
{
    var dashboard = await store.GetDashboardAsync(slug, ct);
    return dashboard == null ? Results.NotFound() : Results.Ok(dashboard);
});
app.MapPost("/api/dashboards/{id:int}/panels", async (int id, PanelBody body, MetadataStore store, CancellationToken ct) =>
{
    var panelId = await store.AddPanelAsync(id, body.SavedSearchId, body.Title, body.Viz, body.ColSpan, ct);
    return Results.Ok(new { id = panelId });
});
app.MapDelete("/api/panels/{id:int}", async (int id, MetadataStore store, CancellationToken ct) =>
{
    await store.DeletePanelAsync(id, ct);
    return Results.NoContent();
});

app.MapGet("/api/alerts", async (MetadataStore store, CancellationToken ct) => Results.Ok(await store.ListAlertsAsync(ct)));
app.MapPost("/api/alerts", async (AlertRecord body, MetadataStore store, CancellationToken ct) =>
{
    ValidateAlert(body);
    return Results.Ok(await store.CreateAlertAsync(body, ct));
});
app.MapPut("/api/alerts/{id:int}", async (int id, AlertRecord body, MetadataStore store, CancellationToken ct) =>
{
    body.Id = id;
    ValidateAlert(body);
    await store.UpdateAlertAsync(body, ct);
    return Results.Ok(body);
});
app.MapDelete("/api/alerts/{id:int}", async (int id, MetadataStore store, CancellationToken ct) =>
{
    await store.DeleteAlertAsync(id, ct);
    return Results.NoContent();
});
app.MapPost("/api/alerts/{id:int}/run", async (int id, AlertRunner runner, MetadataStore store, CancellationToken ct) =>
{
    var alert = await store.GetAlertAsync(id, ct);
    if (alert == null)
    {
        return Results.NotFound();
    }

    await runner.RunAsync(alert, manual: true, ct);
    return Results.Ok(await store.HistoryAsync(id, 5, ct));
});
app.MapGet("/api/alerts/history", async (MetadataStore store, int? alertId, CancellationToken ct) =>
    Results.Ok(await store.HistoryAsync(alertId, 50, ct)));

app.MapPost("/services/collector/event", async (HttpRequest request, IngestHost ingest, IngestOptions options) =>
{
    if (!HecAuthorized(request, options))
    {
        return Results.Json(new { text = "Invalid token", code = 4 }, statusCode: StatusCodes.Status401Unauthorized);
    }

    var body = await new StreamReader(request.Body).ReadToEndAsync();
    var count = IngestJson(body, ingest);
    return Results.Json(new { text = "Success", code = 0, count });
});

app.MapPost("/services/collector/raw", async (HttpRequest request, IngestHost ingest, IngestOptions options) =>
{
    if (!HecAuthorized(request, options))
    {
        return Results.Json(new { text = "Invalid token", code = 4 }, statusCode: StatusCodes.Status401Unauthorized);
    }

    var body = await new StreamReader(request.Body).ReadToEndAsync();
    var host = request.Query["host"].ToString();
    var source = request.Query["source"].ToString();
    var sourcetype = request.Query["sourcetype"].ToString();
    var count = 0;
    foreach (var line in body.Split('\n'))
    {
        var trimmed = line.Trim('\r', ' ');
        if (trimmed.Length == 0)
        {
            continue;
        }

        if (ingest.TrySubmit(new Ingress
        {
            Raw = trimmed,
            Host = string.IsNullOrWhiteSpace(host) ? null : host,
            SourceIp = string.IsNullOrWhiteSpace(source) ? null : source,
            Sourcetype = string.IsNullOrWhiteSpace(sourcetype) ? null : sourcetype,
        }))
        {
            count++;
        }
    }

    return Results.Json(new { text = "Success", code = 0, count });
});

app.MapPost("/api/ingest", async (HttpRequest request, IngestHost ingest, IngestOptions options) =>
{
    if (!HecAuthorized(request, options))
    {
        return Results.Unauthorized();
    }

    var body = await new StreamReader(request.Body).ReadToEndAsync();
    var count = body.TrimStart().StartsWith('{') || body.TrimStart().StartsWith('[')
        ? IngestJson(body, ingest)
        : 0;
    if (count == 0 && body.Contains('\n', StringComparison.Ordinal))
    {
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0 && ingest.TrySubmit(new Ingress { Raw = trimmed }))
            {
                count++;
            }
        }
    }

    return Results.Ok(new { count });
});

app.MapFallbackToFile("index.html");
app.Run();

static async Task MigrateWithRetry(WebApplication app, string connectionString)
{
    for (var attempt = 1; attempt <= 30; attempt++)
    {
        try
        {
            await Database.MigrateAsync(connectionString);
            app.Logger.LogInformation("SQL Server schema is ready");
            return;
        }
        catch (Exception ex) when (attempt < 30)
        {
            app.Logger.LogWarning(ex, "SQL Server is not ready (attempt {Attempt})", attempt);
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }
}

static void ValidateAlert(AlertRecord alert)
{
    if (string.IsNullOrWhiteSpace(alert.Name) || string.IsNullOrWhiteSpace(alert.Query))
    {
        throw new ArgumentException("Alert name and query are required.");
    }

    SplParser.Parse(alert.Query);
    AlertRules.Matches(alert.Cron, DateTime.UtcNow);
    AlertRules.ConditionMet(alert.Condition, 0, []);
}

static bool HecAuthorized(HttpRequest request, IngestOptions options)
{
    if (!options.HecEnabled || string.IsNullOrEmpty(options.HecToken))
    {
        return false;
    }

    string? presented = null;
    if (request.Headers.TryGetValue("Authorization", out var header))
    {
        var value = header.ToString();
        const string splunk = "Splunk ";
        const string bearer = "Bearer ";
        if (value.StartsWith(splunk, StringComparison.OrdinalIgnoreCase))
        {
            presented = value[splunk.Length..].Trim();
        }
        else if (value.StartsWith(bearer, StringComparison.OrdinalIgnoreCase))
        {
            presented = value[bearer.Length..].Trim();
        }
    }

    if (presented == null && request.Headers.TryGetValue("X-Spunk-Token", out var token))
    {
        presented = token.ToString();
    }

    if (presented == null)
    {
        return false;
    }

    var a = Encoding.UTF8.GetBytes(presented);
    var b = Encoding.UTF8.GetBytes(options.HecToken);
    return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

static int IngestJson(string body, IngestHost ingest)
{
    if (string.IsNullOrWhiteSpace(body))
    {
        return 0;
    }

    var count = 0;
    var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(body));
    while (JsonDocument.TryParseValue(ref reader, out var document))
    {
        using (document)
        {
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in document.RootElement.EnumerateArray())
                {
                    if (SubmitElement(item, ingest))
                    {
                        count++;
                    }
                }
            }
            else if (SubmitElement(document.RootElement, ingest))
            {
                count++;
            }
        }
    }

    return count;
}

static bool SubmitElement(JsonElement element, IngestHost ingest)
{
    if (element.ValueKind == JsonValueKind.String)
    {
        var line = element.GetString();
        return !string.IsNullOrWhiteSpace(line) && ingest.TrySubmit(new Ingress { Raw = line });
    }

    if (element.ValueKind != JsonValueKind.Object)
    {
        return false;
    }

    if (element.TryGetProperty("lines", out var lines) && lines.ValueKind == JsonValueKind.Array)
    {
        var any = false;
        foreach (var line in lines.EnumerateArray())
        {
            any |= SubmitElement(line, ingest);
        }

        return any;
    }

    if (!element.TryGetProperty("event", out var rawElement))
    {
        return false;
    }

    var raw = rawElement.ValueKind == JsonValueKind.String ? rawElement.GetString() ?? "" : rawElement.GetRawText();
    DateTime? time = null;
    if (element.TryGetProperty("time", out var timeElement))
    {
        if (timeElement.ValueKind == JsonValueKind.Number && timeElement.TryGetDouble(out var number))
        {
            var ms = number > 10_000_000_000 ? (long)number : (long)(number * 1000);
            time = DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime;
        }
        else if (timeElement.ValueKind == JsonValueKind.String && DateTime.TryParse(timeElement.GetString(), out var parsed))
        {
            time = DateTime.SpecifyKind(parsed.ToUniversalTime(), DateTimeKind.Utc);
        }
    }

    return ingest.TrySubmit(new Ingress
    {
        Raw = raw,
        Time = time,
        Host = StringProp(element, "host"),
        SourceIp = StringProp(element, "source"),
        Sourcetype = StringProp(element, "sourcetype"),
    });
}

static string? StringProp(JsonElement element, string name) =>
    element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

internal sealed class SearchBody
{
    public string? Query { get; set; }
    public string? Earliest { get; set; }
    public string? Latest { get; set; }
    public int? Limit { get; set; }
}

internal sealed class RetentionBody
{
    public int Days { get; set; }
}

internal sealed class PanelBody
{
    public int SavedSearchId { get; set; }
    public string Title { get; set; } = "Panel";
    public string Viz { get; set; } = "table";
    public int ColSpan { get; set; } = 6;
}
