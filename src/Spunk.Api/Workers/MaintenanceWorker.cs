using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using Spunk.Core.Alerts;
using Spunk.Infrastructure.Data;
using Spunk.Infrastructure.Search;

namespace Spunk.Api.Workers;

public sealed class SmtpOptions
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? User { get; set; }
    public string? Password { get; set; }
    public string? From { get; set; }
    public bool EnableSsl { get; set; } = true;
}

public sealed class RetentionOptions
{
    public int Days { get; set; } = 90;
    public int IntervalMinutes { get; set; } = 30;
}

public sealed class AlertRunner
{
    private readonly SearchService _search;
    private readonly MetadataStore _store;
    private readonly SmtpOptions _smtp;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<AlertRunner> _log;

    public AlertRunner(SearchService search, MetadataStore store, SmtpOptions smtp, IHttpClientFactory http, ILogger<AlertRunner> log)
    {
        _search = search;
        _store = store;
        _smtp = smtp;
        _http = http;
        _log = log;
    }

    public async Task RunAsync(AlertRecord alert, bool manual, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        try
        {
            var result = await _search.SearchAsync(alert.Query, alert.Earliest, "now", 200, ct);
            var rows = result.Rows.Cast<IReadOnlyDictionary<string, object?>>().ToList();
            var matched = AlertRules.ConditionMet(alert.Condition, result.Rows.Count, rows);
            var suppressed = matched && !manual && alert.LastFiredUtc != null
                && now - alert.LastFiredUtc.Value < TimeSpan.FromMinutes(Math.Max(0, alert.SuppressMinutes));
            string? detail = null;
            var success = true;
            if (matched && !suppressed)
            {
                detail = await DispatchAsync(alert, result, ct);
                success = detail == null || !detail.StartsWith("error:", StringComparison.OrdinalIgnoreCase);
            }
            else if (suppressed)
            {
                detail = "suppressed";
            }

            var summary = $"{result.Rows.Count} rows, total {result.Total?.ToString() ?? "?"}, condition {(matched ? "met" : "not met")}";
            await _store.AddHistoryAsync(alert.Id, matched && !suppressed, result.Rows.Count, summary, success, detail, ct);
            await _store.TouchAlertAsync(alert.Id, now, matched && !suppressed && success, ct);
            _log.LogInformation("Alert {Name} {Outcome}", alert.Name, summary);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Alert {Name} failed", alert.Name);
            await _store.AddHistoryAsync(alert.Id, false, 0, "failed", false, ex.Message, ct);
            await _store.TouchAlertAsync(alert.Id, now, false, ct);
        }
    }

    private async Task<string?> DispatchAsync(AlertRecord alert, SearchResponse result, CancellationToken ct)
    {
        var action = alert.Action.Trim().ToLowerInvariant();
        if (action is "log" or "")
        {
            return "logged";
        }

        if (action == "webhook")
        {
            if (string.IsNullOrWhiteSpace(alert.WebhookUrl))
            {
                return "error: webhook URL is empty";
            }

            var payload = JsonSerializer.Serialize(new
            {
                alert = alert.Name,
                firedAt = DateTime.UtcNow,
                query = alert.Query,
                condition = alert.Condition,
                rowCount = result.Rows.Count,
                rows = result.Rows.Take(20),
            });
            var client = _http.CreateClient("alerts");
            using var response = await client.PostAsync(alert.WebhookUrl, new StringContent(payload, Encoding.UTF8, "application/json"), ct);
            return response.IsSuccessStatusCode ? $"webhook {(int)response.StatusCode}" : $"error: webhook {(int)response.StatusCode}";
        }

        if (action == "email")
        {
            if (string.IsNullOrWhiteSpace(_smtp.Host) || string.IsNullOrWhiteSpace(_smtp.From) || string.IsNullOrWhiteSpace(alert.EmailTo))
            {
                return "error: SMTP host, from address, and alert recipient are required";
            }

            using var message = new MailMessage(_smtp.From, alert.EmailTo)
            {
                Subject = $"[Spunk] {alert.Name}",
                Body = $"Alert: {alert.Name}\nCondition: {alert.Condition}\nQuery: {alert.Query}\nRows: {result.Rows.Count}\n",
            };
            using var client = new SmtpClient(_smtp.Host, _smtp.Port) { EnableSsl = _smtp.EnableSsl };
            if (!string.IsNullOrWhiteSpace(_smtp.User))
            {
                client.Credentials = new NetworkCredential(_smtp.User, _smtp.Password);
            }

            await client.SendMailAsync(message, ct);
            return "email sent";
        }

        return "error: unknown action " + alert.Action;
    }
}

public sealed class MaintenanceWorker : BackgroundService
{
    private readonly MetadataStore _store;
    private readonly AlertRunner _runner;
    private readonly RetentionOptions _retention;
    private readonly ILogger<MaintenanceWorker> _log;

    public MaintenanceWorker(MetadataStore store, AlertRunner runner, RetentionOptions retention, ILogger<MaintenanceWorker> log)
    {
        _store = store;
        _runner = runner;
        _retention = retention;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nextPurge = DateTime.UtcNow;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var alerts = await _store.ListAlertsAsync(stoppingToken);
                var now = DateTime.UtcNow;
                foreach (var alert in alerts.Where(a => a.Enabled))
                {
                    if (!AlertRules.IsDue(alert.Cron, alert.LastRunUtc, now))
                    {
                        continue;
                    }

                    await _runner.RunAsync(alert, manual: false, stoppingToken);
                }
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _log.LogError(ex, "Alert sweep failed");
            }

            if (DateTime.UtcNow >= nextPurge)
            {
                try
                {
                    var days = await _store.GetRetentionDaysAsync(_retention.Days, stoppingToken);
                    var removed = await _store.PurgeBeforeAsync(DateTime.UtcNow.AddDays(-Math.Max(1, days)), stoppingToken);
                    if (removed > 0)
                    {
                        _log.LogInformation("Retention removed {Count} events older than {Days} days", removed, days);
                    }

                    await _store.EnsureFuturePartitionAsync(stoppingToken);
                }
                catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
                {
                    _log.LogError(ex, "Retention cleanup failed");
                }

                nextPurge = DateTime.UtcNow.AddMinutes(Math.Max(5, _retention.IntervalMinutes));
            }

            await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);
        }
    }
}
