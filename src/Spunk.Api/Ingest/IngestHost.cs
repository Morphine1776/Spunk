using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using Spunk.Core.Models;
using Spunk.Core.Parsing;
using Spunk.Infrastructure.Data;

namespace Spunk.Api.Ingest;

public sealed class IngestOptions
{
    public bool UdpEnabled { get; set; } = true;
    public bool TcpEnabled { get; set; } = true;
    public int UdpPort { get; set; } = 514;
    public int TcpPort { get; set; } = 514;
    public bool HecEnabled { get; set; } = true;
    public string HecToken { get; set; } = "spunk-hec-token";
    public int BatchSize { get; set; } = 2000;
    public int FlushMilliseconds { get; set; } = 400;
}

public sealed class Ingress
{
    public required string Raw { get; init; }
    public string? SourceIp { get; init; }
    public string? Host { get; init; }
    public string? Sourcetype { get; init; }
    public DateTime? Time { get; init; }
}

public sealed class IngestStats
{
    private long _accepted;
    private long _inserted;
    private long _dropped;
    public long Accepted => Interlocked.Read(ref _accepted);
    public long Inserted => Interlocked.Read(ref _inserted);
    public long Dropped => Interlocked.Read(ref _dropped);
    public int Queued;
    public bool UdpListening;
    public bool TcpListening;
    public string? UdpError;
    public string? TcpError;

    public void Accept() => Interlocked.Increment(ref _accepted);
    public void Insert(int n) => Interlocked.Add(ref _inserted, n);
    public void Drop(int n = 1) => Interlocked.Add(ref _dropped, n);
}

public sealed class IngestHost : BackgroundService
{
    private readonly Channel<Ingress> _channel = Channel.CreateBounded<Ingress>(new BoundedChannelOptions(200_000)
    {
        FullMode = BoundedChannelFullMode.DropWrite,
        SingleReader = true,
    });

    private readonly EventWriter _writer;
    private readonly IngestOptions _options;
    private readonly IngestStats _stats;
    private readonly ILogger<IngestHost> _log;

    public IngestHost(EventWriter writer, IngestOptions options, IngestStats stats, ILogger<IngestHost> log)
    {
        _writer = writer;
        _options = options;
        _stats = stats;
        _log = log;
    }

    public bool TrySubmit(Ingress ingress)
    {
        if (_channel.Writer.TryWrite(ingress))
        {
            _stats.Accept();
            Interlocked.Increment(ref _stats.Queued);
            return true;
        }

        _stats.Drop();
        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var udp = _options.UdpEnabled ? ListenUdp(stoppingToken) : Task.CompletedTask;
        var tcp = _options.TcpEnabled ? ListenTcp(stoppingToken) : Task.CompletedTask;
        var write = WriteLoop(stoppingToken);
        await Task.WhenAll(udp, tcp, write);
    }

    private async Task WriteLoop(CancellationToken ct)
    {
        var batch = new List<LogEvent>(_options.BatchSize);
        var reader = _channel.Reader;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var window = CancellationTokenSource.CreateLinkedTokenSource(ct);
                window.CancelAfter(Math.Max(50, _options.FlushMilliseconds));
                while (batch.Count < _options.BatchSize)
                {
                    try
                    {
                        if (!await reader.WaitToReadAsync(window.Token))
                        {
                            break;
                        }
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        break;
                    }

                    while (batch.Count < _options.BatchSize && reader.TryRead(out var item))
                    {
                        Interlocked.Decrement(ref _stats.Queued);
                        batch.Add(LogParser.Parse(item.Raw, DateTime.UtcNow, new ParseHint
                        {
                            SourceIp = item.SourceIp,
                            Host = item.Host,
                            Sourcetype = item.Sourcetype,
                            Time = item.Time,
                        }));
                    }
                }

                if (batch.Count == 0)
                {
                    continue;
                }

                await WriteWithRetry(batch, ct);
                batch.Clear();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Ingest writer failed");
                _stats.Drop(batch.Count);
                batch.Clear();
                await Task.Delay(500, ct);
            }
        }
    }

    private async Task WriteWithRetry(List<LogEvent> batch, CancellationToken ct)
    {
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                await _writer.WriteAsync(batch, ct);
                _stats.Insert(batch.Count);
                return;
            }
            catch (Exception ex) when (attempt < 3 && !ct.IsCancellationRequested)
            {
                _log.LogWarning(ex, "Bulk insert failed, retry {Attempt}", attempt);
                await Task.Delay(200 * attempt, ct);
            }
        }
    }

    private async Task ListenUdp(CancellationToken ct)
    {
        UdpClient? udp = null;
        try
        {
            udp = new UdpClient(new IPEndPoint(IPAddress.Any, _options.UdpPort));
            _stats.UdpListening = true;
            _log.LogInformation("UDP syslog listening on {Port}", _options.UdpPort);
            while (!ct.IsCancellationRequested)
            {
                var result = await udp.ReceiveAsync(ct);
                var text = Encoding.UTF8.GetString(result.Buffer);
                var source = result.RemoteEndPoint.Address.ToString();
                foreach (var line in Split(text))
                {
                    TrySubmit(new Ingress { Raw = line, SourceIp = source });
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _stats.UdpListening = false;
            _stats.UdpError = ex.Message;
            _log.LogError(ex, "UDP syslog listener on port {Port} stopped", _options.UdpPort);
        }
        finally
        {
            udp?.Dispose();
            _stats.UdpListening = false;
        }
    }

    private async Task ListenTcp(CancellationToken ct)
    {
        TcpListener? listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Any, _options.TcpPort);
            listener.Start();
            _stats.TcpListening = true;
            _log.LogInformation("TCP syslog listening on {Port}", _options.TcpPort);
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => ReadTcp(client, ct), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _stats.TcpListening = false;
            _stats.TcpError = ex.Message;
            _log.LogError(ex, "TCP syslog listener on port {Port} stopped", _options.TcpPort);
        }
        finally
        {
            listener?.Stop();
            _stats.TcpListening = false;
        }
    }

    private async Task ReadTcp(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            var source = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString();
            await using var stream = client.GetStream();
            var buffer = new byte[8192];
            var pending = new MemoryStream();
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var n = await stream.ReadAsync(buffer, ct);
                    if (n == 0)
                    {
                        break;
                    }

                    pending.Write(buffer, 0, n);
                    Drain(pending, source);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
            }
        }
    }

    private void Drain(MemoryStream pending, string? source)
    {
        var data = pending.ToArray();
        var index = 0;
        while (index < data.Length)
        {
            if (data[index] is (byte)'\r' or (byte)'\n')
            {
                index++;
                continue;
            }

            if (char.IsDigit((char)data[index]))
            {
                var space = Array.IndexOf(data, (byte)' ', index);
                if (space < 0 || space - index > 8)
                {
                    break;
                }

                if (!int.TryParse(Encoding.ASCII.GetString(data, index, space - index), out var length) || length < 0 || length > 1_000_000)
                {
                    break;
                }

                var start = space + 1;
                if (data.Length - start < length)
                {
                    break;
                }

                var line = Encoding.UTF8.GetString(data, start, length);
                if (!string.IsNullOrWhiteSpace(line))
                {
                    TrySubmit(new Ingress { Raw = line.Trim(), SourceIp = source });
                }

                index = start + length;
                continue;
            }

            var newline = Array.IndexOf(data, (byte)'\n', index);
            if (newline < 0)
            {
                break;
            }

            var text = Encoding.UTF8.GetString(data, index, newline - index).Trim('\r', ' ', '\0');
            if (text.Length > 0)
            {
                TrySubmit(new Ingress { Raw = text, SourceIp = source });
            }

            index = newline + 1;
        }

        var rest = data.Length - index;
        pending.SetLength(0);
        if (rest > 0)
        {
            pending.Write(data, index, rest);
        }
    }

    private static IEnumerable<string> Split(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim('\r', ' ', '\0');
            if (trimmed.Length > 0)
            {
                yield return trimmed;
            }
        }
    }
}
