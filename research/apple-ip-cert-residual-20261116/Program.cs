using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

record ProbeCase(string Name, string CommonName, string? DnsSan, string? IpSan, string TargetHost, bool SecureExpected);
record ProbeResult(
    string Name,
    string CommonName,
    string? DnsSan,
    string? IpSan,
    string TargetHost,
    bool SecureExpected,
    bool HandshakeAccepted,
    string? ClientExceptionType,
    string? ClientExceptionMessage,
    string? ServerExceptionType,
    string? ServerExceptionMessage,
    string CertificateSha256);

static class Program
{
    public static async Task<int> Main()
    {
        const string target = "192.0.2.1";
        ProbeCase[] cases =
        [
            new("positive_ip_san_match", "unrelated.example", null, target, target, true),
            new("negative_ip_san_mismatch", "unrelated.example", null, "192.0.2.2", target, false),
            new("positive_no_san_cn_match", target, null, null, target, true),
            new("candidate_dns_san_blocks_matching_cn", target, "attacker.example", null, target, false),
            new("candidate_numeric_dns_san_mismatch_blocks_matching_cn", target, "192.0.2.2", null, target, false),
            new("compat_numeric_dns_san_match_without_cn", "unrelated.example", target, null, target, true),
        ];

        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Apple IP Residual Probe Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using X509Certificate2 root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));

        var results = new List<ProbeResult>();
        foreach (ProbeCase probe in cases)
        {
            results.Add(await RunCaseAsync(root, probe));
        }

        string sslPath = typeof(SslStream).Assembly.Location;
        string cryptoPath = typeof(X509Certificate2).Assembly.Location;
        bool candidateAccepted = results.Where(r => r.Name.StartsWith("candidate_", StringComparison.Ordinal)).Any(r => r.HandshakeAccepted);
        bool controlsPass = results.Where(r => r.Name.StartsWith("positive_", StringComparison.Ordinal)).All(r => r.HandshakeAccepted)
            && results.Where(r => r.Name.StartsWith("negative_", StringComparison.Ordinal)).All(r => !r.HandshakeAccepted);

        var receipt = new
        {
            schema = "apple-ip-certificate-residual-probe-v1",
            runId = Guid.NewGuid(),
            utc = DateTimeOffset.UtcNow,
            framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            architecture = RuntimeInformation.OSArchitecture.ToString(),
            processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            sslAssembly = new
            {
                name = typeof(SslStream).Assembly.FullName,
                path = sslPath,
                sha256 = HashFile(sslPath),
                mvid = typeof(SslStream).Assembly.ManifestModule.ModuleVersionId,
            },
            cryptoAssembly = new
            {
                name = typeof(X509Certificate2).Assembly.FullName,
                path = cryptoPath,
                sha256 = HashFile(cryptoPath),
                mvid = typeof(X509Certificate2).Assembly.ManifestModule.ModuleVersionId,
            },
            candidateAccepted,
            controlsPass,
            terminalDecision = candidateAccepted && controlsPass ? "APPLE_IP_CERTIFICATE_NAME_RESIDUAL_REPRODUCED" : "NO_CONFIRMED_APPLE_RESIDUAL",
            results,
        };

        string json = JsonSerializer.Serialize(receipt, new JsonSerializerOptions { WriteIndented = true });
        string output = Environment.GetEnvironmentVariable("PROBE_OUTPUT") ?? "probe.json";
        await File.WriteAllTextAsync(output, json + Environment.NewLine);
        Console.WriteLine(json);
        return controlsPass ? 0 : 2;
    }

    private static async Task<ProbeResult> RunCaseAsync(X509Certificate2 root, ProbeCase probe)
    {
        using RSA leafKey = RSA.Create(2048);
        var request = new CertificateRequest($"CN={probe.CommonName}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (probe.DnsSan is not null || probe.IpSan is not null)
        {
            var san = new SubjectAlternativeNameBuilder();
            if (probe.DnsSan is not null) san.AddDnsName(probe.DnsSan);
            if (probe.IpSan is not null) san.AddIpAddress(IPAddress.Parse(probe.IpSan));
            request.CertificateExtensions.Add(san.Build());
        }

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        using X509Certificate2 issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2), serial);
        using X509Certificate2 withKey = issued.CopyWithPrivateKey(leafKey);
        using X509Certificate2 serverCertificate = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task<TcpClient> accept = listener.AcceptTcpClientAsync();
        using var clientTcp = new TcpClient(AddressFamily.InterNetwork);
        await clientTcp.ConnectAsync(IPAddress.Loopback, port);
        using TcpClient serverTcp = await accept;
        listener.Stop();
        using var clientSsl = new SslStream(clientTcp.GetStream(), leaveInnerStreamOpen: false);
        using var serverSsl = new SslStream(serverTcp.GetStream(), leaveInnerStreamOpen: false);

        var serverOptions = new SslServerAuthenticationOptions
        {
            ServerCertificate = serverCertificate,
            AllowTlsResume = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        };
        var clientOptions = new SslClientAuthenticationOptions
        {
            TargetHost = probe.TargetHost,
            AllowTlsResume = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.NoFlag,
                CustomTrustStore = { root },
            },
        };

        Exception? clientError = null;
        Exception? serverError = null;
        Task serverTask = serverSsl.AuthenticateAsServerAsync(serverOptions, CancellationToken.None);
        bool accepted;
        try
        {
            await clientSsl.AuthenticateAsClientAsync(clientOptions, CancellationToken.None);
            accepted = true;
        }
        catch (Exception ex)
        {
            accepted = false;
            clientError = ex;
            clientSsl.Dispose();
            clientTcp.Dispose();
        }

        try
        {
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex)
        {
            serverError = ex;
        }

        return new ProbeResult(
            probe.Name,
            probe.CommonName,
            probe.DnsSan,
            probe.IpSan,
            probe.TargetHost,
            probe.SecureExpected,
            accepted,
            clientError?.GetType().FullName,
            clientError?.Message,
            serverError?.GetType().FullName,
            serverError?.Message,
            Convert.ToHexString(serverCertificate.GetCertHash(HashAlgorithmName.SHA256)).ToLowerInvariant());
    }

    private static string HashFile(string path) => string.IsNullOrEmpty(path)
        ? string.Empty
        : Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
