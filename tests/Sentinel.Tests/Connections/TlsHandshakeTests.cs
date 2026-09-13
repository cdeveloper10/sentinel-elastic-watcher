using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Http;

namespace Sentinel.Tests.Connections;

/// <summary>
/// A real handshake against a real self-signed certificate.
///
/// The policy tests check what is read out of a connection; these check what happens on the wire, which is
/// the only place the claim can be proved. A recorded handler never performs a handshake, so it could not
/// tell a pinned certificate from an ignored one.
///
/// The server here is what an operator is really up against: a certificate signed by a private root whose
/// names do not include the address being called. That is what Elasticsearch 8 and the ECK operator both
/// produce, and until this existed the platform could talk to neither.
/// </summary>
public class TlsHandshakeTests : IAsyncLifetime
{
    private X509Certificate2 _certificate = null!;
    private TlsServer _server = null!;

    public Task InitializeAsync()
    {
        // A name nobody will connect by: requests below go to 127.0.0.1, so every one of them starts out
        // with both a name mismatch and an untrusted root — the two errors in the original report.
        _certificate = SelfSigned("CN=elasticsearch-es-http.elastic.svc");
        _server = TlsServer.Start(_certificate);

        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _server.Dispose();
        _certificate.Dispose();

        return Task.CompletedTask;
    }

    private Connection Connection(string? tls) => new()
    {
        Name = "hamfekran",
        Type = ConnectionType.Elasticsearch,
        Endpoint = $"https://127.0.0.1:{_server.Port}",
        TimeoutSeconds = 10,
        Enabled = true,
        ConfigurationJson = tls ?? "{}"
    };

    private async Task<(bool Ok, string? Error)> TryGet(string? tls)
    {
        using var clients = new ConnectionHttpClients(
            NullLogger<ConnectionHttpClients>.Instance,
            // The server is on 127.0.0.1, which the outbound guard refuses by default and rightly so.
            new OutboundAddressSettings { AllowLoopback = true });

        var connection = Connection(tls);
        using var client = clients.For(connection, "test", maxConnectionsPerServer: 4);

        client.Timeout = TimeSpan.FromSeconds(10);

        try
        {
            var response = await client.GetAsync(connection.Endpoint);
            return (response.IsSuccessStatusCode, null);
        }
        catch (Exception ex)
        {
            return (false, ex.InnerException?.Message ?? ex.Message);
        }
    }

    [Fact]
    public async Task Without_configuration_the_handshake_is_refused()
    {
        // The failure the platform shipped with, reproduced: an unknown root and a name that does not
        // match, and nowhere to say that either was expected.
        var (ok, error) = await TryGet(null);

        Assert.False(ok);
        Assert.NotNull(error);
    }

    [Fact]
    public async Task A_pinned_fingerprint_is_accepted_despite_the_name_and_the_root()
    {
        // Why pinning is the setting that actually helps here: it answers "is this the certificate I was
        // told to expect", which needs neither a trusted issuer nor a matching name.
        var (ok, error) = await TryGet(Tls("\"fingerprint\":\"" + Fingerprint(_certificate) + "\""));

        Assert.True(ok, error);
    }

    [Fact]
    public async Task A_fingerprint_written_with_colons_works_too()
    {
        // How Elasticsearch prints it on first start, and what an operator will paste.
        var raw = Fingerprint(_certificate);
        var colons = string.Join(":", Enumerable.Range(0, raw.Length / 2).Select(i => raw.Substring(i * 2, 2)));

        var (ok, error) = await TryGet(Tls("\"fingerprint\":\"" + colons + "\""));

        Assert.True(ok, error);
    }

    [Fact]
    public async Task A_fingerprint_that_does_not_match_is_refused()
    {
        // Pinning has to be able to say no, or it is only a way of switching verification off.
        using var other = SelfSigned("CN=somewhere-else");

        var (ok, _) = await TryGet(Tls("\"fingerprint\":\"" + Fingerprint(other) + "\""));

        Assert.False(ok);
    }

    [Fact]
    public async Task Accepting_any_certificate_connects()
    {
        var (ok, error) = await TryGet(Tls("\"allowInvalidCertificates\":true"));

        Assert.True(ok, error);
    }

    [Fact]
    public async Task A_supplied_CA_still_refuses_a_name_that_does_not_match()
    {
        // The distinction that makes a supplied CA worth having rather than being a second way to switch
        // checking off: it replaces the trusted roots and nothing else. This certificate chains to itself,
        // so the root is satisfied — and the address is still not on it, so the connection is refused.
        var pem = System.Text.Json.JsonSerializer.Serialize(_certificate.ExportCertificatePem());

        var (ok, _) = await TryGet(Tls("\"caCertificate\":" + pem));

        Assert.False(ok);
    }

    // -- fixtures ------------------------------------------------------------------------------

    private static string Tls(string inner) => "{\"tls\":{" + inner + "}}";

    private static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.Export(X509ContentType.Cert)));

    private static X509Certificate2 SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Round-tripped through PKCS#12 so the private key is usable by SslStream on every platform.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    /// <summary>
    /// The smallest thing that completes a TLS handshake and answers one request.
    ///
    /// Not <see cref="HttpListener"/>: on Windows it cannot be handed a certificate in process without the
    /// certificate first being bound to the port in the operating system, which a test has no business
    /// doing to the machine it runs on.
    /// </summary>
    private sealed class TlsServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _stopping = new();

        private TlsServer(TcpListener listener) => _listener = listener;

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static TlsServer Start(X509Certificate2 certificate)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var server = new TlsServer(listener);
            _ = server.ServeAsync(certificate);

            return server;
        }

        private async Task ServeAsync(X509Certificate2 certificate)
        {
            while (!_stopping.IsCancellationRequested)
            {
                try
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stopping.Token);
                    await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

                    await ssl.AuthenticateAsServerAsync(certificate, false, checkCertificateRevocation: false);

                    // One read is enough: the request is a bare GET and fits in a single segment. The
                    // count is checked rather than discarded because zero means the client hung up during
                    // the handshake, which several of these tests deliberately cause.
                    var buffer = new byte[4096];

                    if (await ssl.ReadAsync(buffer, _stopping.Token) == 0)
                        continue;

                    var body = "{\"cluster_name\":\"test\"}"u8.ToArray();

                    var head = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                        $"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n");

                    await ssl.WriteAsync(head, _stopping.Token);
                    await ssl.WriteAsync(body, _stopping.Token);
                    await ssl.FlushAsync(_stopping.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // A refused handshake is the point of several of these tests. The server waits for the
                    // next connection rather than treating it as a fault.
                }
            }
        }

        public void Dispose()
        {
            _stopping.Cancel();
            _listener.Stop();
            _stopping.Dispose();
        }
    }
}
