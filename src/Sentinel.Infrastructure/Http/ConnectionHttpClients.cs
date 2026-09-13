using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Connections;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;

namespace Sentinel.Infrastructure.Http;

/// <summary>
/// An <see cref="HttpClient"/> that verifies the way a particular connection asks to be verified, and that
/// refuses to open a socket to an address the platform is not allowed to reach.
///
/// <see cref="IHttpClientFactory"/> cannot do this on its own: it hands out clients by name, and the
/// certificate policy lives on the handler, which is shared by every caller of that name. So the handlers
/// are pooled here instead, keyed by the policy rather than by the connection — two connections to one
/// cluster verify identically and should share sockets, and a hundred connections that all use the
/// machine's trust store should share one handler between them.
///
/// Handlers are never disposed while the process lives. That is deliberate and it is the opposite of the
/// usual advice about HttpClient: what must not be created per request is the <em>handler</em>, because
/// each one opens its own connection pool, and discarding them under load is how a process runs out of
/// sockets. The number of distinct policies is bounded by the number of connections an operator has
/// configured.
/// </summary>
public sealed class ConnectionHttpClients : IDisposable
{
    private readonly ConcurrentDictionary<string, SocketsHttpHandler> _handlers = new();
    private readonly ILogger<ConnectionHttpClients> _logger;
    private readonly OutboundAddressSettings _addresses;
    private readonly HttpMessageHandler? _fixed;

    /// <summary>
    /// The one a running process uses.
    ///
    /// The address settings are not optional here. Making them optional would mean the guard was off
    /// wherever the argument was forgotten, and a security control that fails open when someone forgets
    /// it is not a control.
    /// </summary>
    public ConnectionHttpClients(ILogger<ConnectionHttpClients> logger, OutboundAddressSettings addresses)
    {
        _logger = logger;
        _addresses = addresses;
    }

    /// <summary>
    /// Always answers with this handler, whatever a connection's policy says.
    ///
    /// For a test that supplies a recorded handler and is asserting on what went onto the wire rather than
    /// on how a certificate was verified. Certificate behaviour has its own tests, against real
    /// certificates, because a fake handler never performs a handshake and so could not prove anything
    /// about one — and the same goes for the address guard, which only means something on a real socket.
    /// </summary>
    public ConnectionHttpClients(HttpMessageHandler handler)
    {
        _logger = NullLogger<ConnectionHttpClients>.Instance;
        _addresses = new OutboundAddressSettings();
        _fixed = handler;
    }

    /// <summary>
    /// A client for this connection, for the given purpose.
    ///
    /// The purpose separates pools that should not be shared even when their certificate policy matches:
    /// reading from a cluster and calling a gateway have different timeouts and different connection
    /// limits, and a slow gateway should not exhaust the pool the engine reads through.
    /// </summary>
    public HttpClient For(Connection connection, string purpose, int maxConnectionsPerServer)
    {
        if (_fixed is not null)
            return new HttpClient(_fixed, disposeHandler: false);

        var policy = ConnectionTls.For(connection);
        var handler = _handlers.GetOrAdd(
            $"{purpose}|{policy.Key}",
            _ => Build(policy, maxConnectionsPerServer, connection.Name));

        // The client is a thin wrapper; the handler underneath is what holds the sockets, so creating one
        // per call costs nothing as long as it does not dispose the handler.
        return new HttpClient(handler, disposeHandler: false);
    }

    private SocketsHttpHandler Build(ConnectionTls.Policy policy, int maxConnectionsPerServer, string name)
    {
        var handler = new SocketsHttpHandler
        {
            // Unchanged from what every client here already used: a redirect would send a credential to
            // wherever the far side pointed, and a shared cookie jar lets one tenant's system influence
            // another's.
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = maxConnectionsPerServer
        };

        // Set before the shortcut below, because where the platform may send a request has nothing to do
        // with how a certificate is verified: it applies to every connection, including the ordinary ones.
        handler.ConnectCallback = (context, token) => ConnectAsync(context.DnsEndPoint, name, token);

        if (policy.IsDefault)
            return handler;

        _logger.LogInformation(
            "Connection {Connection} uses TLS {Policy}", name, ConnectionTls.Describe(policy));

        if (policy.AllowInvalidCertificates)
        {
            // Said once, at the level it deserves. A connection that verifies nothing is a decision
            // somebody made, and the log is where it has to be visible after they have forgotten.
            _logger.LogWarning(
                "Connection {Connection} accepts any TLS certificate. Anything able to answer on that " +
                "address will be trusted with this connection's credentials.", name);
        }

        handler.SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                Verify(policy, certificate, chain, errors, name)
        };

        return handler;
    }

    /// <summary>
    /// The half of the address policy that could not be decided when the connection was saved.
    ///
    /// Saving checks the endpoint, which closes the obvious case and nothing else: a literal address can
    /// be read, a name cannot. A URL naming a host passes every check a form is able to make and then
    /// resolves to 169.254.169.254 — and it can resolve to something harmless while the form is open and
    /// to the metadata service a second later, which is the whole of DNS rebinding. The only moment the
    /// answer is knowable is here, with the address in hand and the socket not yet open.
    ///
    /// The cost is one lookup per pooled connection, not per request.
    /// </summary>
    private async ValueTask<Stream> ConnectAsync(DnsEndPoint endpoint, string name, CancellationToken token)
    {
        var resolved = await Dns.GetHostAddressesAsync(endpoint.Host, token);

        if (resolved.Length == 0)
            throw new HttpRequestException($"{endpoint.Host} resolved to no addresses.");

        // A host an operator admitted by name is admitted, which is what that setting is for — but not as
        // far as the metadata service or a link-local address, which no deployment needs and which are
        // most of the reason this check exists.
        var settings = _addresses.AllowedHosts.Contains(endpoint.Host, StringComparer.OrdinalIgnoreCase)
            ? AdmittedByName
            : _addresses;

        var allowed = new List<IPAddress>(resolved.Length);
        string? refusal = null;

        foreach (var address in resolved)
        {
            var decision = OutboundAddressPolicy.EvaluateAddress(address, settings);

            if (decision.Allowed)
                allowed.Add(address);
            else
                refusal ??= decision.Reason;
        }

        if (allowed.Count == 0)
        {
            _logger.LogWarning(
                "Connection {Connection} was not opened: {Host} resolves to {Addresses}, and {Reason}",
                name, endpoint.Host, string.Join(", ", resolved.Select(a => a.ToString())), refusal);

            throw new HttpRequestException(
                $"{endpoint.Host} is not an address this platform may call. {refusal}");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

        try
        {
            // Only the addresses that passed. Handing over the whole list would let a refused address be
            // used as a fallback whenever an allowed one happened to be down.
            await socket.ConnectAsync(allowed.ToArray(), endpoint.Port, token);

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>What a host on the allow-list is judged by: everything except the addresses nothing needs.</summary>
    private static readonly OutboundAddressSettings AdmittedByName = new()
    {
        AllowLoopback = true,
        AllowPrivateNetworks = true
    };

    private bool Verify(
        ConnectionTls.Policy policy,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors errors,
        string name)
    {
        if (policy.AllowInvalidCertificates)
            return true;

        if (certificate is null)
        {
            _logger.LogWarning("Connection {Connection} was offered no certificate", name);
            return false;
        }

        // Pinning first, and it is not a weaker check than the chain — it is a different and stronger
        // question. "Is this exactly the certificate I was told to expect" does not need a name or a
        // trusted root to be answered, which is why it works where neither is available.
        if (policy.Fingerprint is not null)
        {
            var actual = Convert.ToHexString(SHA256.HashData(certificate.Export(X509ContentType.Cert)));

            if (string.Equals(actual, policy.Fingerprint, StringComparison.OrdinalIgnoreCase))
                return true;

            _logger.LogWarning(
                "Connection {Connection} was offered a certificate whose fingerprint is {Actual}, not the " +
                "pinned {Expected}", name, actual, policy.Fingerprint);

            return false;
        }

        if (policy.CaCertificatePem is null)
            return errors == SslPolicyErrors.None;

        // A supplied CA replaces the machine's roots and nothing else. The name is still checked, the
        // dates are still checked, revocation is still whatever the chain policy says — so this is full
        // verification against a private root, not an exemption from verification.
        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            _logger.LogWarning(
                "Connection {Connection} was offered a certificate that does not name the address being " +
                "called. Use the name on the certificate, or pin its fingerprint instead.", name);

            return false;
        }

        if (!ConnectionTls.TryParseCertificate(policy.CaCertificatePem, out var root) || root is null)
        {
            _logger.LogError("Connection {Connection} has an unreadable CA certificate", name);
            return false;
        }

        using var verification = new X509Chain();

        verification.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verification.ChainPolicy.CustomTrustStore.Add(root);

        // The chain the handshake offered, minus its root: the server sends its intermediates and the
        // root is the one being supplied here.
        if (chain is not null)
        {
            foreach (var element in chain.ChainElements.Skip(1))
                verification.ChainPolicy.ExtraStore.Add(element.Certificate);
        }

        // Most private CAs publish no CRL or OCSP responder, so requiring revocation would fail every
        // deployment this feature exists for. The chain and the name are still proved.
        verification.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        using var offered = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));

        if (verification.Build(offered))
            return true;

        _logger.LogWarning(
            "Connection {Connection} was offered a certificate that does not chain to the supplied CA: {Status}",
            name,
            string.Join(", ", verification.ChainStatus.Select(s => s.StatusInformation.Trim())));

        return false;
    }

    public void Dispose()
    {
        foreach (var handler in _handlers.Values)
            handler.Dispose();

        _handlers.Clear();
    }
}
