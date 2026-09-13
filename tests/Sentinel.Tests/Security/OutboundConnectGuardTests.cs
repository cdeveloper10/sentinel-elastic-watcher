using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Http;

namespace Sentinel.Tests.Security;

/// <summary>
/// Where the platform will actually open a socket.
///
/// <see cref="OutboundAddressPolicy"/> is checked when a connection is saved, and that closes the obvious
/// case and nothing else: a literal address can be read out of a URL, a name cannot. The class documented
/// a second check — "a name still has to be resolved and its addresses checked again before the request
/// goes out" — which nothing performed. Every one of these tests failed before that check existed.
///
/// They use real sockets. A recorded handler is never asked to connect, so it cannot tell a guard that
/// works from a comment that says one does.
/// </summary>
public class OutboundConnectGuardTests
{
    private static ConnectionHttpClients Clients(OutboundAddressSettings settings) =>
        new(NullLogger<ConnectionHttpClients>.Instance, settings);

    private static Connection To(string endpoint) => new()
    {
        Name = "gateway",
        Type = ConnectionType.SecurityApi,
        Endpoint = endpoint,
        TimeoutSeconds = 5,
        Enabled = true,
        ConfigurationJson = "{}"
    };

    private static async Task<(bool Ok, string Error)> Get(OutboundAddressSettings settings, string endpoint)
    {
        using var clients = Clients(settings);
        using var client = clients.For(To(endpoint), "test", maxConnectionsPerServer: 2);

        client.Timeout = TimeSpan.FromSeconds(5);

        try
        {
            var response = await client.GetAsync(endpoint);
            return (response.IsSuccessStatusCode, "");
        }
        catch (Exception ex)
        {
            return (false, Flatten(ex));
        }
    }

    private static string Flatten(Exception? ex)
    {
        var text = new StringBuilder();

        for (; ex is not null; ex = ex.InnerException)
            text.Append(ex.Message).Append(' ');

        return text.ToString();
    }

    [Fact]
    public async Task A_name_that_resolves_to_loopback_is_refused()
    {
        // The gap, at its smallest: "localhost" is a name, so the save-time check had nothing to look at
        // and allowed it. It resolves to the platform itself — every admin port bound to loopback, and
        // Sentinel's own API among them.
        var (ok, error) = await Get(new OutboundAddressSettings(), "http://localhost:9/");

        Assert.False(ok);
        Assert.Contains("loopback", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_metadata_address_is_refused_before_a_socket_is_opened()
    {
        // Refused rather than attempted, which is also why this test finishes immediately: on a cloud
        // node 169.254.169.254 answers, and anywhere else it hangs until the connect timeout. A run that
        // takes ten seconds here would mean the guard did not fire.
        var clock = Stopwatch.StartNew();

        var (ok, error) = await Get(
            new OutboundAddressSettings { AllowLoopback = true, AllowPrivateNetworks = true },
            "http://169.254.169.254/latest/meta-data/");

        Assert.False(ok);
        Assert.Contains("metadata", error, StringComparison.OrdinalIgnoreCase);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), $"it took {clock.Elapsed}");
    }

    [Fact]
    public async Task A_private_address_is_refused_when_private_networks_are_not_allowed()
    {
        var (ok, error) = await Get(
            new OutboundAddressSettings { AllowPrivateNetworks = false },
            "http://10.20.30.40:9200/");

        Assert.False(ok);
        Assert.Contains("private", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_allowed_address_still_connects()
    {
        // The other half of the claim. A guard that refused everything would pass every test above and
        // leave the platform unable to reach the cluster it exists to read.
        using var server = OneRequestServer.Start();

        var (ok, error) = await Get(
            new OutboundAddressSettings { AllowLoopback = true },
            $"http://127.0.0.1:{server.Port}/");

        Assert.True(ok, error);
    }

    [Fact]
    public async Task A_host_admitted_by_name_is_reached_even_on_loopback()
    {
        // What the allow-list is for: the deployment where the platform genuinely does call something on
        // its own node. Named explicitly by an operator, not inferred.
        using var server = OneRequestServer.Start();

        var (ok, error) = await Get(
            new OutboundAddressSettings { AllowedHosts = ["127.0.0.1"] },
            $"http://127.0.0.1:{server.Port}/");

        Assert.True(ok, error);
    }

    [Fact]
    public async Task The_allow_list_does_not_extend_to_the_metadata_service()
    {
        // The allow-list admits a host past the loopback and private-network rules, and no further. An
        // operator who allow-listed a name cannot have meant "and if it starts resolving to the metadata
        // service, send the credentials there too".
        var (ok, error) = await Get(
            new OutboundAddressSettings { AllowedHosts = ["169.254.169.254"] },
            "http://169.254.169.254/latest/meta-data/");

        Assert.False(ok);
        Assert.Contains("metadata", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Answers one HTTP request per connection and nothing else. Small enough to be obviously correct,
    /// which matters because a fault in it would look like a fault in the guard.
    /// </summary>
    private sealed class OneRequestServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _stopping = new();

        private OneRequestServer(TcpListener listener) => _listener = listener;

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static OneRequestServer Start()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var server = new OneRequestServer(listener);
            _ = server.ServeAsync();

            return server;
        }

        private async Task ServeAsync()
        {
            while (!_stopping.IsCancellationRequested)
            {
                try
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stopping.Token);
                    await using var stream = client.GetStream();

                    var buffer = new byte[4096];

                    if (await stream.ReadAsync(buffer, _stopping.Token) == 0)
                        continue;

                    var body = "{}"u8.ToArray();

                    var head = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                        $"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n");

                    await stream.WriteAsync(head, _stopping.Token);
                    await stream.WriteAsync(body, _stopping.Token);
                    await stream.FlushAsync(_stopping.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // A client that hung up. The next connection is what matters.
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
