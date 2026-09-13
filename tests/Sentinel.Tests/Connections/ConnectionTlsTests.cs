using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sentinel.Application.Connections;
using Sentinel.Domain.Connections;

namespace Sentinel.Tests.Connections;

/// <summary>
/// How a connection's certificate is checked.
///
/// This exists because the platform could not talk to a normal Elasticsearch. Version 8 auto-configures
/// TLS with a CA it generates itself, and on Kubernetes the ECK operator does the same — so the
/// certificate is signed by a root no machine trusts, and its names cover the in-cluster service rather
/// than whatever address an operator reaches it on. The handshake fails twice over, with
/// <c>RemoteCertificateChainErrors</c> and <c>RemoteCertificateNameMismatch</c>, and there was no setting
/// anywhere that could accept either.
/// </summary>
public class ConnectionTlsTests
{
    private static Connection With(string? configuration) => new()
    {
        Name = "hamfekran",
        Type = ConnectionType.Elasticsearch,
        Endpoint = "https://10.0.0.5:9200",
        TimeoutSeconds = 30,
        Enabled = true,
        ConfigurationJson = configuration ?? "{}"
    };

    // -- reading ------------------------------------------------------------------------------

    [Fact]
    public void A_connection_that_says_nothing_uses_the_machine_trust_store()
    {
        var policy = ConnectionTls.For(With(null));

        Assert.True(policy.IsDefault);
        Assert.Equal("verified against the machine's trust store", ConnectionTls.Describe(policy));
    }

    [Fact]
    public void A_fingerprint_is_read_and_normalised()
    {
        // Elasticsearch prints it with colons, openssl prints it with colons and lowercase, a browser
        // shows it with spaces. All three are the same fingerprint and all three must work.
        var colons = ConnectionTls.For(With("""{"tls":{"fingerprint":"ab:cd:ef:01"}}""")).Fingerprint;
        var spaces = ConnectionTls.For(With("""{"tls":{"fingerprint":"ab cd ef 01"}}""")).Fingerprint;
        var plain = ConnectionTls.For(With("""{"tls":{"fingerprint":"ABCDEF01"}}""")).Fingerprint;

        Assert.Equal("ABCDEF01", colons);
        Assert.Equal(colons, spaces);
        Assert.Equal(colons, plain);
    }

    [Fact]
    public void Paths_and_TLS_live_side_by_side_in_one_document()
    {
        // Both are connection configuration. Adding one must not disturb the other.
        var connection = With("""
            { "paths": { "sms": "/sms/send" }, "tls": { "allowInvalidCertificates": true } }
            """);

        Assert.True(ConnectionTls.For(connection).AllowInvalidCertificates);
        Assert.Equal("/sms/send", ConnectionPaths.For(connection, "sms", "/fallback"));
    }

    [Fact]
    public void Unreadable_configuration_falls_back_to_verifying_normally()
    {
        // The safe direction. A malformed document must not be a way to end up trusting everything.
        Assert.True(ConnectionTls.For(With("not json")).IsDefault);
        Assert.True(ConnectionTls.For(With("""{"tls": 3}""")).IsDefault);
    }

    [Fact]
    public void Connections_that_verify_alike_share_a_handler_and_others_do_not()
    {
        // The key is what decides whether two connections share a socket pool. Getting it wrong either
        // leaks handlers or, far worse, lets one connection's certificate policy apply to another's.
        var first = ConnectionTls.For(With("""{"tls":{"fingerprint":"AB"}}"""));
        var same = ConnectionTls.For(With("""{"tls":{"fingerprint":"ab"}}"""));
        var other = ConnectionTls.For(With("""{"tls":{"fingerprint":"CD"}}"""));
        var insecure = ConnectionTls.For(With("""{"tls":{"allowInvalidCertificates":true}}"""));

        Assert.Equal(first.Key, same.Key);
        Assert.NotEqual(first.Key, other.Key);
        Assert.NotEqual(first.Key, insecure.Key);
        Assert.NotEqual(ConnectionTls.Policy.Default.Key, insecure.Key);
    }

    // -- what an author is told at save time ---------------------------------------------------

    [Fact]
    public void A_real_certificate_is_accepted()
    {
        using var certificate = SelfSigned("CN=test-ca");

        var pem = certificate.ExportCertificatePem();
        var result = ConnectionTls.Validate(Tls("\"caCertificate\":" + Quote(pem)));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Text_that_is_not_a_certificate_is_refused_with_advice()
    {
        var result = ConnectionTls.Validate("""{"tls":{"caCertificate":"just some text"}}""");

        Assert.False(result.IsValid);
        Assert.Contains("BEGIN CERTIFICATE", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("abc")]                                                    // too short
    [InlineData("zz3fb1a0b8e5d6c7a9f2e4d8c1b3a5f7e9d2c4b6a8f1e3d5c7b9a0f2")]  // not hexadecimal
    public void A_fingerprint_that_is_not_a_SHA256_hash_is_refused(string fingerprint)
    {
        var result = ConnectionTls.Validate(Tls("\"fingerprint\":\"" + fingerprint + "\""));

        Assert.False(result.IsValid);
        Assert.Contains("SHA-256", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_genuine_SHA256_fingerprint_is_accepted_however_it_is_written()
    {
        using var certificate = SelfSigned("CN=test");

        var raw = Convert.ToHexString(SHA256.HashData(certificate.Export(X509ContentType.Cert)));
        var withColons = string.Join(":", Enumerable.Range(0, 32).Select(i => raw.Substring(i * 2, 2)));

        Assert.True(ConnectionTls.Validate(Tls("\"fingerprint\":\"" + raw + "\"")).IsValid);
        Assert.True(ConnectionTls.Validate(Tls("\"fingerprint\":\"" + withColons + "\"")).IsValid);
    }

    [Fact]
    public void A_certificate_larger_than_the_cap_is_refused()
    {
        var huge = new string('A', ConnectionTls.MaxCertificateLength + 1);

        Assert.False(ConnectionTls.Validate(Tls("\"caCertificate\":\"" + huge + "\"")).IsValid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{}")]
    [InlineData("""{"paths":{"sms":"/sms/send"}}""")]
    [InlineData("""{"tls":{"allowInvalidCertificates":true}}""")]
    public void Configuration_without_a_problem_is_accepted(string? configuration)
    {
        Assert.True(ConnectionTls.Validate(configuration).IsValid);
    }

    // -- how it reads --------------------------------------------------------------------------

    [Fact]
    public void Each_mode_says_plainly_what_it_does()
    {
        // Shown wherever the connection appears, so "not verified" is never something somebody has to
        // infer from an absent setting.
        Assert.Equal("not verified",
            ConnectionTls.Describe(ConnectionTls.For(With("""{"tls":{"allowInvalidCertificates":true}}"""))));

        Assert.Equal("pinned to a certificate fingerprint",
            ConnectionTls.Describe(ConnectionTls.For(With("""{"tls":{"fingerprint":"AB"}}"""))));
    }

    [Fact]
    public void Pinning_wins_over_a_supplied_CA_when_both_are_given()
    {
        // Both configured is a muddle worth resolving predictably rather than refusing: pinning answers a
        // stronger question, so it decides.
        using var certificate = SelfSigned("CN=test-ca");

        var policy = ConnectionTls.For(With(Tls(
            "\"fingerprint\":\"AB\",\"caCertificate\":" + Quote(certificate.ExportCertificatePem()))));

        Assert.Equal("pinned to a certificate fingerprint", ConnectionTls.Describe(policy));
    }

    // -- fixtures ------------------------------------------------------------------------------

    private static X509Certificate2 SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    /// <summary>A tls block, built without fighting raw-string interpolation over its closing braces.</summary>
    private static string Tls(string inner) => "{\"tls\":{" + inner + "}}";

    private static string Quote(string value) => System.Text.Json.JsonSerializer.Serialize(value);
}
