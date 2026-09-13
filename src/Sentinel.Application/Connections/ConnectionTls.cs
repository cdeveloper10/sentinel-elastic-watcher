using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Connections;

/// <summary>
/// How this connection's certificate is checked.
///
/// Needed because the default is not the common case. Elasticsearch 8 auto-configures TLS with a CA it
/// generates itself, and on Kubernetes the ECK operator does the same — so the certificate is signed by a
/// root no machine trusts, and its names cover the in-cluster service (<c>es-http.namespace.svc</c>) and
/// not the node address an operator port-forwards to. Connecting to it fails twice over:
/// <c>RemoteCertificateChainErrors</c> because the root is unknown, and <c>RemoteCertificateNameMismatch</c>
/// because the address is not on the certificate.
///
/// Without any of this the platform could only ever talk to a cluster fronted by a publicly trusted
/// certificate, which describes very few real deployments.
///
/// <code>
/// { "tls": { "caCertificate": "-----BEGIN CERTIFICATE-----\n…" } }
/// { "tls": { "fingerprint": "5F:5A:…" } }
/// { "tls": { "allowInvalidCertificates": true } }
/// </code>
///
/// Three ways, deliberately ordered by how much they prove:
///
/// <list type="number">
/// <item><b>caCertificate</b> — the chain is verified against this root instead of the machine's store.
/// Everything else still holds, including the name, so this is full verification against a private CA.</item>
/// <item><b>fingerprint</b> — the server's certificate must be exactly this one. Name and chain are not
/// consulted, because pinning the certificate answers a stronger question than either. Elasticsearch
/// prints this on first start and Elastic's own clients call it <c>ssl_assert_fingerprint</c>; on
/// Kubernetes it is usually the only thing an operator can copy without extracting the CA.</item>
/// <item><b>allowInvalidCertificates</b> — nothing is checked. Anyone able to answer on that address is
/// trusted with the platform's credentials. It exists because it is occasionally the only way to make
/// progress, and the console shows it as a warning wherever the connection appears.</item>
/// </list>
///
/// Silence means the machine's own trust store, which is the right default and the reason the first two
/// exist as configuration rather than as behaviour.
/// </summary>
public static class ConnectionTls
{
    /// <summary>The property inside a connection's configuration document.</summary>
    public const string Property = "tls";

    /// <summary>Room for a certificate chain, and a bound so the column cannot become a file store.</summary>
    public const int MaxCertificateLength = 16_000;

    public sealed record Policy(
        string? CaCertificatePem,
        string? Fingerprint,
        bool AllowInvalidCertificates)
    {
        /// <summary>The machine's trust store, unmodified.</summary>
        public static readonly Policy Default = new(null, null, false);

        public bool IsDefault => CaCertificatePem is null && Fingerprint is null && !AllowInvalidCertificates;

        /// <summary>
        /// Identifies this policy so connections that verify the same way can share one pooled handler.
        /// Two connections to one cluster should not each hold their own sockets.
        /// </summary>
        public string Key => IsDefault
            ? "default"
            : $"{CaCertificatePem?.GetHashCode() ?? 0:x}:{Fingerprint}:{AllowInvalidCertificates}";
    }

    public static Policy For(Connection connection)
    {
        JsonNode? tls;

        try
        {
            tls = Read(connection.ConfigurationJson);
        }
        catch (JsonException)
        {
            // Whether the document parses is settled when it is saved. At the moment a handshake needs a
            // decision, a malformed one must not throw — and must fall back to verifying rather than to
            // trusting, because the other direction would make a typo a way to disable verification.
            return Policy.Default;
        }

        if (tls is null)
            return Policy.Default;

        return new Policy(
            Text(tls, "caCertificate"),
            NormaliseFingerprint(Text(tls, "fingerprint")),
            tls["allowInvalidCertificates"]?.GetValue<bool>() ?? false);
    }

    /// <summary>
    /// Colons, spaces and case removed, so a fingerprint pasted from Elasticsearch's startup log,
    /// <c>openssl</c>, or a browser's certificate viewer all compare equal.
    /// </summary>
    public static string? NormaliseFingerprint(string? fingerprint) =>
        string.IsNullOrWhiteSpace(fingerprint)
            ? null
            : fingerprint.Replace(":", "").Replace(" ", "").Replace("-", "").Trim().ToUpperInvariant();

    // -- what an author is told at save time ---------------------------------------------------

    public static ValidationResult Validate(string? configurationJson)
    {
        JsonNode? tls;

        try
        {
            tls = Read(configurationJson);
        }
        catch (JsonException ex)
        {
            return ValidationResult.Fail(new ValidationFailure("tls", $"This is not valid JSON: {ex.Message}"));
        }

        if (tls is null)
            return ValidationResult.Success;

        var failures = new List<ValidationFailure>();

        var pem = Text(tls, "caCertificate");

        if (pem is not null)
        {
            if (pem.Length > MaxCertificateLength)
                failures.Add(new ValidationFailure(
                    "tls", $"Keep the CA certificate under {MaxCertificateLength:N0} characters."));
            else if (!TryParseCertificate(pem, out _))
                failures.Add(new ValidationFailure(
                    "tls",
                    "The CA certificate is not readable PEM. Paste the whole block including the " +
                    "BEGIN CERTIFICATE and END CERTIFICATE lines."));
        }

        var fingerprint = NormaliseFingerprint(Text(tls, "fingerprint"));

        // SHA-256, because that is what Elasticsearch prints and what its clients assert on. SHA-1 is
        // still accepted by some tools and is not worth pinning to.
        if (fingerprint is not null &&
            (fingerprint.Length != 64 || !fingerprint.All(Uri.IsHexDigit)))
            failures.Add(new ValidationFailure(
                "tls",
                "The fingerprint must be a SHA-256 hash: 64 hexadecimal characters, with or without colons."));

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    public static bool TryParseCertificate(string pem, out X509Certificate2? certificate)
    {
        certificate = null;

        try
        {
            certificate = X509Certificate2.CreateFromPem(pem);
            return true;
        }
        catch (Exception)
        {
            // CryptographicException for malformed content, ArgumentException for text that has no PEM
            // block at all. Both mean the same thing to whoever pasted it.
            return false;
        }
    }

    /// <summary>How this connection verifies, in one line, for the console and for a log.</summary>
    public static string Describe(Policy policy) => policy switch
    {
        { AllowInvalidCertificates: true } => "not verified",
        { Fingerprint: not null } => "pinned to a certificate fingerprint",
        { CaCertificatePem: not null } => "verified against a supplied CA",
        _ => "verified against the machine's trust store"
    };

    private static JsonNode? Read(string? configurationJson)
    {
        if (string.IsNullOrWhiteSpace(configurationJson))
            return null;

        return JsonNode.Parse(configurationJson) is JsonObject root &&
               root.TryGetPropertyValue(Property, out var tls) &&
               tls is JsonObject
            ? tls
            : null;
    }

    private static string? Text(JsonNode tls, string property)
    {
        var value = tls[property]?.GetValue<string>();

        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
