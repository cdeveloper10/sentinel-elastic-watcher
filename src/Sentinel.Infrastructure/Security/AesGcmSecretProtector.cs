using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;

namespace Sentinel.Infrastructure.Security;

public sealed class SecretProtectionSettings
{
    /// <summary>Base64 of 32 bytes. Required outside development, where a derived non-secret key is used instead.</summary>
    public string Key { get; set; } = "";

    /// <summary>Keys the platform can still decrypt with after a rotation, newest first.</summary>
    public List<string> PreviousKeys { get; set; } = [];
}

/// <summary>
/// AES-256-GCM over the credential bundle.
///
/// GCM rather than CBC because the ciphertext is authenticated: a stored secret that has been altered
/// fails to decrypt instead of decrypting into something else. For material that is about to be used as a
/// credential against a live security API, silently getting a different value is worse than failing.
///
/// The nonce is random per encryption and stored alongside the ciphertext. Reusing a nonce under one key
/// is what breaks GCM, so it is never derived from anything about the connection.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretProtector
{
    private const int NonceBytes = 12;   // 96 bits, the size GCM is specified for.
    private const int TagBytes = 16;

    private readonly byte[] _activeKey;
    private readonly IReadOnlyList<byte[]> _decryptionKeys;

    public AesGcmSecretProtector(IOptions<SecretProtectionSettings> options, bool isProduction)
    {
        var settings = options.Value;

        if (string.IsNullOrWhiteSpace(settings.Key))
        {
            if (isProduction)
                throw new InvalidOperationException(
                    "Secrets:Key is required outside development. Supply 32 bytes of base64, " +
                    "for example from a Kubernetes secret.");

            // Development only, and deliberately not secret: the alternative is refusing to start, which
            // makes the platform impossible to try out.
            _activeKey = SHA256.HashData("sentinel-development-key-not-for-production"u8.ToArray());
        }
        else
        {
            _activeKey = ReadKey(settings.Key, nameof(settings.Key));
        }

        var keys = new List<byte[]> { _activeKey };
        keys.AddRange(settings.PreviousKeys.Select(k => ReadKey(k, nameof(settings.PreviousKeys))));
        _decryptionKeys = keys;
    }

    public string Protect(IReadOnlyDictionary<string, string> secrets)
    {
        var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(secrets));

        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];

        using var aes = new AesGcm(_activeKey, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var envelope = new byte[NonceBytes + TagBytes + ciphertext.Length];
        nonce.CopyTo(envelope, 0);
        tag.CopyTo(envelope, NonceBytes);
        ciphertext.CopyTo(envelope, NonceBytes + TagBytes);

        return Convert.ToBase64String(envelope);
    }

    public IReadOnlyDictionary<string, string> Unprotect(string? ciphertext)
    {
        if (string.IsNullOrWhiteSpace(ciphertext))
            return new Dictionary<string, string>();

        byte[] envelope;
        try
        {
            envelope = Convert.FromBase64String(ciphertext);
        }
        catch (FormatException)
        {
            throw new CryptographicException("The stored secret is not valid base64.");
        }

        if (envelope.Length < NonceBytes + TagBytes)
            throw new CryptographicException("The stored secret is too short to be a valid envelope.");

        var nonce = envelope.AsSpan(0, NonceBytes);
        var tag = envelope.AsSpan(NonceBytes, TagBytes);
        var body = envelope.AsSpan(NonceBytes + TagBytes);
        var plaintext = new byte[body.Length];

        // Every key in turn, so a rotation does not strand connections that were written under the old one.
        foreach (var key in _decryptionKeys)
        {
            try
            {
                using var aes = new AesGcm(key, TagBytes);
                aes.Decrypt(nonce, body, tag, plaintext);

                return JsonSerializer.Deserialize<Dictionary<string, string>>(plaintext)
                       ?? new Dictionary<string, string>();
            }
            catch (CryptographicException)
            {
                // Wrong key. Try the next; the tag check is what makes this safe to attempt.
            }
        }

        throw new CryptographicException(
            "The stored secret could not be decrypted with any configured key. " +
            "It was written under a key that is no longer configured.");
    }

    private static byte[] ReadKey(string base64, string setting)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"{setting} is not valid base64.");
        }

        if (key.Length != 32)
            throw new InvalidOperationException($"{setting} must decode to exactly 32 bytes; got {key.Length}.");

        return key;
    }
}

/// <summary>Reads a connection's credentials through the protector, so callers never touch ciphertext.</summary>
public sealed class ConnectionSecrets(ISecretProtector protector) : IConnectionSecrets
{
    public IReadOnlyDictionary<string, string> For(Connection connection) =>
        protector.Unprotect(connection.SecretCiphertext);
}
