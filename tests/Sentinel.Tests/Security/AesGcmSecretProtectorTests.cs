using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Sentinel.Infrastructure.Security;

namespace Sentinel.Tests.Security;

/// <summary>
/// The credential bundle a connection carries.
///
/// GCM is used rather than CBC because the ciphertext is authenticated: material that has been altered
/// fails to decrypt instead of decrypting into something else. For a value about to be presented as a
/// credential to a live security API, silently getting a different one is worse than failing.
/// </summary>
public class AesGcmSecretProtectorTests
{
    private static readonly string KeyA = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static readonly string KeyB = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void A_bundle_survives_a_round_trip()
    {
        var protector = Protector(KeyA);
        var secrets = new Dictionary<string, string> { ["apiKey"] = "zvk_abc123", ["sender"] = "SECOPS" };

        var restored = protector.Unprotect(protector.Protect(secrets));

        Assert.Equal("zvk_abc123", restored["apiKey"]);
        Assert.Equal("SECOPS", restored["sender"]);
    }

    [Fact]
    public void The_same_secret_encrypts_differently_every_time()
    {
        // A fresh nonce per encryption. Reusing one under a single key is what breaks GCM, so it is never
        // derived from anything about the connection.
        var protector = Protector(KeyA);
        var secrets = new Dictionary<string, string> { ["token"] = "same-value" };

        Assert.NotEqual(protector.Protect(secrets), protector.Protect(secrets));
    }

    [Fact]
    public void The_plaintext_never_appears_in_the_ciphertext()
    {
        var protector = Protector(KeyA);

        var ciphertext = protector.Protect(new Dictionary<string, string> { ["password"] = "hunter2-in-the-clear" });

        Assert.DoesNotContain("hunter2", ciphertext, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", ciphertext, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_tampered_envelope_fails_rather_than_decrypting_into_something_else()
    {
        var protector = Protector(KeyA);
        var envelope = Convert.FromBase64String(
            protector.Protect(new Dictionary<string, string> { ["apiKey"] = "original" }));

        envelope[^1] ^= 0xFF;

        Assert.Throws<CryptographicException>(() => protector.Unprotect(Convert.ToBase64String(envelope)));
    }

    [Fact]
    public void Another_key_cannot_read_it() =>
        Assert.Throws<CryptographicException>(() =>
            Protector(KeyB).Unprotect(Protector(KeyA).Protect(new Dictionary<string, string> { ["k"] = "v" })));

    [Fact]
    public void A_rotation_can_still_read_what_the_previous_key_wrote()
    {
        // Otherwise rotating the key silently strands every connection written before it.
        var written = Protector(KeyA).Protect(new Dictionary<string, string> { ["apiKey"] = "written-under-the-old-key" });

        var afterRotation = Protector(KeyB, previous: [KeyA]);

        Assert.Equal("written-under-the-old-key", afterRotation.Unprotect(written)["apiKey"]);
    }

    [Fact]
    public void After_rotation_new_material_is_written_under_the_new_key()
    {
        var afterRotation = Protector(KeyB, previous: [KeyA]);
        var fresh = afterRotation.Protect(new Dictionary<string, string> { ["apiKey"] = "new" });

        Assert.Equal("new", Protector(KeyB).Unprotect(fresh)["apiKey"]);
    }

    [Fact]
    public void A_connection_with_no_secrets_reads_as_empty()
    {
        var protector = Protector(KeyA);

        Assert.Empty(protector.Unprotect(null));
        Assert.Empty(protector.Unprotect(""));
    }

    [Theory]
    [InlineData("not base64 at all!!")]
    [InlineData("dG9vLXNob3J0")]
    public void Stored_material_that_is_not_an_envelope_fails_clearly(string stored) =>
        Assert.Throws<CryptographicException>(() => Protector(KeyA).Unprotect(stored));

    [Fact]
    public void Production_refuses_to_start_without_a_key()
    {
        // Falling back to a development key in production would encrypt every credential under a value
        // that is published in this repository.
        var error = Assert.Throws<InvalidOperationException>(() =>
            new AesGcmSecretProtector(Options.Create(new SecretProtectionSettings()), isProduction: true));

        Assert.Contains("Secrets:Key", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Development_works_without_configuration_so_the_platform_can_be_tried_out()
    {
        var protector = new AesGcmSecretProtector(Options.Create(new SecretProtectionSettings()), isProduction: false);

        Assert.Equal("v", protector.Unprotect(protector.Protect(new Dictionary<string, string> { ["k"] = "v" }))["k"]);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("bm90LTMyLWJ5dGVz")]
    public void A_key_that_is_not_thirty_two_bytes_is_refused(string key) =>
        Assert.Throws<InvalidOperationException>(() => Protector(key));

    private static AesGcmSecretProtector Protector(string key, string[]? previous = null) =>
        new(Options.Create(new SecretProtectionSettings
        {
            Key = key,
            PreviousKeys = previous?.ToList() ?? []
        }), isProduction: true);
}
