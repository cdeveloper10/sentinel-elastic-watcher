using Sentinel.Domain.Connections;

namespace Sentinel.Application.Security;

/// <summary>
/// Encrypts and decrypts the credential bundle a connection carries.
///
/// Kept as an interface because where secrets live is a deployment decision — a key from the environment
/// today, a key manager or Vault later — and none of the code that <em>uses</em> a credential should have
/// to change when that moves.
/// </summary>
public interface ISecretProtector
{
    string Protect(IReadOnlyDictionary<string, string> secrets);

    IReadOnlyDictionary<string, string> Unprotect(string? ciphertext);
}

/// <summary>
/// Reads a connection's credentials at the moment of use.
///
/// Separate from <see cref="ISecretProtector"/> so that the permission to <em>use</em> a connection and
/// the permission to <em>read</em> its secrets stay distinguishable: an adapter making a call needs this,
/// and nothing in the API surface does.
/// </summary>
public interface IConnectionSecrets
{
    IReadOnlyDictionary<string, string> For(Connection connection);
}
