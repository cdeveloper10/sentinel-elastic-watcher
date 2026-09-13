namespace Sentinel.Domain.Connections;

/// <summary>
/// A configured external system: where it is, how to authenticate to it, and nothing about why.
///
/// Rules reference a connection by name and never carry an endpoint or a credential themselves. That is
/// what lets a rule be authored by someone who is not allowed to see the credential — the separation the
/// RBAC model depends on — and what keeps secrets out of rule exports, audit entries and the UI.
///
/// Elasticsearch is a connection like any other. Treating the event source as one of these rather than a
/// special case in configuration is what gives it the same test button, the same secret handling and the
/// same audit trail as the systems the platform writes to.
/// </summary>
public class Connection
{
    public int Id { get; set; }

    /// <summary>Stable handle a rule refers to, e.g. <c>security-api</c>. Immutable once other records point at it.</summary>
    public string Name { get; set; } = "";

    public string DisplayName { get; set; } = "";

    public string Description { get; set; } = "";

    /// <summary>One of <see cref="ConnectionType"/>.</summary>
    public string Type { get; set; } = "";

    /// <summary>Absolute http(s) base address. Validated against the SSRF policy before it is stored.</summary>
    public string Endpoint { get; set; } = "";

    /// <summary>One of <see cref="AuthenticationMode"/>.</summary>
    public string AuthenticationMode { get; set; } = Connections.AuthenticationMode.None;

    public int TimeoutSeconds { get; set; } = 30;

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Non-secret settings, as JSON. Shape is the connection type's business — an SMS sender id, a default
    /// block duration, the Elasticsearch timestamp field.
    /// </summary>
    public string ConfigurationJson { get; set; } = "{}";

    /// <summary>
    /// Encrypted credential material. Never leaves the process in plaintext: no DTO exposes it, no log
    /// records it, and reading it requires a permission that authoring a rule does not grant.
    /// </summary>
    public string? SecretCiphertext { get; set; }

    /// <summary>Names of the secrets held, so the UI can show what is configured without revealing values.</summary>
    public string SecretKeysJson { get; set; } = "[]";

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = "";
    public string UpdatedBy { get; set; } = "";

    /// <summary>Result of the last connectivity check, so the UI can show a connection as verified or not.</summary>
    public DateTime? LastProbedAt { get; set; }
    public bool? LastProbeSucceeded { get; set; }
    public string? LastProbeMessage { get; set; }
}
