using Sentinel.Domain.Connections;

namespace Sentinel.Tests.Connections;

/// <summary>
/// A connection is stored under the spelling the rest of the platform compares against.
///
/// Found by creating a connection through the API with "Elasticsearch" rather than "elasticsearch".
/// Validation accepted it, because <see cref="ConnectionType.IsKnown"/> is case-insensitive. Every
/// consumer then rejected it, because they compare ordinally against the constant. The connection existed,
/// listed, and could not be probed, could not have its fields discovered, and could not back a rule — and
/// the error named the type it claimed not to be: "'wso2-es' is a Elasticsearch connection, which is not
/// an event source."
///
/// The authentication mode is the same bug with a quieter failure: the switch that attaches credentials
/// has no default arm, so a mode stored as "Bearer" matches no case and the request leaves without the
/// token instead of failing.
/// </summary>
public class ConnectionTypeCanonicalisationTests
{
    [Theory]
    [InlineData("Elasticsearch", ConnectionType.Elasticsearch)]
    [InlineData("ELASTICSEARCH", ConnectionType.Elasticsearch)]
    [InlineData("elasticsearch", ConnectionType.Elasticsearch)]
    [InlineData("Security_Api", ConnectionType.SecurityApi)]
    [InlineData("SMS", ConnectionType.Sms)]
    public void A_known_type_stores_as_the_constant_it_matches(string supplied, string expected)
    {
        Assert.Equal(expected, ConnectionType.Canonical(supplied));
    }

    [Theory]
    [InlineData("Bearer", AuthenticationMode.Bearer)]
    [InlineData("API_KEY", AuthenticationMode.ApiKey)]
    [InlineData("Basic", AuthenticationMode.Basic)]
    [InlineData("None", AuthenticationMode.None)]
    public void A_known_mode_stores_as_the_constant_it_matches(string supplied, string expected)
    {
        Assert.Equal(expected, AuthenticationMode.Canonical(supplied));
    }

    [Fact]
    public void Anything_validation_accepts_compares_equal_to_a_constant_afterwards()
    {
        // The property that was missing. Stated over the whole accepted set rather than the one spelling
        // that happened to be tried, because the next case-only variant would fail the same way.
        foreach (var known in ConnectionType.All)
        foreach (var spelling in new[] { known, known.ToUpperInvariant(), Capitalise(known) })
        {
            Assert.True(ConnectionType.IsKnown(spelling));

            var stored = ConnectionType.Canonical(spelling);
            Assert.Contains(stored, new[] { ConnectionType.Elasticsearch, ConnectionType.SecurityApi, ConnectionType.Sms });
        }
    }

    [Fact]
    public void An_unknown_type_is_left_alone_for_validation_to_reject()
    {
        // Canonicalising is not validating. Silently rewriting an unrecognised value would hide the very
        // thing the caller needs told, so the string survives to reach the error message.
        Assert.Equal("kafka", ConnectionType.Canonical("kafka"));
        Assert.False(ConnectionType.IsKnown("kafka"));
    }

    private static string Capitalise(string value) => char.ToUpperInvariant(value[0]) + value[1..];
}
