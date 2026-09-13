using Microsoft.AspNetCore.Http;
using Sentinel.Api;

namespace Sentinel.Tests.Api;

/// <summary>
/// A caller's mistake is answered as a caller's mistake.
///
/// Found by calling field discovery with the wrong query-parameter name. The answer was 500 and "An error
/// occurred while processing your request" — so the client could not tell it had sent something wrong, and
/// the request counted against the platform's error rate. ASP.NET Core had already decided the right
/// status and put it on the exception; the default exception handler threw that away.
/// </summary>
public class RequestFailureTests
{
    [Fact]
    public void A_missing_query_parameter_is_the_caller_s_fault()
    {
        var thrown = new BadHttpRequestException(
            "Required parameter \"string patterns\" was not provided from query string.",
            StatusCodes.Status400BadRequest);

        Assert.Equal(StatusCodes.Status400BadRequest, RequestFailure.StatusFor(thrown));
    }

    [Fact]
    public void A_body_too_large_keeps_the_status_it_was_raised_with()
    {
        // Not every BadHttpRequestException is a 400 — this one is 413, and hard-coding 400 would be the
        // same class of mistake as hard-coding 500.
        var thrown = new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, RequestFailure.StatusFor(thrown));
    }

    [Fact]
    public void Anything_else_is_the_platform_s_fault()
    {
        Assert.Equal(StatusCodes.Status500InternalServerError,
            RequestFailure.StatusFor(new InvalidOperationException("The connection is not an event source.")));

        Assert.Equal(StatusCodes.Status500InternalServerError, RequestFailure.StatusFor(null));
    }

    [Fact]
    public void Only_a_4xx_repeats_the_message_it_was_given()
    {
        // The 4xx message describes the request the caller sent. A 500's can name a connection string, a
        // path or a row, and the caller is not the one who needs to read it.
        Assert.True(RequestFailure.MayDisclose(StatusCodes.Status400BadRequest));
        Assert.True(RequestFailure.MayDisclose(StatusCodes.Status413PayloadTooLarge));
        Assert.False(RequestFailure.MayDisclose(StatusCodes.Status500InternalServerError));
        Assert.False(RequestFailure.MayDisclose(StatusCodes.Status503ServiceUnavailable));
    }
}
