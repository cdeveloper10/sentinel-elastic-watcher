namespace Sentinel.Api;

/// <summary>
/// What status an unhandled exception deserves.
///
/// Its own type rather than a lambda in the pipeline so it can be stated as a property and tested: the
/// distinction it draws — the caller's mistake against the platform's — decides both what the client is
/// told and what pages an operator at three in the morning.
/// </summary>
public static class RequestFailure
{
    /// <summary>
    /// A malformed request carries the status it deserves. ASP.NET Core raises
    /// <see cref="BadHttpRequestException"/> with a 4xx on it for a missing required query parameter, an
    /// unparseable route value or a body that is not the JSON the endpoint declared — and the default
    /// exception handler discards that and answers 500. Everything else is genuinely a fault here.
    /// </summary>
    public static int StatusFor(Exception? thrown) => thrown is BadHttpRequestException bad
        ? bad.StatusCode
        : StatusCodes.Status500InternalServerError;

    /// <summary>
    /// Whether the exception's own message may be repeated to the caller.
    ///
    /// True only below 500, where the message describes the request that was sent — "Required parameter
    /// 'patterns' was not provided from query string" is exactly what the caller needs. An unexpected
    /// exception's message can name a connection string, a file path or a row, so it stays in the log.
    /// </summary>
    public static bool MayDisclose(int status) => status < StatusCodes.Status500InternalServerError;
}
