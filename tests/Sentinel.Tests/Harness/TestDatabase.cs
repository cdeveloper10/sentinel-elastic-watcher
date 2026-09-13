using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Tests.Harness;

/// <summary>
/// A real relational database for a test, on SQLite in memory.
///
/// <b>Not</b> EF Core's in-memory provider, and the reason is the whole point of these tests: that
/// provider does not enforce unique indexes. Deduplication and action idempotency are unique indexes —
/// not checks in code that a constraint happens to back up, but the constraint itself — so testing them
/// against a provider that ignores constraints would assert nothing while appearing to pass.
///
/// SQLite differs from PostgreSQL in ways that matter elsewhere (types, collation, concurrency), so this
/// is right for constraint and mapping behaviour and wrong for anything depending on Postgres semantics.
/// Those belong in a test against a real server.
/// </summary>
public sealed class TestDatabase : IDisposable
{
    private readonly string _path;

    public TestDatabase()
    {
        // On disk rather than in memory. An in-memory SQLite database lives inside one connection, so every
        // context would have to share it — and sharing a connection is precisely what these tests must not
        // do, because a duplicate caught by one connection's state proves nothing about a duplicate
        // arriving from another node. A file lets each context open its own.
        _path = Path.Combine(Path.GetTempPath(), $"sentinel-test-{Guid.NewGuid():n}.db");

        Options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseSqlite($"DataSource={_path}")
            .EnableSensitiveDataLogging()
            .Options;

        using var context = NewContext();
        context.Database.EnsureCreated();
    }

    public DbContextOptions<SentinelDbContext> Options { get; }

    /// <summary>
    /// A fresh context each time, sharing the database.
    ///
    /// Sharing one context would hide the bugs these tests exist to find: a second insert of the same
    /// fingerprint would be caught by the change tracker rather than by the database, which is not what
    /// happens when the second insert comes from another node.
    /// </summary>
    public SentinelDbContext NewContext() => new(Options);

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        try
        {
            if (File.Exists(_path))
                File.Delete(_path);
        }
        catch (IOException)
        {
            // A pooled handle outlived the test. The file is in the temp directory and the OS will take
            // it; failing a green test over cleanup would be the wrong trade.
        }
    }
}
