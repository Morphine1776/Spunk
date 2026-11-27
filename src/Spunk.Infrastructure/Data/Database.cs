using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Spunk.Infrastructure.Data;

public static partial class Database
{
    public static async Task<string> EnsureDatabaseAsync(string connectionString, CancellationToken ct = default)
    {
        var builder = new SqlConnectionStringBuilder(connectionString);
        var name = string.IsNullOrWhiteSpace(builder.InitialCatalog) ? "Spunk" : builder.InitialCatalog;
        if (!NameRegex().IsMatch(name))
        {
            throw new InvalidOperationException("Database name must be letters, digits, or underscore.");
        }

        builder.InitialCatalog = "master";
        await using (var master = new SqlConnection(builder.ConnectionString))
        {
            await master.OpenAsync(ct);
            await using var create = master.CreateCommand();
            create.CommandText = $"IF DB_ID(N'{name}') IS NULL CREATE DATABASE [{name}]";
            await create.ExecuteNonQueryAsync(ct);
        }

        builder.InitialCatalog = name;
        await using (var db = new SqlConnection(builder.ConnectionString))
        {
            await db.OpenAsync(ct);
            await using var rcsi = db.CreateCommand();
            rcsi.CommandText = $"IF (SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = @name) = 0 ALTER DATABASE [{name}] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE";
            rcsi.Parameters.AddWithValue("@name", name);
            try
            {
                await rcsi.ExecuteNonQueryAsync(ct);
            }
            catch (SqlException)
            {
                // Another session can block the alter; queries still run without snapshot isolation.
            }
        }

        return builder.ConnectionString;
    }

    public static async Task MigrateAsync(string connectionString, CancellationToken ct = default)
    {
        connectionString = await EnsureDatabaseAsync(connectionString, ct);
        var assembly = typeof(Database).Assembly;
        var resources = assembly.GetManifestResourceNames()
            .Where(n => n.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        await using var conn = new SqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using (var ensure = conn.CreateCommand())
        {
            ensure.CommandText = """
                IF OBJECT_ID(N'dbo.SchemaMigrations', N'U') IS NULL
                CREATE TABLE dbo.SchemaMigrations (
                    Name nvarchar(200) NOT NULL CONSTRAINT PK_SchemaMigrations PRIMARY KEY,
                    AppliedUtc datetime2(3) NOT NULL CONSTRAINT DF_SchemaMigrations_Applied DEFAULT SYSUTCDATETIME()
                );
                """;
            await ensure.ExecuteNonQueryAsync(ct);
        }

        foreach (var resource in resources)
        {
            var name = resource.Split('.').Reverse().Skip(1).First();
            await using var check = conn.CreateCommand();
            check.CommandText = "SELECT 1 FROM dbo.SchemaMigrations WHERE Name = @name";
            check.Parameters.AddWithValue("@name", name);
            if (await check.ExecuteScalarAsync(ct) != null)
            {
                continue;
            }

            await using var stream = assembly.GetManifestResourceStream(resource) ?? throw new InvalidOperationException($"Missing {resource}");
            using var reader = new StreamReader(stream);
            var sql = await reader.ReadToEndAsync(ct);
            await using var tx = (SqlTransaction)await conn.BeginTransactionAsync(ct);
            try
            {
                foreach (var batch in GoRegex().Split(sql))
                {
                    var text = batch.Trim();
                    if (text.Length == 0)
                    {
                        continue;
                    }

                    await using var cmd = conn.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandTimeout = 180;
                    cmd.CommandText = text;
                    await cmd.ExecuteNonQueryAsync(ct);
                }

                await using var mark = conn.CreateCommand();
                mark.Transaction = tx;
                mark.CommandText = "INSERT INTO dbo.SchemaMigrations (Name) VALUES (@name)";
                mark.Parameters.AddWithValue("@name", name);
                await mark.ExecuteNonQueryAsync(ct);
                await tx.CommitAsync(ct);
            }
            catch
            {
                await tx.RollbackAsync(ct);
                throw;
            }
        }
    }

    public static void AddParameters(SqlCommand command, IEnumerable<Spunk.Core.Query.QueryParameter> parameters)
    {
        foreach (var parameter in parameters)
        {
            var type = parameter.Type switch
            {
                Spunk.Core.Query.ParamType.BigInt => System.Data.SqlDbType.BigInt,
                Spunk.Core.Query.ParamType.Float => System.Data.SqlDbType.Float,
                Spunk.Core.Query.ParamType.DateTime2 => System.Data.SqlDbType.DateTime2,
                Spunk.Core.Query.ParamType.Int => System.Data.SqlDbType.Int,
                _ => System.Data.SqlDbType.NVarChar,
            };
            var sqlParameter = command.Parameters.Add(parameter.Name, type);
            if (type == System.Data.SqlDbType.NVarChar)
            {
                sqlParameter.Size = -1;
            }

            sqlParameter.Value = parameter.Value ?? DBNull.Value;
        }
    }

    [GeneratedRegex(@"^[A-Za-z0-9_]+$")]
    private static partial Regex NameRegex();

    [GeneratedRegex(@"^\s*GO\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex GoRegex();
}
