namespace Spunk.Core.Query;

public sealed class QueryException : Exception
{
    public QueryException(string message) : base(message)
    {
    }
}

public enum ColType { String, Int64, Float, DateTime }

public enum ParamType { NVarChar, BigInt, Float, DateTime2, Int }

public sealed record QueryParameter(string Name, object? Value, ParamType Type);

public sealed class SplQuery
{
    public List<SplStage> Stages { get; } = [];
    public string? Earliest { get; set; }
    public string? Latest { get; set; }
}

public abstract record SplStage;

public sealed record SearchStage(Sx Expr) : SplStage;

public sealed record WhereStage(Sx Expr) : SplStage;

public sealed record Agg(string Func, string? Arg, string? Alias);

public sealed record StatsStage(IReadOnlyList<Agg> Aggs, IReadOnlyList<string> By) : SplStage;

public sealed record TimechartStage(int? SpanSeconds, IReadOnlyList<Agg> Aggs, string? By) : SplStage;

public sealed record TopStage(int Limit, string Field, string? By, bool Rare, bool ShowPercent = true) : SplStage;

public sealed record TableStage(IReadOnlyList<string> Fields) : SplStage;

public sealed record FieldsStage(IReadOnlyList<string> Fields, bool Exclude) : SplStage;

public sealed record SortKey(string Field, bool Descending);

public sealed record SortStage(IReadOnlyList<SortKey> Keys, int? Limit) : SplStage;

public sealed record HeadStage(int Limit) : SplStage;

public sealed record TailStage(int Limit) : SplStage;

public sealed record RenameStage(IReadOnlyList<(string From, string To)> Names) : SplStage;

public sealed record DedupStage(int Keep, IReadOnlyList<string> Fields) : SplStage;

public sealed record EvalStage(IReadOnlyList<(string Field, Ex Expr)> Assignments) : SplStage;

public sealed record EventStatsStage(IReadOnlyList<Agg> Aggs, IReadOnlyList<string> By) : SplStage;

public sealed record StreamStatsStage(IReadOnlyList<Agg> Aggs, IReadOnlyList<string> By, int? Window) : SplStage;

public sealed record TransactionStage(IReadOnlyList<string> Fields, int? MaxSpanSeconds, int? MaxPauseSeconds) : SplStage;

public sealed record JoinStage(string Type, IReadOnlyList<string> Fields, SplQuery Subsearch) : SplStage;

public sealed record AppendStage(SplQuery Subsearch) : SplStage;

public sealed record LookupStage(string Name, IReadOnlyList<(string EventField, string LookupField)> Keys, IReadOnlyList<(string LookupField, string Output)> Output) : SplStage;

public sealed record InputLookupStage(string Name) : SplStage;

public sealed record OutputLookupStage(string Name) : SplStage;

public sealed record IpLocationStage(string Field, string? Prefix) : SplStage;

public sealed record BinStage(string Field, int? SpanSeconds, double? SpanNumber) : SplStage;

public sealed record ChartStage(IReadOnlyList<Agg> Aggs, string Over, string? By) : SplStage;

public sealed record FillNullStage(string? Value, IReadOnlyList<string> Fields) : SplStage;

public sealed record MakeMvStage(string Field, string Delimiter) : SplStage;

public sealed record MvExpandStage(string Field) : SplStage;

public sealed record SpathStage(string? Input, string? Path, string? Output) : SplStage;

public sealed record RexStage(string? Field, string Pattern, bool Sed) : SplStage;

public abstract record Sx;

public sealed record SxTrue : Sx;

public sealed record SxNot(Sx Inner) : Sx;

public sealed record SxBool(string Op, IReadOnlyList<Sx> Parts) : Sx;

public sealed record SxTerm(string? Field, string Op, string Value) : Sx;

public sealed record SxCall(string Name, IReadOnlyList<string> Args) : Sx;

public sealed record SxIn(string Field, IReadOnlyList<string> Values, SplQuery? Subsearch) : Sx;

public sealed record SxSub(SplQuery Query) : Sx;

public abstract record Ex;

public sealed record ExNum(double Value) : Ex;

public sealed record ExStr(string Value) : Ex;

public sealed record ExField(string Name) : Ex;

public sealed record ExBin(string Op, Ex Left, Ex Right) : Ex;

public sealed record ExCall(string Name, IReadOnlyList<Ex> Args) : Ex;

public sealed record ExIf(Ex Left, string Op, Ex Right, Ex Then, Ex Else) : Ex;

public sealed record ExCmp(Ex Left, string Op, Ex Right) : Ex;

public sealed class CompiledQuery
{
    public required string Sql { get; init; }
    public string? CountSql { get; init; }
    public required string TimelineSql { get; init; }
    public required string FilterSql { get; init; }
    public required IReadOnlyList<QueryParameter> Parameters { get; init; }
    public required string ResultType { get; init; }
    public string? CategoryField { get; init; }
    public string? SplitBy { get; init; }
    public IReadOnlyList<string> Measures { get; init; } = [];
    public int TimelineSpanSeconds { get; init; }
    public int RowLimit { get; init; }
}
