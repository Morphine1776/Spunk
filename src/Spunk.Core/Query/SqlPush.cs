namespace Spunk.Core.Query;

public static class SqlPush
{
    private static readonly HashSet<string> SqlAggs = new(StringComparer.OrdinalIgnoreCase)
    {
        "count", "dc", "sum", "avg", "min", "max", "values",
    };

    private static readonly HashSet<string> SqlEval = new(StringComparer.OrdinalIgnoreCase)
    {
        "lower", "upper", "len", "tonumber", "tostring", "coalesce", "if",
    };

    public static bool CanFullyPush(SplQuery query)
    {
        foreach (var stage in query.Stages)
        {
            switch (stage)
            {
                case SearchStage search when !FilterPushable(search.Expr):
                case WhereStage where when !FilterPushable(where.Expr):
                    return false;
                case StatsStage stats when stats.Aggs.Any(a => !SqlAggs.Contains(a.Func)):
                case TimechartStage chart when chart.Aggs.Any(a => !SqlAggs.Contains(a.Func)):
                    return false;
                case EvalStage eval when eval.Assignments.Any(a => !EvalPushable(a.Expr)):
                    return false;
                case SearchStage or WhereStage or StatsStage or TimechartStage or TopStage or TableStage
                    or FieldsStage or SortStage or HeadStage or TailStage or RenameStage or DedupStage or EvalStage:
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    public static bool FilterPushable(Sx expr) => expr switch
    {
        SxTrue => true,
        SxNot not => FilterPushable(not.Inner),
        SxBool boolean => boolean.Parts.All(FilterPushable),
        SxTerm => true,
        SxIn list => list.Subsearch == null,
        SxCall call => call.Name is "isnull" or "isnotnull" or "like",
        _ => false,
    };

    private static bool EvalPushable(Ex expr) => expr switch
    {
        ExNum or ExStr or ExField => true,
        ExBin bin => EvalPushable(bin.Left) && EvalPushable(bin.Right),
        ExIf iff => EvalPushable(iff.Left) && EvalPushable(iff.Right) && EvalPushable(iff.Then) && EvalPushable(iff.Else),
        ExCall call => SqlEval.Contains(call.Name) && call.Args.All(EvalPushable),
        _ => false,
    };
}
