using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Spunk.Core.Query;

public sealed class EngineContext
{
    public DateTime Now { get; init; } = DateTime.UtcNow;
    public Func<SplQuery, List<Dictionary<string, object?>>>? Subsearch { get; init; }
    public Func<string, List<Dictionary<string, string>>>? Lookup { get; init; }
    public Action<string, List<Dictionary<string, object?>>>? SaveLookup { get; init; }
    public IEnumerable<(string Cidr, GeoIp.Place Place)>? Geo { get; init; }
}

public sealed class EngineResult
{
    public string ResultType { get; set; } = "events";
    public List<Dictionary<string, object?>> Rows { get; set; } = [];
    public string? CategoryField { get; set; }
    public string? SplitBy { get; set; }
    public List<string> Measures { get; set; } = [];
}

public static class RowEngine
{
    private static readonly Dictionary<string, string[]> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["src"] = ["src_ip"],
        ["src_ip"] = ["src"],
        ["dest"] = ["dest_ip", "dst", "dst_ip"],
        ["dest_ip"] = ["dest", "dst_ip", "dst"],
        ["dst"] = ["dest", "dest_ip", "dst_ip"],
        ["dst_ip"] = ["dest_ip", "dest", "dst"],
        ["dest_port"] = ["dst_port"],
        ["dst_port"] = ["dest_port"],
        ["dest_zone"] = ["dst_zone"],
        ["dst_zone"] = ["dest_zone"],
        ["user"] = ["src_user"],
        ["src_user"] = ["user"],
        ["message"] = ["message_text"],
        ["message_text"] = ["message"],
        ["severity_description"] = ["severity"],
        ["src_interface"] = ["interface"],
        ["interface"] = ["src_interface"],
        ["vendor_action"] = ["action"],
        ["transport"] = ["protocol"],
        ["protocol"] = ["transport"],
        ["dvc"] = ["host"],
        ["http_category"] = ["category"],
        ["log_subtype"] = ["subtype"],
    };

    public static void ExpandSubsearches(SplQuery query, Func<SplQuery, List<Dictionary<string, object?>>> run)
    {
        for (var i = 0; i < query.Stages.Count; i++)
        {
            query.Stages[i] = query.Stages[i] switch
            {
                SearchStage search => search with { Expr = Expand(search.Expr, run) },
                WhereStage where => where with { Expr = Expand(where.Expr, run) },
                _ => query.Stages[i],
            };
        }
    }

    public static EngineResult Execute(SplQuery query, IReadOnlyList<Dictionary<string, object?>> input, EngineContext ctx)
    {
        var rows = input.Select(Clone).ToList();
        if (query.Earliest != null || query.Latest != null)
        {
            var from = query.Earliest == null ? DateTime.MinValue : RelativeTime.Resolve(query.Earliest, ctx.Now);
            var to = query.Latest == null ? DateTime.MaxValue : RelativeTime.Resolve(query.Latest, ctx.Now);
            rows = rows.Where(row =>
            {
                var time = AsTime(Get(row, "_time"));
                return time != null && time >= from && time < to;
            }).ToList();
        }

        var result = new EngineResult();
        foreach (var stage in query.Stages)
        {
            switch (stage)
            {
                case SearchStage search:
                    rows = rows.Where(row => Match(row, search.Expr)).ToList();
                    break;
                case WhereStage where:
                    rows = rows.Where(row => Match(row, where.Expr)).ToList();
                    break;
                case RexStage rex:
                    rows.ForEach(row => ApplyRex(row, rex));
                    break;
                case EvalStage eval:
                    foreach (var (field, expr) in eval.Assignments)
                    {
                        foreach (var row in rows)
                        {
                            row[field] = Eval(row, expr, ctx);
                        }
                    }
                    break;
                case StatsStage stats:
                    rows = Aggregate(rows, stats.Aggs, stats.By, broadcast: false);
                    result.ResultType = stats.By.Count == 0 && stats.Aggs.Count == 1 ? "single" : "table";
                    result.CategoryField = stats.By.FirstOrDefault();
                    result.Measures = stats.Aggs.Select(AliasOf).ToList();
                    break;
                case EventStatsStage eventStats:
                    rows = Aggregate(rows, eventStats.Aggs, eventStats.By, broadcast: true);
                    break;
                case StreamStatsStage stream:
                    rows = Stream(rows, stream);
                    break;
                case TimechartStage chart:
                    rows = Timechart(rows, chart, ctx);
                    result.ResultType = "timechart";
                    result.CategoryField = "_time";
                    result.SplitBy = chart.By;
                    result.Measures = chart.Aggs.Select(AliasOf).ToList();
                    break;
                case ChartStage chart:
                    rows = Chart(rows, chart);
                    result.ResultType = "table";
                    result.CategoryField = chart.Over;
                    result.Measures = chart.Aggs.Select(AliasOf).ToList();
                    break;
                case BinStage bin:
                    foreach (var row in rows)
                    {
                        row[bin.Field] = Bucket(Get(row, bin.Field), bin);
                    }
                    break;
                case TopStage top:
                    rows = Top(rows, top);
                    result.ResultType = "table";
                    result.CategoryField = top.Field;
                    result.SplitBy = top.By;
                    result.Measures = ["count"];
                    break;
                case TransactionStage transaction:
                    rows = Transact(rows, transaction);
                    result.ResultType = "events";
                    break;
                case JoinStage join:
                    rows = Join(rows, join, ctx);
                    break;
                case AppendStage append:
                    rows.AddRange(ctx.Subsearch?.Invoke(append.Subsearch) ?? []);
                    break;
                case LookupStage lookup:
                    Lookup(rows, lookup, ctx);
                    break;
                case InputLookupStage lookupIn:
                    rows = (ctx.Lookup?.Invoke(StripCsv(lookupIn.Name)) ?? []).Select(ToObjectRow).ToList();
                    result.ResultType = "table";
                    break;
                case OutputLookupStage output:
                    ctx.SaveLookup?.Invoke(StripCsv(output.Name), rows);
                    break;
                case IpLocationStage geo:
                    Geolocate(rows, geo, ctx);
                    break;
                case FillNullStage fill:
                    Fill(rows, fill);
                    break;
                case MakeMvStage make:
                    foreach (var row in rows)
                    {
                        var text = AsText(Get(row, make.Field));
                        row[make.Field] = text == null ? null : text.Split(make.Delimiter, StringSplitOptions.None).Cast<object?>().ToList();
                    }
                    break;
                case MvExpandStage expand:
                    rows = ExpandMv(rows, expand.Field);
                    break;
                case SpathStage spath:
                    rows.ForEach(row => ApplySpath(row, spath));
                    break;
                case FieldsStage fields:
                    rows = Project(rows, fields.Fields, fields.Exclude);
                    break;
                case TableStage table:
                    rows = Project(rows, table.Fields, false);
                    result.ResultType = "table";
                    result.CategoryField ??= table.Fields.FirstOrDefault();
                    break;
                case RenameStage rename:
                    foreach (var row in rows)
                    {
                        foreach (var (from, to) in rename.Names)
                        {
                            row[to] = Get(row, from);
                            if (!from.Equals(to, StringComparison.OrdinalIgnoreCase))
                            {
                                row.Remove(from);
                            }
                        }
                    }
                    break;
                case DedupStage dedup:
                    rows = Dedup(rows, dedup);
                    break;
                case SortStage sort:
                    rows = Sort(rows, sort.Keys);
                    if (sort.Limit is > 0)
                    {
                        rows = rows.Take(sort.Limit.Value).ToList();
                    }
                    break;
                case HeadStage head:
                    rows = rows.Take(head.Limit).ToList();
                    break;
                case TailStage tail:
                    rows = rows.TakeLast(tail.Limit).ToList();
                    break;
                default:
                    throw new QueryException($"Search command '{stage.GetType().Name.Replace("Stage", "", StringComparison.Ordinal).ToLowerInvariant()}' is not supported.");
            }
        }

        result.Rows = rows;
        return result;
    }

    private static Sx Expand(Sx expr, Func<SplQuery, List<Dictionary<string, object?>>> run) => expr switch
    {
        SxSub sub => Constraints(run(sub.Query)),
        SxIn list when list.Subsearch != null => list with { Values = run(list.Subsearch).Select(row => AsText(Get(row, list.Field)) ?? "").Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Take(1000).ToList(), Subsearch = null },
        SxNot not => not with { Inner = Expand(not.Inner, run) },
        SxBool boolean => boolean with { Parts = boolean.Parts.Select(part => Expand(part, run)).ToList() },
        _ => expr,
    };

    private static Sx Constraints(List<Dictionary<string, object?>> rows)
    {
        if (rows.Count == 0)
        {
            return new SxBool("OR", []);
        }

        var parts = new List<Sx>();
        foreach (var row in rows.Take(500))
        {
            var terms = row.Where(pair => pair.Value != null && pair.Key is not ("_time" or "_raw" or "_extra" or "index"))
                .Select(pair => (Sx)new SxTerm(pair.Key, "=", AsText(pair.Value) ?? ""))
                .ToList();
            if (terms.Count == 1)
            {
                parts.Add(terms[0]);
            }
            else if (terms.Count > 1)
            {
                parts.Add(new SxBool("AND", terms));
            }
        }

        return parts.Count == 0 ? new SxBool("OR", []) : new SxBool("OR", parts);
    }

    private static bool Match(Dictionary<string, object?> row, Sx expr) => expr switch
    {
        SxTrue => true,
        SxNot not => !Match(row, not.Inner),
        SxBool { Op: "OR", Parts.Count: 0 } => false,
        SxBool { Op: "AND", Parts.Count: 0 } => true,
        SxBool { Op: "OR" } boolean => boolean.Parts.Any(part => Match(row, part)),
        SxBool boolean => boolean.Parts.All(part => Match(row, part)),
        SxIn list => list.Values.Any(value => ValuesEqual(Get(row, list.Field), value)),
        SxCall call => CallMatches(row, call),
        SxTerm term => TermMatches(row, term),
        _ => false,
    };

    private static bool CallMatches(Dictionary<string, object?> row, SxCall call)
    {
        var field = call.Args.Count > 0 ? Get(row, call.Args[0]) : null;
        return call.Name switch
        {
            "isnull" => field == null || AsText(field) == "",
            "isnotnull" => field != null && AsText(field) != "",
            "like" => Like(AsText(field), call.Args.ElementAtOrDefault(1) ?? ""),
            "cidrmatch" => SplFields.CidrMatch(call.Args.ElementAtOrDefault(0) ?? "", AsText(Get(row, call.Args.ElementAtOrDefault(1) ?? ""))),
            "match" => RegexMatch(AsText(field), call.Args.ElementAtOrDefault(1) ?? ""),
            _ => throw new QueryException($"The function '{call.Name}' is not supported."),
        };
    }

    private static bool TermMatches(Dictionary<string, object?> row, SxTerm term)
    {
        if (term.Field == null)
        {
            var blob = string.Join(" ", new[] { "_raw", "message", "message_text", "host", "sourcetype", "action", "threat_name", "mnemonic", "user", "app" }.Select(name => AsText(Get(row, name))));
            return term.Value.Contains('*') || term.Value.Contains('?')
                ? Wildcard(blob, term.Value)
                : blob.Contains(term.Value, StringComparison.OrdinalIgnoreCase);
        }

        if (term.Field.Equals("index", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (term.Field.Equals("action", StringComparison.OrdinalIgnoreCase) && term.Op is "=" or "!=")
        {
            var vendor = AsText(Get(row, "action"));
            var equal = SplFields.ActionEquals(vendor, term.Value);
            return term.Op == "=" ? equal : !equal;
        }

        if (term.Field.Equals("severity", StringComparison.OrdinalIgnoreCase))
        {
            var id = AsInt(Get(row, "severity_id"));
            return SplFields.SeverityCompare(AsText(Get(row, "severity")), id, term.Op, term.Value);
        }

        var left = Get(row, term.Field);
        if (term.Op is "=" or "!=" && (term.Value.Contains('*') || term.Value.Contains('?')))
        {
            var wild = Wildcard(AsText(left), term.Value);
            return term.Op == "=" ? wild : !wild;
        }

        var compared = Compare(left, term.Value);
        return term.Op switch
        {
            "=" => compared == 0,
            "!=" => compared != 0,
            "<" => compared < 0,
            ">" => compared > 0,
            "<=" => compared <= 0,
            ">=" => compared >= 0,
            _ => false,
        };
    }

    private static List<Dictionary<string, object?>> Aggregate(List<Dictionary<string, object?>> rows, IReadOnlyList<Agg> aggs, IReadOnlyList<string> by, bool broadcast)
    {
        var groups = rows.GroupBy(row => string.Join("\u001f", by.Select(field => AsText(Get(row, field)) ?? "\0")), StringComparer.OrdinalIgnoreCase);
        if (!broadcast)
        {
            return groups.Select(group =>
            {
                var output = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < by.Count; i++)
                {
                    output[by[i]] = Get(group.First(), by[i]);
                }

                foreach (var agg in aggs)
                {
                    output[AliasOf(agg)] = Compute(agg, group.ToList());
                }

                return output;
            }).ToList();
        }

        foreach (var group in groups)
        {
            var members = group.ToList();
            var values = aggs.ToDictionary(AliasOf, agg => Compute(agg, members), StringComparer.OrdinalIgnoreCase);
            foreach (var row in members)
            {
                foreach (var pair in values)
                {
                    row[pair.Key] = pair.Value;
                }
            }
        }

        return rows;
    }

    private static object? Compute(Agg agg, List<Dictionary<string, object?>> rows)
    {
        if (agg.Func.Equals("count", StringComparison.OrdinalIgnoreCase) && agg.Arg == null)
        {
            return (long)rows.Count;
        }

        var values = rows.Select(row => Get(row, agg.Arg ?? "")).Where(value => value != null).ToList();
        return agg.Func.ToLowerInvariant() switch
        {
            "count" => (long)values.Count,
            "dc" => (long)values.Select(AsText).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            "sum" => values.Select(AsDouble).Where(v => v != null).Sum(),
            "avg" => Average(values),
            "min" => values.Select(AsDouble).Where(v => v != null).DefaultIfEmpty().Min(),
            "max" => values.Select(AsDouble).Where(v => v != null).DefaultIfEmpty().Max(),
            "values" => string.Join(", ", values.Select(AsText).Where(v => v != null).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v)),
            "list" => string.Join(", ", values.Select(AsText).Where(v => v != null)),
            "latest" => PickTime(rows, agg.Arg!, true),
            "earliest" => PickTime(rows, agg.Arg!, false),
            "first" => values.Count == 0 ? null : values[0],
            "last" => values.Count == 0 ? null : values[^1],
            "median" => Percentile(values, 50),
            "stdev" or "stdevp" => Stdev(values, agg.Func.Equals("stdevp", StringComparison.OrdinalIgnoreCase)),
            "perc" or "perc50" => Percentile(values, 50),
            "perc95" => Percentile(values, 95),
            "perc99" => Percentile(values, 99),
            _ => throw new QueryException($"The stats function '{agg.Func}' is not supported."),
        };
    }

    private static List<Dictionary<string, object?>> Stream(List<Dictionary<string, object?>> rows, StreamStatsStage stage)
    {
        var state = new Dictionary<string, Queue<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var key = string.Join("\u001f", stage.By.Select(field => AsText(Get(row, field)) ?? ""));
            if (!state.TryGetValue(key, out var window))
            {
                window = new Queue<Dictionary<string, object?>>();
                state[key] = window;
            }

            window.Enqueue(Clone(row));
            while (stage.Window is > 0 && window.Count > stage.Window)
            {
                window.Dequeue();
            }

            var sample = window.ToList();
            foreach (var agg in stage.Aggs)
            {
                row[AliasOf(agg)] = Compute(agg, sample);
            }
        }

        return rows;
    }

    private static List<Dictionary<string, object?>> Timechart(List<Dictionary<string, object?>> rows, TimechartStage stage, EngineContext ctx)
    {
        var span = stage.SpanSeconds ?? 300;
        var origin = rows.Select(row => AsTime(Get(row, "_time"))).Where(time => time != null).Select(time => time!.Value).DefaultIfEmpty(ctx.Now).Min();
        foreach (var row in rows)
        {
            var time = AsTime(Get(row, "_time"));
            if (time == null)
            {
                continue;
            }

            var bucket = (long)Math.Floor((time.Value - origin).TotalSeconds / span) * span;
            row["_time"] = origin.AddSeconds(bucket);
        }

        var by = stage.By == null ? new List<string> { "_time" } : new List<string> { "_time", stage.By };
        return Aggregate(rows.Where(row => Get(row, "_time") != null).ToList(), stage.Aggs, by, false)
            .OrderBy(row => AsTime(Get(row, "_time")))
            .ToList();
    }

    private static List<Dictionary<string, object?>> Chart(List<Dictionary<string, object?>> rows, ChartStage stage)
    {
        if (stage.By == null)
        {
            return Aggregate(rows, stage.Aggs, [stage.Over], false);
        }

        var flat = Aggregate(rows, stage.Aggs, [stage.Over, stage.By], false);
        var measure = AliasOf(stage.Aggs[0]);
        return flat.GroupBy(row => AsText(Get(row, stage.Over)) ?? "", StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var output = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { [stage.Over] = Get(group.First(), stage.Over) };
                foreach (var row in group)
                {
                    output[AsText(Get(row, stage.By)) ?? "null"] = Get(row, measure);
                }

                return output;
            }).ToList();
    }

    private static List<Dictionary<string, object?>> Top(List<Dictionary<string, object?>> rows, TopStage stage)
    {
        var groups = rows.GroupBy(
            row => (stage.By == null ? "" : AsText(Get(row, stage.By)) ?? "") + "\u001f" + (AsText(Get(row, stage.Field)) ?? ""),
            StringComparer.OrdinalIgnoreCase);
        var ranked = (stage.Rare ? groups.OrderBy(group => group.Count()) : groups.OrderByDescending(group => group.Count())).ToList();
        if (stage.By != null)
        {
            ranked = ranked
                .GroupBy(group => AsText(Get(group.First(), stage.By)) ?? "", StringComparer.OrdinalIgnoreCase)
                .SelectMany(group => group.Take(stage.Limit))
                .ToList();
        }
        else
        {
            ranked = ranked.Take(stage.Limit).ToList();
        }

        var ordered = ranked;

        var total = Math.Max(1, rows.Count);
        return ordered.Select(group =>
        {
            var output = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                [stage.Field] = Get(group.First(), stage.Field),
                ["count"] = (long)group.Count(),
            };
            if (stage.By != null)
            {
                output[stage.By] = Get(group.First(), stage.By);
            }

            if (stage.ShowPercent)
            {
                output["percent"] = Math.Round(100.0 * group.Count() / total, 2);
            }

            return output;
        }).ToList();
    }

    private static List<Dictionary<string, object?>> Transact(List<Dictionary<string, object?>> rows, TransactionStage stage)
    {
        var ordered = rows.OrderBy(row => AsTime(Get(row, "_time")) ?? DateTime.MinValue).ToList();
        var open = new Dictionary<string, List<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        var done = new List<List<Dictionary<string, object?>>>();
        foreach (var row in ordered)
        {
            var key = string.Join("\u001f", stage.Fields.Select(field => AsText(Get(row, field)) ?? ""));
            if (!open.TryGetValue(key, out var current))
            {
                open[key] = [row];
                continue;
            }

            var first = AsTime(Get(current[0], "_time"));
            var previous = AsTime(Get(current[^1], "_time"));
            var time = AsTime(Get(row, "_time"));
            var split = false;
            if (stage.MaxPauseSeconds is > 0 && previous != null && time != null && (time.Value - previous.Value).TotalSeconds > stage.MaxPauseSeconds)
            {
                split = true;
            }

            if (stage.MaxSpanSeconds is > 0 && first != null && time != null && (time.Value - first.Value).TotalSeconds > stage.MaxSpanSeconds)
            {
                split = true;
            }

            if (split)
            {
                done.Add(current);
                open[key] = [row];
            }
            else
            {
                current.Add(row);
            }
        }

        done.AddRange(open.Values);
        return done.Select(group =>
        {
            var output = Clone(group[0]);
            var start = AsTime(Get(group[0], "_time"));
            var end = AsTime(Get(group[^1], "_time"));
            output["eventcount"] = group.Count;
            output["duration"] = start != null && end != null ? (end.Value - start.Value).TotalSeconds : 0d;
            return output;
        }).ToList();
    }

    private static List<Dictionary<string, object?>> Join(List<Dictionary<string, object?>> rows, JoinStage stage, EngineContext ctx)
    {
        var right = ctx.Subsearch?.Invoke(stage.Subsearch) ?? [];
        var keys = stage.Fields;
        var map = right.GroupBy(row => string.Join("\u001f", keys.Select(field => AsText(Get(row, field)) ?? "")), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var leftJoin = stage.Type.Equals("left", StringComparison.OrdinalIgnoreCase) || stage.Type.Equals("outer", StringComparison.OrdinalIgnoreCase);
        var output = new List<Dictionary<string, object?>>();
        foreach (var row in rows)
        {
            var key = string.Join("\u001f", keys.Select(field => AsText(Get(row, field)) ?? ""));
            if (map.TryGetValue(key, out var match))
            {
                var combined = Clone(row);
                foreach (var pair in match)
                {
                    if (!combined.ContainsKey(pair.Key) || combined[pair.Key] == null)
                    {
                        combined[pair.Key] = pair.Value;
                    }
                    else if (!keys.Contains(pair.Key, StringComparer.OrdinalIgnoreCase))
                    {
                        combined[pair.Key] = pair.Value;
                    }
                }

                output.Add(combined);
            }
            else if (leftJoin)
            {
                output.Add(Clone(row));
            }
        }

        return output;
    }

    private static void Lookup(List<Dictionary<string, object?>> rows, LookupStage stage, EngineContext ctx)
    {
        var table = ctx.Lookup?.Invoke(StripCsv(stage.Name)) ?? [];
        foreach (var row in rows)
        {
            var match = table.FirstOrDefault(candidate => stage.Keys.All(key =>
                string.Equals(candidate.GetValueOrDefault(key.LookupField), AsText(Get(row, key.EventField)), StringComparison.OrdinalIgnoreCase)));
            if (match == null)
            {
                continue;
            }

            foreach (var (lookupField, output) in stage.Output)
            {
                if (match.TryGetValue(lookupField, out var value))
                {
                    row[output] = value;
                }
            }
        }
    }

    private static void Geolocate(List<Dictionary<string, object?>> rows, IpLocationStage stage, EngineContext ctx)
    {
        var prefix = stage.Prefix ?? "";
        foreach (var row in rows)
        {
            var place = GeoIp.Locate(AsText(Get(row, stage.Field)), ctx.Geo);
            if (place == null)
            {
                continue;
            }

            row[prefix + "Country"] = place.Value.Country;
            row[prefix + "City"] = place.Value.City;
            row[prefix + "Region"] = place.Value.Region;
            row[prefix + "lat"] = place.Value.Lat;
            row[prefix + "lon"] = place.Value.Lon;
        }
    }

    private static void Fill(List<Dictionary<string, object?>> rows, FillNullStage stage)
    {
        var value = stage.Value ?? "0";
        foreach (var row in rows)
        {
            var fields = stage.Fields.Count == 0 ? row.Keys.ToList() : stage.Fields.ToList();
            foreach (var field in fields)
            {
                if (Get(row, field) == null || AsText(Get(row, field)) == "")
                {
                    row[field] = double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ? number : value;
                }
            }
        }
    }

    private static List<Dictionary<string, object?>> ExpandMv(List<Dictionary<string, object?>> rows, string field)
    {
        var output = new List<Dictionary<string, object?>>();
        foreach (var row in rows)
        {
            var value = Get(row, field);
            if (value is IEnumerable<object?> list && value is not string)
            {
                foreach (var item in list)
                {
                    var copy = Clone(row);
                    copy[field] = item;
                    output.Add(copy);
                }
            }
            else
            {
                output.Add(row);
            }
        }

        return output;
    }

    private static void ApplyRex(Dictionary<string, object?> row, RexStage stage)
    {
        var sourceName = stage.Field ?? "_raw";
        var text = AsText(Get(row, sourceName)) ?? "";
        if (stage.Sed)
        {
            var match = Regex.Match(stage.Pattern, @"^s/(.*?)/(.*?)/([gi]*)$");
            if (!match.Success)
            {
                throw new QueryException("mode=sed expects a s/pattern/replacement/flags expression.");
            }

            var options = match.Groups[3].Value.Contains('i') ? RegexOptions.IgnoreCase : RegexOptions.None;
            var replaced = Regex.Replace(text, match.Groups[1].Value, match.Groups[2].Value.Replace("\\", "$", StringComparison.Ordinal), options);
            row[sourceName] = replaced;
            return;
        }

        var found = Regex.Match(text, stage.Pattern, RegexOptions.IgnoreCase);
        if (!found.Success)
        {
            return;
        }

        foreach (var name in found.Groups.Keys)
        {
            if (name.Length == 0 || char.IsDigit(name[0]))
            {
                continue;
            }

            row[name] = found.Groups[name].Value;
        }
    }

    private static void ApplySpath(Dictionary<string, object?> row, SpathStage stage)
    {
        var text = AsText(Get(row, stage.Input ?? "_raw"));
        if (string.IsNullOrWhiteSpace(text) || !text.TrimStart().StartsWith('{') && !text.TrimStart().StartsWith('['))
        {
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(text);
            if (stage.Path == null)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    return;
                }

                foreach (var property in doc.RootElement.EnumerateObject())
                {
                    row[property.Name] = property.Value.ToString();
                }

                return;
            }

            var node = doc.RootElement;
            foreach (var part in stage.Path.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                if (node.ValueKind != JsonValueKind.Object || !node.TryGetProperty(part, out node))
                {
                    return;
                }
            }

            row[stage.Output ?? stage.Path] = node.ToString();
        }
        catch (JsonException)
        {
        }
    }

    private static object? Eval(Dictionary<string, object?> row, Ex expr, EngineContext ctx) => expr switch
    {
        ExNum number => number.Value,
        ExStr text => text.Value,
        ExField field => Get(row, field.Name),
        ExBin bin => Arithmetic(Eval(row, bin.Left, ctx), Eval(row, bin.Right, ctx), bin.Op),
        ExCmp cmp => CompareOp(Eval(row, cmp.Left, ctx), Eval(row, cmp.Right, ctx), cmp.Op),
        ExIf iff => Truthy(EvalCmp(row, iff, ctx)) ? Eval(row, iff.Then, ctx) : Eval(row, iff.Else, ctx),
        ExCall call => EvalCall(row, call, ctx),
        _ => null,
    };

    private static bool EvalCmp(Dictionary<string, object?> row, ExIf expr, EngineContext ctx)
    {
        var left = Eval(row, expr.Left, ctx);
        var right = AsText(Eval(row, expr.Right, ctx)) ?? "";
        var compared = Compare(left, right);
        return expr.Op switch
        {
            "=" or "==" => compared == 0,
            "!=" => compared != 0,
            "<" => compared < 0,
            ">" => compared > 0,
            "<=" => compared <= 0,
            ">=" => compared >= 0,
            _ => false,
        };
    }

    private static object? EvalCall(Dictionary<string, object?> row, ExCall call, EngineContext ctx)
    {
        var args = call.Args.Select(arg => Eval(row, arg, ctx)).ToList();
        return call.Name switch
        {
            "lower" => AsText(args.ElementAtOrDefault(0))?.ToLowerInvariant(),
            "upper" => AsText(args.ElementAtOrDefault(0))?.ToUpperInvariant(),
            "len" => (long)(AsText(args.ElementAtOrDefault(0))?.Length ?? 0),
            "tonumber" => AsDouble(args.ElementAtOrDefault(0)),
            "tostring" => AsText(args.ElementAtOrDefault(0)),
            "coalesce" => args.FirstOrDefault(value => value != null && AsText(value) != ""),
            "round" => Round(AsDouble(args.ElementAtOrDefault(0)), args.Count > 1 ? (int)(AsDouble(args[1]) ?? 0) : 0),
            "substr" => Substr(AsText(args.ElementAtOrDefault(0)), (int)(AsDouble(args.ElementAtOrDefault(1)) ?? 1), args.Count > 2 ? (int?)AsDouble(args[2]) : null),
            "replace" => Regex.Replace(AsText(args.ElementAtOrDefault(0)) ?? "", args.ElementAtOrDefault(1)?.ToString() ?? "", args.ElementAtOrDefault(2)?.ToString() ?? ""),
            "now" => ctx.Now,
            "true" => true,
            "false" => false,
            "null" => null,
            "cidrmatch" => SplFields.CidrMatch(AsText(args.ElementAtOrDefault(0)) ?? "", AsText(args.ElementAtOrDefault(1))),
            "match" => RegexMatch(AsText(args.ElementAtOrDefault(0)), AsText(args.ElementAtOrDefault(1)) ?? ""),
            "split" => (AsText(args.ElementAtOrDefault(0)) ?? "").Split(AsText(args.ElementAtOrDefault(1)) ?? ",", StringSplitOptions.None).Cast<object?>().ToList(),
            "mvcount" => MvCount(args.ElementAtOrDefault(0)),
            "relative_time" => Relative(args.ElementAtOrDefault(0), AsText(args.ElementAtOrDefault(1)) ?? "now", ctx),
            "strftime" => FormatTime(args.ElementAtOrDefault(0), AsText(args.ElementAtOrDefault(1)) ?? "%Y-%m-%d"),
            "strptime" => ParseTime(AsText(args.ElementAtOrDefault(0)), AsText(args.ElementAtOrDefault(1)) ?? "%Y-%m-%d %H:%M:%S"),
            "case" => Case(call.Args, row, ctx),
            _ => throw new QueryException($"The eval function '{call.Name}' is not supported."),
        };
    }

    private static object? Case(IReadOnlyList<Ex> args, Dictionary<string, object?> row, EngineContext ctx)
    {
        for (var i = 0; i + 1 < args.Count; i += 2)
        {
            var cond = args[i] is ExCmp or ExIf ? Eval(row, args[i], ctx) : Eval(row, args[i], ctx);
            if (Truthy(cond))
            {
                return Eval(row, args[i + 1], ctx);
            }
        }

        return null;
    }

    private static bool Truthy(object? value) => value switch
    {
        bool bit => bit,
        null => false,
        string text => text.Length > 0 && !text.Equals("false", StringComparison.OrdinalIgnoreCase) && text != "0",
        _ => AsDouble(value) is not 0 and not null,
    };

    private static object? Bucket(object? value, BinStage stage)
    {
        var time = AsTime(value);
        if (time != null && stage.SpanSeconds is > 0)
        {
            var origin = new DateTime(time.Value.Year, time.Value.Month, time.Value.Day, 0, 0, 0, DateTimeKind.Utc);
            var bucket = (long)Math.Floor((time.Value - origin).TotalSeconds / stage.SpanSeconds.Value) * stage.SpanSeconds.Value;
            return origin.AddSeconds(bucket);
        }

        var number = AsDouble(value);
        var span = stage.SpanNumber ?? stage.SpanSeconds ?? 1;
        if (number == null || span <= 0)
        {
            return value;
        }

        return Math.Floor(number.Value / span) * span;
    }

    private static List<Dictionary<string, object?>> Project(List<Dictionary<string, object?>> rows, IReadOnlyList<string> fields, bool exclude)
    {
        return rows.Select(row =>
        {
            var output = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            if (exclude)
            {
                foreach (var pair in row)
                {
                    if (!fields.Contains(pair.Key, StringComparer.OrdinalIgnoreCase))
                    {
                        output[pair.Key] = pair.Value;
                    }
                }
            }
            else
            {
                foreach (var field in fields)
                {
                    output[field] = Get(row, field);
                }
            }

            return output;
        }).ToList();
    }

    private static List<Dictionary<string, object?>> Dedup(List<Dictionary<string, object?>> rows, DedupStage stage)
    {
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var output = new List<Dictionary<string, object?>>();
        foreach (var row in rows)
        {
            var key = string.Join("\u001f", stage.Fields.Select(field => AsText(Get(row, field)) ?? ""));
            seen.TryGetValue(key, out var count);
            if (count < stage.Keep)
            {
                seen[key] = count + 1;
                output.Add(row);
            }
        }

        return output;
    }

    private static List<Dictionary<string, object?>> Sort(List<Dictionary<string, object?>> rows, IReadOnlyList<SortKey> keys)
    {
        IOrderedEnumerable<Dictionary<string, object?>>? ordered = null;
        foreach (var key in keys)
        {
            object? Selector(Dictionary<string, object?> row) => Get(row, key.Field);
            if (ordered == null)
            {
                ordered = key.Descending
                    ? rows.OrderByDescending(Selector, Comparer<object?>.Create(CompareObjects))
                    : rows.OrderBy(Selector, Comparer<object?>.Create(CompareObjects));
            }
            else
            {
                ordered = key.Descending
                    ? ordered.ThenByDescending(Selector, Comparer<object?>.Create(CompareObjects))
                    : ordered.ThenBy(Selector, Comparer<object?>.Create(CompareObjects));
            }
        }

        return (ordered ?? rows.OrderBy(_ => 0)).ToList();
    }

    private static object? Get(Dictionary<string, object?> row, string name)
    {
        if (row.TryGetValue(name, out var value) && value != null)
        {
            return value;
        }

        if (name.Equals("cim_action", StringComparison.OrdinalIgnoreCase))
        {
            return SplFields.CimAction(AsText(row.GetValueOrDefault("action") ?? row.GetValueOrDefault("vendor_action")));
        }

        if (Aliases.TryGetValue(name, out var aliases))
        {
            foreach (var alias in aliases)
            {
                if (row.TryGetValue(alias, out value) && value != null)
                {
                    return value;
                }
            }
        }

        return row.TryGetValue(name, out value) ? value : null;
    }

    private static Dictionary<string, object?> Clone(Dictionary<string, object?> row) =>
        new(row, StringComparer.OrdinalIgnoreCase);

    private static Dictionary<string, object?> ToObjectRow(Dictionary<string, string> row) =>
        row.ToDictionary(pair => pair.Key, pair => (object?)pair.Value, StringComparer.OrdinalIgnoreCase);

    private static string AliasOf(Agg agg) =>
        agg.Alias ?? (agg.Func.Equals("count", StringComparison.OrdinalIgnoreCase) && agg.Arg == null ? "count" : agg.Func + "_" + agg.Arg);

    private static string StripCsv(string name) => name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;

    private static object? PickTime(List<Dictionary<string, object?>> rows, string field, bool latest)
    {
        Dictionary<string, object?>? chosen = null;
        DateTime? mark = null;
        foreach (var row in rows)
        {
            var time = AsTime(Get(row, "_time")) ?? DateTime.MinValue;
            if (mark == null || (latest ? time > mark : time < mark))
            {
                mark = time;
                chosen = row;
            }
        }

        return chosen == null ? null : Get(chosen, field);
    }

    private static double? Average(List<object?> values)
    {
        var nums = values.Select(AsDouble).Where(v => v != null).Select(v => v!.Value).ToList();
        return nums.Count == 0 ? null : nums.Average();
    }

    private static double? Percentile(List<object?> values, double percentile)
    {
        var nums = values.Select(AsDouble).Where(v => v != null).Select(v => v!.Value).OrderBy(v => v).ToList();
        if (nums.Count == 0)
        {
            return null;
        }

        var rank = (percentile / 100d) * (nums.Count - 1);
        var low = (int)Math.Floor(rank);
        var high = (int)Math.Ceiling(rank);
        if (low == high)
        {
            return nums[low];
        }

        return nums[low] + (rank - low) * (nums[high] - nums[low]);
    }

    private static double? Stdev(List<object?> values, bool population)
    {
        var nums = values.Select(AsDouble).Where(v => v != null).Select(v => v!.Value).ToList();
        if (nums.Count < 2)
        {
            return null;
        }

        var mean = nums.Average();
        var sum = nums.Sum(value => (value - mean) * (value - mean));
        return Math.Sqrt(sum / (population ? nums.Count : nums.Count - 1));
    }

    private static double? Round(double? value, int digits) =>
        value == null ? null : Math.Round(value.Value, digits, MidpointRounding.AwayFromZero);

    private static string? Substr(string? text, int start, int? length)
    {
        if (text == null)
        {
            return null;
        }

        var index = Math.Max(0, start - 1);
        if (index >= text.Length)
        {
            return "";
        }

        var count = length == null ? text.Length - index : Math.Min(length.Value, text.Length - index);
        return text.Substring(index, Math.Max(0, count));
    }

    private static long MvCount(object? value) => value switch
    {
        IEnumerable<object?> list when value is not string => list.Count(),
        string text when text.Length > 0 => 1,
        _ => 0,
    };

    private static DateTime? Relative(object? time, string modifier, EngineContext ctx)
    {
        var origin = AsTime(time) ?? ctx.Now;
        return RelativeTime.Resolve(modifier, origin);
    }

    private static string? FormatTime(object? time, string format)
    {
        var value = AsTime(time);
        return value?.ToString(SplunkTime(format), CultureInfo.InvariantCulture);
    }

    private static DateTime? ParseTime(string? text, string format)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        return DateTime.TryParseExact(text, SplunkTime(format), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
    }

    private static string SplunkTime(string format) => format
        .Replace("%Y", "yyyy", StringComparison.Ordinal)
        .Replace("%m", "MM", StringComparison.Ordinal)
        .Replace("%d", "dd", StringComparison.Ordinal)
        .Replace("%H", "HH", StringComparison.Ordinal)
        .Replace("%M", "mm", StringComparison.Ordinal)
        .Replace("%S", "ss", StringComparison.Ordinal)
        .Replace("%F", "yyyy-MM-dd", StringComparison.Ordinal)
        .Replace("%T", "HH:mm:ss", StringComparison.Ordinal);

    private static object? Arithmetic(object? left, object? right, string op)
    {
        var a = AsDouble(left);
        var b = AsDouble(right);
        if (a == null || b == null)
        {
            return null;
        }

        return op switch
        {
            "+" => a + b,
            "-" => a - b,
            "*" => a * b,
            "/" => b == 0 ? null : a / b,
            _ => null,
        };
    }

    private static bool CompareOp(object? left, object? right, string op)
    {
        var compared = Compare(left, AsText(right) ?? "");
        return op switch
        {
            "=" or "==" => compared == 0,
            "!=" => compared != 0,
            "<" => compared < 0,
            ">" => compared > 0,
            "<=" => compared <= 0,
            ">=" => compared >= 0,
            _ => false,
        };
    }

    private static int Compare(object? left, string right)
    {
        var number = AsDouble(left);
        if (number != null && double.TryParse(right, NumberStyles.Float, CultureInfo.InvariantCulture, out var other))
        {
            return number.Value.CompareTo(other);
        }

        var time = AsTime(left);
        if (time != null && DateTime.TryParse(right, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var otherTime))
        {
            return time.Value.CompareTo(otherTime);
        }

        return string.Compare(AsText(left), right, StringComparison.OrdinalIgnoreCase);
    }

    private static int CompareObjects(object? left, object? right)
    {
        if (left == null && right == null)
        {
            return 0;
        }

        if (left == null)
        {
            return -1;
        }

        if (right == null)
        {
            return 1;
        }

        var a = AsDouble(left);
        var b = AsDouble(right);
        if (a != null && b != null)
        {
            return a.Value.CompareTo(b.Value);
        }

        return string.Compare(AsText(left), AsText(right), StringComparison.OrdinalIgnoreCase);
    }

    private static bool ValuesEqual(object? left, string right) => Compare(left, right) == 0;

    private static bool Like(string? text, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern).Replace("%", ".*", StringComparison.Ordinal).Replace("_", ".", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(text ?? "", regex, RegexOptions.IgnoreCase);
    }

    private static bool Wildcard(string? text, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*", StringComparison.Ordinal).Replace("\\?", ".", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(text ?? "", regex, RegexOptions.IgnoreCase);
    }

    private static bool RegexMatch(string? text, string pattern)
    {
        try
        {
            return Regex.IsMatch(text ?? "", pattern, RegexOptions.IgnoreCase);
        }
        catch (RegexParseException)
        {
            return false;
        }
    }

    private static string? AsText(object? value) => value switch
    {
        null => null,
        string text => text,
        DateTime time => time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        bool bit => bit ? "true" : "false",
        IEnumerable<object?> list when value is not string => string.Join(",", list.Select(AsText)),
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString(),
    };

    private static double? AsDouble(object? value)
    {
        if (value == null)
        {
            return null;
        }

        if (value is bool)
        {
            return null;
        }

        return double.TryParse(AsText(value), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ? number : null;
    }

    private static int? AsInt(object? value) => AsDouble(value) is { } number ? (int)number : null;

    private static DateTime? AsTime(object? value) => value switch
    {
        DateTime time => time.Kind == DateTimeKind.Utc ? time : DateTime.SpecifyKind(time, DateTimeKind.Utc),
        string text when DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed) => parsed,
        _ => null,
    };
}
