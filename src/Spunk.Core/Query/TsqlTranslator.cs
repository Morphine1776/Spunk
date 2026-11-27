using System.Globalization;
using System.Text;

namespace Spunk.Core.Query;

public static class TsqlTranslator
{
    public static CompiledQuery Compile(SplQuery query, DateTime fromUtc, DateTime toUtc, int maxRows)
    {
        if (fromUtc >= toUtc)
        {
            throw new QueryException("Time range is empty.");
        }

        return new Compiler(DateTime.SpecifyKind(fromUtc, DateTimeKind.Utc), DateTime.SpecifyKind(toUtc, DateTimeKind.Utc), Math.Clamp(maxRows, 1, 50_000)).Compile(query);
    }

    private sealed class Compiler
    {
        private static readonly FieldDef[] Projection =
        [
            new("_time", "EventTime", ColType.DateTime),
            new("_received", "ReceivedTime", ColType.DateTime),
            new("host", "Host", ColType.String),
            new("source", "SourceIp", ColType.String),
            new("sourcetype", "Sourcetype", ColType.String),
            new("vendor", "Vendor", ColType.String),
            new("severity", "SeverityName", ColType.String),
            new("facility", "FacilityName", ColType.String),
            new("appname", "AppName", ColType.String),
            new("mnemonic", "Mnemonic", ColType.String),
            new("message", "Message", ColType.String),
            new("_raw", "Raw", ColType.String),
            new("src_ip", "SrcIp", ColType.String),
            new("src", "SrcIp", ColType.String),
            new("dst_ip", "DstIp", ColType.String),
            new("dst", "DstIp", ColType.String),
            new("dest_ip", "DstIp", ColType.String),
            new("dest", "DstIp", ColType.String),
            new("src_port", "SrcPort", ColType.Int64),
            new("dst_port", "DstPort", ColType.Int64),
            new("dest_port", "DstPort", ColType.Int64),
            new("src_zone", "SrcZone", ColType.String),
            new("dst_zone", "DstZone", ColType.String),
            new("dest_zone", "DstZone", ColType.String),
            new("protocol", "Protocol", ColType.String),
            new("transport", "Protocol", ColType.String),
            new("action", "Action", ColType.String),
            new("vendor_action", "Action", ColType.String),
            new("cim_action", SplFields.CimActionSql, ColType.String),
            new("rule", "RuleName", ColType.String),
            new("app", "Application", ColType.String),
            new("user", "UserName", ColType.String),
            new("src_user", "UserName", ColType.String),
            new("dvc", "Host", ColType.String),
            new("message_text", "Message", ColType.String),
            new("severity_description", "SeverityName", ColType.String),
            new("severity_id", "Severity", ColType.Int64),
            new("bytes", "BytesTotal", ColType.Int64),
            new("bytes_in", "BytesIn", ColType.Int64),
            new("bytes_received", "BytesIn", ColType.Int64),
            new("bytes_out", "BytesOut", ColType.Int64),
            new("bytes_sent", "BytesOut", ColType.Int64),
            new("packets", "Packets", ColType.Int64),
            new("threat_name", "ThreatName", ColType.String),
            new("category", "ThreatCategory", ColType.String),
            new("http_category", "ThreatCategory", ColType.String),
            new("interface", "Interface", ColType.String),
            new("src_interface", "Interface", ColType.String),
            new("log_subtype", "JSON_VALUE(ExtraJson, '$.subtype')", ColType.String),
            new("dest_interface", "COALESCE(JSON_VALUE(ExtraJson, '$.dest_interface'), JSON_VALUE(ExtraJson, '$.outbound_if'))", ColType.String),
            new("serial_number", "COALESCE(JSON_VALUE(ExtraJson, '$.serial_number'), JSON_VALUE(ExtraJson, '$.serial'))", ColType.String),
            new("src_translated_ip", "JSON_VALUE(ExtraJson, '$.natsrc')", ColType.String),
            new("session_end_reason", "JSON_VALUE(ExtraJson, '$.session_end_reason')", ColType.String),
            new("device", "DeviceName", ColType.String),
            new("session_id", "SessionId", ColType.String),
            new("repeat_count", "RepeatCount", ColType.Int64),
            new("_extra", "ExtraJson", ColType.String),
        ];

        private static readonly Dictionary<string, FieldDef> BaseFields = Projection
            .GroupBy(p => p.Alias, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        private static readonly string[] BaseText =
        [
            "Raw", "Message", "Host", "Sourcetype", "Action", "ThreatName", "Mnemonic", "UserName", "Application", "RuleName", "DeviceName",
        ];

        private readonly DateTime _from;
        private readonly DateTime _to;
        private readonly int _maxRows;
        private readonly List<QueryParameter> _params = [];
        private readonly List<(string Name, string Body)> _ctes = [];
        private readonly Dictionary<string, ColType> _types = new(StringComparer.OrdinalIgnoreCase);
        private List<string> _columns = [];
        private string _where;
        private string _timelineWhere;
        private string _source = "";
        private bool _onBase = true;
        private bool _countFromBase = true;
        private string _resultType = "events";
        private string? _category;
        private string? _splitBy;
        private List<string> _measures = [];
        private List<(string Field, bool Desc)>? _order;
        private int? _limit;
        private int? _tail;
        private int _seq;

        public Compiler(DateTime from, DateTime to, int maxRows)
        {
            _from = from;
            _to = to;
            _maxRows = maxRows;
            _where = "EventTime >= @from AND EventTime < @to";
            _timelineWhere = _where;
            _params.Add(new QueryParameter("@from", from, ParamType.DateTime2));
            _params.Add(new QueryParameter("@to", to, ParamType.DateTime2));
        }

        public CompiledQuery Compile(SplQuery query)
        {
            if (query.Stages.Count == 0)
            {
                query.Stages.Add(new SearchStage(new SxTrue()));
            }

            foreach (var stage in query.Stages)
            {
                Apply(stage);
            }

            var span = RelativeTime.DefaultSpan(_from, _to);
            _params.Add(new QueryParameter("@tl_origin", _from, ParamType.DateTime2));
            _params.Add(new QueryParameter("@tl_span", span, ParamType.Int));

            var sql = Finish();
            var timeline = $@"SELECT t.[_time] AS [_time], COUNT_BIG(*) AS [count]
FROM (
    SELECT DATEADD(second, CAST((DATEDIFF_BIG(second, @tl_origin, EventTime) / @tl_span) * @tl_span AS int), @tl_origin) AS [_time]
    FROM dbo.Events
    WHERE {_timelineWhere}
) AS t
GROUP BY t.[_time]
ORDER BY t.[_time]";

            string? count = _resultType == "events" && _countFromBase
                ? $"SELECT COUNT_BIG(*) FROM dbo.Events WHERE {_timelineWhere}"
                : null;

            return new CompiledQuery
            {
                Sql = sql,
                CountSql = count,
                TimelineSql = timeline,
                FilterSql = _timelineWhere,
                Parameters = _params,
                ResultType = _resultType,
                CategoryField = _category,
                SplitBy = _splitBy,
                Measures = _measures,
                TimelineSpanSeconds = span,
                RowLimit = _limit ?? _tail ?? (_resultType == "events" ? _maxRows : 5000),
            };
        }

        private static string CommandName(SplStage stage) => stage switch
        {
            RexStage => "rex",
            EventStatsStage => "eventstats",
            StreamStatsStage => "streamstats",
            TransactionStage => "transaction",
            JoinStage => "join",
            AppendStage => "append",
            LookupStage => "lookup",
            InputLookupStage => "inputlookup",
            OutputLookupStage => "outputlookup",
            IpLocationStage => "iplocation",
            BinStage => "bin",
            ChartStage => "chart",
            FillNullStage => "fillnull",
            MakeMvStage => "makemv",
            MvExpandStage => "mvexpand",
            SpathStage => "spath",
            _ => stage.GetType().Name.Replace("Stage", "", StringComparison.Ordinal).ToLowerInvariant(),
        };

        private void Apply(SplStage stage)
        {
            switch (stage)
            {
                case SearchStage search:
                    AddFilter(search.Expr);
                    break;
                case WhereStage where:
                    AddFilter(where.Expr);
                    break;
                case StatsStage stats:
                    ApplyStats(stats);
                    break;
                case TimechartStage chart:
                    ApplyTimechart(chart);
                    break;
                case TopStage top:
                    ApplyTop(top);
                    break;
                case TableStage table:
                    ApplyFields(table.Fields, false);
                    if (_resultType is "events" or "single")
                    {
                        _resultType = "table";
                    }
                    _category ??= table.Fields.FirstOrDefault();
                    break;
                case FieldsStage fields:
                    ApplyFields(fields.Fields, fields.Exclude);
                    break;
                case SortStage sort:
                    ApplySort(sort);
                    break;
                case HeadStage head:
                    _limit = Math.Min(head.Limit, _maxRows);
                    break;
                case TailStage tail:
                    _tail = Math.Min(tail.Limit, _maxRows);
                    _limit = null;
                    break;
                case RenameStage rename:
                    ApplyRename(rename);
                    break;
                case DedupStage dedup:
                    ApplyDedup(dedup);
                    break;
                case EvalStage eval:
                    ApplyEval(eval);
                    break;
                default:
                    throw new QueryException($"Search command '{CommandName(stage)}' is not supported.");
            }
        }

        private void ApplyStats(StatsStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: true);
            foreach (var field in stage.By)
            {
                EnsureColumn(field);
            }

            foreach (var agg in stage.Aggs)
            {
                if (agg.Arg != null)
                {
                    EnsureColumn(agg.Arg);
                }
            }

            var hasValues = stage.Aggs.Any(a => a.Func == "values");
            string from;
            string? valuesCte = null;
            if (hasValues)
            {
                valuesCte = "v" + _ctes.Count.ToString(CultureInfo.InvariantCulture);
                _ctes.Add((valuesCte, _source));
                from = valuesCte + " AS s";
            }
            else
            {
                from = "(" + _source + ") AS s";
            }

            var select = new List<string>();
            var group = new List<string>();
            var columns = new List<string>();
            var types = new Dictionary<string, ColType>(StringComparer.OrdinalIgnoreCase);
            foreach (var field in stage.By)
            {
                var expr = Resolve(field);
                select.Add($"{expr} AS {B(field)}");
                group.Add(expr);
                columns.Add(field);
                types[field] = TypeOf(field);
            }

            var measures = new List<string>();
            foreach (var agg in stage.Aggs)
            {
                var alias = Alias(agg);
                string sql = agg.Func == "values"
                    ? ValuesSql(agg, valuesCte!, stage.By)
                    : AggSql(agg, Resolve);
                select.Add($"{sql} AS {B(alias)}");
                columns.Add(alias);
                types[alias] = agg.Func switch
                {
                    "avg" => ColType.Float,
                    "values" => ColType.String,
                    _ => ColType.Int64,
                };

                measures.Add(alias);
            }

            _source = "SELECT " + string.Join(", ", select) + " FROM " + from
                      + (group.Count == 0 ? "" : " GROUP BY " + string.Join(", ", group));
            _columns = columns;
            _types.Clear();
            foreach (var pair in types)
            {
                _types[pair.Key] = pair.Value;
            }

            _resultType = stage.By.Count == 0 && measures.Count == 1 ? "single" : "table";
            _category = stage.By.FirstOrDefault();
            _splitBy = null;
            _measures = measures;
            _order = null;
        }

        private void ApplyTimechart(TimechartStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: true);
            if (!_types.ContainsKey("_time"))
            {
                throw new QueryException("timechart needs _time.");
            }

            if (stage.By != null)
            {
                EnsureColumn(stage.By);
            }

            foreach (var agg in stage.Aggs)
            {
                if (agg.Arg != null)
                {
                    EnsureColumn(agg.Arg);
                }
            }

            var span = stage.SpanSeconds ?? RelativeTime.DefaultSpan(_from, _to);
            EnsureFixed("@origin", _from, ParamType.DateTime2);
            EnsureFixed("@span", span, ParamType.Int);
            var bucket = $"DATEADD(second, CAST((DATEDIFF_BIG(second, @origin, {Resolve("_time")}) / @span) * @span AS int), @origin)";

            var inner = new List<string> { $"{bucket} AS [_time]" };
            var outer = new List<string> { "b.[_time] AS [_time]" };
            var group = new List<string> { "b.[_time]" };
            var columns = new List<string> { "_time" };
            var types = new Dictionary<string, ColType>(StringComparer.OrdinalIgnoreCase) { ["_time"] = ColType.DateTime };
            var carried = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "_time" };

            if (stage.By != null)
            {
                inner.Add($"{Resolve(stage.By)} AS {B(stage.By)}");
                outer.Add($"b.{B(stage.By)} AS {B(stage.By)}");
                group.Add($"b.{B(stage.By)}");
                columns.Add(stage.By);
                types[stage.By] = TypeOf(stage.By);
                carried.Add(stage.By);
            }

            var measures = new List<string>();
            foreach (var agg in stage.Aggs)
            {
                if (agg.Arg != null && carried.Add(agg.Arg))
                {
                    inner.Add($"{Resolve(agg.Arg)} AS {B(agg.Arg)}");
                }

                var alias = Alias(agg);
                outer.Add($"{AggSql(agg, name => "b." + B(name))} AS {B(alias)}");
                columns.Add(alias);
                types[alias] = agg.Func == "avg" ? ColType.Float : ColType.Int64;
                measures.Add(alias);
            }

            _source = $@"SELECT {string.Join(", ", outer)}
FROM (
    SELECT {string.Join(", ", inner)}
    FROM ({_source}) AS s
) AS b
GROUP BY {string.Join(", ", group)}";
            _columns = columns;
            _types.Clear();
            foreach (var pair in types)
            {
                _types[pair.Key] = pair.Value;
            }

            _resultType = "timechart";
            _category = "_time";
            _splitBy = stage.By;
            _measures = measures;
            _order = [("_time", false)];
        }

        private void ApplyTop(TopStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: true);
            EnsureColumn(stage.Field);
            if (stage.By != null)
            {
                EnsureColumn(stage.By);
            }

            var limit = Math.Clamp(stage.Limit, 1, _maxRows);
            if (stage.By == null)
            {
                var expr = Resolve(stage.Field);
                _source = $@"SELECT {expr} AS {B(stage.Field)}, COUNT_BIG(*) AS [count],
    CAST(100.0 * COUNT_BIG(*) / NULLIF(SUM(COUNT_BIG(*)) OVER (), 0) AS decimal(18,2)) AS [percent]
FROM ({_source}) AS s
GROUP BY {expr}";
                _columns = [stage.Field, "count", "percent"];
                _types.Clear();
                _types[stage.Field] = TypeOf(stage.Field);
                _types["count"] = ColType.Int64;
                _types["percent"] = ColType.Float;
                _order = [("count", !stage.Rare)];
                _limit = limit;
            }
            else
            {
                var direction = stage.Rare ? "ASC" : "DESC";
                _source = $@"SELECT {B(stage.By)}, {B(stage.Field)}, [count], [percent] FROM (
    SELECT {Resolve(stage.By)} AS {B(stage.By)}, {Resolve(stage.Field)} AS {B(stage.Field)}, COUNT_BIG(*) AS [count],
        CAST(100.0 * COUNT_BIG(*) / NULLIF(SUM(COUNT_BIG(*)) OVER (PARTITION BY {Resolve(stage.By)}), 0) AS decimal(18,2)) AS [percent],
        ROW_NUMBER() OVER (PARTITION BY {Resolve(stage.By)} ORDER BY COUNT_BIG(*) {direction}) AS __rn
    FROM ({_source}) AS s
    GROUP BY {Resolve(stage.By)}, {Resolve(stage.Field)}
) AS g WHERE g.__rn <= {limit.ToString(CultureInfo.InvariantCulture)}";
                _columns = [stage.By, stage.Field, "count", "percent"];
                _types.Clear();
                _types[stage.By] = TypeOf(stage.By);
                _types[stage.Field] = TypeOf(stage.Field);
                _types["count"] = ColType.Int64;
                _types["percent"] = ColType.Float;
                _order = [(stage.By, false), ("count", !stage.Rare)];
            }

            _resultType = "table";
            _category = stage.Field;
            _splitBy = stage.By;
            _measures = ["count"];
        }

        private void ApplyFields(IReadOnlyList<string> fields, bool exclude)
        {
            SealBase();
            Materialize(dropBareOrder: false);
            List<string> keep;
            if (exclude)
            {
                var drop = new HashSet<string>(fields, StringComparer.OrdinalIgnoreCase);
                keep = _columns.Where(c => !drop.Contains(c)).ToList();
            }
            else
            {
                keep = [];
                foreach (var field in fields)
                {
                    EnsureColumn(field);
                    if (!keep.Contains(field, StringComparer.OrdinalIgnoreCase))
                    {
                        keep.Add(field);
                    }
                }
            }

            if (keep.Count == 0)
            {
                throw new QueryException("That fields list removes every column.");
            }

            _source = "SELECT " + string.Join(", ", keep.Select(c => $"s.{B(c)} AS {B(c)}")) + " FROM (" + _source + ") AS s";
            _columns = keep;
            var next = new Dictionary<string, ColType>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in keep)
            {
                next[column] = _types[column];
            }

            _types.Clear();
            foreach (var pair in next)
            {
                _types[pair.Key] = pair.Value;
            }
        }

        private void ApplySort(SortStage stage)
        {
            foreach (var key in stage.Keys)
            {
                if (_onBase && !BaseFields.ContainsKey(key.Field))
                {
                    SealBase();
                }

                if (!_onBase)
                {
                    EnsureColumn(key.Field);
                }
            }

            _order = stage.Keys.Select(k => (k.Field, k.Descending)).ToList();
            if (stage.Limit != null)
            {
                _limit = Math.Min(stage.Limit.Value, _maxRows);
            }
        }

        private void ApplyRename(RenameStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: false);
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (from, to) in stage.Names)
            {
                if (!_types.ContainsKey(from))
                {
                    throw new QueryException($"Field '{from}' is not available to rename.");
                }

                if (!IsIdent(to))
                {
                    throw new QueryException($"'{to}' is not a valid field name.");
                }

                map[from] = to;
            }

            var parts = new List<string>();
            var columns = new List<string>();
            var types = new Dictionary<string, ColType>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in _columns)
            {
                var name = map.TryGetValue(column, out var renamed) ? renamed : column;
                parts.Add($"s.{B(column)} AS {B(name)}");
                columns.Add(name);
                types[name] = _types[column];
            }

            _source = "SELECT " + string.Join(", ", parts) + " FROM (" + _source + ") AS s";
            _columns = columns;
            _types.Clear();
            foreach (var pair in types)
            {
                _types[pair.Key] = pair.Value;
            }

            _order = _order?.Select(o => (map.TryGetValue(o.Field, out var name) ? name : o.Field, o.Desc)).ToList();
            if (_category != null && map.TryGetValue(_category, out var category))
            {
                _category = category;
            }
        }

        private void ApplyDedup(DedupStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: false);
            foreach (var field in stage.Fields)
            {
                EnsureColumn(field);
            }

            var partition = string.Join(", ", stage.Fields.Select(f => $"s.{B(f)}"));
            var ordering = _types.ContainsKey("_time") ? "s.[_time] DESC" : $"s.{B(stage.Fields[0])}";
            var cols = string.Join(", ", _columns.Select(c => $"d.{B(c)}"));
            _source = $@"SELECT {cols} FROM (
    SELECT s.*, ROW_NUMBER() OVER (PARTITION BY {partition} ORDER BY {ordering}) AS __rn
    FROM ({_source}) AS s
) AS d WHERE d.__rn <= {stage.Keep.ToString(CultureInfo.InvariantCulture)}";
            _countFromBase = false;
        }

        private void ApplyEval(EvalStage stage)
        {
            SealBase();
            Materialize(dropBareOrder: false);
            foreach (var (field, expr) in stage.Assignments)
            {
                if (!IsIdent(field))
                {
                    throw new QueryException($"'{field}' is not a valid field name.");
                }

                var sql = CompileEx(expr);
                var type = ExType(expr);
                var parts = new List<string>();
                var columns = new List<string>();
                var types = new Dictionary<string, ColType>(StringComparer.OrdinalIgnoreCase);
                var replaced = false;
                foreach (var column in _columns)
                {
                    if (column.Equals(field, StringComparison.OrdinalIgnoreCase))
                    {
                        parts.Add($"{sql} AS {B(field)}");
                        columns.Add(field);
                        types[field] = type;
                        replaced = true;
                    }
                    else
                    {
                        parts.Add($"s.{B(column)} AS {B(column)}");
                        columns.Add(column);
                        types[column] = _types[column];
                    }
                }

                if (!replaced)
                {
                    parts.Add($"{sql} AS {B(field)}");
                    columns.Add(field);
                    types[field] = type;
                }

                _source = "SELECT " + string.Join(", ", parts) + " FROM (" + _source + ") AS s";
                _columns = columns;
                _types.Clear();
                foreach (var pair in types)
                {
                    _types[pair.Key] = pair.Value;
                }
            }
        }

        private string ValuesSql(Agg agg, string cte, IReadOnlyList<string> groups)
        {
            var arg = agg.Arg ?? throw new QueryException("values() needs a field.");
            var match = groups.Count == 0
                ? "1=1"
                : string.Join(" AND ", groups.Select(g => $"(s2.{B(g)} = s.{B(g)} OR (s2.{B(g)} IS NULL AND s.{B(g)} IS NULL))"));
            return $@"(SELECT STRING_AGG(CONVERT(nvarchar(max), d.v), ', ') WITHIN GROUP (ORDER BY d.v)
FROM (SELECT DISTINCT CONVERT(nvarchar(450), s2.{B(arg)}) AS v FROM {cte} AS s2 WHERE {match} AND s2.{B(arg)} IS NOT NULL) AS d)";
        }

        private string Finish()
        {
            var sql = _onBase ? BaseSelect() : _source;
            var order = _order;
            if (order == null && _resultType == "events" && (_onBase || _types.ContainsKey("_time")))
            {
                order = [("_time", true)];
            }
            else if (order == null && _resultType == "timechart")
            {
                order = [("_time", false)];
            }
            else if (order == null && _resultType == "table" && _measures.Count > 0)
            {
                order = [(_measures[0], true)];
            }

            if (_tail != null)
            {
                var current = order ?? [("_time", true)];
                var reversed = current.Select(o => (o.Field, !o.Desc)).ToList();
                sql = $@"SELECT * FROM (
    SELECT TOP ({_tail.Value.ToString(CultureInfo.InvariantCulture)}) * FROM ({sql}) AS t{OrderClause(reversed)}
) AS u{OrderClause(current)}";
            }
            else
            {
                var cap = _limit ?? (_resultType == "events" ? _maxRows : 5000);
                sql = $"SELECT TOP ({cap.ToString(CultureInfo.InvariantCulture)}) * FROM ({sql}) AS q{OrderClause(order)}";
            }

            if (_ctes.Count > 0)
            {
                var with = string.Join(", ", _ctes.Select(c => $"{c.Name} AS ({c.Body})"));
                sql = "WITH " + with + " " + sql;
            }

            return sql;
        }

        private void AddFilter(Sx expr)
        {
            var pred = CompileSx(expr);
            if (pred == "1=1")
            {
                return;
            }

            if (_onBase)
            {
                _where += " AND (" + pred + ")";
                _timelineWhere = _where;
            }
            else
            {
                _countFromBase = false;
                _source = "SELECT * FROM (" + _source + ") AS s WHERE " + pred;
            }
        }

        private void SealBase()
        {
            if (!_onBase)
            {
                return;
            }

            _source = BaseSelect();
            _onBase = false;
            _columns = Projection.Select(p => p.Alias).ToList();
            _types.Clear();
            foreach (var field in Projection)
            {
                _types[field.Alias] = field.Type;
            }
        }

        private void Materialize(bool dropBareOrder)
        {
            if (_onBase)
            {
                SealBase();
            }

            if (_limit != null)
            {
                var order = _order ?? (_types.ContainsKey("_time") ? [("_time", true)] : null);
                _source = $"SELECT TOP ({_limit.Value.ToString(CultureInfo.InvariantCulture)}) * FROM ({_source}) AS q{OrderClause(order)}";
                _limit = null;
                _order = null;
            }
            else if (dropBareOrder)
            {
                _order = null;
            }
        }

        private void EnsureColumn(string name)
        {
            if (_onBase)
            {
                SealBase();
            }

            if (_types.ContainsKey(name))
            {
                return;
            }

            if (!IsIdent(name) || !_types.ContainsKey("_extra"))
            {
                throw new QueryException($"Field '{name}' is not available.");
            }

            _source = $"SELECT s.*, JSON_VALUE(s.[_extra], '$.{name}') AS {B(name)} FROM ({_source}) AS s";
            _columns.Add(name);
            _types[name] = ColType.String;
        }

        private string BaseSelect() =>
            "SELECT " + string.Join(", ", Projection.Select(p => $"{p.Sql} AS {B(p.Alias)}"))
            + " FROM dbo.Events WHERE " + _where;

        private string CompileSx(Sx expr) => expr switch
        {
            SxTrue => "1=1",
            SxNot not => "NOT (" + CompileSx(not.Inner) + ")",
            SxBool boolean when boolean.Parts.Count == 0 => boolean.Op == "OR" ? "1=0" : "1=1",
            SxBool boolean => string.Join(boolean.Op == "OR" ? " OR " : " AND ", boolean.Parts.Select(p => "(" + CompileSx(p) + ")")),
            SxTerm term => CompileTerm(term),
            SxCall call => CompileCall(call),
            SxIn list => CompileIn(list),
            SxSub => throw new QueryException("A subsearch was not expanded before SQL translation."),
            _ => throw new QueryException("Unsupported search expression."),
        };

        private string CompileTerm(SxTerm term)
        {
            if (term.Field != null && term.Field.Equals("index", StringComparison.OrdinalIgnoreCase))
            {
                return "1=1";
            }

            if (term.Field != null && term.Field.Equals("severity", StringComparison.OrdinalIgnoreCase) && term.Op is "=" or "!=" or "<" or ">" or "<=" or ">=")
            {
                return CompileSeverity(term);
            }

            if (term.Field != null && term.Field.Equals("action", StringComparison.OrdinalIgnoreCase) && term.Op is "=" or "!=" && !HasWild(term.Value))
            {
                return CompileAction(term);
            }

            if (term.Field == null)
            {
                var like = Add(LikePattern(term.Value, substring: true), ParamType.NVarChar);
                var cols = TextColumns();
                if (cols.Count == 0)
                {
                    throw new QueryException("This pipeline has no text field left to search.");
                }

                return "(" + string.Join(" OR ", cols.Select(c => $"{c} LIKE {like} ESCAPE '\\'")) + ")";
            }

            var expr = Resolve(term.Field);
            var type = TypeOf(term.Field);
            if (term.Value.Length == 0)
            {
                return $"({expr} IS NULL OR {expr} = N'')";
            }

            var op = term.Op == "!=" ? "<>" : term.Op;
            if (term.Op is not ("=" or "!=" or "<" or ">" or "<=" or ">="))
            {
                throw new QueryException($"Unsupported operator '{term.Op}'.");
            }

            if (HasWild(term.Value) && term.Op is "=" or "!=")
            {
                var like = Add(LikePattern(term.Value, substring: false), ParamType.NVarChar);
                var column = type == ColType.Int64 ? $"CONVERT(varchar(40), {expr})" : expr;
                var comparison = $"{column} LIKE {like} ESCAPE '\\'";
                return term.Op == "!=" ? "NOT (" + comparison + ")" : comparison;
            }

            if (IsNumber(term.Value) && (type is ColType.Int64 or ColType.Float || term.Op is "<" or ">" or "<=" or ">="))
            {
                if (type == ColType.Int64 && long.TryParse(term.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var whole))
                {
                    return $"{expr} {op} {Add(whole, ParamType.BigInt)}";
                }

                var number = double.Parse(term.Value, CultureInfo.InvariantCulture);
                return $"TRY_CONVERT(float, {expr}) {op} {Add(number, ParamType.Float)}";
            }

            return $"{expr} {op} {Add(term.Value, ParamType.NVarChar)}";
        }

        private string CompileSeverity(SxTerm term)
        {
            var sqlOp = term.Op == "!=" ? "<>" : term.Op;
            if (int.TryParse(term.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) && term.Op is "<" or ">" or "<=" or ">=" or "=" or "!=")
            {
                var id = $"Severity {sqlOp} {Add(number, ParamType.Int)}";
                if (term.Op is "=" or "!=")
                {
                    var words = SplFields.SeverityWords(term.Value);
                    var name = "(" + string.Join(" OR ", words.Select(w => $"SeverityName = {Add(w, ParamType.NVarChar)}")) + ")";
                    return term.Op == "=" ? $"({id} OR {name})" : $"({id} AND NOT {name})";
                }

                return id;
            }

            var equivalents = SplFields.SeverityWords(term.Value);
            var match = "(" + string.Join(" OR ", equivalents.Select(w => $"SeverityName = {Add(w, ParamType.NVarChar)}")) + ")";
            return term.Op == "!=" ? "NOT " + match : match;
        }

        private string CompileAction(SxTerm term)
        {
            var parameter = Add(term.Value, ParamType.NVarChar);
            var both = $"(Action = {parameter} OR {SplFields.CimActionSql} = {parameter})";
            return term.Op == "!=" ? $"NOT {both}" : both;
        }

        private string CompileIn(SxIn list)
        {
            if (list.Subsearch != null)
            {
                throw new QueryException("A subsearch was not expanded before SQL translation.");
            }

            if (list.Values.Count == 0)
            {
                return "1=0";
            }

            var expr = Resolve(list.Field);
            var parameters = list.Values.Select(value => Add(value, ParamType.NVarChar));
            return $"{expr} IN ({string.Join(", ", parameters)})";
        }

        private string CompileCall(SxCall call) => call.Name switch
        {
            "isnull" => Resolve(call.Args[0]) + " IS NULL",
            "isnotnull" => Resolve(call.Args[0]) + " IS NOT NULL",
            "like" => Resolve(call.Args[0]) + " LIKE " + Add(LikePattern(call.Args[1], substring: false), ParamType.NVarChar) + " ESCAPE '\\'",
            _ => throw new QueryException($"Unsupported function '{call.Name}'."),
        };

        private List<string> TextColumns()
        {
            if (_onBase)
            {
                return BaseText.ToList();
            }

            string[] names = ["_raw", "message", "host", "sourcetype", "action", "threat_name", "mnemonic", "user", "app", "rule", "device"];
            return names.Where(n => _types.ContainsKey(n)).Select(n => "s." + B(n)).ToList();
        }

        private string CompileEx(Ex expr) => expr switch
        {
            ExNum n => Literal(n.Value),
            ExStr s => Add(s.Value, ParamType.NVarChar),
            ExField f => Resolve(f.Name),
            ExBin b => Bin(b),
            ExCall c => Call(c),
            ExIf i => If(i),
            _ => throw new QueryException("Unsupported eval expression."),
        };

        private string Bin(ExBin bin)
        {
            var left = $"TRY_CONVERT(float, {CompileEx(bin.Left)})";
            var right = $"TRY_CONVERT(float, {CompileEx(bin.Right)})";
            return bin.Op switch
            {
                "/" => $"({left} / NULLIF({right}, 0))",
                "+" or "-" or "*" => $"({left} {bin.Op} {right})",
                _ => throw new QueryException($"Unsupported math operator '{bin.Op}'."),
            };
        }

        private string Call(ExCall call)
        {
            if (call.Args.Count == 0)
            {
                throw new QueryException($"{call.Name}() needs an argument.");
            }

            if (call.Name == "coalesce")
            {
                return "COALESCE(" + string.Join(", ", call.Args.Select(CompileEx)) + ")";
            }

            var first = CompileEx(call.Args[0]);
            return call.Name switch
            {
                "lower" => $"LOWER(CONVERT(nvarchar(400), {first}))",
                "upper" => $"UPPER(CONVERT(nvarchar(400), {first}))",
                "len" => $"LEN(CONVERT(nvarchar(400), {first}))",
                "tonumber" => $"TRY_CONVERT(float, {first})",
                "tostring" => $"CONVERT(nvarchar(400), {first})",
                _ => throw new QueryException($"Unsupported eval function '{call.Name}'."),
            };
        }

        private string If(ExIf expr)
        {
            var left = CompileEx(expr.Left);
            var right = CompileEx(expr.Right);
            var op = expr.Op == "!=" ? "<>" : expr.Op;
            var numeric = expr.Left is ExNum || expr.Right is ExNum || ExType(expr.Left) is ColType.Int64 or ColType.Float;
            var cond = numeric
                ? $"TRY_CONVERT(float, {left}) {op} TRY_CONVERT(float, {right})"
                : $"{left} {op} {right}";
            return $"CASE WHEN {cond} THEN {CompileEx(expr.Then)} ELSE {CompileEx(expr.Else)} END";
        }

        private ColType ExType(Ex expr) => expr switch
        {
            ExNum => ColType.Float,
            ExStr => ColType.String,
            ExField f => TypeOf(f.Name),
            ExBin => ColType.Float,
            ExCall { Name: "len" } => ColType.Int64,
            ExCall { Name: "tonumber" } => ColType.Float,
            ExIf i when ExType(i.Then) == ColType.String || ExType(i.Else) == ColType.String => ColType.String,
            ExIf => ColType.Float,
            _ => ColType.String,
        };

        private static string AggSql(Agg agg, Func<string, string> resolve)
        {
            if (agg.Func == "count" && agg.Arg == null)
            {
                return "COUNT_BIG(*)";
            }

            var arg = resolve(agg.Arg ?? throw new QueryException($"{agg.Func}() needs a field."));
            return agg.Func switch
            {
                "count" => $"COUNT_BIG({arg})",
                "dc" => $"COUNT(DISTINCT CONVERT(nvarchar(450), {arg}))",
                "sum" => $"SUM(TRY_CONVERT(bigint, {arg}))",
                "avg" => $"AVG(TRY_CONVERT(float, {arg}))",
                "min" => $"MIN({arg})",
                "max" => $"MAX({arg})",
                _ => throw new QueryException($"The stats function '{agg.Func}' is not supported."),
            };
        }

        private string Resolve(string name)
        {
            if (!IsIdent(name))
            {
                throw new QueryException($"'{name}' is not a valid field name.");
            }

            if (_onBase)
            {
                if (BaseFields.TryGetValue(name, out var field))
                {
                    return field.Sql;
                }

                return $"JSON_VALUE(ExtraJson, '$.{name}')";
            }

            if (_types.ContainsKey(name))
            {
                return "s." + B(name);
            }

            if (_types.ContainsKey("_extra"))
            {
                return $"JSON_VALUE(s.[_extra], '$.{name}')";
            }

            throw new QueryException($"Field '{name}' is not available in this pipeline.");
        }

        private ColType TypeOf(string name)
        {
            if (_onBase && BaseFields.TryGetValue(name, out var field))
            {
                return field.Type;
            }

            if (_types.TryGetValue(name, out var type))
            {
                return type;
            }

            return ColType.String;
        }

        private void EnsureFixed(string name, object value, ParamType type)
        {
            if (_params.All(p => p.Name != name))
            {
                _params.Add(new QueryParameter(name, value, type));
            }
        }

        private string Add(object value, ParamType type)
        {
            var name = "@p" + _seq.ToString(CultureInfo.InvariantCulture);
            _seq++;
            _params.Add(new QueryParameter(name, value, type));
            return name;
        }

        private static string Alias(Agg agg)
        {
            if (!string.IsNullOrWhiteSpace(agg.Alias))
            {
                if (!IsIdent(agg.Alias))
                {
                    throw new QueryException($"'{agg.Alias}' is not a valid alias.");
                }

                return agg.Alias;
            }

            if (agg.Func == "count" && agg.Arg == null)
            {
                return "count";
            }

            var alias = agg.Func + "_" + agg.Arg;
            if (!IsIdent(alias))
            {
                throw new QueryException($"Cannot name the column for {agg.Func}({agg.Arg}). Use 'as'.");
            }

            return alias;
        }

        private static string OrderClause(IReadOnlyList<(string Field, bool Desc)>? order)
        {
            if (order == null || order.Count == 0)
            {
                return "";
            }

            return " ORDER BY " + string.Join(", ", order.Select(o => $"{B(o.Field)} {(o.Desc ? "DESC" : "ASC")}"));
        }

        private static string B(string ident) => "[" + ident + "]";

        private static string LikePattern(string value, bool substring)
        {
            var sb = new StringBuilder();
            var wildcard = value.Contains('*') || value.Contains('?');
            if (substring && !wildcard)
            {
                sb.Append('%');
            }

            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '*':
                        sb.Append('%');
                        break;
                    case '?':
                        sb.Append('_');
                        break;
                    case '%' or '_' or '[' or '\\':
                        sb.Append('\\').Append(ch);
                        break;
                    default:
                        sb.Append(ch);
                        break;
                }
            }

            if (substring && !wildcard)
            {
                sb.Append('%');
            }

            return sb.ToString();
        }

        private static bool HasWild(string value) => value.Contains('*') || value.Contains('?');

        private static bool IsNumber(string value) =>
            double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _);

        private static string Literal(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                throw new QueryException("Invalid number.");
            }

            return value.ToString("0.################", CultureInfo.InvariantCulture);
        }

        private static bool IsIdent(string word) =>
            word.Length > 0 && (char.IsLetter(word[0]) || word[0] == '_') && word.All(ch => char.IsLetterOrDigit(ch) || ch == '_');

        private sealed record FieldDef(string Alias, string Sql, ColType Type);
    }
}
