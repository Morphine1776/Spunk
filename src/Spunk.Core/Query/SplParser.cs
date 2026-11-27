using System.Globalization;
using System.Text;

namespace Spunk.Core.Query;

public static class SplParser
{
    private static readonly HashSet<string> Commands = new(StringComparer.OrdinalIgnoreCase)
    {
        "search", "where", "stats", "eventstats", "streamstats", "timechart", "chart", "top", "rare",
        "table", "fields", "sort", "head", "tail", "rename", "dedup", "eval", "rex", "transaction",
        "join", "lookup", "inputlookup", "outputlookup", "iplocation", "bin", "bucket", "fillnull",
        "makemv", "mvexpand", "spath", "append",
    };

    public static SplQuery Parse(string input)
    {
        var query = new SplQuery();
        if (string.IsNullOrWhiteSpace(input))
        {
            query.Stages.Add(new SearchStage(new SxTrue()));
            return query;
        }

        var cursor = new Cursor(input);
        query.Stages.Add(cursor.ParseStage(query, false));
        while (cursor.Eat('|'))
        {
            if (cursor.IsEof)
            {
                throw cursor.Error("Expected a command after '|'.");
            }

            query.Stages.Add(cursor.ParseStage(query, true));
        }

        cursor.Skip();
        if (!cursor.IsEof)
        {
            throw cursor.Error("Unexpected input.");
        }

        if (query.Stages.Count == 0)
        {
            query.Stages.Add(new SearchStage(new SxTrue()));
        }

        return query;
    }

    private sealed class Cursor
    {
        private readonly string _s;
        private int _i;

        public Cursor(string text) => _s = text;

        public bool IsEof
        {
            get
            {
                Skip();
                return _i >= _s.Length;
            }
        }

        public SplStage ParseStage(SplQuery query, bool afterPipe)
        {
            if (EatCommand("search"))
            {
                return new SearchStage(ParseTopExpr(query, true));
            }

            if (EatCommand("where"))
            {
                return new WhereStage(ParseTopExpr(query, true));
            }

            if (EatCommand("stats"))
            {
                return ParseStats();
            }

            if (EatCommand("timechart"))
            {
                return ParseTimechart();
            }

            if (EatCommand("top"))
            {
                return ParseTop(false);
            }

            if (EatCommand("rare"))
            {
                return ParseTop(true);
            }

            if (EatCommand("table"))
            {
                return new TableStage(ReadFieldList());
            }

            if (EatCommand("fields"))
            {
                return ParseFields();
            }

            if (EatCommand("sort"))
            {
                return ParseSort();
            }

            if (EatCommand("head"))
            {
                return new HeadStage(ReadOptionalInt(10));
            }

            if (EatCommand("tail"))
            {
                return new TailStage(ReadOptionalInt(10));
            }

            if (EatCommand("rename"))
            {
                return ParseRename();
            }

            if (EatCommand("dedup"))
            {
                return ParseDedup();
            }

            if (EatCommand("eval"))
            {
                return new EvalStage(EvalParser.Parse(ReadRestOfStage()));
            }

            if (EatCommand("eventstats"))
            {
                return ParseEventStats();
            }

            if (EatCommand("streamstats"))
            {
                return ParseStreamStats();
            }

            if (EatCommand("chart"))
            {
                return ParseChart();
            }

            if (EatCommand("rex"))
            {
                return ParseRex();
            }

            if (EatCommand("transaction"))
            {
                return ParseTransaction();
            }

            if (EatCommand("join"))
            {
                return ParseJoin();
            }

            if (EatCommand("lookup"))
            {
                return ParseLookup();
            }

            if (EatCommand("inputlookup"))
            {
                return new InputLookupStage(ReadWord());
            }

            if (EatCommand("outputlookup"))
            {
                return new OutputLookupStage(ReadWord());
            }

            if (EatCommand("iplocation"))
            {
                return ParseIpLocation();
            }

            if (EatCommand("bin") || EatCommand("bucket"))
            {
                return ParseBin();
            }

            if (EatCommand("fillnull"))
            {
                return ParseFillNull();
            }

            if (EatCommand("makemv"))
            {
                return ParseMakeMv();
            }

            if (EatCommand("mvexpand"))
            {
                return new MvExpandStage(ReadField());
            }

            if (EatCommand("spath"))
            {
                return ParseSpath();
            }

            if (EatCommand("append"))
            {
                Expect('[');
                return new AppendStage(ParseNestedQuery());
            }

            if (afterPipe && LooksLikeUnknownCommand(out var unknown))
            {
                throw Error($"Search command '{unknown}' is not supported.");
            }

            return new SearchStage(ParseTopExpr(query, true));
        }

        private StatsStage ParseStats()
        {
            var aggs = ParseAggList();
            return new StatsStage(aggs, ParseBy());
        }

        private TimechartStage ParseTimechart()
        {
            int? span = null;
            if (EatKeyword("span"))
            {
                Expect('=');
                span = RelativeTime.ParseSpan(ReadWord());
            }

            var aggs = ParseAggList();
            string? by = null;
            if (EatKeyword("by"))
            {
                by = ReadField();
            }

            return new TimechartStage(span, aggs, by);
        }

        private List<Agg> ParseAggList()
        {
            var aggs = new List<Agg> { ParseAgg() };
            while (Eat(','))
            {
                aggs.Add(ParseAgg());
            }

            return aggs;
        }

        private Agg ParseAgg()
        {
            var func = ReadWord().ToLowerInvariant();
            if (func is "distinct_count")
            {
                func = "dc";
            }

            if (func is not ("count" or "dc" or "sum" or "avg" or "min" or "max" or "values" or "list"
                or "latest" or "earliest" or "first" or "last" or "median" or "stdev" or "stdevp"
                or "perc" or "perc50" or "perc95" or "perc99"))
            {
                throw Error($"The stats function '{func}' is not supported.");
            }

            string? arg = null;
            if (Eat('('))
            {
                if (!Peek(')'))
                {
                    arg = ReadField();
                    if (func == "perc" && Eat(','))
                    {
                        var pct = ReadInt();
                        func = pct switch { 95 => "perc95", 99 => "perc99", _ => "perc50" };
                    }
                }

                Expect(')');
            }

            if (func != "count" && arg == null)
            {
                throw Error($"{func}() needs a field.");
            }

            string? alias = null;
            if (EatKeyword("as"))
            {
                alias = ReadField();
            }

            return new Agg(func, arg, alias);
        }

        private List<string> ParseBy()
        {
            var fields = new List<string>();
            if (!EatKeyword("by"))
            {
                return fields;
            }

            fields.Add(ReadField());
            while (Eat(',') || PeekField())
            {
                fields.Add(ReadField());
            }

            return fields;
        }

        private TopStage ParseTop(bool rare)
        {
            var limit = 10;
            var show = true;
            string? field = null;
            string? by = null;
            while (!IsEof && !Peek('|') && !Peek(']'))
            {
                if (EatKeyword("limit"))
                {
                    Expect('=');
                    limit = ReadInt();
                    continue;
                }

                if (EatKeyword("showperc"))
                {
                    Expect('=');
                    show = ReadBool();
                    continue;
                }

                if (EatKeyword("countfield") || EatKeyword("percentfield") || EatKeyword("useother") || EatKeyword("otherstr"))
                {
                    Expect('=');
                    ReadValue();
                    continue;
                }

                if (field == null && PeekBareInt())
                {
                    limit = ReadInt();
                    continue;
                }

                if (EatKeyword("by"))
                {
                    by = ReadField();
                    continue;
                }

                if (field == null)
                {
                    field = ReadField();
                    continue;
                }

                break;
            }

            if (field == null)
            {
                throw Error(rare ? "rare needs a field." : "top needs a field.");
            }

            return new TopStage(limit, field, by, rare, show);
        }

        private EventStatsStage ParseEventStats()
        {
            var aggs = ParseAggList();
            return new EventStatsStage(aggs, ParseBy());
        }

        private StreamStatsStage ParseStreamStats()
        {
            int? window = null;
            if (EatKeyword("window"))
            {
                Expect('=');
                window = ReadInt();
            }

            var aggs = ParseAggList();
            return new StreamStatsStage(aggs, ParseBy(), window);
        }

        private ChartStage ParseChart()
        {
            var aggs = ParseAggList();
            if (!EatKeyword("over"))
            {
                throw Error("chart needs 'over'.");
            }

            var over = ReadField();
            return new ChartStage(aggs, over, EatKeyword("by") ? ReadField() : null);
        }

        private RexStage ParseRex()
        {
            string? field = null;
            var sed = false;
            while (true)
            {
                if (EatKeyword("field"))
                {
                    Expect('=');
                    field = ReadField();
                    continue;
                }

                if (EatKeyword("mode"))
                {
                    Expect('=');
                    sed = ReadWord().Equals("sed", StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                break;
            }

            return new RexStage(field, ReadString(), sed);
        }

        private TransactionStage ParseTransaction()
        {
            var fields = new List<string>();
            int? span = null;
            int? pause = null;
            while (!IsEof && !Peek('|') && !Peek(']'))
            {
                if (EatKeyword("maxspan"))
                {
                    Expect('=');
                    span = RelativeTime.ParseSpan(ReadWord());
                    continue;
                }

                if (EatKeyword("maxpause"))
                {
                    Expect('=');
                    pause = RelativeTime.ParseSpan(ReadWord());
                    continue;
                }

                if (PeekKeyword("startswith") || PeekKeyword("endswith") || PeekKeyword("connected"))
                {
                    ReadWord();
                    if (Eat('='))
                    {
                        ReadValue();
                    }

                    continue;
                }

                if (!(_i < _s.Length && (char.IsLetter(_s[_i]) || _s[_i] == '_')))
                {
                    break;
                }

                fields.Add(ReadField());
            }

            if (fields.Count == 0)
            {
                throw Error("transaction needs at least one field.");
            }

            return new TransactionStage(fields, span, pause);
        }

        private JoinStage ParseJoin()
        {
            var type = "inner";
            var fields = new List<string>();
            while (!IsEof && !Peek('|') && !Peek('['))
            {
                if (EatKeyword("type"))
                {
                    Expect('=');
                    type = ReadWord();
                    continue;
                }

                if (EatKeyword("max"))
                {
                    Expect('=');
                    ReadInt();
                    continue;
                }

                fields.Add(ReadField());
            }

            Expect('[');
            return new JoinStage(type, fields, ParseNestedQuery());
        }

        private LookupStage ParseLookup()
        {
            var name = ReadWord();
            var keys = new List<(string, string)>();
            while (!IsEof && !Peek('|') && !PeekKeyword("OUTPUT") && !PeekKeyword("OUTPUTNEW"))
            {
                var local = ReadField();
                var remote = local;
                if (EatKeyword("as"))
                {
                    remote = ReadField();
                }

                keys.Add((local, remote));
                Eat(',');
            }

            var output = new List<(string, string)>();
            if (EatKeyword("OUTPUT") || EatKeyword("OUTPUTNEW"))
            {
                while (!IsEof && !Peek('|'))
                {
                    var field = ReadField();
                    var alias = field;
                    if (EatKeyword("as"))
                    {
                        alias = ReadField();
                    }

                    output.Add((field, alias));
                    if (!Eat(','))
                    {
                        if (IsEof || Peek('|') || !(_i < _s.Length && (char.IsLetter(_s[_i]) || _s[_i] == '_')))
                        {
                            break;
                        }
                    }
                }
            }

            return new LookupStage(name, keys, output);
        }

        private IpLocationStage ParseIpLocation()
        {
            string? prefix = null;
            if (EatKeyword("prefix"))
            {
                Expect('=');
                prefix = ReadValue();
            }

            var field = IsEof || Peek('|') ? "src_ip" : ReadField();
            return new IpLocationStage(field, prefix);
        }

        private BinStage ParseBin()
        {
            string? field = null;
            int? seconds = null;
            double? number = null;
            while (!IsEof && !Peek('|'))
            {
                if (EatKeyword("span"))
                {
                    Expect('=');
                    var text = ReadWord();
                    if (text.Any(char.IsLetter))
                    {
                        seconds = RelativeTime.ParseSpan(text);
                    }
                    else
                    {
                        number = double.Parse(text, CultureInfo.InvariantCulture);
                    }

                    continue;
                }

                if (field == null)
                {
                    field = ReadField();
                    continue;
                }

                break;
            }

            return new BinStage(field ?? "_time", seconds, number);
        }

        private FillNullStage ParseFillNull()
        {
            string? value = null;
            if (EatKeyword("value"))
            {
                Expect('=');
                value = ReadValue();
            }

            var fields = new List<string>();
            while (!IsEof && !Peek('|') && (_i < _s.Length && (char.IsLetter(_s[_i]) || _s[_i] == '_')))
            {
                fields.Add(ReadField());
                Eat(',');
            }

            return new FillNullStage(value, fields);
        }

        private MakeMvStage ParseMakeMv()
        {
            var delim = ",";
            if (EatKeyword("delim"))
            {
                Expect('=');
                delim = ReadValue();
            }
            else if (EatKeyword("tokenizer"))
            {
                Expect('=');
                ReadValue();
            }

            return new MakeMvStage(ReadField(), delim);
        }

        private SpathStage ParseSpath()
        {
            string? input = null;
            string? path = null;
            string? output = null;
            while (true)
            {
                if (EatKeyword("input"))
                {
                    Expect('=');
                    input = ReadField();
                    continue;
                }

                if (EatKeyword("path"))
                {
                    Expect('=');
                    path = ReadValue();
                    continue;
                }

                if (EatKeyword("output"))
                {
                    Expect('=');
                    output = ReadField();
                    continue;
                }

                break;
            }

            return new SpathStage(input, path, output);
        }

        private SplQuery ParseNestedQuery()
        {
            var nested = new SplQuery();
            if (Peek(']'))
            {
                Expect(']');
                nested.Stages.Add(new SearchStage(new SxTrue()));
                return nested;
            }

            nested.Stages.Add(ParseStage(nested, false));
            while (Eat('|'))
            {
                if (Peek(']'))
                {
                    break;
                }

                nested.Stages.Add(ParseStage(nested, true));
            }

            Expect(']');
            return nested;
        }

        private bool LooksLikeUnknownCommand(out string name)
        {
            name = "";
            var save = _i;
            Skip();
            if (IsEof || Peek('(') || Peek('"') || Peek('\'') || Peek('[') || Peek('|'))
            {
                _i = save;
                return false;
            }

            if (_i >= _s.Length || !(char.IsLetter(_s[_i]) || _s[_i] == '_'))
            {
                _i = save;
                return false;
            }

            var word = ReadWord();
            if (word.Equals("NOT", StringComparison.OrdinalIgnoreCase) || word.Equals("AND", StringComparison.OrdinalIgnoreCase) || word.Equals("OR", StringComparison.OrdinalIgnoreCase))
            {
                _i = save;
                return false;
            }

            Skip();
            if (Peek('=') || Peek('<') || Peek('>') || Peek('!'))
            {
                _i = save;
                return false;
            }

            name = word;
            return true;
        }

        private bool ReadBool()
        {
            var word = ReadWord();
            return word is not ("0" or "f" or "false" or "no" or "n");
        }

        private FieldsStage ParseFields()
        {
            Skip();
            var exclude = Eat('-');
            if (!exclude)
            {
                Eat('+');
            }

            return new FieldsStage(ReadFieldList(), exclude);
        }

        private SortStage ParseSort()
        {
            int? limit = PeekBareInt() ? ReadInt() : null;
            var keys = new List<SortKey> { ParseSortKey() };
            while (Eat(',') || PeekSortKey())
            {
                keys.Add(ParseSortKey());
            }

            return new SortStage(keys, limit);
        }

        private SortKey ParseSortKey()
        {
            Skip();
            var desc = false;
            if (Eat('-'))
            {
                desc = true;
            }
            else
            {
                Eat('+');
            }

            return new SortKey(ReadField(), desc);
        }

        private RenameStage ParseRename()
        {
            var names = new List<(string, string)>();
            while (true)
            {
                var from = ReadField();
                if (!EatKeyword("as"))
                {
                    throw Error("Expected 'as' in rename.");
                }

                names.Add((from, ReadField()));
                if (!Eat(','))
                {
                    if (PeekField())
                    {
                        continue;
                    }

                    break;
                }
            }

            return new RenameStage(names);
        }

        private DedupStage ParseDedup()
        {
            var keep = PeekBareInt() ? ReadInt() : 1;
            if (keep < 1)
            {
                throw Error("dedup keep count must be at least 1.");
            }

            return new DedupStage(keep, ReadFieldList());
        }

        private List<string> ReadFieldList()
        {
            var fields = new List<string> { ReadField() };
            while (Eat(',') || PeekField())
            {
                fields.Add(ReadField());
            }

            return fields;
        }

        private Sx ParseTopExpr(SplQuery query, bool captureTime)
        {
            Skip();
            if (IsEof || Peek('|'))
            {
                return new SxTrue();
            }

            var expr = ParseOr(query, captureTime);
            Skip();
            if (!IsEof && !Peek('|'))
            {
                throw Error("Unexpected token in search.");
            }

            return expr;
        }

        private Sx ParseOr(SplQuery query, bool captureTime)
        {
            var left = ParseAnd(query, captureTime);
            while (EatKeyword("OR"))
            {
                left = new SxBool("OR", [left, ParseAnd(query, captureTime)]);
            }

            return left;
        }

        private Sx ParseAnd(SplQuery query, bool captureTime)
        {
            var parts = new List<Sx> { ParseUnary(query, captureTime) };
            while (true)
            {
                if (IsEof || Peek('|') || Peek(')') || PeekKeyword("OR"))
                {
                    break;
                }

                if (EatKeyword("AND"))
                {
                    parts.Add(ParseUnary(query, captureTime));
                    continue;
                }

                if (CanStartPrimary())
                {
                    parts.Add(ParseUnary(query, captureTime));
                    continue;
                }

                break;
            }

            parts.RemoveAll(p => p is SxTrue);
            return parts.Count switch
            {
                0 => new SxTrue(),
                1 => parts[0],
                _ => new SxBool("AND", parts),
            };
        }

        private Sx ParseUnary(SplQuery query, bool captureTime)
        {
            if (EatKeyword("NOT"))
            {
                return new SxNot(ParseUnary(query, captureTime));
            }

            return ParsePrimary(query, captureTime);
        }

        private Sx ParsePrimary(SplQuery query, bool captureTime)
        {
            if (Eat('['))
            {
                return new SxSub(ParseNestedQuery());
            }

            if (Eat('('))
            {
                var inner = ParseOr(query, captureTime);
                Expect(')');
                return inner;
            }

            if (EatKeyword("cidrmatch") || EatKeyword("match"))
            {
                var name = LastKeyword();
                Expect('(');
                var left = ReadValue();
                Expect(',');
                var right = ReadValue();
                Expect(')');
                return new SxCall(name, [left, right]);
            }

            if (EatKeyword("isnull") || EatKeyword("isnotnull"))
            {
                var name = LastKeyword();
                Expect('(');
                var field = ReadField();
                Expect(')');
                return new SxCall(name, [field]);
            }

            if (EatKeyword("like"))
            {
                Expect('(');
                var field = ReadField();
                Expect(',');
                var pattern = ReadValue();
                Expect(')');
                return new SxCall("like", [field, pattern]);
            }

            if (Peek('"') || Peek('\''))
            {
                return new SxTerm(null, "search", ReadString());
            }

            var word = ReadWord();
            if (EatKeyword("IN"))
            {
                if (!IsIdent(word))
                {
                    throw Error($"'{word}' is not a valid field name.");
                }

                if (Eat('['))
                {
                    return new SxIn(word, [], ParseNestedQuery());
                }

                Expect('(');
                var values = new List<string>();
                if (!Peek(')'))
                {
                    values.Add(ReadValue());
                    while (Eat(','))
                    {
                        values.Add(ReadValue());
                    }
                }

                Expect(')');
                return new SxIn(word, values, null);
            }

            var op = TryReadOp();
            if (op == null)
            {
                return new SxTerm(null, "search", word);
            }

            var value = ReadValue();
            if (captureTime && op == "=" && (word.Equals("earliest", StringComparison.OrdinalIgnoreCase) || word.Equals("latest", StringComparison.OrdinalIgnoreCase)))
            {
                if (word.Equals("earliest", StringComparison.OrdinalIgnoreCase))
                {
                    query.Earliest = value;
                }
                else
                {
                    query.Latest = value;
                }

                return new SxTrue();
            }

            if (!IsIdent(word))
            {
                throw Error($"'{word}' is not a valid field name.");
            }

            return new SxTerm(word, op, value);
        }

        private string LastKeyword()
        {
            var end = _i;
            while (end > 0 && char.IsWhiteSpace(_s[end - 1]))
            {
                end--;
            }

            var start = end;
            while (start > 0 && char.IsLetter(_s[start - 1]))
            {
                start--;
            }

            return _s[start..end].ToLowerInvariant();
        }

        private bool CanStartPrimary()
        {
            Skip();
            if (IsEof || Peek('|') || Peek(')'))
            {
                return false;
            }

            if (Peek('(') || Peek('[') || Peek('"') || Peek('\'') || PeekKeyword("NOT") || PeekKeyword("isnull") || PeekKeyword("isnotnull") || PeekKeyword("like") || PeekKeyword("cidrmatch") || PeekKeyword("match"))
            {
                return true;
            }

            return _i < _s.Length && IsWordStart(_s[_i]);
        }

        private bool PeekField()
        {
            var save = _i;
            try
            {
                Skip();
                if (IsEof || Peek('|') || Peek(')') || Peek(',') || Peek('-') || Peek('+'))
                {
                    return false;
                }

                if (!(_i < _s.Length && IsWordStart(_s[_i])))
                {
                    return false;
                }

                var word = ReadWord();
                return IsIdent(word) && !Commands.Contains(word);
            }
            finally
            {
                _i = save;
            }
        }

        private bool PeekSortKey()
        {
            Skip();
            if (IsEof || Peek('|'))
            {
                return false;
            }

            return Peek('-') || Peek('+') || PeekField();
        }

        private string ReadField()
        {
            var word = ReadWord();
            if (!IsIdent(word))
            {
                throw Error($"'{word}' is not a valid field name.");
            }

            return word;
        }

        private string ReadWord()
        {
            Skip();
            if (_i >= _s.Length || !IsWordStart(_s[_i]))
            {
                throw Error("Expected a term.");
            }

            var start = _i++;
            while (_i < _s.Length && IsWordPart(_s[_i]))
            {
                _i++;
            }

            return _s[start.._i];
        }

        private string ReadValue()
        {
            Skip();
            if (Peek('"') || Peek('\''))
            {
                return ReadString();
            }

            var negative = false;
            if (Peek('-'))
            {
                negative = true;
                _i++;
            }

            var word = ReadWord();
            return negative ? "-" + word : word;
        }

        private string ReadString()
        {
            Skip();
            if (_i >= _s.Length)
            {
                throw Error("Expected a string.");
            }

            var quote = _s[_i++];
            var sb = new StringBuilder();
            while (_i < _s.Length)
            {
                var c = _s[_i++];
                if (c == '\\' && _i < _s.Length)
                {
                    var escaped = _s[_i];
                    if (escaped is '\\' or '"' or '\'')
                    {
                        sb.Append(escaped);
                        _i++;
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    continue;
                }

                if (c == quote)
                {
                    return sb.ToString();
                }

                sb.Append(c);
            }

            throw Error("Unterminated string.");
        }

        private string ReadRestOfStage()
        {
            Skip();
            var start = _i;
            var quoted = false;
            char quote = '\0';
            while (_i < _s.Length)
            {
                var c = _s[_i];
                if (quoted)
                {
                    if (c == '\\' && _i + 1 < _s.Length)
                    {
                        _i += 2;
                        continue;
                    }

                    if (c == quote)
                    {
                        quoted = false;
                    }

                    _i++;
                    continue;
                }

                if (c is '"' or '\'')
                {
                    quoted = true;
                    quote = c;
                    _i++;
                    continue;
                }

                if (c == '|')
                {
                    break;
                }

                _i++;
            }

            return _s[start.._i];
        }

        private string? TryReadOp()
        {
            var save = _i;
            Skip();
            string? op = null;
            if (StartsWith("!="))
            {
                _i += 2;
                op = "!=";
            }
            else if (StartsWith(">="))
            {
                _i += 2;
                op = ">=";
            }
            else if (StartsWith("<="))
            {
                _i += 2;
                op = "<=";
            }
            else if (Peek('='))
            {
                _i++;
                op = "=";
            }
            else if (Peek('>'))
            {
                _i++;
                op = ">";
            }
            else if (Peek('<'))
            {
                _i++;
                op = "<";
            }

            if (op == null)
            {
                _i = save;
            }

            return op;
        }

        private int ReadOptionalInt(int fallback) => PeekBareInt() ? ReadInt() : fallback;

        private bool PeekBareInt()
        {
            Skip();
            if (_i >= _s.Length || !char.IsDigit(_s[_i]))
            {
                return false;
            }

            var j = _i;
            while (j < _s.Length && char.IsDigit(_s[j]))
            {
                j++;
            }

            return j >= _s.Length || !IsWordPart(_s[j]);
        }

        private int ReadInt()
        {
            Skip();
            var start = _i;
            if (_i >= _s.Length || !char.IsDigit(_s[_i]))
            {
                throw Error("Expected a number.");
            }

            while (_i < _s.Length && char.IsDigit(_s[_i]))
            {
                _i++;
            }

            return int.Parse(_s[start.._i], CultureInfo.InvariantCulture);
        }

        private bool EatCommand(string keyword)
        {
            if (!PeekKeyword(keyword))
            {
                return false;
            }

            var save = _i;
            _i += keyword.Length;
            Skip();
            var isAssignment = _i < _s.Length && _s[_i] == '=';
            _i = save;
            if (isAssignment)
            {
                return false;
            }

            _i += keyword.Length;
            return true;
        }

        private bool EatKeyword(string keyword)
        {
            if (!PeekKeyword(keyword))
            {
                return false;
            }

            _i += keyword.Length;
            return true;
        }

        private bool PeekKeyword(string keyword)
        {
            Skip();
            if (!StartsWithWord(keyword))
            {
                return false;
            }

            var after = _i + keyword.Length;
            return after >= _s.Length || !IsWordPart(_s[after]);
        }

        public bool Eat(char c)
        {
            Skip();
            if (_i < _s.Length && _s[_i] == c)
            {
                _i++;
                return true;
            }

            return false;
        }

        private void Expect(char c)
        {
            if (!Eat(c))
            {
                throw Error($"Expected '{c}'.");
            }
        }

        private bool Peek(char c)
        {
            Skip();
            return _i < _s.Length && _s[_i] == c;
        }

        private bool StartsWith(string value) =>
            _i + value.Length <= _s.Length && string.Compare(_s, _i, value, 0, value.Length, StringComparison.Ordinal) == 0;

        private bool StartsWithWord(string value) =>
            _i + value.Length <= _s.Length && string.Compare(_s, _i, value, 0, value.Length, StringComparison.OrdinalIgnoreCase) == 0;

        public void Skip()
        {
            while (_i < _s.Length && char.IsWhiteSpace(_s[_i]))
            {
                _i++;
            }
        }

        private static bool IsWordStart(char c) =>
            char.IsLetterOrDigit(c) || c is '_' or '.' or ':' or '*' or '?' or '/' or '\\' or '%' or '@';

        private static bool IsWordPart(char c) =>
            IsWordStart(c) || c is '-' or ';' or '#' or '$';

        public static bool IsIdent(string word) =>
            word.Length > 0 && (char.IsLetter(word[0]) || word[0] == '_') && word.All(ch => char.IsLetterOrDigit(ch) || ch == '_');

        public QueryException Error(string message) => new($"{message} (at position {_i})");
    }
}

internal static class EvalParser
{
    public static IReadOnlyList<(string Field, Ex Expr)> Parse(string text)
    {
        var cursor = new Cursor(text);
        var list = new List<(string, Ex)>();
        if (cursor.IsEof)
        {
            throw new QueryException("eval needs an assignment.");
        }

        while (true)
        {
            var field = cursor.ReadIdent();
            cursor.Expect('=');
            var expr = cursor.ParseExpr();
            list.Add((field, expr));
            if (!cursor.Eat(','))
            {
                break;
            }
        }

        cursor.Skip();
        if (!cursor.IsEof)
        {
            throw cursor.Error("Unexpected input in eval.");
        }

        return list;
    }

    private sealed class Cursor
    {
        private readonly string _s;
        private int _i;

        public Cursor(string text) => _s = text;

        public bool IsEof
        {
            get
            {
                Skip();
                return _i >= _s.Length;
            }
        }

        public Ex ParseExpr()
        {
            var left = ParseTerm();
            while (Peek('+') || Peek('-'))
            {
                var op = Next();
                left = new ExBin(op.ToString(), left, ParseTerm());
            }

            return left;
        }

        private Ex ParseTerm()
        {
            var left = ParseUnary();
            while (Peek('*') || Peek('/'))
            {
                var op = Next();
                left = new ExBin(op.ToString(), left, ParseUnary());
            }

            return left;
        }

        private Ex ParseUnary()
        {
            if (Eat('+'))
            {
                return ParseUnary();
            }

            if (Eat('-'))
            {
                return new ExBin("-", new ExNum(0), ParseUnary());
            }

            return ParsePrimary();
        }

        private Ex ParsePrimary()
        {
            Skip();
            if (Eat('('))
            {
                var inner = ParseExpr();
                Expect(')');
                return inner;
            }

            if (Peek('"') || Peek('\''))
            {
                return new ExStr(ReadString());
            }

            if (_i < _s.Length && (char.IsDigit(_s[_i]) || _s[_i] == '.'))
            {
                return new ExNum(ReadNumber());
            }

            var ident = ReadIdent();
            if (!Eat('('))
            {
                return new ExField(ident);
            }

            if (ident.Equals("if", StringComparison.OrdinalIgnoreCase))
            {
                var left = ParseExpr();
                var op = ReadCompare();
                var right = ParseExpr();
                Expect(',');
                var then = ParseExpr();
                Expect(',');
                var els = ParseExpr();
                Expect(')');
                return new ExIf(left, op, right, then, els);
            }

            if (ident.Equals("case", StringComparison.OrdinalIgnoreCase))
            {
                var pairs = new List<Ex>();
                while (!Peek(')'))
                {
                    pairs.Add(ParseCaseCond());
                    Expect(',');
                    pairs.Add(ParseExpr());
                    if (!Eat(','))
                    {
                        break;
                    }
                }

                Expect(')');
                return new ExCall("case", pairs);
            }

            var args = new List<Ex>();
            if (!Peek(')'))
            {
                args.Add(ParseExpr());
                while (Eat(','))
                {
                    args.Add(ParseExpr());
                }
            }

            Expect(')');
            return new ExCall(ident.ToLowerInvariant(), args);
        }

        public string ReadIdent()
        {
            Skip();
            if (_i >= _s.Length || !(char.IsLetter(_s[_i]) || _s[_i] == '_'))
            {
                throw Error("Expected a name.");
            }

            var start = _i++;
            while (_i < _s.Length && (char.IsLetterOrDigit(_s[_i]) || _s[_i] == '_'))
            {
                _i++;
            }

            return _s[start.._i];
        }

        private double ReadNumber()
        {
            var start = _i;
            while (_i < _s.Length && char.IsDigit(_s[_i]))
            {
                _i++;
            }

            if (_i < _s.Length && _s[_i] == '.')
            {
                _i++;
                while (_i < _s.Length && char.IsDigit(_s[_i]))
                {
                    _i++;
                }
            }

            var text = _s[start.._i];
            if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            {
                throw Error($"Invalid number '{text}'.");
            }

            return value;
        }

        private Ex ParseCaseCond()
        {
            var left = ParseExpr();
            if (!TryCompare(out var op))
            {
                return left;
            }

            return new ExCmp(left, op, ParseExpr());
        }

        private bool TryCompare(out string op)
        {
            var save = _i;
            Skip();
            if (StartsWith("!="))
            {
                _i += 2;
                op = "!=";
                return true;
            }

            if (StartsWith(">="))
            {
                _i += 2;
                op = ">=";
                return true;
            }

            if (StartsWith("<="))
            {
                _i += 2;
                op = "<=";
                return true;
            }

            if (Peek('=') || Peek('>') || Peek('<'))
            {
                op = Next().ToString();
                return true;
            }

            _i = save;
            op = "";
            return false;
        }

        private string ReadCompare()
        {
            Skip();
            if (StartsWith("!="))
            {
                _i += 2;
                return "!=";
            }

            if (StartsWith(">="))
            {
                _i += 2;
                return ">=";
            }

            if (StartsWith("<="))
            {
                _i += 2;
                return "<=";
            }

            if (Peek('=') || Peek('>') || Peek('<'))
            {
                return Next().ToString();
            }

            throw Error("Expected a comparison inside if().");
        }

        private string ReadString()
        {
            Skip();
            var quote = _s[_i++];
            var sb = new StringBuilder();
            while (_i < _s.Length)
            {
                var c = _s[_i++];
                if (c == '\\' && _i < _s.Length)
                {
                    var escaped = _s[_i];
                    if (escaped is '\\' or '"' or '\'')
                    {
                        sb.Append(escaped);
                        _i++;
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    continue;
                }

                if (c == quote)
                {
                    return sb.ToString();
                }

                sb.Append(c);
            }

            throw Error("Unterminated string.");
        }

        public void Expect(char c)
        {
            if (!Eat(c))
            {
                throw Error($"Expected '{c}'.");
            }
        }

        public bool Eat(char c)
        {
            Skip();
            if (_i < _s.Length && _s[_i] == c)
            {
                _i++;
                return true;
            }

            return false;
        }

        private bool Peek(char c)
        {
            Skip();
            return _i < _s.Length && _s[_i] == c;
        }

        private char Next()
        {
            Skip();
            if (_i >= _s.Length)
            {
                throw Error("Unexpected end.");
            }

            return _s[_i++];
        }

        private bool StartsWith(string value) =>
            _i + value.Length <= _s.Length && string.Compare(_s, _i, value, 0, value.Length, StringComparison.Ordinal) == 0;

        public void Skip()
        {
            while (_i < _s.Length && char.IsWhiteSpace(_s[_i]))
            {
                _i++;
            }
        }

        public QueryException Error(string message) => new($"{message} (at position {_i})");
    }
}
