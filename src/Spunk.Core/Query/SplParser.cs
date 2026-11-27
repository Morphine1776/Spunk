using System.Globalization;
using System.Text;

namespace Spunk.Core.Query;

public static class SplParser
{
    private static readonly HashSet<string> Commands = new(StringComparer.OrdinalIgnoreCase)
    {
        "search", "where", "stats", "timechart", "top", "rare", "table", "fields",
        "sort", "head", "tail", "rename", "dedup", "eval",
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
        query.Stages.Add(cursor.ParseStage(query));
        while (cursor.Eat('|'))
        {
            if (cursor.IsEof)
            {
                throw cursor.Error("Expected a command after '|'.");
            }

            query.Stages.Add(cursor.ParseStage(query));
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

        public SplStage ParseStage(SplQuery query)
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
            if (func is not ("count" or "dc" or "sum" or "avg" or "min" or "max" or "values"))
            {
                throw Error($"Unknown aggregation '{func}'.");
            }

            string? arg = null;
            if (Eat('('))
            {
                if (!Peek(')'))
                {
                    arg = ReadField();
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
            var limit = PeekBareInt() ? ReadInt() : 10;
            var field = ReadField();
            string? by = EatKeyword("by") ? ReadField() : null;
            return new TopStage(limit, field, by, rare);
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
            if (Eat('('))
            {
                var inner = ParseOr(query, captureTime);
                Expect(')');
                return inner;
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

            if (Peek('(') || Peek('"') || Peek('\'') || PeekKeyword("NOT") || PeekKeyword("isnull") || PeekKeyword("isnotnull") || PeekKeyword("like"))
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
                    sb.Append(_s[_i++]);
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
            IsWordStart(c) || c is '-' or ';' or '#' or '$' or '[' or ']';

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
                    sb.Append(_s[_i++]);
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
