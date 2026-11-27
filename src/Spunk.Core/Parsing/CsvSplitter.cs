using System.Text;

namespace Spunk.Core.Parsing;

public static class CsvSplitter
{
    public static List<string> Split(string input)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (quoted)
            {
                if (c == '"')
                {
                    if (i + 1 < input.Length && input[i + 1] == '"')
                    {
                        sb.Append('"');
                        i++;
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    sb.Append(c);
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == ',')
            {
                fields.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }

        fields.Add(sb.ToString());
        return fields;
    }
}
