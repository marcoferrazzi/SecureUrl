using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace SecureUrl.Benchmarks;

/// <summary>
/// Compares the length of the tokens produced for the same file name and the same 15-minute lifetime.
/// It needs no benchmark framework: lengths are deterministic.
/// </summary>
internal static class LengthComparison
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    public static void Run()
    {
        using var set = new ProtectorSet();

        string[] header =
        {
            "Name chars",
            "SecureUrl AES-GCM",
            "SecureUrl ChaCha20",
            "DataProtection (default)",
            "DataProtection (AES-GCM)",
            "JWT HS256 (signed only)",
            "JSON + Base64Url (no crypto)"
        };

        var rows = new List<string[]>();
        foreach (int length in new[] { 10, 30, 100, 300 })
        {
            string name = ProtectorSet.MakeName(length);
            rows.Add(new[]
            {
                length.ToString(),
                set.SecureAes.Protect(name, Lifetime).Length.ToString(),
                set.SecureChaCha is null ? "n/a" : set.SecureChaCha.Protect(name, Lifetime).Length.ToString(),
                set.DataProtectionDefault.Protect(name, Lifetime).Length.ToString(),
                set.DataProtectionGcm.Protect(name, Lifetime).Length.ToString(),
                BuildJwt(name).Length.ToString(),
                BuildPlainJson(name).Length.ToString()
            });
        }

        string environment =
            $"{RuntimeInformation.FrameworkDescription} on {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}); " +
            $"Microsoft.AspNetCore.DataProtection {typeof(DataProtectionProvider).Assembly.GetName().Version}";

        Console.WriteLine("Token length in characters (URL-safe, Base64Url) for the same file name and a 15-minute lifetime.");
        Console.WriteLine(environment);
        Console.WriteLine();
        PrintAligned(header, rows);

        string markdown = ToMarkdown(header, rows, environment);
        File.WriteAllText("results-lengths.md", markdown);
        Console.WriteLine();
        Console.WriteLine("Markdown table written to results-lengths.md");
    }

    // A JWT built by hand: header.payload.signature, HS256. It is only signed, NOT encrypted.
    private static string BuildJwt(string name)
    {
        long exp = DateTimeOffset.UtcNow.Add(Lifetime).ToUnixTimeSeconds();
        string header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
        string payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes($"{{\"file\":\"{name}\",\"exp\":{exp}}}"));

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] signature = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes($"{header}.{payload}"));

        return $"{header}.{payload}.{Base64Url.EncodeToString(signature)}";
    }

    // The payload alone as JSON in Base64Url: no signature and no encryption. A lower bound for text formats.
    private static string BuildPlainJson(string name)
    {
        long exp = DateTimeOffset.UtcNow.Add(Lifetime).ToUnixTimeSeconds();
        return Base64Url.EncodeToString(Encoding.UTF8.GetBytes($"{{\"file\":\"{name}\",\"exp\":{exp}}}"));
    }

    private static void PrintAligned(string[] header, List<string[]> rows)
    {
        int[] widths = header.Select((h, i) => Math.Max(h.Length, rows.Max(r => r[i].Length))).ToArray();

        Console.WriteLine(string.Join("  ", header.Select((h, i) => h.PadRight(widths[i]))));
        Console.WriteLine(string.Join("  ", widths.Select(w => new string('-', w))));
        foreach (string[] row in rows)
        {
            Console.WriteLine(string.Join("  ", row.Select((c, i) => c.PadRight(widths[i]))));
        }
    }

    private static string ToMarkdown(string[] header, List<string[]> rows, string environment)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"<!-- {environment} -->");
        sb.AppendLine("| " + string.Join(" | ", header) + " |");
        sb.AppendLine("|" + string.Join("|", header.Select(_ => "---")) + "|");
        foreach (string[] row in rows)
        {
            sb.AppendLine("| " + string.Join(" | ", row) + " |");
        }

        return sb.ToString();
    }
}
