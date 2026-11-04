using BenchmarkDotNet.Running;
using SecureUrl.Benchmarks;

switch (args.FirstOrDefault())
{
    case "lengths":
        LengthComparison.Run();
        break;

    case "bench":
        // Remaining arguments are passed to BenchmarkDotNet (e.g. --filter "*Unprotect*").
        BenchmarkRunner.Run<TokenBenchmarks>(args: args.Skip(1).ToArray());
        break;

    default:
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -c Release -- lengths   token length comparison (fast, deterministic)");
        Console.WriteLine("  dotnet run -c Release -- bench     BenchmarkDotNet: time and allocations (takes a few minutes)");
        break;
}
