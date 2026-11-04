using BenchmarkDotNet.Attributes;
using Microsoft.AspNetCore.DataProtection;
using SecureUrl.Core;

namespace SecureUrl.Benchmarks;

/// <summary>
/// Time and allocations of Protect / Unprotect: SecureUrl.Core (AES-GCM) vs Data Protection
/// (time-limited, default algorithms and AES-GCM).
/// </summary>
[MemoryDiagnoser]
public class TokenBenchmarks
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private ProtectorSet _set = null!;
    private IUrlProtector _secure = null!;
    private ITimeLimitedDataProtector _dpDefault = null!;
    private ITimeLimitedDataProtector _dpGcm = null!;

    private string _name = null!;
    private string _secureToken = null!;
    private string _dpDefaultToken = null!;
    private string _dpGcmToken = null!;

    [Params(30, 100)]
    public int NameLength { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _set = new ProtectorSet();
        _secure = _set.SecureAes;
        _dpDefault = _set.DataProtectionDefault;
        _dpGcm = _set.DataProtectionGcm;

        _name = ProtectorSet.MakeName(NameLength);
        _secureToken = _secure.Protect(_name, Lifetime);
        _dpDefaultToken = _dpDefault.Protect(_name, Lifetime);
        _dpGcmToken = _dpGcm.Protect(_name, Lifetime);
    }

    [GlobalCleanup]
    public void Cleanup() => _set.Dispose();

    // ---- Protect ----

    [Benchmark, BenchmarkCategory("Protect")]
    public string Protect_SecureUrl_AesGcm() => _secure.Protect(_name, Lifetime);

    [Benchmark, BenchmarkCategory("Protect")]
    public string Protect_DataProtection_Default() => _dpDefault.Protect(_name, Lifetime);

    [Benchmark, BenchmarkCategory("Protect")]
    public string Protect_DataProtection_AesGcm() => _dpGcm.Protect(_name, Lifetime);

    // ---- Unprotect ----

    [Benchmark, BenchmarkCategory("Unprotect")]
    public string? Unprotect_SecureUrl_AesGcm() => _secure.Unprotect(_secureToken);

    [Benchmark, BenchmarkCategory("Unprotect")]
    public string Unprotect_DataProtection_Default() => _dpDefault.Unprotect(_dpDefaultToken, out _);

    [Benchmark, BenchmarkCategory("Unprotect")]
    public string Unprotect_DataProtection_AesGcm() => _dpGcm.Unprotect(_dpGcmToken, out _);
}
