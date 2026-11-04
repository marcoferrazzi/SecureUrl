# SecureUrl.Benchmarks

Measurements to back (or correct) the claims in the article about **SecureUrl.Core vs ASP.NET Core Data Protection** (`ITimeLimitedDataProtector`): token length, time and allocations.

## Run

Always in **Release** mode, from this folder:

```bash
# 1. Token length (seconds, deterministic, no extra tooling)
dotnet run -c Release -- lengths

# 2. Time and allocations with BenchmarkDotNet (a few minutes)
dotnet run -c Release -- bench
# only one group, e.g.:
dotnet run -c Release -- bench --filter "*Unprotect*"
```

`lengths` prints a table and writes `results-lengths.md`. `bench` writes its reports to `BenchmarkDotNet.Artifacts/`.

## What is compared

| Protector | Notes |
|---|---|
| SecureUrl.Core, AES-GCM | the library, default settings |
| SecureUrl.Core, ChaCha20-Poly1305 | only in `lengths`, and only if the platform supports it |
| Data Protection, default | time-limited, default algorithms (AES-256-CBC + HMACSHA256) |
| Data Protection, AES-GCM | time-limited, same algorithm as the library: the fairest comparison |
| JWT HS256 | built by hand: **signed but not encrypted**; only in `lengths` |
| JSON + Base64Url | the bare payload with **no crypto at all**: a lower bound; only in `lengths` |

Same file name, same 15-minute lifetime, name lengths of 10, 30, 100 and 300 characters (30 and 100 in the benchmarks).

## How to read the results (and what to say in the article)

- **Compare like with like.** JWT and plain JSON do not encrypt: they are references, not competitors. The meaningful comparison is SecureUrl.Core vs Data Protection, ideally with the same algorithm (AES-GCM).
- Report **the environment** (the tables include it): .NET version, OS, CPU, Data Protection package version. Numbers change between machines and versions.
- Say **what was measured** ("token length for a 30-character file name"), not just "X% smaller", and give absolute numbers.
- Time results are **micro-benchmarks**: they show the cost of the cryptographic operation, not the latency of a real request, which is dominated by file I/O and the network. Do not present them as such.
- If the library is not clearly better in some metric, say so: an honest comparison is worth more than a flattering one.
- Data Protection notes: its keys are persisted to a temporary folder created by the program (and deleted at the end); the first call, which creates the key ring, is excluded from the measurements. In a real deployment key management has additional costs that are not measured here.

## Not covered (yet)

- **Cold start and memory with Native AOT**: it requires a separate publish and measuring the process from the outside (time to first response, resident memory, image size).
- Validation under concurrency and throughput of a real endpoint.
