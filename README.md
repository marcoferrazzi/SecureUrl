# SecureUrl.Core

A .NET 10 library that creates **expiring, opaque and tamper-proof** download links, with no database.

- Encrypted and authenticated token (AEAD): **AES-256-GCM** or **ChaCha20-Poly1305**
- Compact **binary** format, encoded as **Base64Url** (`System.Buffers.Text.Base64Url`, .NET 9+)
- **Weekly key rotation** with a configurable acceptance window (default 8 weeks): keys derived with **HKDF-SHA256** from a `MasterKey`
- Expiry and **Associated Data** (purpose + optional context, e.g. a user ID) authenticated by the tag
- Validation runs entirely on the CPU: no shared state

## Structure

```
src/SecureUrl.Core/
  Configuration/        SecureUrlOptions, SecureUrlAlgorithm, SecureUrlOptionsValidator
  Extensions/           AddSecureUrlProtector(...)
  Internal/             TokenEncoding, KeyDerivation (HKDF), AeadCipher
  IUrlProtector.cs      the interface
  UrlProtector.cs       the implementation
tests/SecureUrl.Core.Tests/   xUnit tests (FakeTimeProvider)
samples/SecureUrl.Samples ASP.NET Core Minimal Api example
benchmarks/SecureUrl.Benchmarks/  length, time and allocation comparison with Data Protection
```

## Usage

```csharp
// Program.cs
builder.Services.AddSecureUrlProtector(builder.Configuration);
```

```json
// appsettings.json
"SecureUrl": { "Algorithm": "AesGcm", "DefaultExpiration": "00:15:00", "KeyWindowWeeks": 8, "Purpose": "download-v1" }
```

```bash
# the MasterKey (Base64, at least 32 bytes) must NOT be committed to the repository
# Use in macOs / linux:
dotnet user-secrets set "SecureUrl:MasterKey" "$(openssl rand -base64 32)"
```

```bash
# the MasterKey (Base64, at least 32 bytes) must NOT be committed to the repository
# Use in windows:

$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$key = [Convert]::ToBase64String($bytes)
dotnet user-secrets set "SecureUrl:MasterKey" $key
```

```csharp
string token = protector.Protect("contracts/offer.pdf", TimeSpan.FromMinutes(30), context: userId);
string? file = protector.Unprotect(token, context: userId);   // null if expired, tampered with, or the context does not match
```

## Purposes

The configured `Purpose` (default `download-v1`) is authenticated as Associated Data, so a token created for one purpose is rejected by any other. To use several purposes in the same application, derive sub-purposes at runtime with `ForPurpose`:

```csharp
public class MyService(IUrlProtector protector)
{
    // create them once and reuse them: they are cheap and share keys with the parent
    private readonly IUrlProtector _downloads = protector.ForPurpose("download");
    private readonly IUrlProtector _previews  = protector.ForPurpose("preview");
}
```

Purposes are hierarchical (`download-v1/download`, `download-v1/preview`): a token created by one protector is only valid for protectors created with the same chain of purposes, including the parent. Choose them in code, never from user input; a sub-purpose cannot contain `/` or the NUL character and is limited to 128 characters. `Purpose` identifies the *function* of the token and is fixed per protector, while `context` (e.g. a user ID) is passed on every call and binds the token to a specific person or request.

### Choosing the `context`

Use a **stable, immutable identifier of the authenticated identity**, such as the JWT `sub` claim (mapped to `ClaimTypes.NameIdentifier`) or the internal user ID. Avoid the user name or the e-mail address, which can change. **Do not use the IP address or the User-Agent**: they look like extra security, but they break legitimate downloads. The IP changes with Wi-Fi to 4G roaming and behind corporate proxies and CGNAT, and the User-Agent changes with every browser update and is trivial to copy, so it only gives a false sense of security.

Binding a token to a user only works if the person downloading is authenticated at that moment: a link opened by someone without a session, or a `<video src>` tag that does not send credentials, cannot use it. The `context` is authenticated but never stored in the token, so it does not expose personal data.

## Secret management

The library does not know where the secret lives. It only reads `SecureUrl:MasterKey` from the .NET configuration, **once at startup** (the protector is a singleton and there is no hot reload: changing the key requires a restart). Where the value comes from is up to you, by adding the right configuration provider. The rule is always the same: the secret never lives in the repository or in a Docker image, and it reaches the application at runtime from a place with controlled access.

The key is 32 random bytes, Base64-encoded. Use a different one for every environment:

```bash
openssl rand -base64 32
```

```powershell
# Windows PowerShell
$b = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b)
```

Environment by environment (in .NET, the environment variable `SecureUrl__MasterKey` with a double underscore maps to `SecureUrl:MasterKey`):

- **Local development:** User Secrets, `dotnet user-secrets set "SecureUrl:MasterKey" "<key>"`. They only apply in development.
- **Linux server:** an environment variable loaded from a systemd `EnvironmentFile` with mode `600`, owned by the service user.
- **Windows server:** a JSON file outside the web root, with ACLs restricted to the application account (`icacls`), or a file encrypted with DPAPI. A machine-wide environment variable is readable by every user on the machine, so use it only on servers dedicated to a single application.
- **Docker and Kubernetes:** never in the `Dockerfile` (it can be read with `docker history`). Use a secret mounted as an environment variable or a file. Kubernetes secrets are only Base64-encoded: enable encryption at rest or use the External Secrets Operator.
- **Cloud:** Azure Key Vault with a Managed Identity, AWS Secrets Manager or Parameter Store with an IAM role, Google Secret Manager with a service account. Grant read-only access to that single secret and enable access audit logs.

For example, with Azure Key Vault you only add the provider; the library keeps reading from the configuration:

```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential());
```

In the vault the secret is named `SecureUrl--MasterKey` (a double dash replaces the colon).

General rules:

- A different key for development, test and production.
- Secret scanning on the repository (GitHub push protection, gitleaks) and no secrets in logs.
- Run the application with a low-privilege account, not as an administrator.
- Changing the `MasterKey` **invalidates every link already issued**. With short lifetimes this is acceptable; a seamless replacement would require accepting two keys at the same time, which the library does not support today.

## Token format

```
[ key ID: 1 B ][ nonce: 12 B ][ ciphertext: expiry uint32 + resource name ][ tag: 16 B ]
```

Fixed overhead: 29 bytes (key ID, nonce, tag) + 4 bytes of expiry, before Base64Url encoding (+33%).

The key ID is only a routing hint: it is the weekly epoch modulo 256 (about 4.9 years), so it repeats after that. The accepted window is far narrower (at most 104 previous weeks + current + next = 106 candidate epochs, see `MaxKeyWindowWeeks`), so inside the window each key ID maps to exactly one epoch. If an old token happened to share its key ID with a current key, the library would try that key, the authentication tag would not match (the key is derived from the full epoch number, not from its remainder) and the token would be rejected. Security never depends on the key ID, only on the tag.

## Known limitations

- **Maximum lifetime = `KeyWindowWeeks` weeks** (8 weeks = 56 days by default). Keys rotate every Monday at 00:00 UTC and the previous `KeyWindowWeeks` weekly keys are accepted; a token created in the last second of a week is guaranteed to stay valid for exactly that many weeks. `MaxExpiration` defaults to that limit and cannot exceed it: `Protect` rejects longer lifetimes instead of producing links that would break silently. A wider window means more keys accepted at the same time, hence a weaker rotation.
- **Key rotation does not protect against a compromised `MasterKey`:** all weekly keys can be derived from it. Keep it in Key Vault / Secrets Manager and have a procedure to replace it.
- **No revocation of a single link**, no one-time use, no replay protection (these require state). Mitigations: short lifetimes, a `context` bound to the user.
- The token shows up in logs, browser history and the `Referer` header: use HTTPS, `Referrer-Policy: no-referrer`, `Cache-Control: private, no-store`, and do not log the full token.
- Behind a CDN the token must be part of the cache key, and the response must not stay cacheable beyond the expiry.
- Add rate limiting to the download endpoint.

## Benchmarks

`benchmarks/SecureUrl.Benchmarks` compares token length, time and allocations against ASP.NET Core Data Protection (`ITimeLimitedDataProtector`). See its README for how to run it and how to read the results.

```bash
dotnet run -c Release --project SecureUrl.Benchmarks -- lengths
dotnet run -c Release --project SecureUrl.Benchmarks -- bench
```

## Tests

```bash
dotnet test SecureUrl.Core.Tests
```
