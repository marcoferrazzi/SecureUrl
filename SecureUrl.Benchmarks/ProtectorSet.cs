using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.Extensions.Options;
using SecureUrl.Core;
using SecureUrl.Core.Configuration;

namespace SecureUrl.Benchmarks;

/// <summary>
/// Builds every protector used in the comparison, all with a 15-minute-style lifetime API:
///  - SecureUrl.Core with AES-GCM and (if supported) ChaCha20-Poly1305;
///  - ASP.NET Core Data Protection, time-limited, with the default algorithms (AES-256-CBC + HMACSHA256)
///    and with AES-256-GCM, so the comparison is also fair at equal algorithm.
/// </summary>
internal sealed class ProtectorSet : IDisposable
{
    private readonly string _keysDirectory =
        Path.Combine(Path.GetTempPath(), "secureurl-bench-" + Guid.NewGuid().ToString("N"));

    public IUrlProtector SecureAes { get; }
    public IUrlProtector? SecureChaCha { get; }
    public ITimeLimitedDataProtector DataProtectionDefault { get; }
    public ITimeLimitedDataProtector DataProtectionGcm { get; }

    public ProtectorSet()
    {
        string masterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        SecureAes = new UrlProtector(Options.Create(new SecureUrlOptions
        {
            MasterKey = masterKey,
            Algorithm = SecureUrlAlgorithm.AesGcm
        }));

        SecureChaCha = ChaCha20Poly1305.IsSupported
            ? new UrlProtector(Options.Create(new SecureUrlOptions
            {
                MasterKey = masterKey,
                Algorithm = SecureUrlAlgorithm.ChaCha20Poly1305
            }))
            : null;

        IDataProtectionProvider defaultProvider =
            DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(_keysDirectory, "default")));

        IDataProtectionProvider gcmProvider = DataProtectionProvider.Create(
            new DirectoryInfo(Path.Combine(_keysDirectory, "gcm")),
            builder => builder.UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
            }));

        DataProtectionDefault = defaultProvider.CreateProtector("download").ToTimeLimitedDataProtector();
        DataProtectionGcm = gcmProvider.CreateProtector("download").ToTimeLimitedDataProtector();

        // Warm-up: the first call creates the key ring on disk, which must not be measured.
        DataProtectionDefault.Protect("warm-up", TimeSpan.FromMinutes(1));
        DataProtectionGcm.Protect("warm-up", TimeSpan.FromMinutes(1));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_keysDirectory))
            {
                Directory.Delete(_keysDirectory, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort: it is only a temporary folder.
        }
    }

    /// <summary>A file name of exactly <paramref name="length"/> characters (minimum 10), e.g. "file-xxxx.pdf".</summary>
    public static string MakeName(int length) =>
        "file-" + new string('x', Math.Max(1, length - 9)) + ".pdf";
}
