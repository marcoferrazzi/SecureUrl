using System.Security.Cryptography;

namespace SecureUrl.Core.Configuration;

public sealed class SecureUrlOptions
{
    /// <summary>Default configuration section name.</summary>
    public const string SectionName = "SecureUrl";

    /// <summary>Minimum MasterKey length, in bytes.</summary>
    public const int MinMasterKeyBytes = 32;

    /// <summary>Minimum value of <see cref="KeyWindowWeeks"/>.</summary>
    public const int MinKeyWindowWeeks = 1;

    /// <summary>
    /// Maximum value of <see cref="KeyWindowWeeks"/>. The 1-byte key ID identifies an epoch modulo 256,
    /// so the accepted window (previous weeks + current + next) must stay well below that.
    /// </summary>
    public const int MaxKeyWindowWeeks = 104;

    /// <summary>Secret master key, Base64-encoded (at least 32 bytes). Never put it in source code.</summary>
    public string MasterKey { get; set; } = string.Empty;

    /// <summary>AEAD algorithm. Default: AES-GCM.</summary>
    public SecureUrlAlgorithm Algorithm { get; set; } = SecureUrlAlgorithm.AesGcm;

    /// <summary>Lifetime used when <c>Protect</c> is called without an explicit expiration.</summary>
    public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Keys rotate every week (Monday 00:00 UTC). This is how many previous weekly keys are still accepted
    /// when validating a token, in addition to the current one. It is also the number of weeks a token is
    /// guaranteed to stay verifiable: a token created in the last second of a week is still valid
    /// <c>KeyWindowWeeks</c> weeks later. Default: 8 weeks.
    /// </summary>
    public int KeyWindowWeeks { get; set; } = 8;

    /// <summary>
    /// Maximum lifetime accepted by <c>Protect</c>. When null (default) it equals
    /// <see cref="MaxSupportedLifetime"/>. It cannot exceed <see cref="MaxSupportedLifetime"/>.
    /// </summary>
    public TimeSpan? MaxExpiration { get; set; }

    /// <summary>
    /// Longest lifetime that is guaranteed to work with the configured <see cref="KeyWindowWeeks"/>:
    /// longer lifetimes could stop working before their declared expiry because the key would be outside the window.
    /// </summary>
    public TimeSpan MaxSupportedLifetime => TimeSpan.FromDays(7.0 * KeyWindowWeeks);

    /// <summary>
    /// Root purpose of the tokens, authenticated as Associated Data. A token created with one purpose
    /// is not valid with another (e.g. "download-v1" vs "preview-v1"). To use several purposes in the same
    /// application, derive sub-purposes at runtime with <c>IUrlProtector.ForPurpose</c>.
    /// </summary>
    public string Purpose { get; set; } = "download-v1";

    internal TimeSpan EffectiveMaxExpiration => MaxExpiration ?? MaxSupportedLifetime;

    internal bool TryDecodeMasterKey(out byte[] key)
    {
        key = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(MasterKey))
        {
            return false;
        }

        var buffer = new byte[MasterKey.Length];
        try
        {
            if (!Convert.TryFromBase64String(MasterKey, buffer, out int written))
            {
                return false;
            }

            key = buffer.AsSpan(0, written).ToArray();
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
