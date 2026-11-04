using System.Security.Cryptography;
using System.Text;
using SecureUrl.Core.Configuration;

namespace SecureUrl.Core.Internal;

/// <summary>Derives the weekly keys from the MasterKey using HKDF-SHA256.</summary>
internal static class KeyDerivation
{
    public const int KeySize = 32;

    private const long SecondsPerWeek = 7L * 24 * 60 * 60;

    // The Unix epoch (1970-01-01) was a Thursday: shifting by 3 days aligns weeks to Monday 00:00 UTC.
    private const long MondayOffsetSeconds = 3L * 24 * 60 * 60;

    /// <summary>
    /// Sequential week number (weeks start on Monday, 00:00 UTC) used as the rotation "epoch".
    /// It is a continuous counter, not an ISO week-of-year: there is no week 52/53 ambiguity and
    /// nothing special happens at year boundaries. Using UTC avoids time-zone inconsistencies.
    /// </summary>
    public static int GetEpoch(DateTimeOffset now) =>
        checked((int)((now.ToUnixTimeSeconds() + MondayOffsetSeconds) / SecondsPerWeek));

    /// <summary>1-byte identifier of the epoch, written in the token header.</summary>
    public static byte GetKeyId(int epoch) => unchecked((byte)epoch);

    public static byte[] Derive(byte[] masterKey, SecureUrlAlgorithm algorithm, int epoch)
    {
        // Algorithm and epoch go into the "info" parameter: a different key for each context.
        byte[] info = Encoding.UTF8.GetBytes($"secureurl:v1:{algorithm}:{epoch}");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, KeySize, salt: null, info: info);
    }
}
