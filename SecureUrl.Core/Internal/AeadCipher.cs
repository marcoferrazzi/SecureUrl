using System.Security.Cryptography;
using SecureUrl.Core.Configuration;

namespace SecureUrl.Core.Internal;

/// <summary>Thin adapter over the supported AEAD algorithms.</summary>
internal static class AeadCipher
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    public static void Encrypt(
        SecureUrlAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        switch (algorithm)
        {
            case SecureUrlAlgorithm.AesGcm:
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                break;
            }
            case SecureUrlAlgorithm.ChaCha20Poly1305:
            {
                using var chacha = new ChaCha20Poly1305(key);
                chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                break;
            }
            default:
                throw new NotSupportedException($"Unsupported algorithm: {algorithm}.");
        }
    }

    /// <exception cref="CryptographicException">The authentication tag does not match.</exception>
    public static void Decrypt(
        SecureUrlAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        switch (algorithm)
        {
            case SecureUrlAlgorithm.AesGcm:
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                break;
            }
            case SecureUrlAlgorithm.ChaCha20Poly1305:
            {
                using var chacha = new ChaCha20Poly1305(key);
                chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                break;
            }
            default:
                throw new NotSupportedException($"Unsupported algorithm: {algorithm}.");
        }
    }
}
