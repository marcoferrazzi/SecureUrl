namespace SecureUrl.Core.Configuration;

/// <summary>AEAD algorithm used to encrypt and authenticate the token.</summary>
public enum SecureUrlAlgorithm
{
    /// <summary>AES-256-GCM (hardware-accelerated on most CPUs).</summary>
    AesGcm = 0,

    /// <summary>ChaCha20-Poly1305 (check <c>ChaCha20Poly1305.IsSupported</c> on the target platform).</summary>
    ChaCha20Poly1305 = 1
}
