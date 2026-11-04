namespace SecureUrl.Core;

/// <summary>
/// Single entry point of the library: creates and validates opaque, expiring tokens.
/// Easy to replace with a mock in tests.
/// </summary>
public interface IUrlProtector
{
    /// <summary>
    /// Creates an encrypted and authenticated token that is safe to use in a route (Base64Url).
    /// </summary>
    /// <param name="resourceName">Name (or identifier) of the resource to protect.</param>
    /// <param name="expiration">Validity period. When null, <c>DefaultExpiration</c> is used.</param>
    /// <param name="context">
    /// Optional value bound to the token as Associated Data (e.g. a user ID).
    /// The same value must be passed to <see cref="Unprotect"/>.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">The lifetime exceeds <c>MaxExpiration</c> or is not positive.</exception>
    string Protect(string resourceName, TimeSpan? expiration = null, string? context = null);

    /// <summary>
    /// Validates and decrypts the token. Returns null if it is expired, tampered with, created with
    /// a different context, or otherwise invalid. The reason is never revealed.
    /// </summary>
    string? Unprotect(string token, string? context = null);

    /// <summary>
    /// Returns a protector bound to a sub-purpose, appended to the configured one (hierarchical, like ASP.NET Core
    /// Data Protection). Tokens created by it are only valid for protectors created with the same chain of purposes:
    /// a token for <c>ForPurpose("download")</c> is rejected by <c>ForPurpose("preview")</c> and by the parent.
    /// The returned instance is cheap and shares keys with its parent: create it once (e.g. in a constructor) and reuse it.
    /// </summary>
    /// <param name="purpose">A short, fixed name chosen in code (not user input). Cannot contain '/' or NUL.</param>
    IUrlProtector ForPurpose(string purpose);
}
