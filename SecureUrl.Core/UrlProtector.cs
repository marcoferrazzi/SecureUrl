using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecureUrl.Core.Configuration;
using SecureUrl.Core.Internal;

namespace SecureUrl.Core;

/// <summary>
/// Stateless implementation of <see cref="IUrlProtector"/>.
///
/// Token format (before Base64Url encoding):
/// <code>
/// [ key ID: 1 byte ][ nonce: 12 bytes ][ ciphertext ][ tag: 16 bytes ]
///   ciphertext = encryption of [ expiry: uint32 (Unix seconds, UTC) ][ resource name: length-prefixed UTF-8 string ]
/// </code>
/// Associated Data (authenticated but not encrypted): Purpose + 0x00 + context.
/// </summary>
public sealed class UrlProtector : IUrlProtector
{
    private const int NonceSize = AeadCipher.NonceSize;
    private const int TagSize = AeadCipher.TagSize;
    private const int HeaderSize = 1 + NonceSize;

    // key ID + nonce + expiry (4) + length prefix (>= 1) + tag
    private const int MinTokenSize = HeaderSize + 4 + 1 + TagSize;

    private const int MaxResourceNameLength = 1024;
    private const int MaxTokenLength = 4096;
    private const int MaxPurposeLength = 128;

    private readonly SecureUrlOptions _options;
    private readonly TimeProvider _time;
    private readonly byte[] _masterKey;
    private readonly string _purpose;
    private readonly byte[] _purposeBytes;
    private readonly int _keyWindowWeeks;
    private readonly ConcurrentDictionary<int, byte[]> _keyCache;

    public UrlProtector(IOptions<SecureUrlOptions> options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _time = timeProvider ?? TimeProvider.System;

        // Validate here too, so manual instantiation outside DI (e.g. in tests) is checked as well.
        var result = new SecureUrlOptionsValidator().Validate(null, _options);
        if (result.Failed)
        {
            throw new OptionsValidationException(
                nameof(SecureUrlOptions), typeof(SecureUrlOptions), result.Failures ?? Array.Empty<string>());
        }

        _options.TryDecodeMasterKey(out byte[] masterKey);
        _masterKey = masterKey;
        _keyCache = new ConcurrentDictionary<int, byte[]>();
        _purpose = _options.Purpose;
        _purposeBytes = Encoding.UTF8.GetBytes(_purpose);
        _keyWindowWeeks = _options.KeyWindowWeeks;
    }

    // Used by ForPurpose: shares options, clock, master key and derived-key cache with the parent.
    private UrlProtector(UrlProtector parent, string purpose)
    {
        _options = parent._options;
        _time = parent._time;
        _masterKey = parent._masterKey;
        _keyCache = parent._keyCache;
        _keyWindowWeeks = parent._keyWindowWeeks;
        _purpose = purpose;
        _purposeBytes = Encoding.UTF8.GetBytes(purpose);
    }

    /// <inheritdoc />
    public IUrlProtector ForPurpose(string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        if (purpose.Length > MaxPurposeLength || purpose.AsSpan().IndexOfAny('/', '\0') >= 0)
        {
            throw new ArgumentException(
                $"A purpose must be at most {MaxPurposeLength} characters long and cannot contain '/' or the NUL character.",
                nameof(purpose));
        }

        // Hierarchical: "download-v1" + "preview" => "download-v1/preview".
        // '/' is forbidden inside a sub-purpose, so different chains can never produce the same string.
        return new UrlProtector(this, $"{_purpose}/{purpose}");
    }

    /// <inheritdoc />
    public string Protect(string resourceName, TimeSpan? expiration = null, string? context = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceName);
        if (resourceName.Length > MaxResourceNameLength)
        {
            throw new ArgumentException(
                $"The resource name exceeds {MaxResourceNameLength} characters.", nameof(resourceName));
        }

        TimeSpan lifetime = expiration ?? _options.DefaultExpiration;
        if (lifetime <= TimeSpan.Zero || lifetime > _options.EffectiveMaxExpiration)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiration), lifetime,
                $"The lifetime must be positive and not greater than {_options.EffectiveMaxExpiration}.");
        }

        DateTimeOffset now = _time.GetUtcNow();
        long expiry = now.Add(lifetime).ToUnixTimeSeconds();
        if (expiry is < 0 or > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(expiration), "The expiration is outside the representable range.");
        }

        // Binary payload: 4 bytes of expiry + length-prefixed string.
        byte[] payload;
        using (var stream = new MemoryStream())
        {
            using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write((uint)expiry);
                writer.Write(resourceName);
            }

            payload = stream.ToArray();
        }

        int epoch = KeyDerivation.GetEpoch(now);
        byte[] key = GetKey(epoch);

        var token = new byte[HeaderSize + payload.Length + TagSize];
        token[0] = KeyDerivation.GetKeyId(epoch);

        Span<byte> nonce = token.AsSpan(1, NonceSize);
        Span<byte> ciphertext = token.AsSpan(HeaderSize, payload.Length);
        Span<byte> tag = token.AsSpan(HeaderSize + payload.Length, TagSize);

        // Random 96-bit nonce, new for every token: never deliberately reused with the same key.
        RandomNumberGenerator.Fill(nonce);

        AeadCipher.Encrypt(_options.Algorithm, key, nonce, payload, ciphertext, tag, BuildAssociatedData(context));
        CryptographicOperations.ZeroMemory(payload);

        return TokenEncoding.Encode(token);
    }

    /// <inheritdoc />
    public string? Unprotect(string token, string? context = null)
    {
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
        {
            return null;
        }

        if (!TokenEncoding.TryDecode(token, out byte[] data) || data.Length < MinTokenSize)
        {
            return null;
        }

        DateTimeOffset now = _time.GetUtcNow();
        int currentEpoch = KeyDerivation.GetEpoch(now);
        byte keyId = data[0];

        int ciphertextLength = data.Length - HeaderSize - TagSize;
        ReadOnlySpan<byte> nonce = data.AsSpan(1, NonceSize);
        ReadOnlySpan<byte> ciphertext = data.AsSpan(HeaderSize, ciphertextLength);
        ReadOnlySpan<byte> tag = data.AsSpan(HeaderSize + ciphertextLength, TagSize);
        byte[] associatedData = BuildAssociatedData(context);

        // The key ID tells immediately which key to use: no wasted decryption attempts.
        // Accepted window: the current week, the previous KeyWindowWeeks weeks (the "changing of the guard")
        // and the next week (tolerance for slightly out-of-sync clocks between servers).
        // The window is far narrower than 256 epochs, so the 1-byte key ID matches at most one candidate.
        for (int epoch = currentEpoch + 1; epoch >= currentEpoch - _keyWindowWeeks; epoch--)
        {
            if (KeyDerivation.GetKeyId(epoch) != keyId)
            {
                continue;
            }

            var plaintext = new byte[ciphertextLength];
            try
            {
                AeadCipher.Decrypt(_options.Algorithm, GetKey(currentEpoch, epoch), nonce, ciphertext, tag, plaintext, associatedData);
                return ParsePayload(plaintext, now);
            }
            catch (CryptographicException)
            {
                // Invalid tag: tampered token, or wrong key or context.
                return null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        return null;
    }

    private static string? ParsePayload(byte[] plaintext, DateTimeOffset now)
    {
        try
        {
            using var stream = new MemoryStream(plaintext, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            uint expiry = reader.ReadUInt32();
            string resourceName = reader.ReadString();

            if (stream.Position != stream.Length)
            {
                return null; // trailing bytes: unexpected format
            }

            return now.ToUnixTimeSeconds() > expiry ? null : resourceName;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or FormatException)
        {
            return null;
        }
    }

    private byte[] BuildAssociatedData(string? context)
    {
        if (string.IsNullOrEmpty(context))
        {
            return _purposeBytes;
        }

        int contextLength = Encoding.UTF8.GetByteCount(context);
        var buffer = new byte[_purposeBytes.Length + 1 + contextLength];
        _purposeBytes.CopyTo(buffer, 0);
        buffer[_purposeBytes.Length] = 0x00; // separator
        Encoding.UTF8.GetBytes(context, 0, context.Length, buffer, _purposeBytes.Length + 1);
        return buffer;
    }

    private byte[] GetKey(int epoch) => GetKey(epoch, epoch);

    /// <summary>Returns the key for the requested epoch (cached), evicting keys that are now outside the window.</summary>
    private byte[] GetKey(int currentEpoch, int epoch)
    {
        byte[] key = _keyCache.GetOrAdd(epoch, e => KeyDerivation.Derive(_masterKey, _options.Algorithm, e));

        if (_keyCache.Count > _keyWindowWeeks + 4)
        {
            foreach (int cached in _keyCache.Keys)
            {
                if ((cached < currentEpoch - _keyWindowWeeks || cached > currentEpoch + 1) && _keyCache.TryRemove(cached, out byte[]? old))
                {
                    CryptographicOperations.ZeroMemory(old);
                }
            }
        }

        return key;
    }
}
