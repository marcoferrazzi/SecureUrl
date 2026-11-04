using System.Buffers.Text;

namespace SecureUrl.Core.Internal;

/// <summary>
/// Token encoding in Base64Url (RFC 4648 §5): '-' and '_' instead of '+' and '/', no '=' padding.
/// The actual encoding is provided by the framework (<see cref="Base64Url"/>, .NET 9+);
/// this class only adds strict input checking.
/// </summary>
internal static class TokenEncoding
{
    public static string Encode(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);

    /// <summary>Decodes the token. Rejects standard Base64 characters and padding.</summary>
    public static bool TryDecode(string value, out byte[] result)
    {
        result = Array.Empty<byte>();

        if (value.AsSpan().IndexOfAny('+', '/', '=') >= 0)
        {
            return false;
        }

        try
        {
            var buffer = new byte[Base64Url.GetMaxDecodedLength(value.Length)];
            if (!Base64Url.TryDecodeFromChars(value, buffer, out int written))
            {
                return false;
            }

            result = buffer.AsSpan(0, written).ToArray();
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
