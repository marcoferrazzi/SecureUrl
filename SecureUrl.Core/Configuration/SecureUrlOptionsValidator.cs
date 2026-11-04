using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace SecureUrl.Core.Configuration;

/// <summary>Validates the configuration at startup, so problems surface immediately and not on the first request.</summary>
public sealed class SecureUrlOptionsValidator : IValidateOptions<SecureUrlOptions>
{
    public ValidateOptionsResult Validate(string? name, SecureUrlOptions options)
    {
        var failures = new List<string>();

        if (!options.TryDecodeMasterKey(out var key) || key.Length < SecureUrlOptions.MinMasterKeyBytes)
        {
            failures.Add($"MasterKey must be a Base64 string encoding at least {SecureUrlOptions.MinMasterKeyBytes} bytes.");
        }

        if (string.IsNullOrWhiteSpace(options.Purpose))
        {
            failures.Add("Purpose cannot be empty.");
        }

        if (options.Purpose?.Contains('\0') == true)
        {
            failures.Add("Purpose cannot contain the NUL character.");
        }

        if (options.DefaultExpiration <= TimeSpan.Zero)
        {
            failures.Add("DefaultExpiration must be positive.");
        }

        if (options.KeyWindowWeeks is < SecureUrlOptions.MinKeyWindowWeeks or > SecureUrlOptions.MaxKeyWindowWeeks)
        {
            failures.Add($"KeyWindowWeeks must be between {SecureUrlOptions.MinKeyWindowWeeks} and {SecureUrlOptions.MaxKeyWindowWeeks}.");
        }

        TimeSpan maxSupported = options.MaxSupportedLifetime;
        if (options.MaxExpiration is { } max && (max <= TimeSpan.Zero || max > maxSupported))
        {
            failures.Add($"MaxExpiration must be between 0 and {maxSupported.TotalDays:0} days " +
                         $"(a limit imposed by the key window: {options.KeyWindowWeeks} weekly keys are accepted).");
        }

        if (options.DefaultExpiration > options.EffectiveMaxExpiration)
        {
            failures.Add("DefaultExpiration cannot exceed the maximum expiration.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            failures.Add("Invalid Algorithm.");
        }
        else if (options.Algorithm == SecureUrlAlgorithm.AesGcm && !AesGcm.IsSupported)
        {
            failures.Add("AES-GCM is not supported on this platform: use ChaCha20Poly1305.");
        }
        else if (options.Algorithm == SecureUrlAlgorithm.ChaCha20Poly1305 && !ChaCha20Poly1305.IsSupported)
        {
            failures.Add("ChaCha20-Poly1305 is not supported on this platform: use AesGcm.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
