using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SecureUrl.Core;
using SecureUrl.Core.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IUrlProtector"/>, reading the configuration from the given section
    /// (default: "SecureUrl"). Provide the MasterKey through User Secrets, Key Vault or Secrets Manager.
    /// </summary>
    public static IServiceCollection AddSecureUrlProtector(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = SecureUrlOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SecureUrlOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateOnStart();

        return AddCore(services);
    }

    /// <summary>Registers <see cref="IUrlProtector"/> with code-based configuration.</summary>
    public static IServiceCollection AddSecureUrlProtector(
        this IServiceCollection services,
        Action<SecureUrlOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SecureUrlOptions>()
            .Configure(configure)
            .ValidateOnStart();

        return AddCore(services);
    }

    private static IServiceCollection AddCore(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SecureUrlOptions>, SecureUrlOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IUrlProtector, UrlProtector>();
        return services;
    }
}
