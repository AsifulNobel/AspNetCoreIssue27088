using Microsoft.AspNetCore.Identity;

namespace CustomTotpTokenProviders;

// Source: https://github.com/dotnet/aspnetcore/blob/7f18f8fea5c8e2efc26050f0815f8c911bb26ff1/src/Identity/Extensions.Core/src/EmailTokenProvider.cs
public class CustomEmailTokenProvider<TUser>(CustomEmailTokenProviderOptions options, TimeProvider timeProvider) : CustomTotpSecurityStampBasedTokenProvider<TUser> where TUser : class
{
    private readonly CustomEmailTokenProviderOptions _options = options;
    private readonly TimeProvider _timeProvider = timeProvider;

    public override string GetUserModifier(UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        string userId = manager.GetUserIdAsync(user).Result;

        return $"Email:login:{userId}";
    }

    public override TimeSpan? GetTimestep() =>
        _options?.TokenLifespanInSeconds.HasValue ?? false
        ? TimeSpan.FromSeconds(_options.TokenLifespanInSeconds.Value / 3) // This is intentional integer division
        : null;

    public override TimeProvider GetTimeProvider() => _timeProvider;

    public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        string? email = await manager.GetEmailAsync(user).ConfigureAwait(false);

        return !string.IsNullOrWhiteSpace(email) && await manager.IsEmailConfirmedAsync(user);
    }
}

public class CustomEmailTokenProviderOptions
{
    public int? TokenLifespanInSeconds { get; set; }
}