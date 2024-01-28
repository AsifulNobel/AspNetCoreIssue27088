using Microsoft.AspNetCore.Identity;
using System.Globalization;

namespace CustomTotpTokenProviders;

// Source: https://github.com/dotnet/aspnetcore/blob/5cd5fe0c017255da4b521d0ad737bb6e260ed167/src/Identity/Extensions.Core/src/TotpSecurityStampBasedTokenProvider.cs
public abstract class CustomTotpSecurityStampBasedTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser> where TUser: class
{
    public virtual string GetUserModifier(UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        string userId = manager.GetUserIdAsync(user).Result;

        return $"Totp:login:{userId}";
    }

    public abstract TimeSpan? GetTimestep();

    public virtual TimeProvider GetTimeProvider() => TimeProvider.System;

    public virtual async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(manager);
        byte[] token = await manager.CreateSecurityTokenAsync(user);
        string modifier = GetUserModifier(manager, user);

        return CustomRfc6238AuthenticationService.GenerateCode(token, modifier, GetTimestep(), GetTimeProvider())
            .ToString("D6", CultureInfo.InvariantCulture);
    }

    public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (!int.TryParse(token, out int code))
        {
            return false;
        }

        byte[] securityToken = await manager.CreateSecurityTokenAsync(user);
        string modifier = GetUserModifier(manager, user);

        return securityToken != null && CustomRfc6238AuthenticationService.ValidateCode(securityToken, code, modifier, GetTimestep(), GetTimeProvider());
    }

    public abstract Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user);
}