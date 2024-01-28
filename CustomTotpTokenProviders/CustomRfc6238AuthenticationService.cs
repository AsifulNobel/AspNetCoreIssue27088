using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace CustomTotpTokenProviders;

// Source: https://github.com/dotnet/aspnetcore/blob/d634f2bd1ad6e319f26ff0f1d7ada5539158a19f/src/Identity/Extensions.Core/src/Rfc6238AuthenticationService.cs
public static class CustomRfc6238AuthenticationService
{
    private static readonly TimeSpan Timestep = TimeSpan.FromMinutes(3);
    private static readonly Encoding Encoding = new UTF8Encoding(false, true);

    // Generates a new 80-bit security token
    public static byte[] GenerateRandomKey()
    {
        byte[] bytes = new byte[20];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    internal static int ComputeTotp(
        byte[] key,
        ulong timestepNumber,
        string? modifier)
    {
        // # of 0's = length of pin
        const int Mod = 1000000;

        // See https://tools.ietf.org/html/rfc4226
        // We can add an optional modifier
        byte[] timestepAsBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)timestepNumber));

        byte[] hash = HMACSHA1.HashData(key, ApplyModifier(timestepAsBytes, modifier));

        // Generate DT string
        int offset = hash[hash.Length - 1] & 0xf;
        Debug.Assert(offset + 4 < hash.Length);
        int binaryCode = (hash[offset] & 0x7f) << 24
                            | (hash[offset + 1] & 0xff) << 16
                            | (hash[offset + 2] & 0xff) << 8
                            | (hash[offset + 3] & 0xff);

        return binaryCode % Mod;
    }

    private static byte[] ApplyModifier(byte[] input, string? modifier)
    {
        if (string.IsNullOrEmpty(modifier))
        {
            return input;
        }

        byte[] modifierBytes = Encoding.GetBytes(modifier);
        byte[] combined = new byte[checked(input.Length + modifierBytes.Length)];
        Buffer.BlockCopy(input, 0, combined, 0, input.Length);
        Buffer.BlockCopy(modifierBytes, 0, combined, input.Length, modifierBytes.Length);
        return combined;
    }

    // More info: https://tools.ietf.org/html/rfc6238#section-4
    private static ulong GetCurrentTimeStepNumber(TimeSpan? timestep, TimeProvider? timeProvider)
    {
        timeProvider ??= TimeProvider.System;
        var utcnow = timeProvider.GetUtcNow();
        TimeSpan delta = timeProvider.GetUtcNow() - DateTimeOffset.UnixEpoch;
        return (ulong)(delta.Ticks / (timestep ?? Timestep).Ticks);
    }

    public static int GenerateCode(byte[] securityToken, string? modifier = null, TimeSpan? timestep = default, TimeProvider? timeProvider = default)
    {
        ArgumentNullException.ThrowIfNull(securityToken);

        ulong currentTimeStep = GetCurrentTimeStepNumber(timestep, timeProvider);

        return ComputeTotp(securityToken, currentTimeStep, modifier);
    }

    public static bool ValidateCode(byte[] securityToken, int code, string? modifier = null, TimeSpan? timestep = default, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(securityToken);

        // Allow a variance of no greater than 3 times the timestep in either direction
        ulong currentTimeStep = GetCurrentTimeStepNumber(timestep, timeProvider);

        for (int i = -2; i <= 2; i++)
        {
            int computedTotp = ComputeTotp(securityToken, (ulong)((long)currentTimeStep + i), modifier);
            if (computedTotp == code)
            {
                return true;
            }
        }

        // No match
        return false;
    }
}