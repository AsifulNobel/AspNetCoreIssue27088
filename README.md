# Workaround for ASP.NET [Issue 27088](https://github.com/dotnet/aspnetcore/issues/27088)

This repository provides a workaround for ASP.NET [Issue 27088](https://github.com/dotnet/aspnetcore/issues/27088) where the token provider is not yet configurable. The workaround introduces custom providers to enable developers to configure the email OTP (One-Time Password) lifetime. The default lifetime in ASP.NET is 9 minutes.

## Usage

1. Add the classes in the `CustomTotpTokenProviders` directory to your Auth project.
2. Locate the place in your project where `builder.Services.AddIdentity` is defined (usually in `Startup.cs` or an extension class).
3. After finding the location, add the following code after `identityBuilder.AddDefaultTokenProviders()`.

```csharp
.AddTokenProvider(TokenOptions.DefaultEmailProvider, typeof(CustomEmailTokenProvider<>).MakeGenericType(identityBuilder.UserType))
```

Import the namespace where CustomEmailTokenProvider is located.

To use the token provider, configure the email token lifetime by adding the following code (before using the provider):

```csharp
services.AddSingleton(new CustomEmailTokenProviderOptions
{
    TokenLifespanInSeconds = 120
});
```

This can be added in Startup.cs or wherever you are configuring dependencies. The provider options have been configured as singleton arbitrarily.

## Unit Tests

Unit tests for the email token provider can be found in the CustomTotpTokenProviders.Tests project.

## Note

The solution was built with .NET 8.
