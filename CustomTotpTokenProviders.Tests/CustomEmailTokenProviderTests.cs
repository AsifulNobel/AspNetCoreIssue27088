using AutoFixture;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace CustomTotpTokenProviders.Tests;

public sealed class CustomEmailTokenProviderTests
{
    [Theory]
    [InlineData(3, 0, true)]
    [InlineData(3, 1000, true)]
    [InlineData(3, 4000, false)]
    public async Task GIVEN_A_Token_With_Specific_Lifespan_WHEN_Token_Is_Validated_On_Specified_Time_THEN_Token_Validity_Is_Expected(
        int lifespanInSeconds, int waitTimeInMilliseconds, bool expectedValidity)
    {
        CustomEmailTokenProviderOptions options = new() { TokenLifespanInSeconds = lifespanInSeconds };
        TestContext context = TestContext.ArrangeUnitDependencies(options);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        context.TimeProvider.Setup(provider => provider.GetUtcNow()).Returns(now);
        string token = await context.CustomEmailTokenProvider.GenerateAsync(context.Purpose, context.UserManager.Object, context.User);

        context.TimeProvider.Setup(provider => provider.GetUtcNow()).Returns(now.AddMilliseconds(waitTimeInMilliseconds));
        bool isValidToken = await context.CustomEmailTokenProvider.ValidateAsync(context.Purpose, token, context.UserManager.Object, context.User);

        isValidToken.Should().Be(expectedValidity);
    }

    [Fact]
    public async Task GIVEN_A_Token_With_Unspecified_Lifespan_WHEN_Token_Is_Validated_THEN_Token_Is_Valid()
    {
        TestContext context = TestContext.ArrangeUnitDependencies(null);

        string token = await context.CustomEmailTokenProvider.GenerateAsync(context.Purpose, context.UserManager.Object, context.User);

        bool isValidToken = await context.CustomEmailTokenProvider.ValidateAsync(context.Purpose, token, context.UserManager.Object, context.User);

        isValidToken.Should().BeTrue();
    }

    private record TestContext(
        CustomEmailTokenProvider<IdentityUser> CustomEmailTokenProvider,
        Mock<UserManager<IdentityUser>> UserManager,
        IdentityUser User,
        string Purpose,
        Mock<TimeProvider> TimeProvider)
    {
        private readonly IFixture _fixture = new Fixture();

        public static TestContext ArrangeUnitDependencies(CustomEmailTokenProviderOptions? tokenOptions)
        {
            Mock<TimeProvider> timeProvider = new();
            CustomEmailTokenProvider<IdentityUser> customEmailTokenProvider = new(tokenOptions ?? new(), timeProvider.Object);
            Mock<UserManager<IdentityUser>> userManager = new(
                new Mock<IUserStore<IdentityUser>>().Object,
                new Mock<IOptions<IdentityOptions>>().Object,
                new Mock<IPasswordHasher<IdentityUser>>().Object,
                Array.Empty<IUserValidator<IdentityUser>>(),
                Array.Empty<IPasswordValidator<IdentityUser>>(),
                new Mock<ILookupNormalizer>().Object,
                new Mock<IdentityErrorDescriber>().Object,
                new Mock<IServiceProvider>().Object,
                NullLogger<UserManager<IdentityUser>>.Instance
            );
            IFixture fixture = new Fixture();
            IdentityUser user = fixture.Create<IdentityUser>();
            string purpose = fixture.Create<string>();

            TestContext context = new(customEmailTokenProvider, userManager, user, purpose, timeProvider);
            context.MockUserManagerUserId();
            context.MockUserManagerSecurityToken();

            return context;
        }

        private void MockUserManagerUserId() =>
            UserManager.Setup(um => um.GetUserIdAsync(User)).ReturnsAsync(User.Id);

        private void MockUserManagerSecurityToken() =>
            UserManager.Setup(um => um.CreateSecurityTokenAsync(User))
                .ReturnsAsync(_fixture.Create<byte[]>());
    };
}