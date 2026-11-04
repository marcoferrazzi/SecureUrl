using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using SecureUrl.Core.Configuration;
using SecureUrl.Core.Internal;
using Xunit;

namespace SecureUrl.Core.Tests;

public class UrlProtectorTests
{
    // Sunday, March 15th 2026: the last day of a (Monday-based) week.
    private static readonly DateTimeOffset Start = new(2026, 3, 15, 10, 0, 0, TimeSpan.Zero);

    private static string MakeKey(byte seed) =>
        Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)(seed + i)).ToArray());

    private static UrlProtector Create(
        FakeTimeProvider time,
        SecureUrlAlgorithm algorithm = SecureUrlAlgorithm.AesGcm,
        byte keySeed = 1,
        string purpose = "download-v1",
        int windowWeeks = 8) =>
        new(Options.Create(new SecureUrlOptions
        {
            MasterKey = MakeKey(keySeed),
            Algorithm = algorithm,
            Purpose = purpose,
            KeyWindowWeeks = windowWeeks
        }), time);

    private static bool Supported(SecureUrlAlgorithm a) => a switch
    {
        SecureUrlAlgorithm.AesGcm => AesGcm.IsSupported,
        SecureUrlAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305.IsSupported,
        _ => false
    };

    [Theory]
    [InlineData(SecureUrlAlgorithm.AesGcm)]
    [InlineData(SecureUrlAlgorithm.ChaCha20Poly1305)]
    public void RoundTrip_ReturnsOriginalResourceName(SecureUrlAlgorithm algorithm)
    {
        if (!Supported(algorithm)) return;

        var protector = Create(new FakeTimeProvider(Start), algorithm);
        string token = protector.Protect("contract/2026/offer-1.pdf");

        Assert.Equal("contract/2026/offer-1.pdf", protector.Unprotect(token));
    }

    [Fact]
    public void RoundTrip_SupportsNonAsciiNames()
    {
        var protector = Create(new FakeTimeProvider(Start));
        const string name = "final report – ready ✓.pdf";

        Assert.Equal(name, protector.Unprotect(protector.Protect(name)));
    }

    [Fact]
    public void Token_IsUrlSafe()
    {
        var protector = Create(new FakeTimeProvider(Start));

        for (int i = 0; i < 200; i++)
        {
            string token = protector.Protect($"file-{i}.pdf");
            Assert.Matches(new Regex("^[A-Za-z0-9_-]+$"), token);
        }
    }

    [Fact]
    public void Token_IsDifferentEveryTime_ForTheSameResource()
    {
        var protector = Create(new FakeTimeProvider(Start));

        Assert.NotEqual(protector.Protect("a.pdf"), protector.Protect("a.pdf"));
    }

    [Fact]
    public void Unprotect_ReturnsNull_WhenExpired()
    {
        var time = new FakeTimeProvider(Start);
        var protector = Create(time);
        string token = protector.Protect("a.pdf", TimeSpan.FromMinutes(10));

        time.Advance(TimeSpan.FromMinutes(9));
        Assert.Equal("a.pdf", protector.Unprotect(token));

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Null(protector.Unprotect(token));
    }

    [Fact]
    public void Unprotect_ReturnsNull_WhenAnyBitIsFlipped()
    {
        var protector = Create(new FakeTimeProvider(Start));
        Assert.True(TokenEncoding.TryDecode(protector.Protect("a.pdf"), out byte[] raw));

        for (int i = 0; i < raw.Length; i++)
        {
            byte[] tampered = (byte[])raw.Clone();
            tampered[i] ^= 0x01;

            Assert.Null(protector.Unprotect(TokenEncoding.Encode(tampered)));
        }
    }

    [Fact]
    public void Unprotect_ReturnsNull_WhenTruncatedOrExtended()
    {
        var protector = Create(new FakeTimeProvider(Start));
        Assert.True(TokenEncoding.TryDecode(protector.Protect("a.pdf"), out byte[] raw));

        Assert.Null(protector.Unprotect(TokenEncoding.Encode(raw.AsSpan(0, raw.Length - 1))));
        Assert.Null(protector.Unprotect(TokenEncoding.Encode(raw.Concat(new byte[] { 0 }).ToArray())));
    }

    [Fact]
    public void Unprotect_ReturnsNull_WithDifferentMasterKey()
    {
        var time = new FakeTimeProvider(Start);
        string token = Create(time, keySeed: 1).Protect("a.pdf");

        Assert.Null(Create(time, keySeed: 2).Unprotect(token));
    }

    [Fact]
    public void Unprotect_ReturnsNull_WithDifferentPurpose()
    {
        var time = new FakeTimeProvider(Start);
        string token = Create(time, purpose: "download-v1").Protect("a.pdf");

        Assert.Null(Create(time, purpose: "preview-v1").Unprotect(token));
    }

    [Fact]
    public void Context_MustMatch()
    {
        var protector = Create(new FakeTimeProvider(Start));
        string token = protector.Protect("a.pdf", context: "user-42");

        Assert.Equal("a.pdf", protector.Unprotect(token, "user-42"));
        Assert.Null(protector.Unprotect(token, "user-43"));
        Assert.Null(protector.Unprotect(token));
    }

    // ---- Weekly key rotation ----

    [Fact]
    public void Token_CreatedOnLastMinuteOfWeek_IsStillValidInNextWeek()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 3, 15, 23, 59, 0, TimeSpan.Zero)); // Sunday
        var protector = Create(time);
        string token = protector.Protect("a.pdf", TimeSpan.FromHours(1));

        time.Advance(TimeSpan.FromMinutes(2)); // now it is Monday, March 16th: a new weekly key

        Assert.Equal("a.pdf", protector.Unprotect(token));
    }

    [Fact]
    public void Token_AcrossIsoWeekAndYearBoundary_IsStillValid()
    {
        // Sunday, January 3rd 2027 -> Monday, January 4th 2027 (ISO week 53 of 2026 -> week 1 of 2027)
        var time = new FakeTimeProvider(new DateTimeOffset(2027, 1, 3, 23, 59, 0, TimeSpan.Zero));
        var protector = Create(time);
        string token = protector.Protect("a.pdf", TimeSpan.FromHours(1));

        time.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal("a.pdf", protector.Unprotect(token));
    }

    [Fact]
    public void Token_CreatedOnLastMinuteOfWeek_LivesForTheWholeWindow()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 3, 15, 23, 59, 0, TimeSpan.Zero));
        var protector = Create(time, windowWeeks: 8);
        string token = protector.Protect("a.pdf", TimeSpan.FromDays(56)); // the maximum for an 8-week window

        time.Advance(TimeSpan.FromDays(55) + TimeSpan.FromHours(23));
        Assert.Equal("a.pdf", protector.Unprotect(token)); // 8 weeks later, the key is still accepted

        time.Advance(TimeSpan.FromHours(2));
        Assert.Null(protector.Unprotect(token)); // expired
    }

    [Fact]
    public void Unprotect_ReturnsNull_WhenKeyIsOutsideTheWindow_EvenIfNotExpired()
    {
        var creatorTime = new FakeTimeProvider(Start);
        string token = Create(creatorTime, windowWeeks: 8).Protect("a.pdf", TimeSpan.FromDays(56));

        // A verifier that only keeps 2 previous weekly keys (same MasterKey).
        var verifierTime = new FakeTimeProvider(Start + TimeSpan.FromDays(10)); // 2 weeks later
        Assert.Equal("a.pdf", Create(verifierTime, windowWeeks: 2).Unprotect(token));

        verifierTime.Advance(TimeSpan.FromDays(20)); // now 4+ weeks later, token not yet expired
        Assert.Null(Create(verifierTime, windowWeeks: 2).Unprotect(token));
    }

    [Fact]
    public void Token_FromServerWithClockSlightlyAhead_IsAccepted()
    {
        var aheadTime = new FakeTimeProvider(new DateTimeOffset(2026, 3, 16, 0, 0, 5, TimeSpan.Zero));  // Monday
        var behindTime = new FakeTimeProvider(new DateTimeOffset(2026, 3, 15, 23, 59, 59, TimeSpan.Zero)); // Sunday

        string token = Create(aheadTime).Protect("a.pdf", TimeSpan.FromHours(1));

        Assert.Equal("a.pdf", Create(behindTime).Unprotect(token));
    }

    [Fact]
    public void Protect_RejectsLifetimeBeyondMaximum()
    {
        var protector = Create(new FakeTimeProvider(Start)); // 8 weeks => 56 days maximum

        Assert.Equal("a.pdf", protector.Unprotect(protector.Protect("a.pdf", TimeSpan.FromDays(56))));
        Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect("a.pdf", TimeSpan.FromDays(57)));
        Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect("a.pdf", TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect("a.pdf", TimeSpan.FromMinutes(-1)));
    }

    [Fact]
    public void Protect_MaximumFollowsTheConfiguredWindow()
    {
        var protector = Create(new FakeTimeProvider(Start), windowWeeks: 2); // 14 days

        Assert.Equal("a.pdf", protector.Unprotect(protector.Protect("a.pdf", TimeSpan.FromDays(14))));
        Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect("a.pdf", TimeSpan.FromDays(15)));
    }

    [Fact]
    public void Protect_RejectsEmptyResourceName()
    {
        var protector = Create(new FakeTimeProvider(Start));

        Assert.Throws<ArgumentException>(() => protector.Protect(""));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("!!!!")]
    [InlineData("a+b/c=")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Unprotect_ReturnsNull_ForGarbage(string token)
    {
        var protector = Create(new FakeTimeProvider(Start));

        Assert.Null(protector.Unprotect(token));
    }

    [Fact]
    public void Unprotect_ReturnsNull_ForVeryLongInput()
    {
        var protector = Create(new FakeTimeProvider(Start));

        Assert.Null(protector.Unprotect(new string('A', 100_000)));
    }

    // ---- Sub-purposes ----

    [Fact]
    public void ForPurpose_CreatesIsolatedProtectors()
    {
        var root = Create(new FakeTimeProvider(Start));
        var downloads = root.ForPurpose("download");
        var previews = root.ForPurpose("preview");

        string token = downloads.Protect("a.pdf");

        Assert.Equal("a.pdf", downloads.Unprotect(token));
        Assert.Null(previews.Unprotect(token));
        Assert.Null(root.Unprotect(token));
        Assert.Null(downloads.Unprotect(root.Protect("a.pdf")));
    }

    [Fact]
    public void ForPurpose_SamePurpose_IsInterchangeableBetweenInstances()
    {
        var time = new FakeTimeProvider(Start);
        var a = Create(time).ForPurpose("download");
        var b = Create(time).ForPurpose("download");

        Assert.Equal("a.pdf", b.Unprotect(a.Protect("a.pdf")));
    }

    [Fact]
    public void ForPurpose_CanBeChained()
    {
        var root = Create(new FakeTimeProvider(Start));
        var nested = root.ForPurpose("download").ForPurpose("v2");
        var sameNested = root.ForPurpose("download").ForPurpose("v2");

        string token = nested.Protect("a.pdf");

        Assert.Equal("a.pdf", sameNested.Unprotect(token));
        Assert.Null(root.ForPurpose("download").Unprotect(token));
        Assert.Null(root.ForPurpose("v2").Unprotect(token));
    }

    [Fact]
    public void ForPurpose_WorksTogetherWithContext()
    {
        var downloads = Create(new FakeTimeProvider(Start)).ForPurpose("download");
        string token = downloads.Protect("a.pdf", context: "user-42");

        Assert.Equal("a.pdf", downloads.Unprotect(token, "user-42"));
        Assert.Null(downloads.Unprotect(token, "user-43"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a/b")]
    [InlineData("a\0b")]
    public void ForPurpose_RejectsInvalidNames(string purpose)
    {
        var root = Create(new FakeTimeProvider(Start));

        Assert.ThrowsAny<ArgumentException>(() => root.ForPurpose(purpose));
    }

    [Fact]
    public void ForPurpose_RejectsTooLongNames()
    {
        var root = Create(new FakeTimeProvider(Start));

        Assert.Throws<ArgumentException>(() => root.ForPurpose(new string('x', 129)));
    }

    // ---- Options validation ----

    [Fact]
    public void Constructor_RejectsWeakMasterKey()
    {
        var options = Options.Create(new SecureUrlOptions { MasterKey = Convert.ToBase64String(new byte[16]) });

        Assert.Throws<OptionsValidationException>(() => new UrlProtector(options));
    }

    [Fact]
    public void Constructor_RejectsMaxExpirationBeyondTheWindow()
    {
        var options = Options.Create(new SecureUrlOptions
        {
            MasterKey = MakeKey(1),
            KeyWindowWeeks = 8,
            MaxExpiration = TimeSpan.FromDays(57)
        });

        Assert.Throws<OptionsValidationException>(() => new UrlProtector(options));
    }

    [Fact]
    public void Constructor_RejectsPurposeWithNulCharacter()
    {
        var options = Options.Create(new SecureUrlOptions { MasterKey = MakeKey(1), Purpose = "a\0b" });

        Assert.Throws<OptionsValidationException>(() => new UrlProtector(options));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-3)]
    [InlineData(105)]
    public void Constructor_RejectsWindowOutOfRange(int weeks)
    {
        var options = Options.Create(new SecureUrlOptions { MasterKey = MakeKey(1), KeyWindowWeeks = weeks });

        Assert.Throws<OptionsValidationException>(() => new UrlProtector(options));
    }
}

public class TokenEncodingTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    [InlineData(255)]
    public void EncodeDecode_RoundTrips(int length)
    {
        byte[] data = new byte[length];
        RandomNumberGenerator.Fill(data);

        string encoded = TokenEncoding.Encode(data);

        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);
        Assert.True(TokenEncoding.TryDecode(encoded, out byte[] decoded));
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void TryDecode_RejectsStandardBase64Characters()
    {
        Assert.False(TokenEncoding.TryDecode("ab+/", out _));
        Assert.False(TokenEncoding.TryDecode("abcd=", out _));
    }
}

public class KeyDerivationTests
{
    [Fact]
    public void Epoch_ChangesOnMondayMidnightUtc()
    {
        int sunday = KeyDerivation.GetEpoch(new DateTimeOffset(2026, 3, 15, 23, 59, 59, TimeSpan.Zero));
        int monday = KeyDerivation.GetEpoch(new DateTimeOffset(2026, 3, 16, 0, 0, 0, TimeSpan.Zero));
        int laterMonday = KeyDerivation.GetEpoch(new DateTimeOffset(2026, 3, 22, 23, 59, 59, TimeSpan.Zero));

        Assert.Equal(sunday + 1, monday);
        Assert.Equal(monday, laterMonday);
    }

    [Fact]
    public void Epoch_UsesUtc_NotTheOffsetOfTheInput()
    {
        // 2026-03-16 00:30 in UTC+2 is still Sunday 22:30 in UTC.
        int local = KeyDerivation.GetEpoch(new DateTimeOffset(2026, 3, 16, 0, 30, 0, TimeSpan.FromHours(2)));
        int utcSunday = KeyDerivation.GetEpoch(new DateTimeOffset(2026, 3, 15, 22, 30, 0, TimeSpan.Zero));

        Assert.Equal(utcSunday, local);
    }
}
