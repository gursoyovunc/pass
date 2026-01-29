using pass.utils;

namespace pass.tests.utils;

public class HashMachine_Tests
{
    private static byte[] Salt(int size = 16)
    {
        // deterministic salt for tests
        var salt = new byte[size];

        for (var i = 0; i < salt.Length; i++)
        {
            salt[i] = (byte)(i + 1);
        }

        return salt;
    }

    [Fact]
    public void ComputeHash_produces_same_outputs_with_same_inputs()
    {
        // Arrange
        const string password = "P@ssw0rd!";
        const int iterations  = 100_000;
        var salt              = Salt();

        // Act
        var hash1 = HashGenerator.ComputeHash(password, salt, iterations);
        var hash2 = HashGenerator.ComputeHash(password, salt, iterations);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_produces_different_outputs_with_different_salts()
    {
        // Arrange
        const string password = "P@ssw0rd!";
        var salt1             = Salt();
        var salt2             = Salt();

        salt2[0] ^= 0xFF; // change one byte

        // Act
        var hashWithSalt1 = HashGenerator.ComputeHash(password, salt1, 200_000);
        var hashWithSalt2 = HashGenerator.ComputeHash(password, salt2, 200_000);

        // Assert
        Assert.NotEqual(hashWithSalt1, hashWithSalt2);
    }

    [Fact]
    public void ComputeHash_produces_different_outputs_with_different_iterations()
    {
        // Arrange
        const string password = "P@ssw0rd!";
        var salt              = Salt();

        // Act
        var hashWithLowIterationCount  = HashGenerator.ComputeHash(password, salt, 10_000);
        var hashWithHighIterationCount = HashGenerator.ComputeHash(password, salt, 600_000);

        // Assert
        Assert.NotEqual(hashWithLowIterationCount, hashWithHighIterationCount);
    }

    [Fact]
    public void ComputeHash_applies_default_iterations_when_none_provided()
    {
        // Arrange
        const string password = "defaults";
        var salt              = Salt();

        // Act
        var hashWithDefaults = HashGenerator.ComputeHash(password, salt);
        var hashWithExplicit = HashGenerator.ComputeHash(password, salt, 600_000);

        // Assert
        Assert.Equal(hashWithDefaults, hashWithExplicit);
    }

    [Fact]
    public void ComputeHash_succeeds_when_empty_password_is_provided()
    {
        // Arrange
        var password = string.Empty;
        var salt     = Salt();

        // Act
        var hash = HashGenerator.ComputeHash(password, salt, 5_000);

        // Assert
        Assert.False(hash.Length == 0, "Hash should not be empty.");
    }
}