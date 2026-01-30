using System.Security.Cryptography;

namespace pass.utils;

internal static class HashGenerator
{
    private const int DefaultIterations = 600_000;
    private const int OutputLength      = 32;

    public static string ComputeHash(string password, byte[] salt, int iterations = DefaultIterations)
    {
        var bytes = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, OutputLength);

        return Convert.ToHexString(bytes);
    }
}