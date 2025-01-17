using System.Security.Cryptography;

namespace Shared.Encryptions;

public class AESKeyGenerator
{
    // Generate a random AES key with a specified size (128, 192, or 256 bits)
    public static byte[] GenerateKey(int keySizeInBits)
    {
        if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256)
        {
            throw new ArgumentException("Key size must be 128, 192, or 256 bits.");
        }

        byte[] key = new byte[keySizeInBits / 8]; // Convert bits to bytes
        RandomNumberGenerator.Fill(key); // Fill the byte array with cryptographically strong random bytes
        return key;
    }

    // Convert the key to a Base64 string for easier storage and display
    public static string GenerateKeyBase64(int keySizeInBits)
    {
        byte[] key = GenerateKey(keySizeInBits);
        return Convert.ToBase64String(key);
    }
}

