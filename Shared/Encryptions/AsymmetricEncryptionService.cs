using System.Security.Cryptography;
using System.Text;

namespace Shared.Encryptions;

public class AsymmetricEncryptionService
{
    // Encrypt a message using the recipient's public key
    public static string Encrypt(string plainText, string publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);

        byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encryptedData);
    }

    // Decrypt a message using the recipient's private key
    public static string Decrypt(string cipherText, string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);

        byte[] decryptedData = rsa.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedData);
    }

    public static byte[] DecryptBytes(byte[] bytes, string privateKey)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);

        byte[] decryptedData = rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
        return decryptedData;
    }
}
