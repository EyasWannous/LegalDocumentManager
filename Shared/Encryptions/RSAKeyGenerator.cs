using System.Security.Cryptography;

namespace Shared.Encryptions;

public class RSAKeyGenerator
{
    public static (string publicKey, string privateKey) GenerateKeys()
    {
        using var rsa = RSA.Create();

        var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

        var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

        return (publicKey, privateKey);
    }

    public static string GetPublicKeyFromPrivateKey(string privateKeyBase64)
    {
        // Convert the Base64 string to bytes
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        // Export the public key from the imported private key
        var publicKeyBytes = rsa.ExportRSAPublicKey();

        // Convert the public key bytes to a Base64 string
        return Convert.ToBase64String(publicKeyBytes);
    }
}

