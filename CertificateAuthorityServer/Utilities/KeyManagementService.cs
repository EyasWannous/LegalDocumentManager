using CertificateAuthorityServer.Controllers;
using System.Security.Cryptography;
using System.Text;

namespace CertificateAuthorityServer.Utilities;

public class KeyManagementService
{
    private const string PrivateKeyPath = "Keys/private_key.pem";
    private const string PublicKeyPath = "Keys/public_key.pem";
    private const string Passphrase = "YourSecurePassphraseHere";
    private readonly string DomainUrl;

    public KeyManagementService(IConfiguration configuration)
    {
        DomainUrl = configuration["DomainUrl"]!;
    }

    public Certificate GenerateCertificate(CertificateRequest request)
    {
        if (string.IsNullOrEmpty(request.ClientPublicKey))
        {
            throw new ArgumentException("Client public key is required.");
        }

        var certificate = new Certificate
        {
            IssuedTo = request.IssuedTo,
            IssuedFrom = DomainUrl,
            IssuedAt = DateTime.Now,
            Expiry = request.Expiry,
            ClientPublicKey = request.ClientPublicKey
        };

        var certificateData = System.Text.Json.JsonSerializer.Serialize(new
        {
            certificate.IssuedTo,
            certificate.IssuedFrom,
            certificate.IssuedAt,
            certificate.Expiry,
            certificate.ClientPublicKey
        });

        using (RSA rsa = GetPrivateKey())
        {
            byte[] certificateBytes = Encoding.UTF8.GetBytes(certificateData);
            byte[] signature = rsa.SignData(certificateBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificate.Signature = Convert.ToBase64String(signature);
        }

        return certificate;
    }

    public bool ValidateCertificate(Certificate certificate)
    {
        // Check if the certificate has expired
        if (DateTime.UtcNow < certificate.IssuedAt || DateTime.UtcNow > certificate.Expiry)
            return false;

        // Serialize the certificate data (excluding the signature) to JSON
        var certificateData = System.Text.Json.JsonSerializer.Serialize(new
        {
            certificate.IssuedTo,
            certificate.IssuedFrom,
            certificate.IssuedAt,
            certificate.Expiry,
            certificate.ClientPublicKey
        });

        // Verify the signature
        using RSA rsa = GetPublicKey();
        byte[] certificateBytes = Encoding.UTF8.GetBytes(certificateData);
        byte[] signatureBytes = Convert.FromBase64String(certificate.Signature);
        return rsa.VerifyData(certificateBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void GenerateKeyPair()
    {
        using RSA rsa = RSA.Create(2048); // Generate a 2048-bit RSA key pair
                                          // Export public key
        var publicKey = rsa.ExportRSAPublicKey();
        File.WriteAllBytes(PublicKeyPath, publicKey);

        // Export and encrypt private key
        var privateKey = rsa.ExportRSAPrivateKey();
        var encryptedPrivateKey = EncryptPrivateKey(privateKey);
        File.WriteAllBytes(PrivateKeyPath, encryptedPrivateKey);
    }

    public RSA GetPrivateKey()
    {
        if (!File.Exists(PrivateKeyPath))
            throw new FileNotFoundException("Private key not found.");

        var encryptedPrivateKey = File.ReadAllBytes(PrivateKeyPath);
        var privateKey = DecryptPrivateKey(encryptedPrivateKey);

        RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);
        return rsa;
    }

    public RSA GetPublicKey()
    {
        if (!File.Exists(PublicKeyPath))
            throw new FileNotFoundException("Public key not found.");

        var publicKey = File.ReadAllBytes(PublicKeyPath);
        RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        return rsa;
    }

    public byte[] SignData(string dataToSign)
    {
        using RSA rsa = GetPrivateKey();
        byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);
        return rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public bool VerifySignature(string originalData, byte[] signature)
    {
        using RSA rsa = GetPublicKey();
        byte[] dataBytes = Encoding.UTF8.GetBytes(originalData);
        return rsa.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private byte[] EncryptPrivateKey(byte[] privateKey)
    {
        using Aes aes = Aes.Create();
        aes.Key = DeriveKeyFromPassphrase();
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();

        ms.Write(aes.IV, 0, aes.IV.Length); // Write IV to the beginning
        using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cryptoStream.Write(privateKey, 0, privateKey.Length);
        }

        return ms.ToArray();
    }

    private byte[] DecryptPrivateKey(byte[] encryptedPrivateKey)
    {
        using Aes aes = Aes.Create();
        aes.Key = DeriveKeyFromPassphrase();

        using var ms = new MemoryStream(encryptedPrivateKey);
        var iv = new byte[16];
        ms.Read(iv, 0, iv.Length); // Read IV from the beginning
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        
        var decrypted = new MemoryStream();
        cryptoStream.CopyTo(decrypted);
        return decrypted.ToArray();
    }

    private byte[] DeriveKeyFromPassphrase()
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(Passphrase));
    }
}