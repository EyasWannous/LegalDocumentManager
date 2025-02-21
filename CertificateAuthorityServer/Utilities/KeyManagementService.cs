using CertificateAuthorityServer.Controllers.Dtos;
using CertificateAuthorityServer.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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

    public async Task<Certificate> GenerateCertificateAsync(CertificateRequest request)
    {
        if (string.IsNullOrEmpty(request.ClientPublicKey))
            throw new ArgumentException("Client public key is required.");

        var certificate = new Certificate
        {
            IssuedTo = request.IssuedTo,
            IssuedFrom = DomainUrl,
            IssuedAt = DateTime.Now,
            Expiry = request.Expiry,
            ClientPublicKey = request.ClientPublicKey
        };

        string certificateData = JsonSerializer.Serialize(new
        {
            certificate.IssuedTo,
            certificate.IssuedFrom,
            certificate.IssuedAt,
            certificate.Expiry,
            certificate.ClientPublicKey
        });

        using (RSA rsa = await GetPrivateKeyAsync())
        {
            byte[] certificateBytes = Encoding.UTF8.GetBytes(certificateData);
            byte[] signature = rsa.SignData(certificateBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            certificate.Signature = Convert.ToBase64String(signature);
        }

        return certificate;
    }

    public async Task<bool> ValidateCertificateAsync(Certificate certificate)
    {
        if (DateTime.UtcNow < certificate.IssuedAt || DateTime.UtcNow > certificate.Expiry)
            return false;

        // Serialize the certificate data (excluding the signature) to JSON
        string certificateData = JsonSerializer.Serialize(new
        {
            certificate.IssuedTo,
            certificate.IssuedFrom,
            certificate.IssuedAt,
            certificate.Expiry,
            certificate.ClientPublicKey
        });

        // Verify the signature
        using RSA rsa = await GetPublicKeyAsync();
        byte[] certificateBytes = Encoding.UTF8.GetBytes(certificateData);
        byte[] signatureBytes = Convert.FromBase64String(certificate.Signature);

        return rsa.VerifyData(
            certificateBytes,
            signatureBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }

    public async Task GenerateKeyPairAsync()
    {
        using RSA rsa = RSA.Create(2048);

        byte[] publicKey = rsa.ExportRSAPublicKey();
        File.WriteAllBytes(PublicKeyPath, publicKey);

        byte[] privateKey = rsa.ExportRSAPrivateKey();
        byte[] encryptedPrivateKey = await EncryptPrivateKeyAsync(privateKey);

        File.WriteAllBytes(PrivateKeyPath, encryptedPrivateKey);
    }

    public async Task<RSA> GetPrivateKeyAsync()
    {
        if (!File.Exists(PrivateKeyPath))
            throw new FileNotFoundException("Private key not found.");

        byte[] encryptedPrivateKey = File.ReadAllBytes(PrivateKeyPath);
        byte[] privateKey = await DecryptPrivateKeyAsync(encryptedPrivateKey);

        RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        return rsa;
    }

    public Task<RSA> GetPublicKeyAsync()
    {
        if (!File.Exists(PublicKeyPath))
            throw new FileNotFoundException("Public key not found.");

        byte[] publicKey = File.ReadAllBytes(PublicKeyPath);
        RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);

        return Task.FromResult(rsa);
    }

    public async Task<byte[]> SignDataAsync(string dataToSign)
    {
        using RSA rsa = await GetPrivateKeyAsync();
        byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

        return rsa.SignData(
            dataBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }

    public async Task<bool> VerifySignatureAsync(string originalData, byte[] signature, string publicKey64)
    {
        using RSA rsa = await ConvertBase64PublicKeyToRsaAsync(publicKey64);
        byte[] dataBytes = Encoding.UTF8.GetBytes(originalData);

        return rsa.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private async Task<byte[]> EncryptPrivateKeyAsync(byte[] privateKey)
    {
        using Aes aes = Aes.Create();
        aes.Key = await DeriveKeyFromPassphraseAsync();
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

    private async Task<byte[]> DecryptPrivateKeyAsync(byte[] encryptedPrivateKey)
    {
        using Aes aes = Aes.Create();
        aes.Key = await DeriveKeyFromPassphraseAsync();

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

    private Task<byte[]> DeriveKeyFromPassphraseAsync()
    {
        return Task.FromResult(
            SHA256.HashData(Encoding.UTF8.GetBytes(Passphrase))
        );
    }

    private Task<RSA> ConvertBase64PublicKeyToRsaAsync(string base64PublicKey)
    {
        byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

        RSA rsa = RSA.Create();

        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        return Task.FromResult(rsa);
    }
}