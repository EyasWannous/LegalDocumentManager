﻿using Shared.Encryptions;
using System.Security.Cryptography;
using System.Text;

namespace LegalDocumentManager.Services;

public class KeyManagementService
{
    private const string PrivateKeyPath = "Keys/private_key.pem";
    private const string PublicKeyPath = "Keys/public_key.pem";
    private const string Passphrase = "YourSecurePassphraseHere";
    public static string AESKey = AESKeyGenerator.GenerateKeyBase64(128);
    public static string ClientPublicKeyString64;

    public KeyManagementService()
    {
    }

    public async Task GenerateKeyPairAsync()
    {
        using RSA rsa = RSA.Create(2048); // Generate a 2048-bit RSA key pair
                                          // Export public key
        byte[] publicKey = rsa.ExportRSAPublicKey();
        File.WriteAllBytes(PublicKeyPath, publicKey);

        // Export and encrypt private key
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

    private RSA ConvertBase64PublicKeyToRsa(string base64PublicKey)
    {
        // Decode the Base64-encoded string to get the DER bytes
        byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

        // Create an RSA instance
        RSA rsa = RSA.Create();

        // Import the public key in DER format
        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        return rsa;
    }

    public static async Task<string> EncryptSymmetricAsync(string plainText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(AESKey);
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;

        aesAlg.GenerateIV();
        byte[] iv = aesAlg.IV;

        using var msEncrypt = new MemoryStream();
        await msEncrypt.WriteAsync(iv, 0, iv.Length); // Store IV first

        using (var csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(aesAlg.Key, iv), CryptoStreamMode.Write))

        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            await swEncrypt.WriteAsync(plainText);
            swEncrypt.Flush(); // Ensure everything is written
        }

        byte[] encryptedBytes = msEncrypt.ToArray();
        //Console.WriteLine($"Encrypted Bytes Length: {encryptedBytes.Length}");
        return Convert.ToBase64String(encryptedBytes);
    }

    public static async Task<string> DecryptSymmetricAsync(string cipherText)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(AESKey);
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;

        byte[] iv = new byte[aesAlg.BlockSize / 8];
        Array.Copy(fullCipher, iv, iv.Length);

        //Console.WriteLine($"Decryption IV: {BitConverter.ToString(iv)}");

        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);
        using var msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        var decryptedText = await srDecrypt.ReadToEndAsync();

        //Console.WriteLine($"Decrypted Text: {decryptedText}");
        return decryptedText;
    }
}
