using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace WebClient;


public class KeyManagementService
{
    private const string PrivateKeyPath = "Keys/private_key.pem";
    private const string PublicKeyPath = "Keys/public_key.pem";
    private const string Passphrase = "YourSecurePassphraseHere";
    private const string ServerKeysURL = "https://localhost:7011/api/keys";
    public static RSA ServerPublicKey = null;
    public static string SymmetricKey = null;

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

    public async Task GetServerPublicKeyAsync()
    {
        try
        {
            var rsa = (await GetPublicKeyAsync());

            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

            var requestUrl = $"{ServerKeysURL}/public?publickey={Uri.EscapeDataString(publicKey)}";

            var _httpClient = new HttpClient();

            HttpResponseMessage response = await _httpClient.GetAsync(requestUrl);

            response.EnsureSuccessStatusCode();

            string publicKeyString = await response.Content.ReadAsStringAsync();

            ServerPublicKey = ConvertBase64PublicKeyToRsa(publicKeyString);
        }
        catch (Exception ex)
        {
            // Handle or log the exception as needed
            throw new ApplicationException("Failed to fetch the public key.", ex);
        }
    }

    public async Task FetchSymmetricKeyAsync()
    {
        try
        {
            var requestUri = $"{ServerKeysURL}/symmetric";

            var _httpClient = new HttpClient();

            var response = await _httpClient.GetAsync(requestUri);

            response.EnsureSuccessStatusCode();

            var hashedKey = await response.Content.ReadAsStringAsync();

            SymmetricKey = Decrypt(hashedKey, await GetPrivateKeyAsync());
        }
        catch (Exception ex)
        {
            // Handle or log the exception as needed
            throw new ApplicationException("Failed to fetch the public key.", ex);
        }
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

    private string Decrypt(string cipherText, RSA privateKeyRSA)
    {
        byte[] decryptedData = privateKeyRSA.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedData);
    }

    private RSA ConvertBase64PublicKeyToRsa(string base64PublicKey)
    {
        byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

        RSA rsa = RSA.Create();

        rsa.ImportRSAPublicKey(publicKeyBytes, out _);

        return rsa;
    }

    private RSA ConvertBase64PrivateKeyToRsa(string base64PrivateKey)
    {
        byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey);

        RSA rsa = RSA.Create();

        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        return rsa;
    }

    public async Task<string> EncryptAsync(string plainText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(SymmetricKey);
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
}

