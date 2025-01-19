using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebClient;


public class KeyManagementService
{
    private const string PrivateKeyPath = "Keys/private_key.pem";
    private const string PublicKeyPath = "Keys/public_key.pem";
    private const string Passphrase = "YourSecurePassphraseHere";
    private const string ServerKeysURL = "https://localhost:7011/api/keys";
    private const string CertificateAuthorityURL = "https://localhost:7154/api/key";
    public static RSA CAPublicKey = null;
    public static RSA ServerPublicKey = null;
    public static string SymmetricKey = null;
    public static bool IsValidSignature = false;

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

    public static async Task<string> EncryptSymmetricAsync(string plainText)
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

    public static async Task<string> DecryptSymmetricAsync(string cipherText)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(SymmetricKey);
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

    public async Task GetCAPublicKey()
    {
        try
        {
            var requestUrl = $"{CertificateAuthorityURL}";

            var _httpClient = new HttpClient();

            HttpResponseMessage response = await _httpClient.GetAsync(requestUrl);

            response.EnsureSuccessStatusCode();

            string publicKeyString = await response.Content.ReadAsStringAsync();

            CAPublicKey = ConvertBase64PublicKeyToRsa(publicKeyString);
        }
        catch (Exception ex)
        {
            // Handle or log the exception as needed
            throw new ApplicationException("Failed to fetch the public key.", ex);
        }
    }
    public async Task VerifyCertificate(Certificate certificate)
    {
        if (certificate == null)
            throw new ArgumentNullException(nameof(certificate), "Certificate cannot be null.");

        if (CAPublicKey == null)
            throw new InvalidOperationException("CA public key is not available. Fetch it using GetCAPublicKey.");

        try
        {
            // Recreate the certificate data string
            string certificateData = JsonSerializer.Serialize(new
            {
                certificate.IssuedTo,
                certificate.IssuedFrom,
                certificate.IssuedAt,
                certificate.Expiry,
                certificate.ClientPublicKey
            });

            // Convert the signature from Base64 to byte array
            byte[] signatureBytes = Convert.FromBase64String(certificate.Signature);

            // Verify the signature using the CA public key
            byte[] certificateDataBytes = Encoding.UTF8.GetBytes(certificateData);
            bool isValidSignature = CAPublicKey.VerifyData(
                certificateDataBytes,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );

            if (!isValidSignature)
                throw new CryptographicException("Invalid certificate signature.");

            IsValidSignature = isValidSignature;

            // Validate the certificate fields
            if (certificate.Expiry < DateTime.Now)
                throw new InvalidOperationException("The certificate has expired.");

            if (string.IsNullOrEmpty(certificate.IssuedTo) || string.IsNullOrEmpty(certificate.IssuedFrom))
                throw new InvalidOperationException("The certificate has missing fields.");

            // Ensure the certificate was issued by the expected authority
            if (certificate.IssuedFrom != "Certifier.com") // Replace with your CA URL
                throw new InvalidOperationException("The certificate was not issued by a trusted authority.");

            // If all checks pass
            Console.WriteLine("Certificate is valid.");
        }
        catch (Exception ex)
        {
            throw new ApplicationException("Certificate verification failed.", ex);
        }
    }


}

