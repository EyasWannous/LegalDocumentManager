using System.Security.Cryptography;
using System.Text;

namespace Shared.Encryptions;

public class EncryptionAES
{
    private readonly byte[] key; // Symmetric key shared between users

    public EncryptionAES(string encryptionKey)
    {
        // Ensure the key is 32 bytes (256 bits) for AES-256
        key = Encoding.UTF8.GetBytes(PadOrTrimKey(encryptionKey, 32));
    }

    private string PadOrTrimKey(string key, int length)
    {
        if (key.Length == length) return key;

        if (key.Length > length)
            return key[..length];

        return key.PadRight(length, '0'); // Padding with zeros if too short
    }


    public async Task<string> EncryptAsync(string plainText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
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

    public async Task<string> DecryptAsync(string cipherText)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
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

    public async Task<string> DecryptWithCatchAsync(string cipherText)
    {
        try
        {
            byte[] fullCipher = Convert.FromBase64String(cipherText);

            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            // Extract IV from the first part of the ciphertext
            byte[] iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(fullCipher, iv, iv.Length);

            // Debugging: check the IV value
            Console.WriteLine($"Decryption IV: {BitConverter.ToString(iv)}");

            // Create decryptor
            using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

            // Use the remaining ciphertext after the IV
            using var msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            var decryptedText = await srDecrypt.ReadToEndAsync();

            Console.WriteLine($"Decrypted Text: {decryptedText}");
            return decryptedText;
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            throw;
        }
    }


}
