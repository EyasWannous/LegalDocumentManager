using System.Security.Cryptography;
using System.Text;

namespace LegalDocumentManager;

public class EncryptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _targetHost;
    private readonly byte[] _key;

    public EncryptionMiddleware(RequestDelegate next, string targetHost, byte[] key)
    {
        _next = next;
        _targetHost = targetHost;
        _key = key;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Encrypt outgoing data
        if (context.Request.Host.Host.Equals(_targetHost, StringComparison.OrdinalIgnoreCase))
        {
            if (context.Request.ContentLength > 0)
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                string requestBody = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;

                string encryptedBody = await EncryptAsync(requestBody);
                byte[] encryptedBytes = Encoding.UTF8.GetBytes(encryptedBody);
                context.Request.Body = new MemoryStream(encryptedBytes);
                context.Request.ContentLength = encryptedBytes.Length;
            }
        }

        // Invoke the next middleware
        await _next(context);

        // Decrypt incoming data
        if (context.Request.Host.Host.Equals(_targetHost, StringComparison.OrdinalIgnoreCase) &&
            context.Response.ContentLength > 0 &&
            context.Response.Body.CanRead)
        {
            context.Response.Body.Seek(0, SeekOrigin.Begin);
            using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
            string encryptedResponseBody = await reader.ReadToEndAsync();
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            string decryptedBody = await DecryptAsync(encryptedResponseBody);
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decryptedBody);

            context.Response.Body.SetLength(0);
            await context.Response.Body.WriteAsync(decryptedBytes, 0, decryptedBytes.Length);
        }
    }

    public async Task<string> EncryptAsync(string plainText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = _key;
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
        aesAlg.Key = _key;
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