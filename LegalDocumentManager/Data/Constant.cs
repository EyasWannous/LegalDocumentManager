using Shared.Encryptions;

namespace LegalDocumentManager.Data;

public static class Constant
{
    // A public or internal dictionary to store keys
    public static Dictionary<string, string> Keys { get; } = [];
    public static string key = AESKeyGenerator.GenerateKeyBase64(128);

    // A method to initialize the keys
    public static void InitializeKeys()
    {
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        Keys.Add(privateKey, publicKey);
    }
}
