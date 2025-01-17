using Shared.Encryptions;

namespace LegalDocumentManager.Data;

public static class Constant
{
    // A public or internal dictionary to store keys
    public static Dictionary<string, string> ASymmetricKeys { get; } = [];
    public static string AESKey = AESKeyGenerator.GenerateKeyBase64(128);

    // A method to initialize the keys
    public static void InitializeKeys()
    {
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        ASymmetricKeys.Add(privateKey, publicKey);
    }
}
