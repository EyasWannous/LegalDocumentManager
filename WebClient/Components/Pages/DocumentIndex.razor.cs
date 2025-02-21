using Microsoft.JSInterop;
using System.Security.Cryptography;
using System.Text.Json;
using WebClient.Models;

namespace WebClient.Components.Pages;

public partial class DocumentIndex
{
    private List<Attachment> attachments = new();
    private string searchNationalNumber = string.Empty;
    private bool isLoading = false;
    private string errorMessage = string.Empty;
    private string? userToken;

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            try
            {
                var userSessionResult = await ProtectedSessionStorage.GetAsync<UserSession>("UserSession");
                var userSession = userSessionResult.Success ? userSessionResult.Value : null;

                if (userSession?.Token == null)
                {
                    errorMessage = "You are not authorized. Please log in.";
                    NavigationManager.NavigateTo("/login");
                }
                else
                {
                    userToken = userSession.Token;
                }

                await LoadAttachments();
            }
            catch (Exception ex)
            {
                errorMessage = $"Failed to retrieve user session: {ex.Message}";
            }
            finally
            {
                StateHasChanged(); // Re-render the component after initialization
            }
        }
    }

    private async Task LoadAttachments()
    {
        if (string.IsNullOrEmpty(userToken))
        {
            errorMessage = "You are not authorized. Please log in.";
            return;
        }

        isLoading = true;
        errorMessage = string.Empty;

        try
        {
            Http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", userToken);

            var query = string.IsNullOrWhiteSpace(searchNationalNumber)
                ? string.Empty
                : $"?searchNationalNumber={searchNationalNumber}";

            var response = await Http.GetAsync($"https://localhost:7011/api/Attachment/List{query}");

            if (response.IsSuccessStatusCode)
            {
                var res = await response.Content.ReadAsStringAsync();
                if (string.IsNullOrWhiteSpace(res) || res == "[]")
                    attachments = new List<Attachment>();
                else
                {
                    var decBody = await KeyManagementService.DecryptSymmetricAsync(res);
                    attachments = JsonSerializer.Deserialize<List<Attachment>>(decBody) ?? new List<Attachment>();
                }
            }
            else
            {
                errorMessage = $"Error: {response.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            errorMessage = $"An error occurred: {ex.Message}";
        }
        finally
        {
            isLoading = false;
        }
    }

    private async Task DownloadFile(int attachmentId)
    {
        if (string.IsNullOrEmpty(userToken))
        {
            errorMessage = "You are not authorized. Please log in.";
            return;
        }

        isLoading = true;
        errorMessage = string.Empty;

        try
        {
            // Add token to the request headers
            Http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", userToken);

            // Call the Download API
            var response = await Http.GetAsync($"https://localhost:7011/api/Attachment/Download/{attachmentId}");

            if (response.IsSuccessStatusCode)
            {
                // Read the response content
                var result = await response.Content.ReadFromJsonAsync<DownloadViewModel>();

                if (result is not null)
                {
                    result.CheckProperties();

                    // Decrypt the file
                    var decryptedFileBytes = Convert.FromBase64String(await KeyManagementService.DecryptSymmetricAsync(result.EncryptedFile!));

                    var isVerified = VerifySignature(decryptedFileBytes, Convert.FromBase64String(result.Signature!));

                    await JS.InvokeVoidAsync("downloadFile", result.FileName, decryptedFileBytes);

                    errorMessage = "File downloaded successfully!";
                }
                else
                {
                    errorMessage = "Failed to parse the download response.";
                }
            }
            else
            {
                errorMessage = $"Failed to download file. Status: {response.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            errorMessage = $"An error occurred: {ex.Message}";
        }
        finally
        {
            isLoading = false;
        }
    }

    private bool VerifySignature(byte[] fileData, byte[] signature)
    {
        try
        {
            if (KeyManagementService.ServerPublicKey is null)
                throw new InvalidOperationException(nameof(KeyManagementService.ServerPublicKey));

            return KeyManagementService.ServerPublicKey.VerifyData(
                fileData,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error verifying signature: {ex.Message}");
            return false;
        }
    }
}
