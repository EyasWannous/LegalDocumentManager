using Microsoft.AspNetCore.Components.Forms;
using System.Text.Json;
using WebClient.Models;

namespace WebClient.Components.Pages;

public partial class FileUpload
{
    private IBrowserFile? SelectedFile;
    private string FileName = string.Empty;
    private bool IsLoading = false;
    private string Message = string.Empty;
    private string MessageClass = string.Empty;
    private string? userToken;

    private Task HandleFileSelected(InputFileChangeEventArgs e)
    {
        SelectedFile = e.File;
        FileName = SelectedFile?.Name ?? string.Empty;
        Message = string.Empty;

        return Task.CompletedTask;
    }

    private async Task UploadFile()
    {
        if (SelectedFile is null || string.IsNullOrWhiteSpace(FileName))
        {
            Message = "Please select a file and enter a valid file name.";
            MessageClass = "text-danger";
            return;
        }

        IsLoading = true;
        Message = string.Empty;

        try
        {
            // Retrieve token from ProtectedSessionStorage
            var userSessionResult = await ProtectedSessionStorage.GetAsync<UserSession>("UserSession");
            var userSession = userSessionResult.Success ? userSessionResult.Value : null;

            if (userSession?.Token == null)
            {
                Message = "You are not authorized. Please log in.";
                MessageClass = "text-danger";
                return;
            }

            userToken = userSession.Token;

            // Add token to the request headers
            Http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", userToken);

            // Read the file into a byte array
            using var fileStream = SelectedFile.OpenReadStream(maxAllowedSize: 10 * 1024 * 1024); // Limit to 10MB

            using var memoryStream = new MemoryStream();
            await fileStream.CopyToAsync(memoryStream);
            var fileBytes = memoryStream.ToArray();

            // Encrypt the file
            // var encryptedFile = KeyManagementService.EncryptSymmetricAsync EncryptFile(fileBytes, KeyManagementService.SymmetricKey);

            // Prepare the upload view model (JSON payload)
            var uploadModel = new UploadViewModel
            {
                EncryptedFile = Convert.ToBase64String(fileBytes),
                FileName = FileName
            };

            // Send the data as JSON
            var response = await Http.PostAsJsonAsync(
                "https://localhost:7011/api/Attachment/Upload",
                await KeyManagementService.EncryptSymmetricAsync(JsonSerializer.Serialize(uploadModel))
            );

            if (response.IsSuccessStatusCode)
            {
                Message = "File uploaded successfully!";
                MessageClass = "text-success";
            }
            else
            {
                Message = $"Failed to upload file. Status: {response.StatusCode}";
                MessageClass = "text-danger";
            }
        }
        catch (Exception ex)
        {
            Message = $"An error occurred: {ex.Message}";
            MessageClass = "text-danger";
        }
        finally
        {
            IsLoading = false;
        }
    }

}
