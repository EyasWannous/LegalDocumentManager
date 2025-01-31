# Legal Document Manager

Legal Document Manager is a system designed for securely managing legal documents with digital signing capabilities. It includes a **Certificate Authority Server** to provide cryptographic signing for document authentication.

## Features
- **Document Management**: Upload, store, and organize legal documents.
- **Digital Signing**: Sign documents securely using cryptographic certificates.
- **Certificate Authority (CA) Server**: Issue and manage digital certificates.
- **Secure Storage**: Encrypt and store sensitive legal documents.
- **User Authentication**: Role-based access control for enhanced security.

## Project Structure
```
LegalDocumentManager/
├── CertificateAuthorityServer/   # Handles digital signing and certificate management
│   ├── Controllers/
│   │   ├── CertificateController.cs
│   ├── appsettings.json
│   ├── Program.cs
│   ├── CertificateAuthorityServer.csproj
│
├── LegalDocumentManager.sln       # Solution file
├── LICENSE.txt                    # License information
├── README.md                      # Project documentation
```

## Prerequisites
- .NET SDK 6.0 or later
- A code editor (Visual Studio, VS Code, or Rider)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/legal-document-manager.git
   ```
2. Navigate to the project directory:
   ```sh
   cd LegalDocumentManager
   ```
3. Build the solution:
   ```sh
   dotnet build
   ```

## Usage
### Running the Certificate Authority Server
```sh
dotnet run --project CertificateAuthorityServer/CertificateAuthorityServer.csproj
```

## License
This project is licensed under the MIT License. See `LICENSE.txt` for more details.

## Contributing
Contributions are welcome! Feel free to fork the repository and submit a pull request.

## Contact
For issues and feature requests, please open an issue in the repository.

