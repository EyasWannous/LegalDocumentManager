using System.Diagnostics;

namespace LegalDocumentManager.Services;

public static class ScanService
{
    public static Task<bool> ScanFileWithWindowsDefenderAsync(string filePath)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = @"C:\Program Files\Windows Defender\mpcmdrun.exe",
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.Start();
        process.WaitForExit();

        return Task.FromResult(process.ExitCode == 0); // 0 means no threats found
    }
}
