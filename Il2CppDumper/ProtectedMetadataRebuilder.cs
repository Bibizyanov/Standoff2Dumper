using System;
using System.Diagnostics;
using System.IO;

namespace Il2CppDumper
{
    internal static class ProtectedMetadataRebuilder
    {
        public static string Rebuild(string binaryPath, string outputDir, Config config)
        {
            var script = Path.Combine(AppContext.BaseDirectory, "protected_metadata.py");
            var cacheDir = Path.Combine(outputDir, ".metadata");
            var metadataPath = Path.Combine(cacheDir, "global-metadata.dat");

            Directory.CreateDirectory(cacheDir);
            if (File.Exists(metadataPath) && File.GetLastWriteTimeUtc(metadataPath) >= File.GetLastWriteTimeUtc(binaryPath))
                return metadataPath;

            var startInfo = new ProcessStartInfo
            {
                FileName = string.IsNullOrWhiteSpace(config.PythonExecutable) ? "python" : config.PythonExecutable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            startInfo.ArgumentList.Add(script);
            startInfo.ArgumentList.Add(binaryPath);
            startInfo.ArgumentList.Add("-o");
            startInfo.ArgumentList.Add(cacheDir);
            startInfo.ArgumentList.Add("--metadata-va");
            startInfo.ArgumentList.Add(config.ProtectedMetadataVA);
            startInfo.ArgumentList.Add("--code-reg-va");
            startInfo.ArgumentList.Add(config.ProtectedCodeRegistration);
            startInfo.ArgumentList.Add("--metadata-reg-va");
            startInfo.ArgumentList.Add(config.ProtectedMetadataRegistration);

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("python start failed");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0 || !File.Exists(metadataPath))
                throw new InvalidOperationException((string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim());

            return metadataPath;
        }
    }
}
