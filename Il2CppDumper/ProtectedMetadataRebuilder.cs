using System;
using System.Diagnostics;
using System.IO;

namespace Il2CppDumper
{
    internal static class ProtectedMetadataRebuilder
    {
        public readonly record struct RebuildResult(string BinaryPath, string MetadataPath);

        public static RebuildResult Rebuild(string binaryPath, string outputDir, Config config)
        {
            var script = Path.Combine(AppContext.BaseDirectory, "protected_metadata.py");
            var solver = new FileInfo(Path.Combine(AppContext.BaseDirectory, "autoprofile.py"));
            var cacheDir = Path.Combine(outputDir, ".metadata");
            var metadataPath = Path.Combine(cacheDir, "global-metadata.dat");
            var rebuiltBinaryPath = Path.Combine(cacheDir, "libunity.so");

            Directory.CreateDirectory(cacheDir);

            var stampPath = Path.Combine(cacheDir, "cache-key.txt");
            var input = new FileInfo(binaryPath);
            var rebuild = new FileInfo(script);
            var cacheKey = string.Join("|", Path.GetFullPath(binaryPath),
                input.Length, input.LastWriteTimeUtc.Ticks,
                rebuild.Length, rebuild.LastWriteTimeUtc.Ticks,
                solver.Length, solver.LastWriteTimeUtc.Ticks);
            if (File.Exists(metadataPath) && File.Exists(rebuiltBinaryPath) &&
                File.Exists(stampPath) && File.ReadAllText(stampPath) == cacheKey)
            {
                return new RebuildResult(rebuiltBinaryPath, metadataPath);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = string.IsNullOrWhiteSpace(config.PythonExecutable) ? "python" : config.PythonExecutable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            startInfo.ArgumentList.Add(script);
            startInfo.ArgumentList.Add("--quiet");
            startInfo.ArgumentList.Add(binaryPath);
            startInfo.ArgumentList.Add("-o");
            startInfo.ArgumentList.Add(cacheDir);

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("python start failed");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            // Keep the embedded Python preprocessor silent during normal dumping.
            // Its captured output is surfaced only when the rebuild actually fails.
            if (process.ExitCode != 0 || !File.Exists(metadataPath) || !File.Exists(rebuiltBinaryPath))
            {
                var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                if (!string.IsNullOrWhiteSpace(detail))
                    throw new InvalidOperationException("protected metadata rebuild failed: " + detail.Trim());
                throw new InvalidOperationException("protected metadata rebuild failed");
            }

            File.WriteAllText(stampPath, cacheKey);
            return new RebuildResult(rebuiltBinaryPath, metadataPath);
        }
    }
}
