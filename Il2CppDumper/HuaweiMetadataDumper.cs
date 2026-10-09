using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Il2CppDumper
{
    internal static class HuaweiMetadataDumper
    {
        public static void Dump(string binary, string output, Config cfg)
        {
            Directory.CreateDirectory(output);
            var logPath = Path.Combine(output, "huawei.log");
            using var log = new StreamWriter(new FileStream(logPath, FileMode.Create, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
            var reportLock = new object();
            void Report(string value)
            {
                lock (reportLock)
                {
                    var line = $"[{DateTime.Now:HH:mm:ss}] {value}";
                    Console.WriteLine(line);
                    log.WriteLine(line);
                }
            }

            var py = Path.Combine(AppContext.BaseDirectory, "huawei_dump.py");
            if (!File.Exists(py))
                throw new FileNotFoundException("huawei_dump.py missing next to Il2CppDumper.exe", py);

            var temp = Path.Combine(Path.GetTempPath(), "axent-huawei-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            var wm = Path.Combine(temp, "wm-input.json");
            var dumpCopied = false;
            try
            {
                File.WriteAllText(wm, JsonSerializer.Serialize(WatermarkService.CreateScriptWatermark(),
                    new JsonSerializerOptions { IncludeFields = true }));

                Report("Huawei: starting Python parser");
                using (var process = StartPython(py, binary, temp, wm, cfg, Report))
                {
                    var stdout = Pump(process.StandardOutput, Report);
                    var stderr = Pump(process.StandardError, value => Report("stderr: " + value));
                    process.WaitForExit();
                    Task.WaitAll(stdout, stderr);
                    if (process.ExitCode != 0)
                        throw new InvalidDataException($"Huawei parser failed (exit {process.ExitCode}). Check {logPath}");
                }
                Report("Huawei: Python parser finished");
                if (!File.Exists(Path.Combine(temp, "dump.cs")) || !File.Exists(Path.Combine(temp, "script.json")))
                    throw new InvalidDataException("Huawei parser produced no dump.cs/script.json");

                CopyResults(temp, output);
                dumpCopied = true;
                Report("Huawei: dump.cs and script.json saved");

                if (cfg.GenerateDummyDll)
                {
                    var data = Path.Combine(temp, "huawei.manifest.jsonl");
                    if (!File.Exists(data))
                        throw new InvalidDataException("Huawei manifest missing");
                    Report("Huawei: generating DummyDLL (469 assemblies)");
                    try
                    {
                        GC.Collect();
                        var result = HuaweiDummyAssemblyExporter.Export(data,
                            Path.Combine(output, "DummyDll"), Report);
                        var infoFile = Path.Combine(output, "dump.info.json");
                        var info = JsonNode.Parse(File.ReadAllText(infoFile)) ?? throw new InvalidDataException("dump info missing");
                        info["dummyDll"] = true;
                        info["dummyDllAssemblies"] = result.assemblies;
                        info["dummyDllTypes"] = result.types;
                        info["dummyDllFields"] = result.fields;
                        info["dummyDllMethods"] = result.methods;
                        File.WriteAllText(infoFile, info.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                        Report($"Huawei: DummyDLL done: {result.assemblies} assemblies, {result.types} types, {result.methods} methods");
                    }
                    catch (Exception ex)
                    {
                        var errorPath = Path.Combine(output, "DummyDLL-error.log");
                        File.WriteAllText(errorPath, ex.ToString());
                        Report("WARNING: DummyDLL generation failed; original dump remains valid. See " + errorPath);
                        Report(ex.ToString());
                        var infoFile = Path.Combine(output, "dump.info.json");
                        if (File.Exists(infoFile))
                        {
                            var info = JsonNode.Parse(File.ReadAllText(infoFile));
                            if (info != null)
                            {
                                info["dummyDll"] = false;
                                info["dummyDllError"] = ex.Message;
                                File.WriteAllText(infoFile, info.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                            }
                        }
                    }
                }
                Report("Huawei: complete");
            }
            catch (Exception e)
            {
                if (dumpCopied)
                    Report("Huawei: original dump.cs/script.json preserved; DummyDLL may be incomplete");
                Report("ERROR: " + e);
                throw new InvalidOperationException($"Huawei failed. Details: {logPath}", e);
            }
            finally
            {
                try { Directory.Delete(temp, true); }
                catch (Exception e) { Report("Temporary files cleanup: " + e.Message); }
            }
        }

        private static Process StartPython(string py, string binary, string output, string wm,
            Config cfg, Action<string> report)
        {
            var requested = string.IsNullOrWhiteSpace(cfg.PythonExecutable) ? "python" : cfg.PythonExecutable;
            var candidates = new List<(string executable, bool launcher)> { (requested, false) };
            if (string.Equals(requested, "python", StringComparison.OrdinalIgnoreCase))
            {
                var embedded = Path.Combine(AppContext.BaseDirectory, "python", "python.exe");
                if (File.Exists(embedded)) candidates.Insert(0, (embedded, false));
                candidates.Add(("py", true));
                candidates.Add(("python3", false));
            }
            Exception last = null;
            foreach (var candidate in candidates)
            {
                var p = new ProcessStartInfo
                {
                    FileName = candidate.executable,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                if (candidate.launcher) p.ArgumentList.Add("-3");
                p.ArgumentList.Add("-u");
                p.ArgumentList.Add(py);
                p.ArgumentList.Add(binary);
                p.ArgumentList.Add("-o");
                p.ArgumentList.Add(output);
                p.ArgumentList.Add("--wm");
                p.ArgumentList.Add(wm);
                if (cfg.GenerateStruct) p.ArgumentList.Add("--structs");
                if (cfg.GenerateDummyDll) p.ArgumentList.Add("--dummy-manifest");
                try
                {
                    var process = Process.Start(p);
                    if (process == null) throw new InvalidOperationException("Python process did not start");
                    report("Python executable: " + candidate.executable);
                    return process;
                }
                catch (Win32Exception e) { last = e; report("Python not available: " + candidate.executable); }
                catch (FileNotFoundException e) { last = e; report("Python not found: " + candidate.executable); }
            }
            throw new InvalidOperationException(
                "Python 3 is required for Huawei mode. Install it, add python.exe to PATH or set PythonExecutable in config.json.", last);
        }

        private static Task Pump(StreamReader reader, Action<string> report) => Task.Run(async () =>
        {
            string line;
            while ((line = await reader.ReadLineAsync()) != null)
                report(line);
        });

        private static void CopyResults(string temp, string output)
        {
            foreach (var f in Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(f);
                if (name == "wm-input.json" || name == "huawei.manifest.jsonl") continue;
                var relative = Path.GetRelativePath(temp, f);
                var dest = Path.Combine(output, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(f, dest, true);
            }
        }
    }
}
