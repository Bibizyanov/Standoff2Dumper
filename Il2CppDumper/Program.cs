using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config cfg;

        [STAThread]
        static void Main(string[] args)
        {
            cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "config.json"))) ?? new Config();

            string bp = null;
            string variant = null;
            bool noDummy = false;
            var pos = new List<string>();

            for (var i = 0; i < args.Length; i++)
            {
                var a = args[i];
                if (a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase))
                {
                    Usage();
                    return;
                }
                else if (a.Equals("--version", StringComparison.OrdinalIgnoreCase) || a.Equals("--edition", StringComparison.OrdinalIgnoreCase))
                {
                    if (++i >= args.Length)
                        throw new ArgumentException("missing version");
                    variant = args[i];
                }
                else if (a.Equals("--google", StringComparison.OrdinalIgnoreCase))
                    variant = "google";
                else if (a.Equals("--huawei", StringComparison.OrdinalIgnoreCase))
                    variant = "huawei";
                else if (a.Equals("--no-dummy-dll", StringComparison.OrdinalIgnoreCase))
                    noDummy = true;
                else if (a.StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("unknown option: " + a);
                else
                    pos.Add(a);
            }

            var od = Path.Combine(AppContext.BaseDirectory, "dump");
            if (pos.Count > 0 && File.Exists(pos[0]))
                bp = pos[0];
            if (pos.Count > 1)
                od = Path.GetFullPath(pos[1]);

            Directory.CreateDirectory(od);
            od = Path.GetFullPath(od);
            if (!od.EndsWith(Path.DirectorySeparatorChar))
                od += Path.DirectorySeparatorChar;

            if (bp == null && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var d = new OpenFileDialog { Filter = "libunity.so|libunity.so|Binary|*.*" };
                if (d.ShowDialog())
                    bp = d.FileName;
            }

            if (bp == null)
            {
                Usage();
                return;
            }

            if (string.IsNullOrWhiteSpace(variant))
            {
                variant = string.IsNullOrWhiteSpace(cfg.GameVersion) ? "google" : cfg.GameVersion;
                if (!Console.IsInputRedirected)
                {
                    Console.Write("version [1 Google / 2 Huawei] (1): ");
                    var input = Console.ReadLine()?.Trim();
                    if (input == "2" || input?.Equals("huawei", StringComparison.OrdinalIgnoreCase) == true)
                        variant = "huawei";
                    else if (input == "1" || input?.Equals("google", StringComparison.OrdinalIgnoreCase) == true)
                        variant = "google";
                }
            }
            variant = variant.Trim().ToLowerInvariant();
            if (variant != "google" && variant != "huawei")
            {
                Console.WriteLine("error: version must be google or huawei");
                return;
            }

            if (noDummy)
                cfg.GenerateDummyDll = false;

            if (pos.Count < 2)
            {
                od = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "dump", variant));
                Directory.CreateDirectory(od);
                if (!od.EndsWith(Path.DirectorySeparatorChar))
                    od += Path.DirectorySeparatorChar;
            }

            ProtectedMetadataRebuilder.RebuildResult rb = default;
            try
            {
                var ss = AxentApi.Session(bp);
                WatermarkService.Initialize(cfg, bp, ss.Token, ss.PublicKey);
                if (variant == "huawei")
                {
                    Console.WriteLine("Huawei: beginning dump");
                    HuaweiMetadataDumper.Dump(bp, od, cfg);
                    Console.WriteLine("Huawei: applying watermark");
                    WatermarkService.ApplyTextWatermarks(od);
                    Console.WriteLine("Huawei: hashing output files");
                    WatermarkService.WriteManifest(od);
                    Console.WriteLine("done");
                }
                else
                {
                    rb = ProtectedMetadataRebuilder.Rebuild(bp, cfg, ss.Protected);
                    Init(rb.BinaryPath, rb.MetadataPath, out var md, out var il);
                    Dump(md, il, od);
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("error: " + e);
                try
                {
                    Directory.CreateDirectory(od);
                    File.AppendAllText(Path.Combine(od, "error.log"),
                        DateTime.Now.ToString("s") + Environment.NewLine + e + Environment.NewLine);
                    Console.Error.WriteLine("Saved: " + Path.Combine(od, "error.log"));
                }
                catch { }
                if (args.Length == 0 && RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !Console.IsInputRedirected)
                {
                    Console.WriteLine("Press Enter to close...");
                    Console.ReadLine();
                }
            }
            finally
            {
                ProtectedMetadataRebuilder.Clean(rb);
            }
        }

        private static void Usage()
        {
            Console.WriteLine("usage: Il2CppDumper <libunity.so> [output-directory] --version google|huawei [--no-dummy-dll]");
        }

        private static void Init(string bp, string mp, out Metadata md, out Il2Cpp il)
        {
            var mb = File.ReadAllBytes(mp);
            md = new Metadata(new MemoryStream(mb));

            var bb = File.ReadAllBytes(bp);
            if (bb.Length < 5 || BitConverter.ToUInt32(bb, 0) != 0x464C457F || bb[4] != 2)
                throw new NotSupportedException("ELF64 required");

            il = new Elf64(new MemoryStream(bb));
            il.SetProperties(md.Version, md.metadataUsagesCount);

            Console.WriteLine("searching registrations...");
            var mc = md.methodDefs.Count(x => x.methodIndex >= 0);
            if (!il.PlusSearch(mc, md.typeDefs.Length, md.imageDefs.Length))
                throw new InvalidDataException("registrations not found");
        }

        private static void Dump(Metadata md, Il2Cpp il, string od)
        {
            Directory.CreateDirectory(od);
            if (!od.EndsWith(Path.DirectorySeparatorChar))
                od += Path.DirectorySeparatorChar;

            var ex = new Il2CppExecutor(md, il);
            var dc = new Il2CppDecompiler(ex);
            dc.Decompile(cfg, od);

            if (cfg.GenerateStruct)
            {
                var sg = new StructGenerator(ex);
                sg.WriteScript(od);
            }

            if (cfg.GenerateDummyDll)
                DummyAssemblyExporter.Export(ex, od, cfg.DummyDllAddToken);

            WatermarkService.ApplyTextWatermarks(od);
            WatermarkService.WriteManifest(od);
            Console.WriteLine("done");
        }
    }
}
