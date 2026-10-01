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
            cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "config.json")));

            string bp = null;
            var pos = new List<string>();

            for (var i = 0; i < args.Length; i++)
            {
                var a = args[i];
                if (a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase))
                {
                    Usage();
                    return;
                }
                else if (a.StartsWith("--", StringComparison.Ordinal))
                    Console.WriteLine($"unknown option: {a}");
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

            ProtectedMetadataRebuilder.RebuildResult rb = default;
            try
            {
                var ss = AxentApi.Session(bp);
                WatermarkService.Initialize(cfg, bp, ss.Token, ss.PublicKey);
                rb = ProtectedMetadataRebuilder.Rebuild(bp, cfg, ss.Protected);
                Init(rb.BinaryPath, rb.MetadataPath, out var md, out var il);
                Dump(md, il, od);
            }
            catch (Exception e)
            {
                Console.WriteLine($"error: {e.Message}");
            }
            finally
            {
                ProtectedMetadataRebuilder.Clean(rb);
            }
        }

        private static void Usage()
        {
            Console.WriteLine("usage: Il2CppDumper <libunity.so> [output-directory]");
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
