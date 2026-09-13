using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonSerializer.Deserialize<Config>(
                File.ReadAllText(
                    Path.Combine(
                        AppContext.BaseDirectory,
                        "config.json"
                    )
                )
            );

            string binaryPath = null;

            string outputDir = Path.Combine(
                AppContext.BaseDirectory,
                "dump"
            );

            Directory.CreateDirectory(outputDir);

            outputDir = Path.GetFullPath(outputDir);

            if (!outputDir.EndsWith(Path.DirectorySeparatorChar))
                outputDir += Path.DirectorySeparatorChar;

            if (args.Length > 0 && File.Exists(args[0]))
            {
                binaryPath = args[0];
            }

            if (args.Length > 1)
            {
                outputDir = Path.GetFullPath(args[1]);

                Directory.CreateDirectory(outputDir);

                if (!outputDir.EndsWith(Path.DirectorySeparatorChar))
                    outputDir += Path.DirectorySeparatorChar;
            }

            if (binaryPath == null &&
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var dialog = new OpenFileDialog
                {
                    Filter = "libunity.so|libunity.so|Binary|*.*"
                };

                if (dialog.ShowDialog())
                {
                    binaryPath = dialog.FileName;
                }
            }

            if (binaryPath == null)
            {
                Console.WriteLine(
                    "usage: Il2CppDumper <libunity.so> [output-directory]"
                );

                return;
            }

            try
            {
                var metadataPath =
                    ProtectedMetadataRebuilder.Rebuild(
                        binaryPath,
                        outputDir,
                        config
                    );

                Init(
                    binaryPath,
                    metadataPath,
                    out var metadata,
                    out var il2Cpp
                );

                Dump(
                    metadata,
                    il2Cpp,
                    outputDir
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"ERROR: {ex.Message}"
                );
            }
        }

        private static ulong Hex(string value)
        {
            return Convert.ToUInt64(
                value.Replace("0x", ""),
                16
            );
        }

        private static void Init(
            string binaryPath,
            string metadataPath,
            out Metadata metadata,
            out Il2Cpp il2Cpp
        )
        {
            var metadataBytes =
                File.ReadAllBytes(metadataPath);

            metadata = new Metadata(
                new MemoryStream(metadataBytes)
            );

            var binaryBytes =
                File.ReadAllBytes(binaryPath);

            if (binaryBytes.Length < 5 ||
                BitConverter.ToUInt32(binaryBytes, 0) != 0x464C457F ||
                binaryBytes[4] != 2)
            {
                throw new NotSupportedException(
                    "ELF64 required"
                );
            }

            il2Cpp = new Elf64(
                new MemoryStream(binaryBytes)
            );

            il2Cpp.SetProperties(
                metadata.Version,
                metadata.metadataUsagesCount
            );

            il2Cpp.InitProtected(
                Hex(config.ProtectedCodeRegistration),
                Hex(config.ProtectedMetadataRegistration)
            );
        }

        private static void Dump(
            Metadata metadata,
            Il2Cpp il2Cpp,
            string outputDir
        )
        {
            Directory.CreateDirectory(outputDir);

            if (!outputDir.EndsWith(Path.DirectorySeparatorChar))
                outputDir += Path.DirectorySeparatorChar;

            var executor = new Il2CppExecutor(
                metadata,
                il2Cpp
            );

            var decompiler = new Il2CppDecompiler(
                executor
            );

            decompiler.Decompile(
                config,
                outputDir
            );

            if (config.GenerateStruct)
            {
                var structGenerator =
                    new StructGenerator(
                        executor
                    );

                structGenerator.WriteScript(
                    outputDir
                );
            }

            Console.WriteLine("Done");
        }
    }
}