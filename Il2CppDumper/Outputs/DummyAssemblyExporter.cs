using Mono.Cecil;
using System;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public static class DummyAssemblyExporter
    {
        public static void Export(Il2CppExecutor executor, string outputDir, bool addToken)
        {
            var dir = Path.Combine(outputDir, "DummyDll");
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
            Directory.CreateDirectory(dir);

            DummyAssemblyGenerator generator = null;
            try
            {
                generator = new DummyAssemblyGenerator(executor, addToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine("WARNING: rich DummyDll generation failed: " + ex.Message);
            }

            int written = 0;
            foreach (var assembly in generator?.Assemblies ?? Enumerable.Empty<AssemblyDefinition>())
            {
                if (assembly == null)
                    continue;

                var name = assembly.MainModule?.Name;
                if (string.IsNullOrWhiteSpace(name))
                    name = (assembly.Name?.Name ?? $"Assembly_{written}") + ".dll";
                name = SanitizeFileName(name);
                if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    name += ".dll";

                var path = Path.Combine(dir, name);
                try
                {
                    assembly.Write(path);
                    written++;
                }
                catch
                {
                    try
                    {
                        var fallbackName = Path.GetFileNameWithoutExtension(name);
                        using var fallback = AssemblyDefinition.CreateAssembly(
                            new AssemblyNameDefinition(fallbackName, new Version(0, 0, 0, 0)),
                            name,
                            ModuleKind.Dll);
                        fallback.Write(path);
                        written++;
                    }
                    catch
                    {
                    }
                }
            }

            if (written == 0)
                written = WriteMinimalAssemblies(executor, dir);

            if (written == 0)
                throw new InvalidOperationException("DummyDll generation produced no assemblies.");
        }

        private static int WriteMinimalAssemblies(Il2CppExecutor executor, string dir)
        {
            var metadata = executor?.metadata;
            if (metadata?.imageDefs == null)
                return 0;

            int written = 0;
            for (int i = 0; i < metadata.imageDefs.Length; i++)
            {
                var image = metadata.imageDefs[i];
                if (image == null)
                    continue;

                string imageName;
                try { imageName = metadata.GetStringFromIndex(image.nameIndex); }
                catch { imageName = null; }
                if (string.IsNullOrWhiteSpace(imageName))
                    imageName = $"Image_{i}.dll";
                if (!imageName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    imageName += ".dll";
                imageName = SanitizeFileName(Path.GetFileName(imageName));

                var assemblyName = Path.GetFileNameWithoutExtension(imageName);
                try
                {
                    using var assembly = AssemblyDefinition.CreateAssembly(
                        new AssemblyNameDefinition(assemblyName, new Version(0, 0, 0, 0)),
                        imageName,
                        ModuleKind.Dll);
                    assembly.Write(Path.Combine(dir, imageName));
                    written++;
                }
                catch
                {
                }
            }
            return written;
        }

        private static string SanitizeFileName(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            return new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        }
    }
}
