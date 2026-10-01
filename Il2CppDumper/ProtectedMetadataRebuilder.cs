using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Il2CppDumper
{
    internal static class ProtectedMetadataRebuilder
    {
        public readonly record struct RebuildResult(string BinaryPath, string MetadataPath, string WorkDir);

        public static RebuildResult Rebuild(string bp, Config cfg, ProtectedProfile x)
        {
            if (x == null || string.IsNullOrWhiteSpace(x.rk))
                throw new InvalidOperationException("profile missing");

            var cd = Path.Combine(Path.GetTempPath(), "axd", Guid.NewGuid().ToString("N"));
            var py = Path.Combine(cd, "r.py");
            var mp = Path.Combine(cd, "global-metadata.dat");
            var rb = Path.Combine(cd, "libunity.so");
            Directory.CreateDirectory(cd);

            try
            {
                OpenScript(Path.Combine(AppContext.BaseDirectory, "protected_metadata.bin"), py, x.rk);
            }
            catch
            {
                Clean(new RebuildResult(null, null, cd));
                throw new InvalidOperationException("rebuilder unavailable");
            }

            var si = new ProcessStartInfo
            {
                FileName = string.IsNullOrWhiteSpace(cfg.PythonExecutable) ? "python" : cfg.PythonExecutable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            si.ArgumentList.Add(py);
            si.ArgumentList.Add("--quiet");
            si.ArgumentList.Add(bp);
            si.ArgumentList.Add("-o");
            si.ArgumentList.Add(cd);
            si.ArgumentList.Add("--metadata-va");
            si.ArgumentList.Add(x.mv);
            si.ArgumentList.Add("--code-reg-va");
            si.ArgumentList.Add(x.cr);
            si.ArgumentList.Add("--metadata-reg-va");
            si.ArgumentList.Add(x.mr);
            si.ArgumentList.Add("--string-literal-offsets-field");
            si.ArgumentList.Add(x.slo);
            si.ArgumentList.Add("--string-literal-data-field");
            si.ArgumentList.Add(x.sld);
            si.ArgumentList.Add("--string-literal-count-field");
            si.ArgumentList.Add(x.slc);
            si.ArgumentList.Add("--string-literal-offsets-count-field");
            si.ArgumentList.Add(x.sloc);
            if (x.kr)
                si.ArgumentList.Add("--keep-method-rgctx");

            using var p = Process.Start(si) ?? throw new InvalidOperationException("python start failed");
            var so = p.StandardOutput.ReadToEnd();
            var se = p.StandardError.ReadToEnd();
            p.WaitForExit();

            try { File.Delete(py); } catch { }

            if (p.ExitCode != 0 || !File.Exists(mp) || !File.Exists(rb))
            {
                Clean(new RebuildResult(null, null, cd));
                var e = string.IsNullOrWhiteSpace(se) ? so : se;
                if (!string.IsNullOrWhiteSpace(e))
                    throw new InvalidOperationException("protected metadata rebuild failed: " + e.Trim());
                throw new InvalidOperationException("protected metadata rebuild failed");
            }

            return new RebuildResult(rb, mp, cd);
        }

        static void OpenScript(string src, string dst, string k)
        {
            var b = File.ReadAllBytes(src);
            if (b.Length < 29)
                throw new InvalidDataException();
            var key = B64(k);
            if (key.Length != 32)
                throw new InvalidDataException();

            var nonce = new byte[12];
            var tag = new byte[16];
            var ct = new byte[b.Length - 28];
            Buffer.BlockCopy(b, 0, nonce, 0, 12);
            Buffer.BlockCopy(b, b.Length - 16, tag, 0, 16);
            Buffer.BlockCopy(b, 12, ct, 0, ct.Length);
            var pt = new byte[ct.Length];
            using (var a = new AesGcm(key))
                a.Decrypt(nonce, ct, tag, pt);
            File.WriteAllBytes(dst, pt);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(pt);
        }

        static byte[] B64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            if (s.Length % 4 == 2) s += "==";
            else if (s.Length % 4 == 3) s += "=";
            return Convert.FromBase64String(s);
        }

        public static void Clean(RebuildResult r)
        {
            if (string.IsNullOrWhiteSpace(r.WorkDir))
                return;
            try
            {
                if (Directory.Exists(r.WorkDir))
                    Directory.Delete(r.WorkDir, true);
            }
            catch { }
        }
    }
}
