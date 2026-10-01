using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Il2CppDumper
{
    internal static class WatermarkService
    {
        private const string Tp = "AX1";
        private static WatermarkIdentity wm = WatermarkIdentity.Disabled;
        private static string bh = string.Empty;
        private static string rt = string.Empty;

        public static WatermarkIdentity Current => wm;
        public static bool Enabled => wm.Enabled;

        public static void Initialize(Config cfg, string bp, string tok, string pem)
        {
            if (cfg == null)
                throw new InvalidOperationException("config missing");

            bh = FileHash(bp);

            if (string.IsNullOrWhiteSpace(tok))
                throw new InvalidOperationException("axent token required");

            if (!CheckTok(tok, pem, out var lc, out var err))
                throw new InvalidOperationException("bad token: " + (err ?? "unknown"));

            rt = tok;
            var own = Pick(lc?.name, lc?.sub);
            var id = Pick(lc?.jti, lc?.sub);
            if (string.IsNullOrWhiteSpace(own) || string.IsNullOrWhiteSpace(id))
                throw new InvalidDataException("bad token user");

            var lf = H(own + "|" + id, 16);
            var fp = H(lf + "|" + bh, 20);

            wm = new WatermarkIdentity
            {
                Enabled = true,
                Brand = string.IsNullOrWhiteSpace(cfg.WatermarkBrand) ? "axent.cc" : cfg.WatermarkBrand.Trim(),
                Owner = OneLine(own),
                LicenseId = OneLine(id),
                LicenseFingerprint = lf,
                Fingerprint = fp,
                TokenVerified = true,
                TokenId = lc?.jti,
                TokenSubject = lc?.sub
            };

            Console.WriteLine($"wm {wm.Owner} {Code()}");
        }

        public static string Banner(string p = "// ")
        {
            if (!Enabled)
                return string.Empty;
            return $"{p}{wm.Brand.ToLowerInvariant()} | {Code()}\n";
        }

        public static string TypeMarker(int td)
        {
            if (!Enabled)
                return string.Empty;
            return $"// {wm.Brand.ToLowerInvariant()}/{Code()}\n";
        }

        public static string TypeDefSpacing(int td)
        {
            if (!Enabled)
                return " ";

            return Bit(td) != 0 ? "  " : " ";
        }

        public static bool ShouldRepeatAtType(int td, Config cfg)
        {
            if (!Enabled)
                return false;
            var n = cfg?.WatermarkRepeatEveryTypes ?? 0;
            return n > 0 && td > 0 && td % n == 0;
        }

        public static IEnumerable<int> TypeOrder(int start, int end)
        {
            if (!Enabled)
            {
                for (var i = start; i < end; i++)
                    yield return i;
                yield break;
            }

            var pair = 0;
            for (var i = start; i < end; i += 2, pair++)
            {
                var swap = i + 1 < end && pair % 8 == 0 && Bit(pair / 8) != 0;
                if (swap)
                {
                    yield return i + 1;
                    yield return i;
                }
                else
                {
                    yield return i;
                    if (i + 1 < end) yield return i + 1;
                }
            }
        }

        static int Bit(int i)
        {
            var x = wm.Fingerprint?.Replace("-", string.Empty, StringComparison.Ordinal) ?? string.Empty;
            if (x.Length == 0) return 0;
            var bc = x.Length * 4;
            var bi = Math.Abs(i) % bc;
            var n = Convert.ToInt32(x[bi / 4].ToString(), 16);
            return (n >> (3 - bi % 4)) & 1;
        }

        public static ScriptWatermark CreateScriptWatermark()
        {
            if (!Enabled)
                return null;
            return new ScriptWatermark
            {
                Brand = wm.Brand,
                Owner = wm.Owner,
                LicenseId = wm.LicenseId,
                LicenseFingerprint = wm.LicenseFingerprint,
                Fingerprint = wm.Fingerprint,
                TokenVerified = wm.TokenVerified
            };
        }

        public static void EmbedAssemblyMetadata(AssemblyDefinition ia)
        {
            if (!Enabled || ia?.MainModule == null)
                return;

            try
            {
                var ci = typeof(AssemblyMetadataAttribute).GetConstructor(new[] { typeof(string), typeof(string) });
                if (ci == null)
                    return;
                var c = ia.MainModule.ImportReference(ci);
                AddMeta(ia, c, "BuildId", wm.Fingerprint);
                AddMeta(ia, c, "BuildUser", wm.Owner);
                AddMeta(ia, c, "BuildTag", wm.LicenseFingerprint);
            }
            catch (Exception e)
            {
                Console.WriteLine("dll meta: " + e.Message);
            }
        }

        private static void AddMeta(AssemblyDefinition ia, MethodReference c, string k, string v)
        {
            var a = new CustomAttribute(c);
            a.ConstructorArguments.Add(new CustomAttributeArgument(ia.MainModule.TypeSystem.String, k));
            a.ConstructorArguments.Add(new CustomAttributeArgument(ia.MainModule.TypeSystem.String, v ?? string.Empty));
            ia.CustomAttributes.Add(a);
        }

        public static void ApplyTextWatermarks(string od)
        {
            if (!Enabled)
                return;
            AddTop(Path.Combine(od, "il2cpp.h"), Banner());
        }

        private static void AddTop(string f, string s)
        {
            if (string.IsNullOrEmpty(s) || !File.Exists(f))
                return;
            var x = File.ReadAllText(f);
            if (x.Contains(Code(), StringComparison.Ordinal))
                return;
            File.WriteAllText(f, s + x, new UTF8Encoding(false));
        }

        public static void WriteManifest(string od)
        {
            if (!Enabled)
                return;

            var fs = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in Directory.EnumerateFiles(od, "*", SearchOption.AllDirectories))
            {
                var r = Path.GetRelativePath(od, f).Replace('\\', '/');
                if (r.Equals("wm.json", StringComparison.OrdinalIgnoreCase) || r.StartsWith(".metadata/", StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    fs[r] = FileHash(f);
                }
                catch
                {
                }
            }

            var m = new WatermarkManifest
            {
                Brand = wm.Brand,
                Owner = wm.Owner,
                LicenseId = wm.LicenseId,
                LicenseFingerprint = wm.LicenseFingerprint,
                Fingerprint = wm.Fingerprint,
                TokenVerified = wm.TokenVerified,
                SourceBinarySha256 = bh,
                LicenseTokenSha256 = string.IsNullOrWhiteSpace(rt) ? null : Hex(Encoding.UTF8.GetBytes(rt)),
                GeneratedUtc = DateTimeOffset.UtcNow,
                Files = fs
            };

            File.WriteAllText(Path.Combine(od, "wm.json"), JsonSerializer.Serialize(m, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        }

        private static bool CheckTok(string tok, string pem, out LicenseClaims lc, out string err)
        {
            lc = null;
            err = null;
            try
            {
                var p = tok.Split('.');
                if (p.Length != 3 || !p[0].Equals(Tp, StringComparison.Ordinal))
                    throw new InvalidDataException("bad format");

                var pb = B64(p[1]);
                var sg = B64(p[2]);
                lc = JsonSerializer.Deserialize<LicenseClaims>(pb);
                if (lc == null)
                    throw new InvalidDataException("empty token");

                if (string.IsNullOrWhiteSpace(pem) || !pem.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal))
                    throw new InvalidDataException("no public key");

                using var ec = ECDsa.Create();
                ec.ImportFromPem(pem);
                if (!ec.VerifyData(Encoding.ASCII.GetBytes(p[1]), sg, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                    throw new CryptographicException("bad signature");

                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (lc.exp > 0 && now >= lc.exp)
                    throw new InvalidDataException("expired");
                if (lc.nbf > 0 && now < lc.nbf)
                    throw new InvalidDataException("not active");
                if (!string.IsNullOrWhiteSpace(lc.aud) && !lc.aud.Equals("standoff2dumper", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("bad aud");
                if (string.IsNullOrWhiteSpace(lc.bin) || !lc.bin.Equals(bh, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("bad binary");
                if (string.IsNullOrWhiteSpace(lc.sub) && string.IsNullOrWhiteSpace(lc.name))
                    throw new InvalidDataException("no user");

                return true;
            }
            catch (Exception e)
            {
                lc = null;
                err = e.Message;
                return false;
            }
        }

        private static byte[] B64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            if (s.Length % 4 == 2) s += "==";
            else if (s.Length % 4 == 3) s += "=";
            return Convert.FromBase64String(s);
        }

        private static string Pick(params string[] x) => x?.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();

        private static string OneLine(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return string.Empty;
            return s.Replace("\r", " ").Replace("\n", " ").Trim();
        }

        private static string H(string s, int n)
        {
            var x = Hex(Encoding.UTF8.GetBytes(s ?? string.Empty));
            n = Math.Clamp(n, 4, x.Length);
            var r = x.Substring(0, n).ToUpperInvariant();
            var a = Enumerable.Range(0, (r.Length + 3) / 4).Select(i => r.Substring(i * 4, Math.Min(4, r.Length - i * 4)));
            return string.Join("-", a);
        }

        private static string Code()
        {
            var x = wm.Fingerprint?.Replace("-", string.Empty, StringComparison.Ordinal) ?? string.Empty;
            return x.Length <= 8 ? x : x.Substring(0, 8);
        }

        private static string FileHash(string f)
        {
            using var s = File.OpenRead(f);
            using var h = SHA256.Create();
            return Convert.ToHexString(h.ComputeHash(s));
        }

        private static string Hex(byte[] b)
        {
            using var h = SHA256.Create();
            return Convert.ToHexString(h.ComputeHash(b));
        }

        internal sealed class LicenseClaims
        {
            [JsonPropertyName("sub")] public string sub { get; set; }
            [JsonPropertyName("name")] public string name { get; set; }
            [JsonPropertyName("jti")] public string jti { get; set; }
            [JsonPropertyName("aud")] public string aud { get; set; }
            [JsonPropertyName("iat")] public long iat { get; set; }
            [JsonPropertyName("nbf")] public long nbf { get; set; }
            [JsonPropertyName("exp")] public long exp { get; set; }
            [JsonPropertyName("bin")] public string bin { get; set; }
        }

        private sealed class WatermarkManifest
        {
            public string Brand { get; set; }
            public string Owner { get; set; }
            public string LicenseId { get; set; }
            public string LicenseFingerprint { get; set; }
            public string Fingerprint { get; set; }
            public bool TokenVerified { get; set; }
            public string SourceBinarySha256 { get; set; }
            public string LicenseTokenSha256 { get; set; }
            public DateTimeOffset GeneratedUtc { get; set; }
            public SortedDictionary<string, string> Files { get; set; }
        }
    }

    internal sealed class WatermarkIdentity
    {
        public static readonly WatermarkIdentity Disabled = new WatermarkIdentity { Enabled = false };
        public bool Enabled { get; set; }
        public string Brand { get; set; }
        public string Owner { get; set; }
        public string LicenseId { get; set; }
        public string LicenseFingerprint { get; set; }
        public string Fingerprint { get; set; }
        public bool TokenVerified { get; set; }
        public string TokenId { get; set; }
        public string TokenSubject { get; set; }
    }

    public sealed class ScriptWatermark
    {
        public string Brand;
        public string Owner;
        public string LicenseId;
        public string LicenseFingerprint;
        public string Fingerprint;
        public bool TokenVerified;
    }
}
