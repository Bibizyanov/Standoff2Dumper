using System;
using System.IO;
using System.Net.Http;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Il2CppDumper
{
    internal static class AxentApi
    {
        const string api = "https://api.axent.cc";
        const string pk = @"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeAsU509HIkhdQrMFQ4M/+Upp5FXJ
+SpVJScO3Po35XW07GDeK9jpFeHKFGMb6/MvEu5qIaAXUdqinQ4WatDcYw==
-----END PUBLIC KEY-----
";
        static readonly HttpClient h = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };

        public static DumperSession Session(string bp)
        {
            var d = Device();
            if (string.IsNullOrWhiteSpace(d.id))
                Claim(d);

            var bin = Hash(bp);
            var dev = DeviceHash();
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var msg = d.id + "\n" + bin + "\n" + nonce + "\n" + dev;

            byte[] sig;
            using (var ec = ECDsa.Create())
            {
                ec.ImportPkcs8PrivateKey(Convert.FromBase64String(d.k), out _);
                sig = ec.SignData(Encoding.UTF8.GetBytes(msg), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            using var r = Post(api + "/api/dumper/session", new { id = d.id, bin, nonce, dev, sig = B64(sig) });
            var raw = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var j = JsonDocument.Parse(string.IsNullOrWhiteSpace(raw) ? "{}" : raw);
            if (!r.IsSuccessStatusCode)
            {
                var e = Get(j.RootElement, "error");
                if (e == "unsupported_build") throw new InvalidOperationException("unsupported game build");
                if (e == "license_disabled") throw new InvalidOperationException("license disabled");
                if (e == "device_mismatch") throw new InvalidOperationException("license belongs to another pc");
                throw new InvalidOperationException("session failed");
            }

            var root = j.RootElement;
            var tok = Get(root, "token");
            if (string.IsNullOrWhiteSpace(tok))
                throw new InvalidDataException("bad session");
            if (!root.TryGetProperty("cfg", out var ce))
                throw new InvalidDataException("missing profile");

            var p = ce.Deserialize<ProtectedProfile>();
            if (p == null || string.IsNullOrWhiteSpace(p.mv) || string.IsNullOrWhiteSpace(p.cr) || string.IsNullOrWhiteSpace(p.mr))
                throw new InvalidDataException("bad profile");

            var n = Get(root, "name");
            if (!string.IsNullOrWhiteSpace(n))
                Console.WriteLine("user: " + n);

            return new DumperSession
            {
                Token = tok,
                PublicKey = pk,
                Protected = p,
                LicenseId = Get(root, "id"),
                Name = n
            };
        }

        static void Claim(DeviceState d)
        {
            var n = Environment.GetEnvironmentVariable("AXENT_DUMPER_NAME");
            if (string.IsNullOrWhiteSpace(n))
            {
                Console.Write("name: ");
                n = Console.IsInputRedirected ? Console.ReadLine() : Console.ReadLine();
            }
            if (string.IsNullOrWhiteSpace(n))
                n = Environment.UserName;

            using var r = Post(api + "/api/dumper/claim", new { name = n?.Trim(), pub = d.p, dev = DeviceHash() });
            var raw = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var j = JsonDocument.Parse(string.IsNullOrWhiteSpace(raw) ? "{}" : raw);
            if (!r.IsSuccessStatusCode)
            {
                var e = Get(j.RootElement, "error");
                if (e == "already_registered")
                    throw new InvalidOperationException("this pc is already activated");
                throw new InvalidOperationException("activation failed");
            }

            d.id = Get(j.RootElement, "id");
            d.n = Get(j.RootElement, "name");
            if (string.IsNullOrWhiteSpace(d.id))
                throw new InvalidDataException("bad activation");
            Save(d);
            Console.WriteLine("id: " + d.id);
        }

        static DeviceState Device()
        {
            try
            {
                var f = DeviceFile();
                if (File.Exists(f))
                {
                    var x = JsonSerializer.Deserialize<DeviceState>(File.ReadAllText(f));
                    if (x != null && !string.IsNullOrWhiteSpace(x.k) && !string.IsNullOrWhiteSpace(x.p))
                        return x;
                }
            }
            catch { }

            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var d = new DeviceState
            {
                k = Convert.ToBase64String(ec.ExportPkcs8PrivateKey()),
                p = Pem(ec.ExportSubjectPublicKeyInfo())
            };
            Save(d);
            return d;
        }

        static void Save(DeviceState d)
        {
            Directory.CreateDirectory(Dir());
            File.WriteAllText(DeviceFile(), JsonSerializer.Serialize(d), new UTF8Encoding(false));
        }

        static HttpResponseMessage Post(string u, object v)
        {
            var r = new HttpRequestMessage(HttpMethod.Post, u);
            r.Content = new StringContent(JsonSerializer.Serialize(v), Encoding.UTF8, "application/json");
            return h.SendAsync(r).GetAwaiter().GetResult();
        }


        static string DeviceHash()
        {
            var mg = string.Empty;
            try
            {
                if (OperatingSystem.IsWindows())
                    mg = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", string.Empty)?.ToString() ?? string.Empty;
            }
            catch { }
            var s = mg + "|" + Environment.MachineName + "|" + Environment.UserName;
            using var h = SHA256.Create();
            return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        }

        static string Hash(string f)
        {
            using var x = SHA256.Create();
            using var s = File.OpenRead(f);
            return Convert.ToHexString(x.ComputeHash(s)).ToLowerInvariant();
        }

        static string Pem(byte[] b)
        {
            var s = Convert.ToBase64String(b);
            var x = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
            for (var i = 0; i < s.Length; i += 64)
                x.AppendLine(s.Substring(i, Math.Min(64, s.Length - i)));
            x.Append("-----END PUBLIC KEY-----\n");
            return x.ToString();
        }

        static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        static string Get(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static string Dir()
        {
            var d = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(d)) d = AppContext.BaseDirectory;
            return Path.Combine(d, "Axent", "Dumper");
        }
        static string DeviceFile() => Path.Combine(Dir(), "device.json");

        sealed class DeviceState
        {
            public string k { get; set; }
            public string p { get; set; }
            public string id { get; set; }
            public string n { get; set; }
        }
    }

    internal sealed class DumperSession
    {
        public string Token { get; set; }
        public string PublicKey { get; set; }
        public ProtectedProfile Protected { get; set; }
        public string LicenseId { get; set; }
        public string Name { get; set; }
    }

    internal sealed class ProtectedProfile
    {
        [JsonPropertyName("v")] public int v { get; set; }
        [JsonPropertyName("mv")] public string mv { get; set; }
        [JsonPropertyName("cr")] public string cr { get; set; }
        [JsonPropertyName("mr")] public string mr { get; set; }
        [JsonPropertyName("slo")] public string slo { get; set; }
        [JsonPropertyName("sld")] public string sld { get; set; }
        [JsonPropertyName("slc")] public string slc { get; set; }
        [JsonPropertyName("sloc")] public string sloc { get; set; }
        [JsonPropertyName("kr")] public bool kr { get; set; }
        [JsonPropertyName("rk")] public string rk { get; set; }
    }
}
