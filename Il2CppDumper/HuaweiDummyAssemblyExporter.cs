using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Il2CppDumper
{
    internal static class HuaweiDummyAssemblyExporter
    {
        private sealed class ImageState : IDisposable
        {
            public AssemblyDefinition Assembly;
            public Dictionary<string, AssemblyNameReference> References = new(StringComparer.Ordinal);
            public int Types;
            public int Fields;
            public int Methods;
            public int Properties;
            public void Dispose() => Assembly?.Dispose();
        }

        public static (int assemblies, int types, int fields, int methods) Export(
            string manifest, string output, Action<string> report = null)
        {
            var owners = new Dictionary<string, string>(StringComparer.Ordinal);
            var valueTypes = new HashSet<string>(StringComparer.Ordinal);
            var nestedOwners = new Dictionary<string, string>(StringComparer.Ordinal);
            var name = "";
            var expectedImages = 0;
            foreach (var line in File.ReadLines(manifest))
            {
                using var j = JsonDocument.Parse(line);
                var root = j.RootElement;
                if (root.TryGetProperty("image", out var im))
                {
                    name = im.GetString() ?? "";
                    expectedImages++;
                }
                else if (root.TryGetProperty("type", out var tp))
                {
                    var key = tp.TryGetProperty("fullName", out var full) && full.ValueKind == JsonValueKind.String
                        ? full.GetString() ?? ""
                        : FullName(tp.GetProperty("namespace").GetString(), tp.GetProperty("name").GetString());
                    if (tp.TryGetProperty("declaringFullName", out var decl) && decl.ValueKind == JsonValueKind.String)
                        nestedOwners.TryAdd(key, decl.GetString() ?? "");
                    owners.TryAdd(key, name);
                    if (tp.TryGetProperty("bitfield", out var bits) && (bits.GetUInt32() & 1) != 0)
                        valueTypes.Add(key);
                }
            }

            Directory.CreateDirectory(output);
            foreach (var old in Directory.EnumerateFiles(output, "*.dll", SearchOption.TopDirectoryOnly))
                File.Delete(old);
            var counts = (assemblies: 0, types: 0, fields: 0, methods: 0);
            var lines = new List<string>();
            name = "";
            foreach (var line in File.ReadLines(manifest))
            {
                using var j = JsonDocument.Parse(line);
                if (j.RootElement.TryGetProperty("image", out var im))
                {
                    if (name.Length != 0)
                        WriteImage(name, lines, owners, valueTypes, nestedOwners, output, ref counts, report);
                    lines.Clear();
                    name = im.GetString() ?? "";
                }
                else
                    lines.Add(line);
            }
            if (name.Length != 0)
                WriteImage(name, lines, owners, valueTypes, nestedOwners, output, ref counts, report);
            if (counts.assemblies != expectedImages || counts.types == 0)
                throw new InvalidDataException($"Huawei DummyDLL export incomplete: {counts.assemblies}/{expectedImages} assemblies");
            return counts;
        }

        private static void WriteImage(string image, List<string> lines,
            Dictionary<string, string> owners, HashSet<string> valueTypes,
            Dictionary<string, string> nestedOwners, string output,
            ref (int assemblies, int types, int fields, int methods) counts, Action<string> report)
        {
            var file = Path.GetFileName(image);
            if (string.IsNullOrWhiteSpace(file))
                throw new InvalidDataException("Empty assembly image name");
            if (!file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) file += ".dll";
            var shortName = Path.GetFileNameWithoutExtension(file);
            report?.Invoke($"Huawei: DummyDLL {counts.assemblies + 1}: {file}, {lines.Count} types");
            var core = shortName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase);
            using var s = new ImageState
            {
                Assembly = AssemblyDefinition.CreateAssembly(
                    new AssemblyNameDefinition(core ? "Axent.Core.Temp" : shortName, new Version(0, 0, 0, 0)),
                    file, ModuleKind.Dll)
            };
            var mod = s.Assembly.MainModule;
            AddReference(s, "mscorlib", new Version(4, 0, 0, 0));
            _ = mod.TypeSystem.Object;

            var records = lines.Select(x => JsonDocument.Parse(x)).ToList();
            try
            {
                var types = new List<TypeDefinition>(records.Count);
                var indices = new Dictionary<int, TypeDefinition>();
                foreach (var j in records)
                {
                    var t = j.RootElement.GetProperty("type");
                    var ns = t.GetProperty("namespace").GetString() ?? "";
                    var tn = t.GetProperty("name").GetString() ?? "";
                    var attr = (TypeAttributes)t.GetProperty("flags").GetUInt32();
                    TypeDefinition td;
                    if (ns.Length == 0 && tn == "<Module>")
                        td = mod.Types.First(x => x.Name == "<Module>");
                    else
                    {
                        td = new TypeDefinition(ns, tn, attr, null);
                        mod.Types.Add(td);
                    }
                    types.Add(td);
                    indices[t.GetProperty("index").GetInt32()] = td;
                    foreach (var gn in t.GetProperty("generic").EnumerateArray())
                        td.GenericParameters.Add(new GenericParameter(gn.GetString() ?? "T", td));
                    var bt = tn.LastIndexOf('`');
                    if (bt >= 0 && int.TryParse(tn.Substring(bt + 1), out var arity))
                        for (var k = td.GenericParameters.Count; k < Math.Min(arity, 128); k++)
                            td.GenericParameters.Add(new GenericParameter("T" + k, td));
                    s.Types++;
                }

                for (var i = 0; i < records.Count; i++)
                {
                    var tp = records[i].RootElement.GetProperty("type");
                    if (tp.TryGetProperty("declaring", out var pi) && pi.GetInt32() >= 0 &&
                        indices.TryGetValue(pi.GetInt32(), out var parent) && !ReferenceEquals(parent, types[i]))
                    {
                        mod.Types.Remove(types[i]);
                        parent.NestedTypes.Add(types[i]);
                    }
                }

                for (var i = 0; i < records.Count; i++)
                {
                    var root = records[i].RootElement;
                    var t = root.GetProperty("type");
                    var td = types[i];
                    var ns = td.Namespace;
                    var tn = td.Name;
                    try
                    {
                        if (tn == "<Module>" && ns.Length == 0) continue;
                        var fl = (TypeAttributes)t.GetProperty("flags").GetUInt32();
                        var isInterface = (fl & TypeAttributes.Interface) != 0;
                        var bf = t.TryGetProperty("bitfield", out var bit) ? bit.GetUInt32() : 0;
                        var parentName = t.TryGetProperty("base", out var baseType) && baseType.ValueKind == JsonValueKind.String
                            ? baseType.GetString() : null;
                        if (ns == "System" && tn == "Object" && shortName == "mscorlib")
                            td.BaseType = null;
                        else if (isInterface)
                            td.BaseType = null;
                        else if ((bf & 2) != 0)
                            td.BaseType = TypeRef(s, owners, valueTypes, nestedOwners, td, null, "System.Enum");
                        else if ((bf & 1) != 0)
                            td.BaseType = TypeRef(s, owners, valueTypes, nestedOwners, td, null, "System.ValueType");
                        else
                            td.BaseType = TypeRef(s, owners, valueTypes, nestedOwners, td, null,
                                !string.IsNullOrWhiteSpace(parentName) && parentName != "Il2CppUnknown"
                                    ? parentName : "object");

                        foreach (var f in root.GetProperty("fields").EnumerateArray())
                        {
                            var fieldName = f.GetProperty("name").GetString() ?? "field";
                            var fieldType = TypeRef(s, owners, valueTypes, nestedOwners, td, null, f.GetProperty("type").GetString());
                            var fa = (FieldAttributes)f.GetProperty("flags").GetUInt32();
                            fa &= ~(FieldAttributes.HasFieldRVA | FieldAttributes.HasDefault | FieldAttributes.HasFieldMarshal);
                            if ((fa & FieldAttributes.Literal) != 0) fa &= ~FieldAttributes.Literal;
                            td.Fields.Add(new FieldDefinition(fieldName, fa, fieldType));
                            s.Fields++;
                        }

                        foreach (var m in root.GetProperty("methods").EnumerateArray())
                        {
                            var mn = m.GetProperty("name").GetString() ?? "method";
                            var ma = (MethodAttributes)m.GetProperty("flags").GetUInt32();
                            if (isInterface && (ma & MethodAttributes.Static) == 0)
                                ma |= MethodAttributes.Abstract | MethodAttributes.Virtual;
                            ma &= ~(MethodAttributes.PInvokeImpl | MethodAttributes.HasSecurity);
                            if ((ma & MethodAttributes.Abstract) != 0)
                                td.Attributes |= TypeAttributes.Abstract;
                            var method = new MethodDefinition(mn, ma, mod.TypeSystem.Void);
                            td.Methods.Add(method);
                            foreach (var gn in m.GetProperty("generic").EnumerateArray())
                                method.GenericParameters.Add(new GenericParameter(gn.GetString() ?? "T", method));
                            method.ReturnType = TypeRef(s, owners, valueTypes, nestedOwners, td, method, m.GetProperty("return").GetString());
                            foreach (var param in m.GetProperty("params").EnumerateArray())
                            {
                                var el = param.EnumerateArray().ToArray();
                                var pt = TypeRef(s, owners, valueTypes, nestedOwners, td, method, el[0].GetString());
                                var pn = el.Length > 1 ? el[1].GetString() : "p";
                                method.Parameters.Add(new ParameterDefinition(pn, ParameterAttributes.None, pt));
                            }
                            if ((ma & MethodAttributes.Abstract) == 0)
                            {
                                var il = method.Body.GetILProcessor();
                                il.Append(il.Create(OpCodes.Ldnull));
                                il.Append(il.Create(OpCodes.Throw));
                            }
                            s.Methods++;
                        }

                        if (root.TryGetProperty("properties", out var props))
                        {
                            foreach (var prop in props.EnumerateArray())
                            {
                                var getIdx = prop.GetProperty("get").GetInt32();
                                var setIdx = prop.GetProperty("set").GetInt32();
                                var getter = getIdx >= 0 && getIdx < td.Methods.Count ? td.Methods[getIdx] : null;
                                var setter = setIdx >= 0 && setIdx < td.Methods.Count ? td.Methods[setIdx] : null;
                                if (getter == null && setter == null) continue;
                                var pt = getter?.ReturnType ?? setter.Parameters.FirstOrDefault()?.ParameterType ?? mod.TypeSystem.Object;
                                var pa = (PropertyAttributes)prop.GetProperty("flags").GetUInt32();
                                pa &= ~PropertyAttributes.HasDefault;
                                var pd = new PropertyDefinition(prop.GetProperty("name").GetString() ?? "property", pa, pt)
                                {
                                    GetMethod = getter,
                                    SetMethod = setter
                                };
                                td.Properties.Add(pd);
                                s.Properties++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException($"DummyDLL {file} type {t.GetProperty("index").GetInt32()} {ns}.{tn}: {ex.Message}", ex);
                    }
                }

                if (core) s.Assembly.Name.Name = shortName;
                WatermarkService.EmbedAssemblyMetadata(s.Assembly);
                var target = Path.Combine(output, file);
                var temp = target + ".part";
                try
                {
                    s.Assembly.Write(temp);
                    File.Move(temp, target, true);
                }
                catch
                {
                    if (File.Exists(temp)) File.Delete(temp);
                    throw;
                }
                counts.assemblies++;
                counts.types += s.Types;
                counts.fields += s.Fields;
                counts.methods += s.Methods;
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("DummyDLL failed for " + file + ": " + ex.Message, ex);
            }
            finally
            {
                foreach (var doc in records) doc.Dispose();
            }
        }

        private static AssemblyNameReference AddReference(ImageState s, string shortName, Version version)
        {
            if (s.References.TryGetValue(shortName, out var r)) return r;
            var mod = s.Assembly.MainModule;
            r = mod.AssemblyReferences.FirstOrDefault(x => x.Name == shortName);
            if (r == null)
            {
                r = new AssemblyNameReference(shortName, version);
                mod.AssemblyReferences.Add(r);
            }
            s.References.Add(shortName, r);
            return r;
        }

        private static string FullName(string ns, string name)
            => string.IsNullOrEmpty(ns) ? name ?? "" : ns + "." + (name ?? "");

        private static TypeReference TypeRef(ImageState s, Dictionary<string, string> owner,
            HashSet<string> valueTypes, Dictionary<string, string> nestedOwners,
            TypeDefinition td, MethodDefinition md, string type)
        {
            var mod = s.Assembly.MainModule;
            type = (type ?? "").Trim();
            if (type.Length == 0 || type == "Il2CppUnknown") return mod.TypeSystem.Object;
            if (type.EndsWith("&", StringComparison.Ordinal))
                return new ByReferenceType(TypeRef(s, owner, valueTypes, nestedOwners, td, md, type.Substring(0, type.Length - 1)));
            if (type.EndsWith("*", StringComparison.Ordinal))
                return new PointerType(TypeRef(s, owner, valueTypes, nestedOwners, td, md, type.Substring(0, type.Length - 1)));
            if (type.EndsWith("]", StringComparison.Ordinal))
            {
                var open = type.LastIndexOf('[');
                if (open >= 0 && type.Substring(open + 1, type.Length - open - 2).All(c => c == ','))
                {
                    var count = type.Length - open - 1;
                    return count == 1
                        ? new ArrayType(TypeRef(s, owner, valueTypes, nestedOwners, td, md, type.Substring(0, open)))
                        : new ArrayType(TypeRef(s, owner, valueTypes, nestedOwners, td, md, type.Substring(0, open)), count);
                }
            }
            if (md != null)
                foreach (var gp in md.GenericParameters)
                    if (gp.Name == type) return gp;
            if (td != null)
                foreach (var gp in td.GenericParameters)
                    if (gp.Name == type) return gp;

            var genericStart = -1;
            var genericEnd = type.Length - 1;
            if (genericEnd >= 0 && type[genericEnd] == '>')
            {
                var level = 0;
                for (var z = genericEnd; z >= 0; z--)
                {
                    if (type[z] == '>') level++;
                    if (type[z] == '<' && --level == 0)
                    {
                        genericStart = z;
                        break;
                    }
                }
            }
            if (genericStart > 0)
            {
                var part = type.Substring(genericStart + 1, genericEnd - genericStart - 1);
                var args = SplitGenericArgs(part);
                var baseName = type.Substring(0, genericStart);
                var pos = baseName.LastIndexOf('`');
                if (pos < 0 || !int.TryParse(baseName.Substring(pos + 1), out _))
                    baseName += "`" + args.Count;
                var basic = TypeRef(s, owner, valueTypes, nestedOwners, td, md, baseName);
                var result = new GenericInstanceType(basic);
                foreach (var arg in args)
                    result.GenericArguments.Add(TypeRef(s, owner, valueTypes, nestedOwners, td, md, arg));
                return result;
            }

            switch (type)
            {
                case "void": return mod.TypeSystem.Void;
                case "bool": return mod.TypeSystem.Boolean;
                case "char": return mod.TypeSystem.Char;
                case "sbyte": return mod.TypeSystem.SByte;
                case "byte": return mod.TypeSystem.Byte;
                case "short": return mod.TypeSystem.Int16;
                case "ushort": return mod.TypeSystem.UInt16;
                case "int": return mod.TypeSystem.Int32;
                case "uint": return mod.TypeSystem.UInt32;
                case "long": return mod.TypeSystem.Int64;
                case "ulong": return mod.TypeSystem.UInt64;
                case "float": return mod.TypeSystem.Single;
                case "double": return mod.TypeSystem.Double;
                case "string": return mod.TypeSystem.String;
                case "object": return mod.TypeSystem.Object;
                case "IntPtr": return mod.TypeSystem.IntPtr;
                case "UIntPtr": return mod.TypeSystem.UIntPtr;
            }

            var dot = type.LastIndexOf('.');
            var ns = dot < 0 ? "" : type.Substring(0, dot);
            var name = dot < 0 ? type : type.Substring(dot + 1);
            var full = FullName(ns, name);
            var thisImage = s.Assembly.MainModule.Name;
            IMetadataScope scope = mod;
            if (owner.TryGetValue(full, out var destination) &&
                !string.Equals(destination, thisImage, StringComparison.OrdinalIgnoreCase))
            {
                var shortName = Path.GetFileNameWithoutExtension(destination);
                scope = AddReference(s, shortName, shortName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase)
                    ? new Version(4, 0, 0, 0) : new Version(0, 0, 0, 0));
            }
            else if (ns == "System" && !thisImage.Equals("mscorlib.dll", StringComparison.OrdinalIgnoreCase))
                scope = AddReference(s, "mscorlib", new Version(4, 0, 0, 0));
            if (nestedOwners.TryGetValue(full, out var declaring) && declaring.Length != 0)
            {
                var outer = TypeRef(s, owner, valueTypes, nestedOwners, td, md, declaring);
                return new TypeReference("", name, mod, scope, valueTypes.Contains(full))
                {
                    DeclaringType = outer
                };
            }
            return new TypeReference(ns, name, mod, scope, valueTypes.Contains(full));
        }

        private static List<string> SplitGenericArgs(string s)
        {
            var result = new List<string>();
            var depth = 0;
            var start = 0;
            for (var i = 0; i < s.Length; i++)
            {
                if (s[i] == '<') depth++;
                else if (s[i] == '>') depth--;
                else if (s[i] == ',' && depth == 0)
                {
                    result.Add(s.Substring(start, i - start).Trim());
                    start = i + 1;
                }
            }
            result.Add(s.Substring(start).Trim());
            return result;
        }
    }
}
