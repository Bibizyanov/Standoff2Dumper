using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public sealed class DummyAssemblyGenerator
    {
        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly bool addToken;
        private readonly Dictionary<int, TypeDefinition> typeMap = new();
        private readonly Dictionary<int, MethodDefinition> methodMap = new();
        private readonly Dictionary<int, AssemblyDefinition> imageAssemblies = new();

        public List<AssemblyDefinition> Assemblies { get; } = new();

        public DummyAssemblyGenerator(Il2CppExecutor executor, bool addToken)
        {
            this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
            metadata = executor.metadata ?? throw new InvalidOperationException("Metadata is null");
            il2Cpp = executor.il2Cpp ?? throw new InvalidOperationException("Il2Cpp is null");
            this.addToken = addToken;
            TryStage(CreateAssemblies);
            TryStage(CreateTypes);
            TryStage(AttachNestedTypes);
            TryStage(PopulateTypes);
        }


        private static void TryStage(Action stage)
        {
            try
            {
                stage?.Invoke();
            }
            catch
            {
            }
        }

        private void CreateAssemblies()
        {
            if (metadata?.imageDefs == null)
                return;

            for (int i = 0; i < metadata.imageDefs.Length; i++)
            {
                try
                {
                    var image = metadata.imageDefs[i];
                    if (image == null)
                        continue;

                    var imageName = GetMetadataString(image.nameIndex, $"Image_{i}.dll");
                    imageName = Path.GetFileName(imageName);
                    if (string.IsNullOrWhiteSpace(imageName))
                        imageName = $"Image_{i}.dll";
                    if (!imageName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                        imageName += ".dll";

                    string assemblyName = Path.GetFileNameWithoutExtension(imageName);
                    if (string.IsNullOrWhiteSpace(assemblyName))
                        assemblyName = $"Image_{i}";

                    Version version = new(0, 0, 0, 0);
                    if (metadata.assemblyDefs != null && image.assemblyIndex >= 0 && image.assemblyIndex < metadata.assemblyDefs.Length)
                    {
                        var assemblyDef = metadata.assemblyDefs[image.assemblyIndex];
                        var a = assemblyDef?.aname;
                        if (a != null)
                        {
                            assemblyName = GetMetadataString(a.nameIndex, assemblyName);
                            if (string.IsNullOrWhiteSpace(assemblyName))
                                assemblyName = $"Image_{i}";
                            version = new Version(
                                Math.Max(a.major, 0),
                                Math.Max(a.minor, 0),
                                Math.Max(a.build, 0),
                                Math.Max(a.revision, 0));
                        }
                    }

                    var asm = AssemblyDefinition.CreateAssembly(
                        new AssemblyNameDefinition(assemblyName, version),
                        imageName,
                        ModuleKind.Dll);
                    if (asm?.MainModule == null)
                    {
                        asm?.Dispose();
                        continue;
                    }

                    Assemblies.Add(asm);
                    imageAssemblies[i] = asm;
                }
                catch
                {
                }
            }
        }

        private void CreateTypes()
        {
            if (metadata?.imageDefs == null || metadata.typeDefs == null)
                return;

            for (int imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                try
                {
                    var image = metadata.imageDefs[imageIndex];
                    if (image == null || !imageAssemblies.TryGetValue(imageIndex, out var assembly) || assembly?.MainModule == null)
                        continue;

                    var module = assembly.MainModule;
                    long start64 = Math.Max((long)image.typeStart, 0);
                    long end64 = Math.Min(start64 + Math.Max((long)image.typeCount, 0), metadata.typeDefs.LongLength);
                    int startIndex = (int)Math.Min(start64, int.MaxValue);
                    int endIndex = (int)Math.Min(end64, int.MaxValue);

                    for (int index = startIndex; index < endIndex; index++)
                    {
                        try
                        {
                            var td = metadata.typeDefs[index];
                            if (td == null)
                                continue;

                            var ns = GetMetadataString(td.namespaceIndex, string.Empty);
                            var name = GetMetadataString(td.nameIndex, $"Type_{index}");
                            if (string.IsNullOrWhiteSpace(name))
                                name = $"Type_{index}";

                            var attrs = (TypeAttributes)td.flags;
                            var baseType = module.TypeSystem?.Object;
                            if (baseType == null)
                                continue;

                            var type = new TypeDefinition(ns ?? string.Empty, name, attrs, baseType);
                            module.Types.Add(type);
                            typeMap[index] = type;
                            AddGenericParameters(type, td.genericContainerIndex);
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private void AttachNestedTypes()
        {
            if (metadata?.typeDefs == null || metadata.nestedTypeIndices == null)
                return;

            for (int parentIndex = 0; parentIndex < metadata.typeDefs.Length; parentIndex++)
            {
                try
                {
                    if (!typeMap.TryGetValue(parentIndex, out var parent) || parent == null)
                        continue;
                    var td = metadata.typeDefs[parentIndex];
                    if (td == null)
                        continue;

                    int count = Math.Max((int)td.nested_type_count, 0);
                    for (int i = 0; i < count; i++)
                    {
                        try
                        {
                            long pos64 = (long)td.nestedTypesStart + i;
                            if (pos64 < 0 || pos64 >= metadata.nestedTypeIndices.LongLength)
                                continue;
                            int nestedIndex = metadata.nestedTypeIndices[(int)pos64];
                            if (!typeMap.TryGetValue(nestedIndex, out var nested) || nested == null || ReferenceEquals(parent, nested))
                                continue;

                            if (nested.DeclaringType != null)
                                nested.DeclaringType.NestedTypes.Remove(nested);
                            else if (nested.Module != null)
                                nested.Module.Types.Remove(nested);

                            if (!parent.NestedTypes.Contains(nested))
                                parent.NestedTypes.Add(nested);
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private void PopulateTypes()
        {
            foreach (var pair in typeMap.OrderBy(x => x.Key))
            {
                try
                {
                int typeIndex = pair.Key;
                var type = pair.Value;
                var td = metadata.typeDefs[typeIndex];
                var module = type?.Module;
                if (td == null || module == null)
                    continue;

                if (td.parentIndex >= 0)
                    type.BaseType = ResolveType(td.parentIndex, module, type, null);
                else if (td.IsValueType && type.FullName != "System.Enum")
                    type.BaseType = module.TypeSystem.Object;

                for (int i = 0; i < td.interfaces_count; i++)
                {
                    int p = td.interfacesStart + i;
                    if (metadata.interfaceIndices == null || (uint)p >= (uint)metadata.interfaceIndices.Length)
                        continue;
                    var iface = ResolveType(metadata.interfaceIndices[p], module, type, null);
                    if (iface != null)
                        type.Interfaces.Add(new InterfaceImplementation(iface));
                }

                for (int i = 0; i < td.field_count; i++)
                {
                    int fieldIndex = td.fieldStart + i;
                    if (metadata.fieldDefs == null || (uint)fieldIndex >= (uint)metadata.fieldDefs.Length)
                        continue;
                    var fd = metadata.fieldDefs[fieldIndex];
                    var fieldType = ResolveType(fd.typeIndex, module, type, null) ?? module.TypeSystem.Object;
                    var attrs = FieldAttributes.Public;
                    try { attrs = (FieldAttributes)il2Cpp.types[fd.typeIndex].attrs; } catch { }
                    var field = new FieldDefinition(GetMetadataString(fd.nameIndex, $"field_{fieldIndex}"), attrs, fieldType);
                    type.Fields.Add(field);
                }

                for (int i = 0; i < td.method_count; i++)
                {
                    int methodIndex = td.methodStart + i;
                    if (metadata.methodDefs == null || (uint)methodIndex >= (uint)metadata.methodDefs.Length)
                        continue;
                    var md = metadata.methodDefs[methodIndex];
                    var method = new MethodDefinition(GetMetadataString(md.nameIndex, $"Method_{methodIndex}"), (MethodAttributes)md.flags, module.TypeSystem.Void)
                    {
                        ImplAttributes = (MethodImplAttributes)md.iflags
                    };
                    AddGenericParameters(method, md.genericContainerIndex);
                    method.ReturnType = ResolveType(md.returnType, module, type, method) ?? module.TypeSystem.Object;
                    for (int p = 0; p < md.parameterCount; p++)
                    {
                        int parameterIndex = md.parameterStart + p;
                        if (metadata.parameterDefs == null || (uint)parameterIndex >= (uint)metadata.parameterDefs.Length)
                            continue;
                        var pd = metadata.parameterDefs[parameterIndex];
                        var pt = ResolveType(pd.typeIndex, module, type, method) ?? module.TypeSystem.Object;
                        var parameter = new ParameterDefinition(GetMetadataString(pd.nameIndex, $"param_{p}"), ParameterAttributes.None, pt);
                        method.Parameters.Add(parameter);
                    }
                    type.Methods.Add(method);
                    methodMap[methodIndex] = method;
                    BuildBody(method);
                }

                for (int i = 0; i < td.property_count; i++)
                {
                    int propIndex = td.propertyStart + i;
                    if (metadata.propertyDefs == null || (uint)propIndex >= (uint)metadata.propertyDefs.Length)
                        continue;
                    var pd = metadata.propertyDefs[propIndex];
                    MethodDefinition get = null, set = null;
                    if (pd.get >= 0) methodMap.TryGetValue(td.methodStart + pd.get, out get);
                    if (pd.set >= 0) methodMap.TryGetValue(td.methodStart + pd.set, out set);
                    var propType = get?.ReturnType ?? (set != null && set.Parameters.Count > 0 ? set.Parameters[^1].ParameterType : module.TypeSystem.Object);
                    var prop = new PropertyDefinition(GetMetadataString(pd.nameIndex, $"Property_{propIndex}"), (PropertyAttributes)pd.attrs, propType)
                    {
                        GetMethod = get,
                        SetMethod = set
                    };
                    type.Properties.Add(prop);
                }

                for (int i = 0; i < td.event_count; i++)
                {
                    int eventIndex = td.eventStart + i;
                    if (metadata.eventDefs == null || (uint)eventIndex >= (uint)metadata.eventDefs.Length)
                        continue;
                    var ed = metadata.eventDefs[eventIndex];
                    var ev = new EventDefinition(GetMetadataString(ed.nameIndex, $"Event_{eventIndex}"), EventAttributes.None, ResolveType(ed.typeIndex, module, type, null) ?? module.TypeSystem.Object);
                    if (ed.add >= 0 && methodMap.TryGetValue(td.methodStart + ed.add, out var addMethod)) ev.AddMethod = addMethod;
                    if (ed.remove >= 0 && methodMap.TryGetValue(td.methodStart + ed.remove, out var removeMethod)) ev.RemoveMethod = removeMethod;
                    if (ed.raise >= 0 && methodMap.TryGetValue(td.methodStart + ed.raise, out var raiseMethod)) ev.InvokeMethod = raiseMethod;
                    type.Events.Add(ev);
                }
                }
                catch
                {
                }
            }
        }

        private void AddGenericParameters(IGenericParameterProvider owner, int containerIndex)
        {
            if (owner == null || metadata.genericContainers == null || containerIndex < 0 || containerIndex >= metadata.genericContainers.Length)
                return;
            var gc = metadata.genericContainers[containerIndex];
            if (gc == null)
                return;
            for (int i = 0; i < gc.type_argc; i++)
            {
                int index = gc.genericParameterStart + i;
                var gp = metadata.genericParameters != null && index >= 0 && index < metadata.genericParameters.Length
                    ? metadata.genericParameters[index]
                    : null;
                var name = gp != null
                    ? GetMetadataString(gp.nameIndex, $"T{i}")
                    : $"T{i}";
                owner.GenericParameters.Add(new GenericParameter(name, owner));
            }
        }

        private TypeReference ResolveType(int typeIndex, ModuleDefinition module, TypeDefinition declaringType, MethodDefinition method)
        {
            try
            {
                if (il2Cpp.types == null || (uint)typeIndex >= (uint)il2Cpp.types.Length)
                    return module.TypeSystem.Object;
                return ResolveIl2CppType(il2Cpp.types[typeIndex], module, declaringType, method);
            }
            catch
            {
                return module.TypeSystem.Object;
            }
        }

        private TypeReference ResolveIl2CppType(Il2CppType t, ModuleDefinition module, TypeDefinition declaringType, MethodDefinition method)
        {
            if (t == null)
                return module.TypeSystem.Object;
            switch (t.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID: return module.TypeSystem.Void;
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN: return module.TypeSystem.Boolean;
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR: return module.TypeSystem.Char;
                case Il2CppTypeEnum.IL2CPP_TYPE_I1: return module.TypeSystem.SByte;
                case Il2CppTypeEnum.IL2CPP_TYPE_U1: return module.TypeSystem.Byte;
                case Il2CppTypeEnum.IL2CPP_TYPE_I2: return module.TypeSystem.Int16;
                case Il2CppTypeEnum.IL2CPP_TYPE_U2: return module.TypeSystem.UInt16;
                case Il2CppTypeEnum.IL2CPP_TYPE_I4: return module.TypeSystem.Int32;
                case Il2CppTypeEnum.IL2CPP_TYPE_U4: return module.TypeSystem.UInt32;
                case Il2CppTypeEnum.IL2CPP_TYPE_I8: return module.TypeSystem.Int64;
                case Il2CppTypeEnum.IL2CPP_TYPE_U8: return module.TypeSystem.UInt64;
                case Il2CppTypeEnum.IL2CPP_TYPE_R4: return module.TypeSystem.Single;
                case Il2CppTypeEnum.IL2CPP_TYPE_R8: return module.TypeSystem.Double;
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING: return module.TypeSystem.String;
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT: return module.TypeSystem.Object;
                case Il2CppTypeEnum.IL2CPP_TYPE_I: return module.TypeSystem.IntPtr;
                case Il2CppTypeEnum.IL2CPP_TYPE_U: return module.TypeSystem.UIntPtr;
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF: return module.ImportReference(typeof(TypedReference));
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var td = executor.GetTypeDefinitionFromIl2CppType(t);
                        if (td == null) return module.TypeSystem.Object;
                        int idx = Array.IndexOf(metadata.typeDefs, td);
                        return idx >= 0 && typeMap.TryGetValue(idx, out var def) ? module.ImportReference(def) : module.TypeSystem.Object;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    return new ArrayType(ResolveIl2CppType(il2Cpp.GetIl2CppType(t.data.type), module, declaringType, method));
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    return new PointerType(ResolveIl2CppType(il2Cpp.GetIl2CppType(t.data.type), module, declaringType, method));
                case Il2CppTypeEnum.IL2CPP_TYPE_BYREF:
                    return new ByReferenceType(ResolveIl2CppType(il2Cpp.GetIl2CppType(t.data.type), module, declaringType, method));
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var at = il2Cpp.MapVATR<Il2CppArrayType>(t.data.array);
                        if (at == null) return new ArrayType(module.TypeSystem.Object);
                        var et = ResolveIl2CppType(il2Cpp.GetIl2CppType(at.etype), module, declaringType, method);
                        return new ArrayType(et, Math.Max((int)at.rank, 1));
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        var gp = executor.GetGenericParameteFromIl2CppType(t);
                        int num = gp?.num ?? 0;
                        if (t.type == Il2CppTypeEnum.IL2CPP_TYPE_MVAR && method != null && num < method.GenericParameters.Count)
                            return method.GenericParameters[num];
                        if (declaringType != null && num < declaringType.GenericParameters.Count)
                            return declaringType.GenericParameters[num];
                        return module.TypeSystem.Object;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var gc = il2Cpp.MapVATR<Il2CppGenericClass>(t.data.generic_class);
                        if (gc == null) return module.TypeSystem.Object;
                        var td = executor.GetGenericClassTypeDefinition(gc);
                        if (td == null) return module.TypeSystem.Object;
                        int idx = Array.IndexOf(metadata.typeDefs, td);
                        if (idx < 0 || !typeMap.TryGetValue(idx, out var def)) return module.TypeSystem.Object;
                        var gi = new GenericInstanceType(module.ImportReference(def));
                        var inst = il2Cpp.MapVATR<Il2CppGenericInst>(gc.context.class_inst);
                        if (inst == null || inst.type_argc <= 0 || inst.type_argv == 0) return gi;
                        var argv = il2Cpp.MapVATR<ulong>(inst.type_argv, inst.type_argc);
                        if (argv == null) return gi;
                        foreach (var p in argv)
                            gi.GenericArguments.Add(ResolveIl2CppType(il2Cpp.GetIl2CppType(p), module, declaringType, method));
                        return gi;
                    }
                default:
                    return module.TypeSystem.Object;
            }
        }

        private static void BuildBody(MethodDefinition method)
        {
            if (method.IsAbstract || method.IsPInvokeImpl || method.IsRuntime || method.IsInternalCall)
                return;
            method.ImplAttributes &= ~MethodImplAttributes.Runtime;
            method.ImplAttributes |= MethodImplAttributes.IL | MethodImplAttributes.Managed;
            var il = method.Body.GetILProcessor();
            var rt = method.ReturnType;
            if (rt.MetadataType == MetadataType.Void)
            {
                il.Emit(OpCodes.Ret);
                return;
            }
            if (!rt.IsValueType && !rt.IsGenericParameter && rt is not PointerType)
            {
                il.Emit(OpCodes.Ldnull);
                il.Emit(OpCodes.Ret);
                return;
            }
            switch (rt.MetadataType)
            {
                case MetadataType.Boolean:
                case MetadataType.Char:
                case MetadataType.SByte:
                case MetadataType.Byte:
                case MetadataType.Int16:
                case MetadataType.UInt16:
                case MetadataType.Int32:
                case MetadataType.UInt32:
                    il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ret); return;
                case MetadataType.Int64:
                case MetadataType.UInt64:
                    il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Conv_I8); il.Emit(OpCodes.Ret); return;
                case MetadataType.Single:
                    il.Emit(OpCodes.Ldc_R4, 0f); il.Emit(OpCodes.Ret); return;
                case MetadataType.Double:
                    il.Emit(OpCodes.Ldc_R8, 0d); il.Emit(OpCodes.Ret); return;
                case MetadataType.IntPtr:
                case MetadataType.UIntPtr:
                case MetadataType.Pointer:
                    il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Conv_I); il.Emit(OpCodes.Ret); return;
            }
            method.Body.InitLocals = true;
            var local = new VariableDefinition(rt);
            method.Body.Variables.Add(local);
            il.Emit(OpCodes.Ldloca_S, local);
            il.Emit(OpCodes.Initobj, rt);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ret);
        }

        private string GetMetadataString(uint index, string fallback)
        {
            try
            {
                return Safe(metadata.GetStringFromIndex(index), fallback);
            }
            catch
            {
                return fallback;
            }
        }

        private static string Safe(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;
    }
}
