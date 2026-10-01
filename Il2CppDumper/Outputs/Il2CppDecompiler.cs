using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class Il2CppDecompiler
    {
        private readonly Il2CppExecutor executor;
        private readonly Metadata metadata;
        private readonly Il2Cpp il2Cpp;
        private readonly Dictionary<Il2CppMethodDefinition, string> methodModifiers;

        public Il2CppDecompiler(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
            methodModifiers = new();
        }

        private bool IsConst(int fi, Il2CppType ft)
        {
            if ((ft.attrs & FIELD_ATTRIBUTE_LITERAL) == 0)
                return false;
            if (!metadata.GetFieldDefaultValueFromIndex(fi, out _))
                return false;

            switch (ft.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    return executor.GetTypeDefinitionFromIl2CppType(ft)?.IsEnum == true;
                default:
                    return false;
            }
        }

        private string Tn(int ti)
        {
            try
            {
                if (ti < 0 || il2Cpp.types == null || ti >= il2Cpp.types.Length)
                    return null;
                return executor.GetTypeName(il2Cpp.types[ti], false, false);
            }
            catch
            {
                return null;
            }
        }

        private IEnumerable<string> Gc(int gi)
        {
            if (gi < 0 || metadata.genericContainers == null || gi >= metadata.genericContainers.Length)
                yield break;

            var gc = metadata.genericContainers[gi];
            for (var i = 0; i < gc.type_argc; i++)
            {
                var pi = gc.genericParameterStart + i;
                if (pi < 0 || metadata.genericParameters == null || pi >= metadata.genericParameters.Length)
                    continue;

                var gp = metadata.genericParameters[pi];
                var n = metadata.GetStringFromIndex(gp.nameIndex);
                if (string.IsNullOrEmpty(n))
                    n = $"T{i}";

                var a = new List<string>();
                if ((gp.flags & 0x4) != 0)
                    a.Add("class");
                if ((gp.flags & 0x8) != 0)
                    a.Add("struct");

                if (gp.constraintsCount > 0 && gp.constraintsStart >= 0 && metadata.constraintIndices != null)
                {
                    for (var j = 0; j < gp.constraintsCount; j++)
                    {
                        var ci = gp.constraintsStart + j;
                        if (ci < 0 || ci >= metadata.constraintIndices.Length)
                            continue;
                        var tn = Tn(metadata.constraintIndices[ci]);
                        if (!string.IsNullOrEmpty(tn) && tn != "System.ValueType" && tn != "ValueType")
                            a.Add(tn);
                    }
                }

                if ((gp.flags & 0x10) != 0 && (gp.flags & 0x8) == 0)
                    a.Add("new()");

                if (a.Count > 0)
                    yield return $"where {n} : {string.Join(", ", a.Distinct())}";
            }
        }

        public void Decompile(Config config, string outputDir)
        {
            var writer = new StreamWriter(new FileStream(outputDir + "dump.cs", FileMode.Create), new UTF8Encoding(false));
            writer.Write(WatermarkService.Banner());
            if (WatermarkService.Enabled)
                writer.Write("\n");
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)} - {imageDef.typeStart}\n");
            }
            foreach (var imageDef in metadata.imageDefs)
            {
                try
                {
                    var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                    var ts = Math.Max(0, imageDef.typeStart);
                    if (ts > metadata.typeDefs.Length) ts = metadata.typeDefs.Length;
                    var te = (int)Math.Min(metadata.typeDefs.LongLength, Math.Max((long)ts, (long)imageDef.typeStart + imageDef.typeCount));
                    foreach (var typeDefIndex in WatermarkService.TypeOrder(ts, te))
                    {
                        try
                        {
                        var typeDef = metadata.typeDefs[typeDefIndex];
                        var extends = new List<string>();
                        if (typeDef.parentIndex >= 0)
                        {
                            var parentName = Tn(typeDef.parentIndex);
                            if (!string.IsNullOrWhiteSpace(parentName) &&
                                !typeDef.IsValueType && !typeDef.IsEnum &&
                                parentName != "object" && parentName != "System.Object")
                            {
                                extends.Add(parentName);
                            }
                        }
                        if (typeDef.interfaces_count > 0 && metadata.interfaceIndices != null)
                        {
                            for (int i = 0; i < typeDef.interfaces_count; i++)
                            {
                                var pos = typeDef.interfacesStart + i;
                                if (pos < 0 || pos >= metadata.interfaceIndices.Length)
                                    continue;
                                var interfaceName = Tn(metadata.interfaceIndices[pos]);
                                if (!string.IsNullOrWhiteSpace(interfaceName))
                                    extends.Add(interfaceName);
                            }
                        }
                        if (WatermarkService.ShouldRepeatAtType(typeDefIndex, config))
                            writer.Write("\n" + WatermarkService.TypeMarker(typeDefIndex));
                        writer.Write($"\n// Namespace: {metadata.GetStringFromIndex(typeDef.namespaceIndex)}\n");
                        if (config.DumpAttribute)
                        {
                            writer.Write(GetCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token));
                        }
                        if (config.DumpAttribute && (typeDef.flags & TYPE_ATTRIBUTE_SERIALIZABLE) != 0)
                            writer.Write("[Serializable]\n");
                        var visibility = typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
                        switch (visibility)
                        {
                            case TYPE_ATTRIBUTE_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_PUBLIC:
                                writer.Write("public ");
                                break;
                            case TYPE_ATTRIBUTE_NOT_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
                            case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
                                writer.Write("internal ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_PRIVATE:
                                writer.Write("private ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAMILY:
                                writer.Write("protected ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
                                writer.Write("protected internal ");
                                break;
                        }
                        if ((typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0 && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("static ");
                        else if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) == 0 && (typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0)
                            writer.Write("abstract ");
                        else if (!typeDef.IsValueType && !typeDef.IsEnum && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("sealed ");
                        if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0)
                            writer.Write("interface ");
                        else if (typeDef.IsEnum)
                            writer.Write("enum ");
                        else if (typeDef.IsValueType)
                            writer.Write("struct ");
                        else
                            writer.Write("class ");
                        var typeName = executor.GetTypeDefName(typeDef, false, true);
                        writer.Write($"{typeName}");
                        if (extends.Count > 0)
                            writer.Write($" : {string.Join(", ", extends)}");
                        if (config.DumpTypeDefIndex)
                            writer.Write($"{WatermarkService.TypeDefSpacing(typeDefIndex)}// TypeDefIndex: {typeDefIndex}\n");
                        else
                            writer.Write("\n");
                        foreach (var constraint in Gc(typeDef.genericContainerIndex))
                            writer.Write($"\t{constraint}\n");
                        writer.Write("{");

                        if (config.DumpField && typeDef.field_count > 0)
                        {
                            writer.Write("\n\t// Fields\n");
                            var fieldStart = Math.Max(0, typeDef.fieldStart);
                            var fieldEnd = Math.Min(metadata.fieldDefs.Length, typeDef.fieldStart + typeDef.field_count);
                            for (var i = fieldStart; i < fieldEnd; ++i)
                            {
                                var fieldDef = metadata.fieldDefs[i];
                                if (fieldDef.typeIndex < 0 || il2Cpp.types == null || fieldDef.typeIndex >= il2Cpp.types.Length)
                                {
                                    writer.Write($"\tobject {metadata.GetStringFromIndex(fieldDef.nameIndex)}; // invalid TypeIndex {fieldDef.typeIndex}\n");
                                    continue;
                                }
                                var fieldType = il2Cpp.types[fieldDef.typeIndex];
                                var isStatic = false;
                                var isConst = false;
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, "\t"));
                                }
                                writer.Write("\t");
                                var access = fieldType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
                                switch (access)
                                {
                                    case FIELD_ATTRIBUTE_PRIVATE:
                                        writer.Write("private ");
                                        break;
                                    case FIELD_ATTRIBUTE_PUBLIC:
                                        writer.Write("public ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAMILY:
                                        writer.Write("protected ");
                                        break;
                                    case FIELD_ATTRIBUTE_ASSEMBLY:
                                    case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                                        writer.Write("internal ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                                        writer.Write("protected internal ");
                                        break;
                                }
                                if (IsConst(i, fieldType))
                                {
                                    isConst = true;
                                    writer.Write("const ");
                                }
                                else
                                {
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                    {
                                        isStatic = true;
                                        writer.Write("static ");
                                    }
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                    {
                                        writer.Write("readonly ");
                                    }
                                }
                                writer.Write($"{executor.GetTypeName(fieldType, false, false)} {metadata.GetStringFromIndex(fieldDef.nameIndex)}");
                                if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefaultValue))
                                {
                                    if (fieldDefaultValue.dataIndex == -1)
                                    {
                                        writer.Write(" = null");
                                    }
                                    else if (executor.TryGetDefaultValue(fieldDefaultValue.typeIndex, fieldDefaultValue.dataIndex, out var value))
                                    {
                                        writer.Write($" = ");
                                        if (value is string str)
                                        {
                                            writer.Write($"\"{str.ToEscapedString()}\"");
                                        }
                                        else if (value is char c)
                                        {
                                            var v = (int)c;
                                            writer.Write($"'\\x{v:x}'");
                                        }
                                        else if (value is bool b)
                                        {
                                            writer.Write(b ? "true" : "false");
                                        }
                                        else if (value != null)
                                        {
                                            writer.Write($"{value}");
                                        }
                                        else
                                        {
                                            writer.Write("null");
                                        }
                                    }
                                    else
                                    {
                                        writer.Write($" /*Metadata offset 0x{value:X}*/");
                                    }
                                }
                                if (config.DumpFieldOffset && !isConst)
                                    writer.Write("; // 0x{0:X}\n", il2Cpp.GetFieldOffsetFromIndex(typeDefIndex, i - typeDef.fieldStart, i, typeDef.IsValueType, isStatic));
                                else
                                    writer.Write(";\n");
                            }
                        }
                        if (config.DumpProperty && typeDef.property_count > 0)
                        {
                            writer.Write("\n\t// Properties\n");
                            var propertyStart = Math.Max(0, typeDef.propertyStart);
                            var propertyEnd = Math.Min(metadata.propertyDefs.Length, typeDef.propertyStart + typeDef.property_count);
                            for (var i = propertyStart; i < propertyEnd; ++i)
                            {
                                var propertyDef = metadata.propertyDefs[i];
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, "\t"));
                                }
                                writer.Write("\t");
                                var propertyName = metadata.GetStringFromIndex(propertyDef.nameIndex);
                                var propertyTypeName = "object";
                                var propertyModifiers = string.Empty;
                                var accessorRel = propertyDef.get >= 0 ? propertyDef.get : propertyDef.set;
                                var accessorIndex = accessorRel >= 0 ? typeDef.methodStart + accessorRel : -1;
                                if (accessorIndex >= 0 && accessorIndex < metadata.methodDefs.Length)
                                {
                                    var accessorMethod = metadata.methodDefs[accessorIndex];
                                    propertyModifiers = GetModifiers(accessorMethod);
                                    if (propertyDef.get >= 0)
                                    {
                                        propertyTypeName = Tn(accessorMethod.returnType) ?? "object";
                                    }
                                    else if (accessorMethod.parameterStart >= 0 && accessorMethod.parameterStart < metadata.parameterDefs.Length)
                                    {
                                        var parameterDef = metadata.parameterDefs[accessorMethod.parameterStart];
                                        propertyTypeName = Tn(parameterDef.typeIndex) ?? "object";
                                    }
                                }
                                writer.Write($"{propertyModifiers}{propertyTypeName} {propertyName} {{ ");
                                if (propertyDef.get >= 0)
                                    writer.Write("get; ");
                                if (propertyDef.set >= 0)
                                    writer.Write("set; ");
                                writer.Write("}\n");
                            }
                        }
                        if (typeDef.event_count > 0 && metadata.eventDefs != null)
                        {
                            writer.Write("\n\t// Events\n");
                            var eventStart = Math.Max(0, typeDef.eventStart);
                            var eventEnd = Math.Min(metadata.eventDefs.Length, typeDef.eventStart + typeDef.event_count);
                            for (var i = eventStart; i < eventEnd; ++i)
                            {
                                if (i < 0 || i >= metadata.eventDefs.Length)
                                    continue;
                                var eventDef = metadata.eventDefs[i];
                                if (config.DumpAttribute)
                                    writer.Write(GetCustomAttribute(imageDef, eventDef.customAttributeIndex, eventDef.token, "\t"));
                                var eventTypeName = Tn(eventDef.typeIndex) ?? "object";
                                var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                                var eventModifiers = string.Empty;
                                var accessor = eventDef.add >= 0 ? eventDef.add : eventDef.remove;
                                var accessorIndex = accessor >= 0 ? typeDef.methodStart + accessor : -1;
                                if (accessorIndex >= 0 && accessorIndex < metadata.methodDefs.Length)
                                    eventModifiers = GetModifiers(metadata.methodDefs[accessorIndex]);
                                writer.Write($"\t{eventModifiers}event {eventTypeName} {eventName};");
                                writer.Write($" // add: {eventDef.add}, remove: {eventDef.remove}, raise: {eventDef.raise}\n");
                            }
                        }

                        if (config.DumpMethod && typeDef.method_count > 0)
                        {
                            writer.Write("\n\t// Methods\n");
                            var methodStart = Math.Max(0, typeDef.methodStart);
                            var methodEnd = Math.Min(metadata.methodDefs.Length, typeDef.methodStart + typeDef.method_count);
                            for (var i = methodStart; i < methodEnd; ++i)
                            {
                                writer.Write("\n");
                                var methodDef = metadata.methodDefs[i];
                                var isAbstract = (methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0;
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, "\t"));
                                }
                                if (config.DumpMethodOffset)
                                {
                                    var methodPointer = il2Cpp.GetMethodPointer(imageName, methodDef);
                                    if (!isAbstract && methodPointer > 0)
                                    {
                                        var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                        writer.Write("\t// RVA: 0x{0:X} Offset: 0x{1:X} VA: 0x{2:X}", fixedMethodPointer, il2Cpp.MapVATR(methodPointer), methodPointer);
                                    }
                                    else
                                    {
                                        writer.Write("\t// RVA: -1 Offset: -1");
                                    }
                                    if (methodDef.slot != ushort.MaxValue)
                                    {
                                        writer.Write(" Slot: {0}", methodDef.slot);
                                    }
                                    writer.Write("\n");
                                }
                                writer.Write("\t");
                                writer.Write(GetModifiers(methodDef));
                                var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                                if (methodDef.returnType < 0 || il2Cpp.types == null || methodDef.returnType >= il2Cpp.types.Length)
                                {
                                    writer.Write($"object {methodName}(/* invalid return TypeIndex {methodDef.returnType} */) {{ }}\n");
                                    continue;
                                }
                                var methodReturnType = il2Cpp.types[methodDef.returnType];
                                if (methodDef.genericContainerIndex >= 0 &&
                                    metadata.genericContainers != null &&
                                    methodDef.genericContainerIndex < metadata.genericContainers.Length)
                                {
                                    var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                                    methodName += executor.GetGenericContainerParams(genericContainer);
                                }
                                if (methodReturnType.byref == 1)
                                {
                                    writer.Write("ref ");
                                }
                                writer.Write($"{executor.GetTypeName(methodReturnType, false, false)} {methodName}(");
                                var parameterStrs = new List<string>();
                                for (var j = 0; j < methodDef.parameterCount; ++j)
                                {
                                    var parameterStr = "";
                                    var parameterIndex = methodDef.parameterStart + j;
                                    if (parameterIndex < 0 || parameterIndex >= metadata.parameterDefs.Length)
                                    {
                                        parameterStrs.Add($"object arg{j} /* invalid ParameterIndex {parameterIndex} */");
                                        continue;
                                    }
                                    var parameterDef = metadata.parameterDefs[parameterIndex];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                    if (parameterDef.typeIndex < 0 || il2Cpp.types == null || parameterDef.typeIndex >= il2Cpp.types.Length)
                                    {
                                        parameterStrs.Add($"object {parameterName} /* invalid TypeIndex {parameterDef.typeIndex} */");
                                        continue;
                                    }
                                    var parameterType = il2Cpp.types[parameterDef.typeIndex];
                                    var parameterTypeName = executor.GetTypeName(parameterType, false, false);
                                    if (parameterType.byref == 1)
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) == 0)
                                        {
                                            parameterStr += "out ";
                                        }
                                        else if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) == 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "in ";
                                        }
                                        else
                                        {
                                            parameterStr += "ref ";
                                        }
                                    }
                                    else
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "[In] ";
                                        }
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                        {
                                            parameterStr += "[Out] ";
                                        }
                                    }
                                    parameterStr += $"{parameterTypeName} {parameterName}";
                                    if (metadata.GetParameterDefaultValueFromIndex(parameterIndex, out var parameterDefault))
                                    {
                                        if (parameterDefault.dataIndex == -1)
                                        {
                                            parameterStr += " = null";
                                        }
                                        else if (executor.TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                        {
                                            parameterStr += " = ";
                                            if (value is string str)
                                            {
                                                parameterStr += $"\"{str.ToEscapedString()}\"";
                                            }
                                            else if (value is char c)
                                            {
                                                var v = (int)c;
                                                parameterStr += $"'\\x{v:x}'";
                                            }
                                            else if (value is bool b)
                                            {
                                                parameterStr += b ? "true" : "false";
                                            }
                                            else if (value != null)
                                            {
                                                parameterStr += $"{value}";
                                            }
                                            else
                                            {
                                                parameterStr += "null";
                                            }
                                        }
                                        else
                                        {
                                            parameterStr += $" /*Metadata offset 0x{value:X}*/";
                                        }
                                    }
                                    parameterStrs.Add(parameterStr);
                                }
                                writer.Write(string.Join(", ", parameterStrs));
                                writer.Write(")");
                                var methodConstraints = Gc(methodDef.genericContainerIndex).ToList();
                                if (methodConstraints.Count > 0)
                                {
                                    writer.Write("\n");
                                    for (var gcIndex = 0; gcIndex < methodConstraints.Count; gcIndex++)
                                    {
                                        writer.Write($"\t\t{methodConstraints[gcIndex]}");
                                        if (gcIndex + 1 < methodConstraints.Count)
                                            writer.Write("\n");
                                    }
                                }
                                if (isAbstract)
                                    writer.Write(";\n");
                                else
                                    writer.Write(" { }\n");

                                if (il2Cpp.methodDefinitionMethodSpecs.TryGetValue(i, out var methodSpecs))
                                {
                                    writer.Write("\t/* GenericInstMethod :\n");
                                    var groups = methodSpecs.GroupBy(x =>
                                        il2Cpp.methodSpecGenericMethodPointers.TryGetValue(x, out var p) ? p : 0UL);
                                    foreach (var group in groups)
                                    {
                                        writer.Write("\t|\n");
                                        var genericMethodPointer = group.Key;
                                        if (genericMethodPointer > 0)
                                        {
                                            var fixedPointer = il2Cpp.GetRVA(genericMethodPointer);
                                            writer.Write($"\t|-RVA: 0x{fixedPointer:X} Offset: 0x{il2Cpp.MapVATR(genericMethodPointer):X} VA: 0x{genericMethodPointer:X}\n");
                                        }
                                        else
                                        {
                                            writer.Write("\t|-RVA: -1 Offset: -1\n");
                                        }
                                        foreach (var methodSpec in group)
                                        {
                                            (var methodSpecTypeName, var methodSpecMethodName) = executor.GetMethodSpecName(methodSpec);
                                            writer.Write($"\t|-{methodSpecTypeName}.{methodSpecMethodName}\n");
                                        }
                                    }
                                    writer.Write("\t*/\n");
                                }
                            }
                        }
                        writer.Write("}\n");
                        }
                        catch (Exception e)
                        {
                            writer.Write($"\n/* TypeDefIndex {typeDefIndex} dump error: {e.GetType().Name}: {e.Message} */\n");
                        }
                    }
                }
                catch (Exception e)
                {
                    
                    writer.Write("/* Image dump error: ");
                    writer.Write(e);
                    writer.Write(" */\n");
                }
            }
            writer.Close();
        }

        public string GetCustomAttribute(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token, string padding = "")
        {
            if (il2Cpp.Version < 21)
                return string.Empty;
            var attributeIndex = metadata.GetCustomAttributeIndex(imageDef, customAttributeIndex, token);
            if (attributeIndex >= 0)
            {
                if (il2Cpp.Version < 29)
                {
                    var methodPointer = executor.customAttributeGenerators[attributeIndex];
                    var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                    var attributeTypeRange = metadata.attributeTypeRanges[attributeIndex];
                    var sb = new StringBuilder();
                    for (var i = 0; i < attributeTypeRange.count; i++)
                    {
                        var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                        sb.AppendFormat("{0}[{1}] // RVA: 0x{2:X} Offset: 0x{3:X} VA: 0x{4:X}\n",
                            padding,
                            executor.GetTypeName(il2Cpp.types[typeIndex], false, false),
                            fixedMethodPointer,
                            il2Cpp.MapVATR(methodPointer),
                            methodPointer);
                    }
                    return sb.ToString();
                }
                else
                {
                    var startRange = metadata.attributeDataRanges[attributeIndex];
                    var endRange = metadata.attributeDataRanges[attributeIndex + 1];
                    metadata.Position = metadata.header.attributeDataOffset + startRange.startOffset;
                    var buff = metadata.ReadBytes((int)(endRange.startOffset - startRange.startOffset));
                    var reader = new CustomAttributeDataReader(executor, buff);
                    if (reader.Count == 0)
                    {
                        return string.Empty;
                    }
                    var sb = new StringBuilder();
                    for (var i = 0; i < reader.Count; i++)
                    {
                        sb.Append(padding);
                        sb.Append(reader.GetStringCustomAttributeData());
                        sb.Append('\n');
                    }
                    return sb.ToString();
                }
            }
            else
            {
                return string.Empty;
            }
        }

        public string GetModifiers(Il2CppMethodDefinition methodDef)
        {
            if (methodModifiers.TryGetValue(methodDef, out string str))
                return str;
            var access = methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
            switch (access)
            {
                case METHOD_ATTRIBUTE_PRIVATE:
                    str += "private ";
                    break;
                case METHOD_ATTRIBUTE_PUBLIC:
                    str += "public ";
                    break;
                case METHOD_ATTRIBUTE_FAMILY:
                    str += "protected ";
                    break;
                case METHOD_ATTRIBUTE_ASSEM:
                case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
                    str += "internal ";
                    break;
                case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
                    str += "protected internal ";
                    break;
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                str += "static ";
            if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
            {
                str += "abstract ";
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_FINAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "sealed override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
                    str += "virtual ";
                else
                    str += "override ";
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) != 0)
                str += "extern ";
            methodModifiers.Add(methodDef, str);
            return str;
        }
    }
}
