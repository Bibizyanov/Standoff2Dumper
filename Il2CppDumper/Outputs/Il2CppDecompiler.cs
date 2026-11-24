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

        // Protected v31 builds can carry garbage FIELD_ATTRIBUTE_LITERAL bits in
        // Il2CppType.attrs. Trust `const` only when metadata also contains a real
        // field-default entry and the CLR type is legal for a literal constant.
        private bool IsTrustedLiteralField(int fieldIndex, Il2CppType fieldType)
        {
            if ((fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) == 0)
                return false;

            // A protected build may set the Literal bit on ordinary fields.
            // A real literal field, however, has an Il2CppFieldDefaultValue row.
            // dataIndex == -1 is still meaningful (for example a null constant),
            // so presence of the row is the trust signal, not dataIndex >= 0.
            if (!metadata.GetFieldDefaultValueFromIndex(fieldIndex, out _))
                return false;

            switch (fieldType.type)
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
                    return executor.GetTypeDefinitionFromIl2CppType(fieldType)?.IsEnum == true;
                default:
                    return false;
            }
        }

        private string SafeTypeName(int typeIndex)
        {
            try
            {
                if (typeIndex < 0 || il2Cpp.types == null || typeIndex >= il2Cpp.types.Length)
                    return null;
                return executor.GetTypeName(il2Cpp.types[typeIndex], false, false);
            }
            catch
            {
                return null;
            }
        }

        private IEnumerable<string> GetGenericConstraints(int genericContainerIndex)
        {
            if (genericContainerIndex < 0 || metadata.genericContainers == null ||
                genericContainerIndex >= metadata.genericContainers.Length)
                yield break;

            var gc = metadata.genericContainers[genericContainerIndex];
            for (var i = 0; i < gc.type_argc; i++)
            {
                var gpIndex = gc.genericParameterStart + i;
                if (gpIndex < 0 || metadata.genericParameters == null || gpIndex >= metadata.genericParameters.Length)
                    continue;
                var gp = metadata.genericParameters[gpIndex];
                var name = metadata.GetStringFromIndex(gp.nameIndex);
                if (string.IsNullOrEmpty(name))
                    name = $"T{i}";

                var parts = new List<string>();
                // System.Reflection.GenericParameterAttributes special-constraint bits.
                if ((gp.flags & 0x4) != 0)
                    parts.Add("class");
                if ((gp.flags & 0x8) != 0)
                    parts.Add("struct");

                if (gp.constraintsCount > 0 && gp.constraintsStart >= 0 && metadata.constraintIndices != null)
                {
                    for (var c = 0; c < gp.constraintsCount; c++)
                    {
                        var ci = gp.constraintsStart + c;
                        if (ci < 0 || ci >= metadata.constraintIndices.Length)
                            continue;
                        var tn = SafeTypeName(metadata.constraintIndices[ci]);
                        if (!string.IsNullOrEmpty(tn) && tn != "System.ValueType" && tn != "ValueType")
                            parts.Add(tn);
                    }
                }

                if ((gp.flags & 0x10) != 0 && (gp.flags & 0x8) == 0)
                    parts.Add("new()");

                if (parts.Count > 0)
                    yield return $"where {name} : {string.Join(", ", parts.Distinct())}";
            }
        }

        private List<string> GetTypeDependencies(Il2CppTypeDefinition typeDef, int typeDefIndex)
        {
            var deps = new HashSet<string>();
            void AddTypeIndex(int idx)
            {
                var n = SafeTypeName(idx);
                if (!string.IsNullOrWhiteSpace(n) && n != "object" && n != "System.Object")
                    deps.Add(n);
            }

            AddTypeIndex(typeDef.parentIndex);
            AddTypeIndex(typeDef.declaringTypeIndex);

            if (typeDef.interfaces_count > 0 && metadata.interfaceIndices != null)
            {
                for (var i = 0; i < typeDef.interfaces_count; i++)
                {
                    var pos = typeDef.interfacesStart + i;
                    if (pos >= 0 && pos < metadata.interfaceIndices.Length)
                        AddTypeIndex(metadata.interfaceIndices[pos]);
                }
            }

            if (metadata.nestedTypeIndices != null && typeDef.nested_type_count > 0)
            {
                for (var i = 0; i < typeDef.nested_type_count; i++)
                {
                    var pos = typeDef.nestedTypesStart + i;
                    if (pos < 0 || pos >= metadata.nestedTypeIndices.Length)
                        continue;
                    var nestedTdIndex = metadata.nestedTypeIndices[pos];
                    if (nestedTdIndex >= 0 && nestedTdIndex < metadata.typeDefs.Length)
                    {
                        var nested = metadata.typeDefs[nestedTdIndex];
                        var n = executor.GetTypeDefName(nested, false, true);
                        if (!string.IsNullOrWhiteSpace(n))
                            deps.Add(n);
                    }
                }
            }

            for (var i = 0; i < typeDef.field_count; i++)
            {
                var idx = typeDef.fieldStart + i;
                if (idx >= 0 && idx < metadata.fieldDefs.Length)
                    AddTypeIndex(metadata.fieldDefs[idx].typeIndex);
            }
            for (var i = 0; i < typeDef.method_count; i++)
            {
                var idx = typeDef.methodStart + i;
                if (idx < 0 || idx >= metadata.methodDefs.Length)
                    continue;
                var md = metadata.methodDefs[idx];
                AddTypeIndex(md.returnType);
                for (var p = 0; p < md.parameterCount; p++)
                {
                    var pi = md.parameterStart + p;
                    if (pi >= 0 && pi < metadata.parameterDefs.Length)
                        AddTypeIndex(metadata.parameterDefs[pi].typeIndex);
                }
                if (md.genericContainerIndex >= 0 && metadata.genericContainers != null && metadata.genericParameters != null)
                {
                    var gc = metadata.genericContainers[md.genericContainerIndex];
                    for (var g = 0; g < gc.type_argc; g++)
                    {
                        var gpi = gc.genericParameterStart + g;
                        if (gpi < 0 || gpi >= metadata.genericParameters.Length) continue;
                        var gp = metadata.genericParameters[gpi];
                        for (var c = 0; c < gp.constraintsCount; c++)
                        {
                            var ci = gp.constraintsStart + c;
                            if (metadata.constraintIndices != null && ci >= 0 && ci < metadata.constraintIndices.Length)
                                AddTypeIndex(metadata.constraintIndices[ci]);
                        }
                    }
                }
            }
            for (var i = 0; i < typeDef.event_count; i++)
            {
                var idx = typeDef.eventStart + i;
                if (metadata.eventDefs != null && idx >= 0 && idx < metadata.eventDefs.Length)
                    AddTypeIndex(metadata.eventDefs[idx].typeIndex);
            }

            if (typeDef.genericContainerIndex >= 0 && metadata.genericContainers != null && metadata.genericParameters != null)
            {
                var gc = metadata.genericContainers[typeDef.genericContainerIndex];
                for (var g = 0; g < gc.type_argc; g++)
                {
                    var gpi = gc.genericParameterStart + g;
                    if (gpi < 0 || gpi >= metadata.genericParameters.Length) continue;
                    var gp = metadata.genericParameters[gpi];
                    for (var c = 0; c < gp.constraintsCount; c++)
                    {
                        var ci = gp.constraintsStart + c;
                        if (metadata.constraintIndices != null && ci >= 0 && ci < metadata.constraintIndices.Length)
                            AddTypeIndex(metadata.constraintIndices[ci]);
                    }
                }
            }

            return deps.OrderBy(x => x, StringComparer.Ordinal).ToList();
        }

        public void Decompile(Config config, string outputDir)
        {
            var writer = new StreamWriter(new FileStream(outputDir + "dump.cs", FileMode.Create), new UTF8Encoding(false));
            //dump image
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)} - {imageDef.typeStart}\n");
            }
            //dump type
            foreach (var imageDef in metadata.imageDefs)
            {
                try
                {
                    var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                    var typeEnd = imageDef.typeStart + imageDef.typeCount;
                    for (int typeDefIndex = imageDef.typeStart; typeDefIndex < typeEnd; typeDefIndex++)
                    {
                        var typeDef = metadata.typeDefs[typeDefIndex];
                        var extends = new List<string>();
                        if (typeDef.parentIndex >= 0)
                        {
                            var parent = il2Cpp.types[typeDef.parentIndex];
                            var parentName = executor.GetTypeName(parent, false, false);
                            if (!typeDef.IsValueType && !typeDef.IsEnum && parentName != "object")
                            {
                                extends.Add(parentName);
                            }
                        }
                        if (typeDef.interfaces_count > 0)
                        {
                            for (int i = 0; i < typeDef.interfaces_count; i++)
                            {
                                var @interface = il2Cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                                extends.Add(executor.GetTypeName(@interface, false, false));
                            }
                        }
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
                            writer.Write($" // TypeDefIndex: {typeDefIndex}\n");
                        else
                            writer.Write("\n");
                        foreach (var constraint in GetGenericConstraints(typeDef.genericContainerIndex))
                            writer.Write($"\t{constraint}\n");
                        writer.Write("{");

                        //dump field
                        if (config.DumpField && typeDef.field_count > 0)
                        {
                            writer.Write("\n\t// Fields\n");
                            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                            for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                            {
                                var fieldDef = metadata.fieldDefs[i];
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
                                if (IsTrustedLiteralField(i, fieldType))
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
                        //dump property
                        if (config.DumpProperty && typeDef.property_count > 0)
                        {
                            writer.Write("\n\t// Properties\n");
                            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                            for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                            {
                                var propertyDef = metadata.propertyDefs[i];
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, "\t"));
                                }
                                writer.Write("\t");
                                if (propertyDef.get >= 0)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.get];
                                    writer.Write(GetModifiers(methodDef));
                                    var propertyType = il2Cpp.types[methodDef.returnType];
                                    writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }
                                else if (propertyDef.set >= 0)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.set];
                                    writer.Write(GetModifiers(methodDef));
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart];
                                    var propertyType = il2Cpp.types[parameterDef.typeIndex];
                                    writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }
                                if (propertyDef.get >= 0)
                                    writer.Write("get; ");
                                if (propertyDef.set >= 0)
                                    writer.Write("set; ");
                                writer.Write("}");
                                writer.Write("\n");
                            }
                        }
                        //dump event
                        if (typeDef.event_count > 0 && metadata.eventDefs != null)
                        {
                            writer.Write("\n\t// Events\n");
                            var eventEnd = typeDef.eventStart + typeDef.event_count;
                            for (var i = typeDef.eventStart; i < eventEnd; ++i)
                            {
                                if (i < 0 || i >= metadata.eventDefs.Length)
                                    continue;
                                var eventDef = metadata.eventDefs[i];
                                if (config.DumpAttribute)
                                    writer.Write(GetCustomAttribute(imageDef, eventDef.customAttributeIndex, eventDef.token, "\t"));
                                var eventTypeName = SafeTypeName(eventDef.typeIndex) ?? "object";
                                var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                                writer.Write($"\t{eventTypeName} {eventName};");
                                writer.Write($" // add: {eventDef.add}, remove: {eventDef.remove}, raise: {eventDef.raise}\n");
                            }
                        }

                        //dump method
                        if (config.DumpMethod && typeDef.method_count > 0)
                        {
                            writer.Write("\n\t// Methods\n");
                            var methodEnd = typeDef.methodStart + typeDef.method_count;
                            for (var i = typeDef.methodStart; i < methodEnd; ++i)
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
                                var methodReturnType = il2Cpp.types[methodDef.returnType];
                                var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                                if (methodDef.genericContainerIndex >= 0)
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
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
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
                                    if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault))
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
                                var methodConstraints = GetGenericConstraints(methodDef.genericContainerIndex).ToList();
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
                                    var groups = methodSpecs.GroupBy(x => il2Cpp.methodSpecGenericMethodPointers[x]);
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
                }
                catch (Exception e)
                {
                    
                    writer.Write("/*");
                    writer.Write(e);
                    writer.Write("*/\n}\n");
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
