using System;
using System.Collections.Generic;
using System.IO;

namespace Il2CppDumper
{
    public abstract partial class Il2Cpp
    {
        private ulong P64(ulong va)
        {
            Position = MapVATR(va);
            return ReadUInt64();
        }

        private uint P32(ulong va)
        {
            Position = MapVATR(va);
            return ReadUInt32();
        }

        private int PI32(ulong va)
        {
            Position = MapVATR(va);
            return ReadInt32();
        }

        private ulong[] P64Array(ulong va, ulong count)
        {
            if (va == 0 || count == 0)
                return Array.Empty<ulong>();

            if (count > int.MaxValue)
                throw new InvalidDataException();

            var result = new ulong[(int)count];

            for (var i = 0; i < result.Length; i++)
                result[i] = P64(va + (ulong)i * 8);

            return result;
        }

        private ulong[] P64Array(ulong va, long count)
        {
            if (count <= 0)
                return Array.Empty<ulong>();

            return P64Array(va, checked((ulong)count));
        }

        private void DecodeType(Il2CppType type)
        {
            type.attrs = type.bits & 0xFFFFu;
            type.byref = type.bits >> 17 & 1u;
            type.type = (Il2CppTypeEnum)(type.bits >> 18 & 0xFFu);
            type.num_mods = type.bits >> 26 & 0x1Fu;
            type.pinned = type.bits >> 31 & 1u;
            type.valuetype = type.type == Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE ? 1u : 0u;
            type.data = new Il2CppType.Union { dummy = type.datapoint };
        }

        public void InitProtected(ulong codeReg, ulong metadataReg)
        {
            if (PointerSize != 8)
                throw new NotSupportedException("ELF64 required");

            IsDumped = false;

            pCodeRegistration = new Il2CppCodeRegistration
            {
                reversePInvokeWrappers = P64(codeReg + 0x08),
                reversePInvokeWrapperCount = P32(codeReg + 0x68),
                genericMethodPointers = P64(codeReg + 0x70),
                genericMethodPointersCount = P32(codeReg + 0x58),
                genericAdjustorThunks = P64(codeReg + 0x48),
                invokerPointers = P64(codeReg + 0x28),
                invokerPointersCount = P32(codeReg + 0x54),
                unresolvedVirtualCallPointers = P64(codeReg + 0x00),
                unresolvedInstanceCallPointers = P64(codeReg + 0x10),
                unresolvedStaticCallPointers = P64(codeReg + 0x18),
                unresolvedVirtualCallCount = P32(codeReg + 0x50),
                interopData = P64(codeReg + 0x60),
                interopDataCount = P32(codeReg + 0x40),
                codeGenModules = P64(codeReg + 0x30),
                codeGenModulesCount = P32(codeReg + 0x44),
                windowsRuntimeFactoryCount = 0,
                windowsRuntimeFactoryTable = 0
            };

            pMetadataRegistration = new Il2CppMetadataRegistration
            {
                genericClasses = P64(metadataReg + 0x08),
                genericClassesCount = P32(metadataReg + 0x58),
                genericInsts = P64(metadataReg + 0x18),
                genericInstsCount = P32(metadataReg + 0x20),
                genericMethodTable = P64(metadataReg + 0x60),
                genericMethodTableCount = P32(metadataReg + 0x00),
                types = P64(metadataReg + 0x48),
                typesCount = P32(metadataReg + 0x30),
                methodSpecs = P64(metadataReg + 0x50),
                methodSpecsCount = P32(metadataReg + 0x40),
                fieldOffsets = P64(metadataReg + 0x68),
                fieldOffsetsCount = P32(metadataReg + 0x04),
                typeDefinitionsSizes = P64(metadataReg + 0x28),
                typeDefinitionsSizesCount = P32(metadataReg + 0x34),
                metadataUsages = 0,
                metadataUsagesCount = 0
            };

            genericMethodPointers = P64Array(pCodeRegistration.genericMethodPointers, pCodeRegistration.genericMethodPointersCount);
            invokerPointers = P64Array(pCodeRegistration.invokerPointers, pCodeRegistration.invokerPointersCount);
            reversePInvokeWrappers = P64Array(pCodeRegistration.reversePInvokeWrappers, pCodeRegistration.reversePInvokeWrapperCount);
            unresolvedVirtualCallPointers = P64Array(pCodeRegistration.unresolvedVirtualCallPointers, pCodeRegistration.unresolvedVirtualCallCount);

            genericInstPointers = P64Array(pMetadataRegistration.genericInsts, pMetadataRegistration.genericInstsCount);
            genericInsts = Array.ConvertAll(genericInstPointers, MapVATR<Il2CppGenericInst>);

            fieldOffsetsArePointers = true;
            fieldOffsets = P64Array(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);

            var typePointers = P64Array(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[typePointers.Length];
            typeDic.Clear();
            for (var i = 0; i < typePointers.Length; i++)
            {
                var type = MapVATR<Il2CppType>(typePointers[i]);
                DecodeType(type);
                types[i] = type;
                typeDic[typePointers[i]] = type;
            }

            var modulePointers = P64Array(pCodeRegistration.codeGenModules, pCodeRegistration.codeGenModulesCount);
            codeGenModules = new Dictionary<string, Il2CppCodeGenModule>(modulePointers.Length, StringComparer.OrdinalIgnoreCase);
            codeGenModuleMethodPointers = new Dictionary<string, ulong[]>(modulePointers.Length, StringComparer.OrdinalIgnoreCase);
            rgctxsDictionary = new(modulePointers.Length, StringComparer.OrdinalIgnoreCase);

            foreach (var ptr in modulePointers)
            {
                var namePtr = P64(ptr + 0x80);
                var name = ReadStringToNull(MapVATR(namePtr));
                var module = new Il2CppCodeGenModule
                {
                    moduleName = namePtr,
                    methodPointerCount = checked((long)P64(ptr + 0x08)),
                    rgctxsCount = checked((long)P64(ptr + 0x18)),
                    adjustorThunks = P64(ptr + 0x20),
                    methodPointers = P64(ptr + 0x30),
                    rgctxRanges = P64(ptr + 0x38),
                    reversePInvokeWrapperCount = P64(ptr + 0x40),
                    rgctxRangesCount = checked((long)P64(ptr + 0x58)),
                    invokerIndices = P64(ptr + 0x60),
                    adjustorThunkCount = checked((long)P64(ptr + 0x68)),
                    reversePInvokeWrapperIndices = P64(ptr + 0x70),
                    rgctxs = P64(ptr + 0x78)
                };

                ulong[] pointers;
                try
                {
                    pointers = P64Array(module.methodPointers, module.methodPointerCount);
                }
                catch (EndOfStreamException)
                {
                    pointers = new ulong[checked((int)module.methodPointerCount)];
                }

                void AddModuleAlias(string alias)
                {
                    if (string.IsNullOrWhiteSpace(alias))
                        return;
                    codeGenModules[alias] = module;
                    codeGenModuleMethodPointers[alias] = pointers;
                    if (!rgctxsDictionary.ContainsKey(alias))
                        rgctxsDictionary[alias] = new();
                }

                AddModuleAlias(name);
                if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    AddModuleAlias(name[..^4]);
                else
                    AddModuleAlias(name + ".dll");
            }

            methodSpecs = new Il2CppMethodSpec[pMetadataRegistration.methodSpecsCount];
            for (var i = 0; i < methodSpecs.Length; i++)
            {
                var ptr = pMetadataRegistration.methodSpecs + (ulong)i * 12;
                methodSpecs[i] = new Il2CppMethodSpec
                {
                    classIndexIndex = PI32(ptr),
                    methodIndexIndex = PI32(ptr + 4),
                    methodDefinitionIndex = PI32(ptr + 8)
                };
            }

            var count = checked((int)pMetadataRegistration.genericMethodTableCount);
            genericMethodTable = new Il2CppGenericMethodFunctionsDefinitions[count];
            methodDefinitionMethodSpecs.Clear();
            methodSpecGenericMethodPointers.Clear();

            for (var i = 0; i < count; i++)
            {
                var ptr = pMetadataRegistration.genericMethodTable + (ulong)i * 0x10;
                var item = new Il2CppGenericMethodFunctionsDefinitions
                {
                    genericMethodIndex = PI32(ptr + 0x0C),
                    indices = new Il2CppGenericMethodIndices
                    {
                        adjustorThunk = PI32(ptr),
                        invokerIndex = PI32(ptr + 4),
                        methodIndex = PI32(ptr + 8)
                    }
                };
                genericMethodTable[i] = item;

                if ((uint)item.genericMethodIndex >= (uint)methodSpecs.Length)
                    continue;

                var spec = methodSpecs[item.genericMethodIndex];
                if (spec.methodDefinitionIndex < 0 ||
                    spec.classIndexIndex < -1 || spec.classIndexIndex >= genericInsts.Length ||
                    spec.methodIndexIndex < -1 || spec.methodIndexIndex >= genericInsts.Length)
                    continue;

                if (!methodDefinitionMethodSpecs.TryGetValue(spec.methodDefinitionIndex, out var list))
                {
                    list = new List<Il2CppMethodSpec>();
                    methodDefinitionMethodSpecs.Add(spec.methodDefinitionIndex, list);
                }
                list.Add(spec);

                if ((uint)item.indices.methodIndex < (uint)genericMethodPointers.Length)
                    methodSpecGenericMethodPointers[spec] = genericMethodPointers[item.indices.methodIndex];
            }

            metadataUsages = Array.Empty<ulong>();
        }
    }
}
