using System;

namespace Il2CppDumper
{
    public class Il2CppGlobalMetadataHeader
    {
        public uint sanity;
        public int version;
        public uint stringLiteralOffset; 
        public int stringLiteralSize;
        public uint stringLiteralDataOffset;
        public int stringLiteralDataSize;
        public uint stringOffset; 
        public int stringSize;
        public uint eventsOffset; 
        public int eventsSize;
        public uint propertiesOffset; 
        public int propertiesSize;
        public uint methodsOffset; 
        public int methodsSize;
        public uint parameterDefaultValuesOffset; 
        public int parameterDefaultValuesSize;
        public uint fieldDefaultValuesOffset; 
        public int fieldDefaultValuesSize;
        public uint fieldAndParameterDefaultValueDataOffset; 
        public int fieldAndParameterDefaultValueDataSize;
        public int fieldMarshaledSizesOffset; 
        public int fieldMarshaledSizesSize;
        public uint parametersOffset; 
        public int parametersSize;
        public uint fieldsOffset; 
        public int fieldsSize;
        public uint genericParametersOffset; 
        public int genericParametersSize;
        public uint genericParameterConstraintsOffset; 
        public int genericParameterConstraintsSize;
        public uint genericContainersOffset; 
        public int genericContainersSize;
        public uint nestedTypesOffset; 
        public int nestedTypesSize;
        public uint interfacesOffset; 
        public int interfacesSize;
        public uint vtableMethodsOffset; 
        public int vtableMethodsSize;
        public int interfaceOffsetsOffset; 
        public int interfaceOffsetsSize;
        public uint typeDefinitionsOffset; 
        public int typeDefinitionsSize;
        [Version(Max = 24.1)]
        public uint rgctxEntriesOffset; 
        [Version(Max = 24.1)]
        public int rgctxEntriesCount;
        public uint imagesOffset; 
        public int imagesSize;
        public uint assembliesOffset; 
        public int assembliesSize;
        [Version(Min = 19, Max = 24.5)]
        public uint metadataUsageListsOffset; 
        [Version(Min = 19, Max = 24.5)]
        public int metadataUsageListsCount;
        [Version(Min = 19, Max = 24.5)]
        public uint metadataUsagePairsOffset; 
        [Version(Min = 19, Max = 24.5)]
        public int metadataUsagePairsCount;
        [Version(Min = 19)]
        public uint fieldRefsOffset; 
        [Version(Min = 19)]
        public int fieldRefsSize;
        [Version(Min = 20)]
        public int referencedAssembliesOffset; 
        [Version(Min = 20)]
        public int referencedAssembliesSize;
        [Version(Min = 21, Max = 27.2)]
        public uint attributesInfoOffset; 
        [Version(Min = 21, Max = 27.2)]
        public int attributesInfoCount;
        [Version(Min = 21, Max = 27.2)]
        public uint attributeTypesOffset; 
        [Version(Min = 21, Max = 27.2)]
        public int attributeTypesCount;
        [Version(Min = 29)]
        public uint attributeDataOffset;
        [Version(Min = 29)]
        public int attributeDataSize;
        [Version(Min = 29)]
        public uint attributeDataRangeOffset;
        [Version(Min = 29)]
        public int attributeDataRangeSize;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesOffset; 
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesSize;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesOffset; 
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesSize;
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesOffset; 
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesSize;
        [Version(Min = 27)]
        public int windowsRuntimeStringsOffset; 
        [Version(Min = 27)]
        public int windowsRuntimeStringsSize;
        [Version(Min = 24)]
        public int exportedTypeDefinitionsOffset; 
        [Version(Min = 24)]
        public int exportedTypeDefinitionsSize;
    }

    public class Il2CppAssemblyDefinition
    {
        public int imageIndex;
        [Version(Min = 24.1)]
        public uint token;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 20)]
        public int referencedAssemblyStart;
        [Version(Min = 20)]
        public int referencedAssemblyCount;
        public Il2CppAssemblyNameDefinition aname;
    }

    public class Il2CppAssemblyNameDefinition
    {
        public uint nameIndex;
        public uint cultureIndex;
        [Version(Max = 24.3)]
        public int hashValueIndex;
        public uint publicKeyIndex;
        public uint hash_alg;
        public int hash_len;
        public uint flags;
        public int major;
        public int minor;
        public int build;
        public int revision;
        [ArrayLength(Length = 8)]
        public byte[] public_key_token;
    }

    public class Il2CppImageDefinition
    {
        public uint nameIndex;
        public int assemblyIndex;

        public int typeStart;
        public uint typeCount;

        [Version(Min = 24)]
        public int exportedTypeStart;
        [Version(Min = 24)]
        public uint exportedTypeCount;

        public int entryPointIndex;
        [Version(Min = 19)]
        public uint token;

        [Version(Min = 24.1)]
        public int customAttributeStart;
        [Version(Min = 24.1)]
        public uint customAttributeCount;
    }

    public class Il2CppTypeDefinition
    {
        public uint nameIndex;
        public uint namespaceIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int byvalTypeIndex;
        [Version(Max = 24.5)]
        public int byrefTypeIndex;

        public int declaringTypeIndex;
        public int parentIndex;
        public int elementTypeIndex; 

        [Version(Max = 24.1)]
        public int rgctxStartIndex;
        [Version(Max = 24.1)]
        public int rgctxCount;

        public int genericContainerIndex;

        [Version(Max = 22)]
        public int delegateWrapperFromManagedToNativeIndex;
        [Version(Max = 22)]
        public int marshalingFunctionsIndex;
        [Version(Min = 21, Max = 22)]
        public int ccwFunctionIndex;
        [Version(Min = 21, Max = 22)]
        public int guidIndex;

        public uint flags;

        public int fieldStart;
        public int methodStart;
        public int eventStart;
        public int propertyStart;
        public int nestedTypesStart;
        public int interfacesStart;
        public int vtableStart;
        public int interfaceOffsetsStart;

        public ushort method_count;
        public ushort property_count;
        public ushort field_count;
        public ushort event_count;
        public ushort nested_type_count;
        public ushort vtable_count;
        public ushort interfaces_count;
        public ushort interface_offsets_count;

        
        
        
        
        
        
        
        
        
        
        
        public uint bitfield;
        [Version(Min = 19)]
        public uint token;

        public bool IsValueType => (bitfield & 0x1) == 1;
        public bool IsEnum => ((bitfield >> 1) & 0x1) == 1;
    }

    public class Il2CppMethodDefinition
    {
        public uint nameIndex;
        public int declaringType;
        public int returnType;
        [Version(Min = 31)]
        public int returnParameterToken;
        public int parameterStart;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int genericContainerIndex;
        [Version(Max = 24.1)]
        public int methodIndex;
        [Version(Max = 24.1)]
        public int invokerIndex;
        [Version(Max = 24.1)]
        public int delegateWrapperIndex;
        [Version(Max = 24.1)]
        public int rgctxStartIndex;
        [Version(Max = 24.1)]
        public int rgctxCount;
        public uint token;
        public ushort flags;
        public ushort iflags;
        public ushort slot;
        public ushort parameterCount;
    }

    public class Il2CppParameterDefinition
    {
        public uint nameIndex;
        public uint token;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int typeIndex;
    }

    public class Il2CppFieldDefinition
    {
        public uint nameIndex;
        public int typeIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppFieldDefaultValue
    {
        public int fieldIndex;
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppPropertyDefinition
    {
        public uint nameIndex;
        public int get;
        public int set;
        public uint attrs;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppCustomAttributeTypeRange
    {
        [Version(Min = 24.1)]
        public uint token;
        public int start;
        public int count;
    }

    public class Il2CppMetadataUsageList
    {
        public uint start;
        public uint count;
    }

    public class Il2CppMetadataUsagePair
    {
        public uint destinationIndex;
        public uint encodedSourceIndex;
    }

    public class Il2CppStringLiteral
    {
        public uint length;
        public int dataIndex;
    }

    public class Il2CppParameterDefaultValue
    {
        public int parameterIndex;
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppEventDefinition
    {
        public uint nameIndex;
        public int typeIndex;
        public int add;
        public int remove;
        public int raise;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppGenericContainer
    {
        
        public int ownerIndex; 
        public int type_argc;
        
        public int is_method;
        
        public int genericParameterStart;
    }

    public class Il2CppFieldRef
    {
        public int typeIndex;
        public int fieldIndex; 
    }

    public class Il2CppGenericParameter
    {
        public int ownerIndex;  
        public uint nameIndex;
        public short constraintsStart;
        public short constraintsCount;
        public ushort num;
        public ushort flags;
    }

    public enum Il2CppRGCTXDataType
    {
        IL2CPP_RGCTX_DATA_INVALID,
        IL2CPP_RGCTX_DATA_TYPE,
        IL2CPP_RGCTX_DATA_CLASS,
        IL2CPP_RGCTX_DATA_METHOD,
        IL2CPP_RGCTX_DATA_ARRAY,
        IL2CPP_RGCTX_DATA_CONSTRAINED,
    }

    public class Il2CppRGCTXDefinitionData
    {
        public int rgctxDataDummy;
        public int methodIndex => rgctxDataDummy;
        public int typeIndex => rgctxDataDummy;
    }

    public class Il2CppRGCTXDefinition
    {
        public Il2CppRGCTXDataType type => type_post29 == 0 ? (Il2CppRGCTXDataType)type_pre29 : (Il2CppRGCTXDataType)type_post29;
        [Version(Max = 27.1)]
        public int type_pre29;
        [Version(Min = 29)]
        public ulong type_post29;
        [Version(Max = 27.1)]
        public Il2CppRGCTXDefinitionData data;
        [Version(Min = 27.2)]
        public ulong _data;
    }

    public enum Il2CppMetadataUsage
    {
        kIl2CppMetadataUsageInvalid,
        kIl2CppMetadataUsageTypeInfo,
        kIl2CppMetadataUsageIl2CppType,
        kIl2CppMetadataUsageMethodDef,
        kIl2CppMetadataUsageFieldInfo,
        kIl2CppMetadataUsageStringLiteral,
        kIl2CppMetadataUsageMethodRef,
    };

    public class Il2CppCustomAttributeDataRange
    {
        public uint token;
        public uint startOffset;
    }
}
