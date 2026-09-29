# Поиск полей для protected IL2CPP dump

!! я тут сука ни при чем это соляна вьебала 100 и делает такое говно описание.
Обновлено под 1.0.0


## 1. Protected metadata base

Ищи строку `global-metadata.dat` и xref на код, который загружает/инициализирует metadata. В этой сборке registration path подтверждается вызовом:

```text
sub_6365C4C -> sub_6331CF0(&off_B8CE740, &unk_B8CE7C0, ...)
```

После init runtime хранит указатели на registration blocks в:

```text
qword_C5728A8 -> CodeRegistration
qword_C5728B0 -> MetadataRegistration
```

Текущая база protected metadata:

```text
ProtectedMetadataVA = 0x1A9A580
```

Текущие registration roots:

```text
ProtectedCodeRegistration     = 0xB8CE740
ProtectedMetadataRegistration = 0xB8CE7C0
```

Быстрая проверка header-а:

```text
header + 0x34 -> imagesCount          = 476
header + 0xFC -> typeDefinitionsCount = 34466
header + 0xD8 -> genericContainersCount = 4041
```

Для type definitions также подтверждены:

```text
header + 0xF8 -> packed typeDefinitions size = 0x2B1FE4
header + 0xFC -> typeDefinitions count       = 34466
```

Как найти offsets после обновления:

1. Найти global metadata init и глобал `globalMetadataHeader`.
2. Найти consumer-функции, которые читают `[header + imm]`.
3. Отдельно определить `table offset`, `packed size`, `count`.
4. Проверять минимум по двум consumer-функциям.
5. Не переносить старый offset только потому, что рядом лежит похожее число.

В текущем binary подтверждены основные count/data поля:

```text
methods:            offset/count path -> +0x40 / +0x04
fields:             size/count        -> +0x138 / +0x5C
parameters:         size/count        -> +0x0B0 / +0x10C
events:             size/count        -> +0x114 / +0x150
images:             size/count        -> +0x160 / +0x34
genericContainers:  size/count        -> +0x12C / +0xD8
genericParameters:  size/count        -> +0x078 / +0xDC
nestedTypes:        size/count        -> +0x164 / +0x64
interfaces:         size/count        -> +0x09C / +0x44
vtableMethods:      size/count        -> +0x098 / +0x130
interfaceOffsets:   size/count        -> +0x0CC / +0x124
properties:         size/count        -> +0x00C / +0x08C
```

## 2. String literals

Критичные поля для полного `stringliteral.json` в текущей сборке:

```text
ProtectedStringLiteralCountField        = 0x000
ProtectedStringLiteralOffsetsField      = 0x06C
ProtectedStringLiteralDataField         = 0x0C4
ProtectedStringLiteralOffsetsCountField = 0x0D4
```

Проверочные значения:

```text
literalCount        = 28481
offsetsCount        = 28482
offsets table RVA   = 0x126B87C
literal data RVA    = 0x37BA38
```

То есть offsets содержит `count + 1` элементов:

```text
offset[i]
offset[i + 1]
length = offset[i + 1] - offset[i]
```

Указатель на bytes:

```text
metadataBase
+ *(uint32_t *)(header + 0x0C4)
+ offset[i]
```

После обновления версии ищи именно data-flow `literal index -> offsets[i/i+1] -> data base`, а не старый номер функции.

## 3. String heap, images и DLL names

String heap base в текущем header:

```text
header + 0x88 -> string heap RVA = 0x1287584
```

Images:

```text
header + 0x160 -> packed images size = 0x42F0
header + 0x034 -> images count       = 476
```

Имена image/module нужно сверять между metadata image definitions и `CodeRegistration.codeGenModules`.

Нормальная проверка:

```text
Assembly-CSharp.dll
UnityEngine*.dll
mscorlib.dll / System.Private.CoreLib-like core image
```

Для lookup удобно нормализовать оба варианта:

```text
Name.dll
Name
```

и использовать case-insensitive сравнение.

## 4. CodeRegistration

Текущий protected адрес:

```text
ProtectedCodeRegistration = 0xB8CE740
```

Проверенный protected layout:

```text
+0x00 interopData
+0x10 unresolvedInstanceCallPointers
+0x20 codeGenModulesCount             = 476
+0x28 invokerPointers
+0x30 codeGenModules
+0x38 invokerPointersCount            = 33522
+0x3C interopDataCount                = 1586
+0x40 genericMethodPointers
+0x48 genericMethodPointersCount      = 227255
+0x50 unresolvedVirtualCallPointers
+0x58 unresolvedStaticCallPointers
+0x60 unresolvedVirtualCallCount      = 8572
+0x68 genericAdjustorThunks
+0x70 reversePInvokeWrapperCount
+0x78 reversePInvokeWrappers
```

Что проверено consumer-кодом:

```text
CR + 0x20 / +0x30 -> codeGenModules count + pointer
CR + 0x28 / +0x38 -> invoker pointers + count
CR + 0x40 / +0x48 -> genericMethodPointers + count
CR + 0x00 / +0x3C -> interopData + count
CR + 0x50 / +0x60 -> unresolvedVirtual + count
CR + 0x70 / +0x78 -> reverse P/Invoke count + pointer
```

`genericMethodPointersCount = 227255` дополнительно подтверждается доменом индексов из `genericMethodTable`.

Как найти после обновления:

1. Найти registration init.
2. Найти count images и pointer на module array.
3. `codeGenModulesCount` должен совпадать с `imagesCount`.
4. Проверить несколько module pointers и их `.dll` names.
5. Для generic/invoker массивов проверить, что большая часть pointers ведёт в executable mapping.
6. Не считать любой соседний qword стандартным полем — protector переставляет поля.

## 5. Il2CppCodeGenModule

Protected `Il2CppCodeGenModule` в этой сборке имеет размер:

```text
0x88 bytes
```

Проверенный layout:

```text
+0x00 methodPointers
+0x08 methodPointerCount

+0x10 adjustorThunks
+0x80 adjustorThunkCount

+0x18 reversePInvokeWrapperCount
+0x38 reversePInvokeWrapperIndices

+0x20 invokerIndices

+0x28 rgctxsCount
+0x50 rgctxs

+0x48 rgctxRangesCount
+0x60 rgctxRanges

+0x78 moduleName
```

Важно:

```text
+0x88 / +0x90 / +0x98 НЕ являются полями этого CodeGenModule.
```

Это уже начало следующей соседней структуры в плотных массивах modules. Старые заметки, где RGCTX искался через `+0x88/+0x90/+0x98`, для этой версии неверны.

Проверка module struct:

1. `module + 0x78` -> null-terminated `.dll` name.
2. `module + 0x08` -> реалистичный method count.
3. `module + 0x00` -> method pointer array.
4. `+0x80/+0x10` -> adjustor thunk count/pointer.
5. `+0x48/+0x60` -> RGCTX ranges.
6. `+0x28/+0x50` -> RGCTX definitions.

Protected adjustor thunk entry, size `0x10`:

```text
+0x00 function pointer
+0x08 MethodDef token
```

Stock ожидает обратный смысл полей:

```text
+0x00 uint32 token (+ padding)
+0x08 function pointer
```

Protected reverse-P/Invoke tuple, size `0x18`:

```text
+0x00 genericMethodIndex
+0x04 index
+0x08 method
+0x10 token
```

Stock order отличается, поэтому запись нужно нормализовать.

## 6. MetadataRegistration

Текущий protected адрес:

```text
ProtectedMetadataRegistration = 0xB8CE7C0
```

Проверенный protected layout:

```text
+0x08 fieldOffsets
+0x10 genericClasses
+0x18 fieldOffsetsCount             = 34466
+0x1C typesCount                    = 100603
+0x20 genericMethodTableCount       = 228222
+0x28 methodSpecs
+0x30 typeDefinitionSizes
+0x38 typeDefinitionSizesCount      = 34466
+0x40 genericMethodTable
+0x48 genericInstsCount             = 29183
+0x50 genericInsts
+0x58 methodSpecsCount              = 282476
+0x68 types
+0x70 genericClassesCount           = 38212
```

Ключевая поправка относительно старых заметок:

```text
MR + 0x10 / +0x70 = GenericClass*[]
MR + 0x50 / +0x48 = GenericInst*[]
```

То есть это НЕ наоборот.

Проверки:

```text
fieldOffsetsCount          == typeDefinitionsCount == 34466
typeDefinitionSizesCount   == typeDefinitionsCount == 34466
typesCount                 == 100603
genericMethodTableCount    == 228222
methodSpecsCount           == 282476
genericInstsCount          == 29183
genericClassesCount        == 38212
```

`genericInsts` элементы имеют stock-подобный runtime layout:

```text
Il2CppGenericInst:
+0x00 type_argc
+0x08 type_argv
```

`genericClasses` элементы указывают на protected `Il2CppGenericClass`:

```text
+0x00 Il2CppType* type
+0x08 method_inst
+0x10 class_inst
+0x18 cached_class
```

## 7. MethodSpec и GenericMethodTable

### Protected Il2CppMethodSpec

Размер:

```text
0x0C
```

В protected binary порядок такой:

```text
+0x00 methodDefinitionIndex
+0x04 methodIndexIndex
+0x08 classIndexIndex
```

А stock Il2CppDumper ожидает:

```text
+0x00 methodDefinitionIndex
+0x04 classIndexIndex
+0x08 methodIndexIndex
```

То есть два последних `int32` обязательно нужно swap-нуть.

Это подтверждено по всем `282476` MethodSpec через generic-container ownership. Без swap StructGenerator получает неправильный `class_inst/method_inst` и может падать в:

```text
System.OverflowException: Array dimensions exceeded supported range
BinaryStream.ReadClassArray
StructGenerator.ParseType
```

### Protected GenericMethodTable entry

Размер:

```text
0x10
```

Protected order:

```text
+0x00 genericMethodIndex   -> MethodSpec index
+0x04 invokerIndex
+0x08 adjustorThunkIndex
+0x0C methodIndex          -> genericMethodPointers index
```

Stock order:

```text
+0x00 genericMethodIndex
+0x04 methodIndex
+0x08 invokerIndex
+0x0C adjustorThunkIndex
```

Проверка index domains:

```text
genericMethodIndex < 282476
methodIndex == -1 или methodIndex < 227255
invokerIndex == -1 или invokerIndex < 33522
```

## 8. Il2CppType и Il2CppGenericClass

Старый decode вида:

```text
type = (bits >> 18) & 0xFF
```

для этой protected сборки НЕВЕРЕН.

Protected `Il2CppType` здесь 16 байт и читается так:

```text
+0x01 byte  -> Il2CppTypeEnum type
+0x02 bit4  -> byref
+0x08 qword -> data
```

То есть:

```text
type  = *(uint8_t *)(type + 1)
byref = (*(uint8_t *)(type + 2) >> 4) & 1
data  = *(uint64_t *)(type + 8)
```

Для stock normalization `attrs/custom modifiers` нельзя угадывать из старой bit-схемы — в текущем rebuilder они выставляются безопасно в ноль, если нет подтверждённых данных.

Protected `Il2CppGenericClass`:

```text
+0x00 Il2CppType* type
+0x08 method_inst
+0x10 class_inst
+0x18 cached_class
```

Это важно для обхода `GENERICINST` и восстановления полного runtime type graph.

## 9. Nested types, interfaces, constraints и attributes

Старый вариант дампера занулял nested/interfaces/vtable/generic constraints. Для этой сборки это неверно.

Подтверждено:

```text
nestedTypes table field      = header + 0xF0
interfaces packed size/count = header + 0x9C / +0x44
generic constraints table    = header + 0x80
attributeDataRange           = header + 0x74
attributeData                = header + 0xA4
```

Проверочный результат rebuild:

```text
nested declaringType links = 9481
interfaces                 = 22494
generic constraints        = 1883
```

Attributes читаются через runtime path, где header offsets `+0x74` и `+0xA4` подтверждены consumer-функциями. Не оставлять `attributeData` / `attributeDataRange` пустыми без причины.

## 10. RGCTX

Protected module RGCTX fields:

```text
module + 0x28 -> rgctxsCount
module + 0x50 -> rgctxs
module + 0x48 -> rgctxRangesCount
module + 0x60 -> rgctxRanges
```

Protected range может иметь переставленный порядок. Для текущей сборки rebuilder определяет формат семантически и нормализует в stock:

```text
stock RGCTX range, size 0x0C:
+0x00 token
+0x04 start
+0x08 length
```

RGCTXData definitions проверяются как 16-байтные записи с допустимым kind.

Для обычного StructGenerator в текущем дампере method-level RGCTX ranges можно скрывать из normalized module view, не удаляя сами generic method mappings/pointers. Это защита от огромного `il2cpp.h`, а не потеря generic methods.

Проверка текущего rebuild:

```text
non-method RGCTX ranges kept = 1339
method ranges hidden         = 2134
raw method RGCTX items       = 912218
```

## 11. Stock-compatible output после normalization

После rebuild в текущем `libunity.so` stock registration blocks создаются по адресам:

```text
CodeRegistration     = 0xCFBA4F8
MetadataRegistration = 0xCFBA478
```

Проверенный итог:

```text
Metadata Version             = 31
runtime types                = 100603
genericMethodTable entries   = 228222
genericMethodPointers        = 227255
MethodSpecs                  = 282476
images/modules               = 476
```

Эти `0xCF...` адреса относятся только к пересобранному stock-compatible output. Их нельзя использовать как protected roots исходного `libunity.so`.

## 12. Что обязательно обновлять после новой версии

Сначала проверить:

```text
ProtectedMetadataVA
ProtectedCodeRegistration
ProtectedMetadataRegistration

ProtectedStringLiteralOffsetsField
ProtectedStringLiteralDataField
ProtectedStringLiteralCountField
ProtectedStringLiteralOffsetsCountField
```

Затем обязательно:

```text
CodeRegistration permutation
MetadataRegistration permutation
Il2CppCodeGenModule size/layout
MethodSpec field order
GenericMethodTable field order
Il2CppType protected representation
GenericClass class_inst/method_inst order
nestedTypes / interfaces / constraints
attributeData / attributeDataRange
RGCTXData ranges + definitions
```

Особенно не переносить между версиями на глаз:

```text
MR + 0x10 / +0x50 semantics
MethodSpec classIndexIndex / methodIndexIndex
CodeGenModule +0x80 и всё после него
Il2CppType bit layout
```

Именно эти места уже оказались отличающимися от предыдущих заметок.

## 13. Минимальный порядок проверки в IDA

```text
1. global-metadata.dat / loader -> protected metadata base
2. registration init -> CodeRegistration + MetadataRegistration
3. metadata header consumers -> table offsets/counts
4. string literal getter -> offsets/data/count fields
5. image definitions -> DLL names
6. CodeRegistration.codeGenModules -> module struct
7. moduleName + methodPointers -> подтвердить CodeGenModule stride
8. generic method resolution -> MethodSpec + GenericMethodTable
9. runtime type consumers -> Il2CppType + GenericClass
10. field resolver -> fieldOffsets
11. nested/interface/constraint consumers
12. attribute getter/parser -> attributeDataRange + attributeData
13. RGCTX consumers -> ranges/definitions
14. только после этого менять dumper/rebuilder
```

Для pointer-полей всегда проверять segment/data semantics:

```text
function pointers -> executable PT_LOAD / .text
strings           -> readable data / metadata
runtime arrays    -> mapped data/bss
metadata tables   -> metadataBase + RVA
```

Если count выглядит правдоподобно, но pointer ведёт в мусор — пара `pointer + count` определена неверно.

