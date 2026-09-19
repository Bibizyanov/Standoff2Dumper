# Поиск полей для protected IL2CPP dump


Сделан тутор от гптшки, я тут нипричем!


## 1. Protected metadata base

Ищи строку `global-metadata.dat` и xref на код, который загружает/декодирует metadata. В этой сборке цепочка приводит к `initialize_protected_metadata` по `0x639C940`.

В `initialize_protected_metadata` после вызова loader-а возвращаемый указатель сохраняется в глобал и дальше из header читаются count-поля. Это и есть base protected metadata header.

Текущая база:

```text
ProtectedMetadataVA = 0x1B60480
```

Быстрая проверка:

```text
header + 0x14C -> imagesCount          = 463
header + 0x154 -> typeDefinitionsCount = 33762
header + 0x100 -> genericContainersCount = 4021
```

Как найти offsets после обновления:

1. Открыть `initialize_protected_metadata`.
2. Найти `LDR W?, [X19,#imm]` или аналогичные чтения из указателя на header.
3. Посмотреть, куда сохраняется значение и какой consumer потом использует его как count.
4. Подтвердить count по соседним metadata-функциям: image/type/method definition getters.
5. Не переносить offset только по похожему числу: проверять минимум двумя consumer-функциями.

В текущем binary:

```text
initialize_protected_metadata:
[header + 0x14C] -> images count
[header + 0x094] -> еще один metadata count, используемый при init
[header + 0x154] -> typeDefinitions count
[header + 0x100] -> genericContainers count
[header + 0x0D0] -> еще один protected table count
[header + 0x124] -> count для отдельной runtime table
```

## 2. String literals

Критичные поля для полного `stringliteral.json`:

```text
ProtectedStringLiteralOffsetsField      = 0x160
ProtectedStringLiteralDataField         = 0x138
ProtectedStringLiteralCountField        = 0x0FC
ProtectedStringLiteralOffsetsCountField = 0x044
```

Как их найти:

1. Найти функцию, которая создаёт managed string из metadata. В этой сборке путь проходит через `sub_639CBA8`.
2. В ветке string-literal она получает индекс literal.
3. Затем берётся таблица offsets:

```text
header + 0x160
```

4. Для literal `i` читаются два соседних offset-а:

```text
offset[i]
offset[i + 1]
```

5. Длина literal определяется как:

```text
offset[i + 1] - offset[i]
```

6. Данные начинаются от:

```text
metadataBase + *(int32_t *)(header + 0x138)
```

7. Указатель на UTF-8 bytes для literal `i`:

```text
metadataBase
+ *(int32_t *)(header + 0x138)
+ offset[i]
```

В текущем binary это видно в `sub_639CBA8`: сначала вычисляется адрес пары offsets через `header + 0x160`, затем bytes берутся через `header + 0x138`.

Для обновления версии ищи именно этот data-flow, а не сигнатуру конкретной функции.

## 3. Images и DLL names

DLL/image names лучше восстанавливать через image definitions, а не искать строки `.dll` отдельно.

Текущая consumer-функция:

```text
metadata_get_image_definition = 0x639D37C
```

Она вычисляет запись image definition как:

```text
metadataBase
+ *(int32_t *)(header + 0x0BC)
+ imageStride * imageIndex
```

где stride выводится из соседних header-полей/count.

Имя image затем разрешается через string table base:

```text
metadataBase + *(int32_t *)(header + 0x150) + nameIndex
```

Проверка правильности: получаются реальные имена вроде:

```text
Assembly-CSharp.dll
UnityEngine.dll
Axlebolt.Standoff.*.dll
```

Если дампер находит images, но не codegen modules, нормализовать ключи в двух вариантах:

```text
Name.dll
Name
```

и использовать case-insensitive lookup.

## 4. CodeRegistration

Текущий адрес:

```text
ProtectedCodeRegistration = 0xB7C32E0
```

Проверочные поля:

```text
+0x44 codeGenModulesCount          = 463
+0x54 invokerPointersCount         = 33045
+0x58 genericMethodPointersCount   = 224501
+0x50 unresolvedVirtualCallCount   = 8399
```

Текущий layout, который использует `ProtectedLayout.cs`:

```text
+0x00 unresolvedVirtualCallPointers
+0x08 reversePInvokeWrappers
+0x10 unresolvedInstanceCallPointers
+0x18 unresolvedStaticCallPointers
+0x28 invokerPointers
+0x30 codeGenModules
+0x40 interopDataCount
+0x44 codeGenModulesCount
+0x48 genericAdjustorThunks
+0x50 unresolvedVirtualCallCount
+0x54 invokerPointersCount
+0x58 genericMethodPointersCount
+0x60 interopData
+0x68 reversePInvokeWrapperCount
+0x70 genericMethodPointers
```

Как найти после обновления:

1. Найти IL2CPP registration/init path.
2. Найти массив codegen module pointers.
3. Кандидат на `codeGenModulesCount` должен совпасть с `imagesCount` или быть очень близок по смыслу; в этой сборке оба равны 463.
4. Указатель рядом должен вести в массив 64-bit pointers.
5. Каждый element массива должен вести на структуру module.
6. В структуре module найти указатель на имя и подтвердить чтением нескольких `.dll` names.
7. После этого размечать остальные поля по consumer-функциям, а не по позиции в старой версии.

## 5. Il2CppCodeGenModule

Текущий protected layout:

```text
+0x08 methodPointerCount
+0x18 rgctxsCount
+0x20 adjustorThunks
+0x30 methodPointers
+0x38 rgctxRanges
+0x40 reversePInvokeWrapperCount
+0x58 rgctxRangesCount
+0x60 invokerIndices
+0x68 adjustorThunkCount
+0x70 reversePInvokeWrapperIndices
+0x78 rgctxs
+0x80 moduleName
```

Как проверить module struct:

1. Взять один pointer из `CodeRegistration.codeGenModules`.
2. `module + 0x80` должен быть pointer на null-terminated DLL name.
3. `module + 0x08` должен быть реалистичным method count.
4. `module + 0x30` должен указывать на массив executable pointers либо runtime-relocated entries.
5. Для нескольких разных modules структура должна интерпретироваться одинаково.

Если `methodPointers` попадают в `.bss`, offline dump может видеть нули до runtime init. Это не означает, что module layout неверен.

## 6. MetadataRegistration

Текущий адрес:

```text
ProtectedMetadataRegistration = 0xB7C3358
```

Проверка:

```text
+0x00 genericMethodTableCount = 225450
+0x20 genericInstsCount       = 28847
+0x30 typesCount              = 98641
+0x40 methodSpecsCount        = 278565
+0x58 genericClassesCount     = 37557
```

Текущий layout:

```text
+0x00 genericMethodTableCount
+0x04 fieldOffsetsCount
+0x08 genericClasses
+0x18 genericInsts
+0x20 genericInstsCount
+0x28 typeDefinitionsSizes
+0x30 typesCount
+0x34 typeDefinitionsSizesCount
+0x40 methodSpecsCount
+0x48 types
+0x50 methodSpecs
+0x58 genericClassesCount
+0x60 genericMethodTable
+0x68 fieldOffsets
```

Как найти:

1. От registration function проследить второй большой static block рядом с CodeRegistration.
2. Найти `types` через consumer, который индексирует массив pointer-ов на `Il2CppType`.
3. `typesCount` должен согласовываться с количеством доступных type entries.
4. Найти `methodSpecs` через generic-method resolution path.
5. Найти `genericMethodTable` через код, который связывает method spec с generic method pointer/invoker.
6. Найти `fieldOffsets` через код, который возвращает runtime field offset для type/field.
7. После идентификации pointer-а и count-а проверить оба как пару.

## 7. MethodSpec и GenericMethodTable

Текущий layout:

```text
Il2CppMethodSpec, size 0x0C:
+0x00 classIndexIndex
+0x04 methodIndexIndex
+0x08 methodDefinitionIndex

GenericMethodTable entry, size 0x10:
+0x00 adjustorThunkIndex
+0x04 invokerIndex
+0x08 methodPointerIndex
+0x0C methodSpecIndex
```

Проверка:

```text
methodSpecIndex < methodSpecsCount
methodDefinitionIndex >= 0
classIndexIndex == -1 или < genericInstsCount
methodIndexIndex == -1 или < genericInstsCount
methodPointerIndex < genericMethodPointersCount
```

Если эти ограничения массово не выполняются, layout или stride неверный.

## 8. Il2CppType bits

Текущий decode:

```text
attrs    = bits & 0xFFFF
byref    = (bits >> 17) & 1
type     = (bits >> 18) & 0xFF
num_mods = (bits >> 26) & 0x1F
pinned   = (bits >> 31) & 1
```

Тип определяется по `type` после сдвига на 18.

## 9. Что обязательно обновлять после новой версии

Сначала проверить только:

```text
ProtectedMetadataVA
ProtectedCodeRegistration
ProtectedMetadataRegistration
ProtectedStringLiteralOffsetsField
ProtectedStringLiteralDataField
ProtectedStringLiteralCountField
ProtectedStringLiteralOffsetsCountField
```

Если dump всё ещё некорректный, затем проверять:

```text
CodeRegistration layout
MetadataRegistration layout
Il2CppCodeGenModule layout
image definition stride/fields
MethodSpec layout
GenericMethodTable layout
Il2CppType bit layout
```

## 10. Минимальный порядок проверки в IDA

```text
1. global-metadata.dat -> loader -> protected metadata base
2. initialize_protected_metadata -> header counts
3. string creation path -> string literal offsets/data
4. metadata_get_image_definition -> images/DLL names
5. registration init -> CodeRegistration
6. codeGenModules array -> Il2CppCodeGenModule fields
7. generic method resolution -> MetadataRegistration/method specs
8. field offset resolver -> fieldOffsets
9. проверить counts и pointer ranges
10. только после этого менять config/layout в dumper
```

Для pointer-полей обязательно проверять, что адрес попадает в ожидаемый segment:

```text
code pointers  -> .text / executable mapping
string/data    -> .rodata / metadata mapping
runtime arrays -> .data/.bss или mapped runtime memory
```

Если count выглядит правдоподобно, но pointer ведёт в мусор, пара `pointer + count` определена неверно.
