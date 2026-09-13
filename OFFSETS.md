# Поиск адресов
чатгпт все тут расписал для ваших агентов крч.
## Metadata base

Найти инициализацию metadata. Нужен адрес начала protected metadata header. В текущей сборке `0x1B60480`.

Проверка header:

```text
+0x14C imagesCount = 463
+0x154 typeDefinitionsCount = 33762
+0x100 genericContainersCount = 4021
```

## CodeRegistration

Найти функцию регистрации IL2CPP и проследить первый статический registration block. Текущий адрес `0xB7C32E0`.

Проверочные поля:

```text
+0x44 codeGenModulesCount = 463
+0x54 invokerPointersCount = 33045
+0x58 genericMethodPointersCount = 224501
+0x50 unresolvedCallCount = 8399
```

Если counts не совпали, адрес неверный.

## MetadataRegistration

В той же цепочке найти второй registration block. Текущий адрес `0xB7C3358`.

Проверка:

```text
+0x00 genericMethodTableCount = 225450
+0x20 genericInstsCount = 28847
+0x30 typesCount = 98641
+0x40 methodSpecsCount = 278565
+0x58 genericClassesCount = 37557
```

## Что менять после обновления

Обычно достаточно обновить три адреса в `config.json`. Если проверки counts не сходятся, изменился layout. Тогда заново проверить offsets через xrefs/consumer-функции.

Критичные layouts текущей версии:

```text
MethodSpec: +0 classIndexIndex, +4 methodIndexIndex, +8 methodDefinitionIndex
GenericMethodTable: +0 adjustor, +4 invoker, +8 methodPointerIndex, +12 methodSpecIndex
Il2CppType kind: (bits >> 18) & 0xFF
Il2CppType byref: bit 17
Il2CppType num_mods: bits 26..30
```

`methodPointers`, которые указывают в `.bss`, появляются только после runtime init. Offline dumper оставляет такие entries нулевыми.
