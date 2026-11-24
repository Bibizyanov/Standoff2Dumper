# Standoff2Dumper 

Работает через стандартный Il2CppDumper: реконструктор создаёт `global-metadata.dat` и нормализованный `libunity.so` в папке `.metadata`, затем оригинальный C#-движок генерирует `dump.cs`, `script.json`, `il2cpp.h` и `DummyDll`.

Адреса и раскладки в конфиге не задаются — `autoprofile.py` восстанавливает их из самого `libunity.so` при каждом запуске:

- корни через хрефы: строка `global-metadata.dat` → `GlobalMetadata::Initialize` → загрузчик метадаты; глобалы `s_Il2CppCodeRegistration`/`s_Il2CppMetadataRegistration` → цепочка вызовов `il2cpp_codegen_register` → CodeRegistration и MetadataRegistration;
- из кода `Initialize`/`ProcessIl2CppTypeDefinitions`: поля header для TypeDefinition/GenericParameter, `types`/`typesCount` в MetadataRegistration, битовое поле kind в Il2CppType;
- перемешанный header раскладывается тайлингом offset/size-полей, секции опознаются по содержимому;
- перестановки полей во всех записях метадаты, в CodeRegistration/MetadataRegistration/CodeGenModule и вспомогательных runtime-структурах решаются по семантике данных.

Восстановленный профиль сохраняется в `.metadata/profile.json`.

Запуск после сборки проекта:

```powershell
Il2CppDumper.exe "C:\path	o\libunity.so" "C:\path	o\dump"
```

Только профиль, без дампа:

```powershell
python protected_metadata.py "C:\path	o\libunity.so" --profile-only
```

Требуется Python 3.10+ с `numpy`. Повторное выполнение использует кэш только при неизменных входном файле и скриптах. Исходный `libunity.so` не перезаписывается.

Тесты: `python -m pytest tests/test_autoprofile.py` (интеграционный тест на реальных либах: переменная `SO2_LIBS` со списком путей через `;`).
