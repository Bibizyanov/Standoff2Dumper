# Standoff 2 Dumper

```bat
Il2CppDumper.exe libunity.so
```

На первом запуске вводится только имя. Установка сама регистрируется в dumper API и получает свой ID.

```text
name: bibizyanov
id: AXD-...
```

Дальше ничего вводить не нужно. Перед каждым дампом клиент получает короткую подписанную сессию для конкретного `libunity.so`.

### Output

```text
dump.cs
stringliteral.json
script.json
il2cpp.h
DLLs
wm.json
```

## Credits

Project Website: **axent.cc**

Developed & Supported by Bibizyanov, Alogen.
