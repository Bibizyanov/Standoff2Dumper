
# Standoff 2 Dumper
<img width="1280" height="720" alt="image" src="https://github.com/user-attachments/assets/68d4b979-4eb9-4086-9cec-9672a3c2c591" />

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

<img width="1688" height="932" alt="image" src="https://github.com/user-attachments/assets/ceeae40d-53ec-44bb-aa69-6069fad50d59" />
