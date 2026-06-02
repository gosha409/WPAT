
# Windows Persistence Audit Tool
Windows persistence audit tool based on persistence-info: https://persistence-info.github.io/


Скрипт собирает артефакты закрепления, обогащает их файловыми метаданными, оценивает риск, группирует результаты по механизмам и формирует HTML/CSV-отчёты для triage.

> Проект предназначен для defensive audit, incident response, hardening review и baseline-контроля. Скрипт ничего не создаёт, не изменяет и не удаляет.

---

## Возможности

- Проверка всех Windows persistence mechanisms из `persistence-info`.
- Read-only режим: только сбор и анализ.
- Группировка по конкретным механизмам:
  - `Task Scheduler`
  - `Windows Services`
  - `IFilter`
  - `Code Signing DLL`
  - `Print Monitor`
  - `Netsh extension DLL`
  - `Authentication Packages`
  - `Password Filter`
  - и другие.
- Отдельный CSV-файл на каждый механизм persistence.
- Общий CSV со всеми находками.
- Review queue для `Medium`, `High`, `Critical`.
- HTML-отчёт со спойлерами:
  - механизм persistence;
  - внутри механизма — градация по риску;
  - `Criticality logic` перед каждой категорией.
- Обогащение файлов:
  - `SHA256`
  - `Authenticode Signature`
  - `Signer`
  - `FileOwner`
  - `CreationTimeUtc`
  - `LastWriteTimeUtc`
  - `CompanyName`
  - `ProductName`
  - `OriginalFilename`
  - `FileDescription`
  - `ZoneId`
  - `WritableByNonAdmin`
- Контекстный resolver для относительных DLL/EXE:
  - `localspl.dll`
  - `tcpmon.dll`
  - `scecli`
  - `msv1_0`
  - `ifmon.dll`
  - и похожих значений из системных registry locations.
- Coverage-файл по всем механизмам из `persistence-info`.
- Более аккуратный scoring, чтобы не поднимать штатные Microsoft/System32 entries без дополнительных подозрительных признаков.

---

## Быстрый запуск

Запускать лучше из elevated PowerShell.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\persistence_audit_tool.ps1 -OutputDirectory C:\Temp\pi-audit
```

---

## Выходные файлы

После запуска в `C:\Temp\pi-audit` появятся raw-результаты и директория triage.

```text
C:\Temp\pi-audit\
  persistence-info-audit-<timestamp>.json
  persistence-info-audit-<timestamp>.csv
  persistence-info-audit-errors-<timestamp>.json

  triage-<timestamp>\
    persistence-info-triage-all.csv
    persistence-info-triage-reviewqueue.csv
    persistence-info-triage-dangerous.csv
    persistence-info-triage-summary.csv
    persistence-info-coverage.csv
    persistence-info-triage-highlighted.html

    categories\
      01_AMSI_Providers.csv
      02_Authentication_Packages.csv
      ...
      20_Windows_Services.csv
      21_Windows_Terminal_Profile.csv
```

### Основные файлы

| Файл | Назначение |
|---|---|
| `persistence-info-audit-*.csv` | Сырой inventory всех найденных артефактов |
| `persistence-info-audit-*.json` | JSON-версия raw inventory |
| `persistence-info-triage-all.csv` | Все находки с risk scoring и enrichment |
| `persistence-info-triage-reviewqueue.csv` | Очередь на ручную проверку: `Medium`, `High`, `Critical` |
| `persistence-info-triage-dangerous.csv` | Alias для совместимости, содержит те же review-строки |
| `persistence-info-triage-summary.csv` | Сводка по механизмам и verdict |
| `persistence-info-coverage.csv` | Покрытие механизмов из `persistence-info` |
| `persistence-info-triage-highlighted.html` | Основной HTML-отчёт |

---

## HTML-отчёт

HTML-отчёт рассчитан на быстрый ручной triage.

Внутри отчёта:

- summary;
- покрытие по всем persistence mechanisms;
- Разделение на уровни риска
  - `Critical`
  - `High`
  - `Medium`
  - `Low`
- перед каждой категорией есть описание `Логики оценки`;
- таблицы имеют горизонтальную прокрутку;
- ширину колонок можно менять мышкой.

---

## Risk scoring

Скрипт использует rule-based scoring. Он не пытается заменить EDR, SIEM или ручной анализ.

На risk влияют:

- критичность persistence mechanism;
- путь в user-writable location:
  - `AppData`
  - `Temp`
  - `Downloads`
  - `Desktop`
  - `Public`
  - `ProgramData`
- unsigned или invalid signature;
- нестандартный signer;
- LOLBin/script host:
  - `powershell.exe`
  - `pwsh.exe`
  - `cmd.exe /c`
  - `mshta.exe`
  - `rundll32.exe`
  - `regsvr32.exe`
  - `wscript.exe`
  - `cscript.exe`
  - `certutil.exe`
  - `bitsadmin.exe`
- признаки script/network retrieval:
  - `-enc`
  - `IEX`
  - `DownloadString`
  - `FromBase64String`
  - `Invoke-WebRequest`
  - `http://`
  - `https://`
- DLL/EXE вне ожидаемых системных директорий;
- writable ACL на исполняемый файл;
- hidden task при наличии дополнительного подозрительного сигнала.

Скрипт также снижает шум для штатных signed Microsoft components из:

```text
C:\Windows\System32
C:\Windows\SysWOW64
C:\Windows\WinSxS
C:\ProgramData\Microsoft\Windows Defender
```

Это важно, потому что многие persistence locations легитимно используются самой Windows.

---

## Verdict

| Verdict | Значение |
|---|---|
| `Critical` | Высокий приоритет расследования. Есть несколько сильных подозрительных признаков. |
| `High` | Требует приоритетной проверки. Обычно есть подозрительный путь, signer, script host или нестандартный механизм. |
| `Medium` | Часто это нестандартная, но не обязательно вредоносная конфигурация. |
| `Low` | Обычно baseline/inventory.|

---

## Поддерживаемые persistence locations

Скрипт реализует read-only checks для всех механизмов из `persistence-info`:

- `.chm helper DLL`
- `.NET Startup Hooks`
- `AeDebug`
- `AMSI Providers`
- `Authentication Packages`
- `Autodial DLL`
- `Boot Verification Program`
- `Code Signing DLL`
- `Credential Manager DLL`
- `Desired State Configuration`
- `Disk Cleanup Handler`
- `Explorer tools`
- `File Extension Hijacking`
- `Filter Handlers for Windows Search`
- `GPO Client-side Extension`
- `hhctrl.ocx`
- `HKCU cmd.exe AutoRun`
- `HKCU Load`
- `HKCU Run and RunOnce registry keys`
- `IFilter`
- `Image File Execution Options key`
- `Keyboard Shortcut`
- `LSA Extension`
- `Monitoring Silent Process Exit`
- `MPNotify`
- `Natural Language Development Platform 6 DLLs`
- `Netsh extension DLL`
- `Password Filter`
- `PowerShell Profiles`
- `Print Monitor`
- `RDP WDS Startup Programs`
- `Recycle Bin COM Extension Handler`
- `Screen Saver`
- `ServerLevelPluginDll`
- `Startup Folder`
- `Task Scheduler`
- `TelemetryController`
- `TS Initial Program`
- `User Init Mpr Logon Script`
- `WER Debugger`
- `Windows Platform Binary Table`
- `Windows Services`
- `Windows Terminal Profile`
- `Winlogon Notification Package`

---

## Ограничения

- Offline user hives не монтируются автоматически.
- Некоторые механизмы, например WPBT, проверяются best-effort из Windows userland.
- Risk scoring является эвристикой.
- Скрипт не удаляет persistence и не выполняет remediation.

---

## Безопасность

Скрипт выполняет только read-only операции:

- чтение registry;
- чтение scheduled tasks;
- чтение service configuration;
- чтение файловых метаданных;
- проверка подписи;
- расчёт SHA256;
- экспорт локальных отчётов.

Он не создаёт, не изменяет и не удаляет persistence entries.

---

## Disclaimer

Этот проект предназначен для защитного аудита и анализа конфигурации Windows.  
Любые результаты scoring требуют ручной проверки. Наличие записи в review queue не означает компрометацию, а отсутствие high-risk findings не гарантирует отсутствие persistence.
