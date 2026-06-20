# Audit-Licensing — Microsoft License Compliance Auditor

**Skrypt audytu licencji Microsoft Windows i Office |  Microsoft Windows & Office license audit script**

[PL](#polski) | [EN](#english)

---

## Polski

### Cel

`Audit-Licensing.ps1` to narzędzie do audytu zgodności licencyjnej Microsoft Windows i Office. Wykrywa zarówno legalne licencje (Retail, OEM, Volume), jak i fałszywe aktywacje narzędziami typu MAS (Microsoft Activation Scripts), KMSpico, HWID, Ohook, TSforge i pokrewnymi.

**Skrypt NIE modyfikuje systemu** — tylko odczytuje stan. Nie naprawia, nie aktywuje, nie usuwa.

### Wymagania

- Windows 10/11 (x64)
- PowerShell 5.1+ jako **Administrator**
- Windows Defender włączony (dla pełnego pokrycia AMSI)
- PowerShell Operational log włączony (dla detekcji skryptów aktywatorów)

### Szybki start

```powershell
# Pełny audyt (tryb tekstowy)
.\Audit-Licensing.ps1

# Wyjście JSON (do integracji z systemami monitoringu)
.\Audit-Licensing.ps1 -AsJson

# Zapis do pliku
.\Audit-Licensing.ps1 -AsJson | Out-File -FilePath audit_result.json -Encoding utf8

# Tryb debug — pokazuje szczegóły pominiętych kluczy rejestru i błędów niekrytycznych
.\Audit-Licensing.ps1 -Debug
```

### Przełączniki

| Przełącznik | Działanie |
|-------------|-----------|
| `-AsJson` | Wyjście w formacie JSON (bez kolorów konsoli). Zwraca obiekt z polami: `RiskLevel`, `WindowsLicenses`, `OfficeLicenses`, `Office365Signals`, `Office365Identity`, `Findings[]`, `Disclaimer`. |
| `-Debug` | Wbudowany przełącznik PowerShell — pokazuje komunikaty `Write-Debug` (pominięte klucze rejestru, błędy odczytu ADS/ACL, niekrytyczne wyjątki). |

### Architektura wykrywania

Skrypt działa w **trzech warstwach**, od najpewniejszych sygnałów do poszlak:

#### Warstwa 1: Twarde dowody (High/Critical)

| ID Findingu | Metoda aktywacji | Co wykrywa |
|-------------|-----------------|------------|
| `HWID_GENUINE_TICKET` | MAS HWID | Pozostałość `GenuineTicket.xml` w `ClipSVC\GenuineTicket\` — plik wstrzyknięty przez ClipSVC przy aktywacji HWID. Normalnie ClipSVC sprząta go po sobie. |
| `OHOOK_FILE_PRESENT` | MAS Ohook | `sppcs.dll` w `System32` lub `SysWOW64` — biblioteka hookująca SPP dla Office. |
| `MAS_OHOOK_REGISTRY` | MAS Ohook | `TimeOfLastHeartbeatFailure = 2040-01-01T00:00:00Z` w `HKCU\...\Office\Licensing\Resiliency` — wartość tłumiąca baner licencyjny Office. |
| `MAS_ONLINE_KMS_DIR` | MAS Online KMS | Katalog `C:\Program Files\Activation-Renewal\` ze skryptami odnowienia aktywacji. |
| `MAS_ONLINE_KMS_TASK` | MAS Online KMS | Zaplanowane zadanie `\Activation-Renewal` (cykliczne odświeżanie KMS). |
| `TSFORGE_FILE_PRESENT` | MAS TSforge | `sppc.dll` / `sppcext.dll` z nieprawidłowym podpisem cyfrowym (DLL hooki Windows SPP). |
| `SPP_STORE_ACL_RELAXED` | MAS HWID | Nadpisane uprawnienia NTFS na katalogu `spp\store\2.0` — dostęp do zapisu poza SYSTEM/TrustedInstaller. |
| `SPP_FILE_ACL_RELAXED` | MAS HWID | Nadpisane ACL na `tokens.dat` / `data.dat` / `cache.dat`. |
| `SPP_FILE_ADS_PRESENT` | MAS HWID | Alternate Data Streams na plikach SPP store — technika ukrywania ładunków w strumieniach NTFS. |
| `SPP_BINARY_INVALID_SIGNATURE` | podmiana binariów | Plik `spp*.dll` / `spp*.exe` z nieważnym podpisem Authenticode. |
| `SPP_BINARY_UNEXPECTED_SIGNER` | podmiana binariów | Plik SPP podpisany przez nie-Microsoft (np. fałszywy certyfikat). |
| `IFEO_DEBUGGER` | Ohook/podmiana | `Debugger` w IFEO dla `osppsvc.exe` / `sppsvc.exe` — przechwytywanie procesów licencyjnych. |
| `IFEO_VERIFIER_DLLS` | Ohook/podmiana | `VerifierDlls` w IFEO — wstrzykiwanie DLL do procesów SPP. |
| `KMS_LOCALHOST` | KMS emulator | KMS host ustawiony na `localhost` / `127.0.0.1` — lokalny emulator KMS. |
| `KMS_ARTIFACT_FOUND` | KMS aktywatory | Pozostałości w `ProgramData`: `KMS*`, `KMSAuto*`, `KMS_VL_ALL*`, kopie `SppExtComObj*`. |
| `AMSI_ACTIVATOR_DETECTION` | dowolny | Windows Defender / AMSI przechwycił skrypt aktywatora po treści (Event ID 1116/1117). |
| `POWERSHELL_LOG_ACTIVATOR` | dowolny | PowerShell Operational log zawiera wzorzec behawioralny aktywatora (Event ID 4103/4104): `slmgr /ipk`, `ClipSVC`, `GenuineTicket`, `tokens.dat`, `sppc.dll` itp. |

#### Warstwa 2: Silne poszlaki (Medium)

| ID Findingu | Co wykrywa |
|-------------|------------|
| `SPP_TOKENS_MOD_MID_SESSION` | `tokens.dat` zmodyfikowany podczas bieżącej sesji (bez restartu) — charakterystyczne dla HWID. |
| `HWID_RETAIL_NO_OEM_KEY` | Windows w kanale Retail, Licensed, ale brak klucza OEM w firmware (tabela MSDM) — anomalia na urządzeniach konsumenckich. |
| `KMS_CUSTOM_HOST` | KMS host na zewnętrznym IP/domenie spoza organizacji. |
| `PREFETCH_ACTIVATOR` | Wpis Prefetch po EXE aktywatora (dowód uruchomienia, nawet jeśli plik skasowany). |
| `RECYCLEBIN_ACTIVATOR` | Plik aktywatora w Koszu — oryginalna ścieżka odtworzona z metadanych `$I` (v1/Vista, v2/Win8+). |
| `SECLOG_DELETION_AUDIT` | Security Event ID 4660 — trwałe usunięcie pliku aktywatora (Shift+Delete) zarejestrowane przez politykę audytu. |
| `SLMGR_2038_HINT` | Rok 2038 w `slmgr /dlv` — wskaźnik KMS38. |
| `SUSPICIOUS_TASK` | Zaplanowane zadanie o nazwie/ścieżce pasującej do wzorca aktywatora. |
| `SUSPICIOUS_SERVICE` | Usługa Windows o nazwie/ścieżce pasującej do wzorca aktywatora. |

#### Warstwa 3: Poszlaki orientacyjne (Low/Info)

| ID Findingu | Co wykrywa |
|-------------|------------|
| `OFFICE365_SUB_NO_SIGNIN` | Subskrypcyjny SKU Office 365 bez zalogowanej tożsamości w HKCU. |
| `OFFICE_M365_VNEXT_ACTIVATED` | M365 Apps z tokenami vNext (`.auth`) i/lub zalogowanym użytkownikiem — **stan prawidłowy**. |
| `OFFICE_M365_NO_SIGNIN` | M365 Apps zainstalowane, ale brak logowania i tokenów — użytkownik musi się zalogować. |
| `OFFICE_NOT_INSTALLED` | Nie wykryto instalacji Office — informacja, nie anomalia. |
| `RUNNING_AS_SYSTEM_NO_USER` | Skrypt jako SYSTEM, brak interaktywnego usera — checki HKCU pominięte. |
| `OS_INFO_READ_ERROR` | Nie można odczytać `Win32_OperatingSystem` — CIM/WMI nie odpowiada. |
| `KMSCLIENT_NO_MACHINE_NAME` | Kanał KMS client bez nazwy maszyny KMS w `slmgr` — możliwe ADBA. |
| `VSS_SHADOW_COPIES_PRESENT` | Snapshoty VSS dostępne do analizy forensiczej (informacja, nie anomalia). |

### Korelacja — Reguły łączone (Critical)

Silnik korelacji łączy słabe sygnały w twarde dowody. 11 reguł:

| Reguła | Kombinacja | Wniosek |
|--------|-----------|---------|
| `CORR_OHOOK_COMPLETE` | IFEO hook + sppcs.dll | 100% Ohook |
| `CORR_ONLINE_KMS_ACTIVE` | Katalog + zadanie Online KMS | 100% Online KMS |
| `CORR_KMS_HEADLESS` | KMS localhost/custom + brak domeny | 100% fałszywy KMS |
| `CORR_FORENSIC_MATCH` | Ślad forensyczny + anomalia KMS/Ohook | Spójny obraz manipulacji |
| `CORR_HWID_GENUINE_TICKET` | GenuineTicket.xml znaleziony | 100% HWID |
| `CORR_HWID_SPP_AND_RETAIL` | SPP mid-session + Retail/brak OEM | Orientacyjny HWID (słabe sygnały!) |
| `CORR_HWID_FORENSIC_MATCH` | Twardy ślad forensyczny + anomalia osi czasu SPP | Wysoka pewność HWID |
| `CORR_TSFORGE_ACTIVE` | DLL TSforge + anomalia osi czasu SPP | 100% TSforge |
| `CORR_SPP_ACL_TAMPER` | ACL SPP naruszone + anomalia osi czasu SPP | Naruszenie integralności |
| `CORR_SPP_ADS_TAMPER` | ADS na SPP + anomalia osi czasu | Ukryte dane aktywatora |
| `CORR_SPP_BINARY_TAMPER` | Podpis SPP nieprawidłowy + anomalia osi czasu | Podmiana binariów SPP |

### Co skrypt NIE wykrywa (ograniczenia)

- **HWID na świeżo po restarcie** — jeśli ClipSVC posprzątał `GenuineTicket.xml`, a ACL nie były modyfikowane, HWID jest kryptograficznie nie do odróżnienia od legalnej licencji cyfrowej. Tylko GenuineTicket.xml, PowerShell log, AMSI lub ślady plikowe aktywatora mogą to ujawnić.
- **Timestampy SPP NIE są dowodem** — `LastWriteTime tokens.dat` zmienia się przy każdej legalnej operacji (Windows Update, feature update, instalacja Office, naprawa sppsvc). Te checki to tylko flagi pomocnicze.
- **TSforge w pamięci** — TSforge może działać bez pozostawiania plików DLL na dysku (in-memory driver). Wykrywalne tylko przez AMSI lub PowerShell log.
- **Kontekst SYSTEM (RMM/SCCM)** — przy uruchomieniu jako SYSTEM, HKCU wskazuje na rejestr SYSTEM. vNext jest automatycznie przekierowywany na profil usera, ale HKCU identity może być puste.
- **M365 Apps nie używają kluczy SPP** — brak `PartialProductKey` dla Microsoft 365 jest **normalny**. Skrypt rozpoznaje to i NIE tworzy false positive `OFFICE_LICENSE_NOT_FOUND`.
- **Aktywatory w kontenerach/VHD** — skrypt skanuje tylko bieżącą instalację Windows.
- **Obfuskacja nazw plików** — Prefetch i Recycle Bin wykrywają tylko niezmienione nazwy. AMSI i PowerShell log (wzorce behawioralne) są odporne na rename.

### Klasyfikacja ryzyka

| Poziom | Warunek |
|--------|---------|
| **Critical** | ≥1 finding Critical |
| **High** | ≥2 High lub 1 High + ≥1 Medium |
| **Elevated** | 1 High lub ≥2 Medium |
| **Moderate** | 1 Medium lub ≥2 Low |
| **Low** | ≥1 Low |
| **Minimal** | Brak findingów |

### Przykładowe wyjście JSON

```json
{
  "GeneratedAtUtc": "2026-04-21T06:31:21Z",
  "ComputerName": "TADEUSZ-PC",
  "RiskLevel": "Minimal",
  "WindowsLicenses": [{
    "Name": "Windows(R), Professional edition",
    "Channel": "Retail",
    "LicenseStatusText": "Licensed",
    "PartialProductKey": "3V66T"
  }],
  "OfficeLicenses": [{
    "FriendlyName": "Microsoft 365 Apps for Business",
    "Channel": "Retail",
    "LicenseStatusText": "Notification",
    "PartialProductKey": "3RQ6B"
  }],
  "Office365Signals": {
    "HasSubscriptionSku": true,
    "HasSignedInIdentity": false,
    "HasVNextTokens": false
  },
  "Findings": [],
  "Disclaimer": "This script detects anomalies and tampering indicators. It cannot provide a 100% legal determination on its own."
}
```

---

## English

### Purpose

`Audit-Licensing.ps1` is a Microsoft Windows & Office license compliance auditor. It detects both legitimate licenses (Retail, OEM, Volume) and fake activations using tools like MAS (Microsoft Activation Scripts), KMSpico, HWID, Ohook, TSforge, and related.

**The script does NOT modify the system** — it is read-only. It does not fix, activate, or remove anything.

### Requirements

- Windows 10/11 (x64)
- PowerShell 5.1+ as **Administrator**
- Windows Defender enabled (for full AMSI coverage)
- PowerShell Operational log enabled (for activator script detection)

### Quick Start

```powershell
# Full audit (text mode)
.\Audit-Licensing.ps1

# JSON output (for monitoring system integration)
.\Audit-Licensing.ps1 -AsJson

# Save to file
.\Audit-Licensing.ps1 -AsJson | Out-File -FilePath audit_result.json -Encoding utf8

# Debug mode — shows skipped registry keys and non-critical errors
.\Audit-Licensing.ps1 -Debug
```

### Switches

| Switch | Effect |
|--------|--------|
| `-AsJson` | JSON output (no console colors). Returns object with fields: `RiskLevel`, `WindowsLicenses`, `OfficeLicenses`, `Office365Signals`, `Office365Identity`, `Findings[]`, `Disclaimer`. |
| `-Debug` | Built-in PowerShell switch — shows `Write-Debug` messages (skipped registry keys, ADS/ACL read errors, non-critical exceptions). |

### Detection Architecture

The script operates in **three layers**, from strongest signals to circumstantial evidence:

#### Layer 1: Hard Evidence (High/Critical)

| Finding ID | Activation Method | What It Detects |
|------------|-------------------|-----------------|
| `HWID_GENUINE_TICKET` | MAS HWID | Leftover `GenuineTicket.xml` in `ClipSVC\GenuineTicket\` — the ticket injection artifact. ClipSVC normally cleans it up. |
| `OHOOK_FILE_PRESENT` | MAS Ohook | `sppcs.dll` in `System32` or `SysWOW64` — SPP hook library for Office. |
| `MAS_OHOOK_REGISTRY` | MAS Ohook | `TimeOfLastHeartbeatFailure = 2040-01-01T00:00:00Z` in `HKCU\...\Office\Licensing\Resiliency` — suppresses Office license banner. |
| `MAS_ONLINE_KMS_DIR` | MAS Online KMS | `C:\Program Files\Activation-Renewal\` directory with renewal scripts. |
| `MAS_ONLINE_KMS_TASK` | MAS Online KMS | Scheduled task `\Activation-Renewal` (periodic KMS refresh). |
| `TSFORGE_FILE_PRESENT` | MAS TSforge | `sppc.dll` / `sppcext.dll` with invalid digital signature (Windows SPP DLL hooks). |
| `SPP_STORE_ACL_RELAXED` | MAS HWID | Overridden NTFS permissions on `spp\store\2.0` — write access beyond SYSTEM/TrustedInstaller. |
| `SPP_FILE_ACL_RELAXED` | MAS HWID | Overridden ACL on `tokens.dat` / `data.dat` / `cache.dat`. |
| `SPP_FILE_ADS_PRESENT` | MAS HWID | Alternate Data Streams on SPP store files — payload hiding in NTFS streams. |
| `SPP_BINARY_INVALID_SIGNATURE` | binary replacement | `spp*.dll` / `spp*.exe` with invalid Authenticode signature. |
| `SPP_BINARY_UNEXPECTED_SIGNER` | binary replacement | SPP binary signed by non-Microsoft entity. |
| `IFEO_DEBUGGER` | Ohook/replacement | `Debugger` in IFEO for `osppsvc.exe` / `sppsvc.exe` — SPP process interception. |
| `IFEO_VERIFIER_DLLS` | Ohook/replacement | `VerifierDlls` in IFEO — DLL injection into SPP processes. |
| `KMS_LOCALHOST` | KMS emulator | KMS host set to `localhost` / `127.0.0.1` — local KMS emulator. |
| `KMS_ARTIFACT_FOUND` | KMS activators | Artifacts in `ProgramData`: `KMS*`, `KMSAuto*`, `KMS_VL_ALL*`, `SppExtComObj*` copies. |
| `AMSI_ACTIVATOR_DETECTION` | any | Windows Defender / AMSI caught activator script by content (Event ID 1116/1117). |
| `POWERSHELL_LOG_ACTIVATOR` | any | PowerShell Operational log contains behavioral activator pattern (Event ID 4103/4104). |

#### Layer 2: Strong Indicators (Medium)

| Finding ID | What It Detects |
|------------|-----------------|
| `SPP_TOKENS_MOD_MID_SESSION` | `tokens.dat` zmodyfikowany podczas bieżącej sesji bez restartu. **Słaby sygnał** — może być skutkiem ubocznym Windows Update lub naprawy sppsvc. |
| `HWID_RETAIL_NO_OEM_KEY` | Windows w kanale Retail, Licensed, ale brak klucza OEM w firmware (MSDM). Anomalia na urządzeniach konsumenckich. |
| `OFFICE_LICENSE_NOT_FOUND` | **Tylko tradycyjny Office** (2016/2019/2021/LTSC) bez klucza SPP. M365 Apps NIE są flagowane — używają tokenów vNext. |
| `KMS_CUSTOM_HOST` | KMS host on external IP/domain outside the organization. |
| `PREFETCH_ACTIVATOR` | Prefetch entry from activator EXE (proof of execution, even if file deleted). |
| `RECYCLEBIN_ACTIVATOR` | Activator file in Recycle Bin — original path reconstructed from `$I` metadata (v1/Vista, v2/Win8+). |
| `SECLOG_DELETION_AUDIT` | Security Event ID 4660 — permanent deletion (Shift+Delete) captured by audit policy. |
| `SLMGR_2038_HINT` | Year 2038 in `slmgr /dlv` — KMS38 indicator. |
| `SUSPICIOUS_TASK` | Scheduled task with name/path matching activator pattern. |
| `SUSPICIOUS_SERVICE` | Windows service with name/path matching activator pattern. |

#### Layer 3: Circumstantial (Low/Info)

| Finding ID | What It Detects |
|------------|-----------------|
| `OFFICE365_SUB_NO_SIGNIN` | Subscription Office 365 SKU without signed-in HKCU identity. |
| `KMSCLIENT_NO_MACHINE_NAME` | KMS client channel without KMS machine name in `slmgr` — possible ADBA. |
| `VSS_SHADOW_COPIES_PRESENT` | VSS snapshots available for forensic analysis (informational, not an anomaly). |

### Correlation Engine (Critical)

The correlation engine combines weak signals into hard evidence. 11 rules:

| Rule | Combination | Conclusion |
|------|-------------|------------|
| `CORR_OHOOK_COMPLETE` | IFEO hook + sppcs.dll | 100% Ohook |
| `CORR_ONLINE_KMS_ACTIVE` | Online KMS dir + task | 100% Online KMS |
| `CORR_KMS_HEADLESS` | KMS localhost/custom + non-domain | 100% fake KMS |
| `CORR_FORENSIC_MATCH` | Forensic trace + KMS/Ohook anomaly | Consistent manipulation picture |
| `CORR_HWID_GENUINE_TICKET` | GenuineTicket.xml found | 100% HWID |
| `CORR_HWID_SPP_AND_RETAIL` | SPP mid-session + Retail/no OEM | Suggestive HWID (weak signals!) |
| `CORR_HWID_FORENSIC_MATCH` | Hard forensic trace + SPP timeline anomaly | High confidence HWID |
| `CORR_TSFORGE_ACTIVE` | TSforge DLL + SPP timeline anomaly | 100% TSforge |
| `CORR_SPP_ACL_TAMPER` | SPP ACL violated + SPP timeline anomaly | Integrity violation |
| `CORR_SPP_ADS_TAMPER` | ADS on SPP + timeline anomaly | Hidden activator data |
| `CORR_SPP_BINARY_TAMPER` | SPP signature invalid + timeline anomaly | SPP binary replacement |

### Limitations

- **Fresh HWID after reboot** — if ClipSVC cleaned up `GenuineTicket.xml` and ACLs were untouched, HWID is cryptographically indistinguishable from a legitimate digital license. Only GenuineTicket.xml, PowerShell log, or file traces can reveal it.
- **In-memory TSforge** — TSforge can operate without leaving DLL files on disk (in-memory driver). Detectable only via AMSI or PowerShell log.
- **Container/VHD activators** — the script scans only the current Windows installation.
- **Filename obfuscation** — Prefetch and Recycle Bin only detect unchanged filenames. Renaming `kmsauto.exe` to `setup.exe` bypasses these checks.

### Risk Classification

| Level | Condition |
|-------|-----------|
| **Critical** | ≥1 Critical finding |
| **High** | ≥2 High or 1 High + ≥1 Medium |
| **Elevated** | 1 High or ≥2 Medium |
| **Moderate** | 1 Medium or ≥2 Low |
| **Low** | ≥1 Low |
| **Minimal** | No findings |

### Forensic Traces — Detection Methods Deep Dive

The script uses 6 independent forensic methods to detect past activator execution:

1. **Prefetch** (`C:\Windows\Prefetch\*.pf`) — Windows records every EXE execution with timestamp and run count. Survives file deletion. Limited to EXE files only (MAS `.ps1`/`.cmd` scripts do NOT create Prefetch entries).

2. **PowerShell Operational Log** (Event ID 4103/4104) — captures executed script blocks with content. Uses behavioral patterns (`slmgr /ipk`, `ClipSVC`, `GenuineTicket`, `tokens.dat`, `sppc.dll`) instead of just activator names — much harder to evade than Prefetch.

3. **AMSI / Windows Defender Log** (Event ID 1116/1117) — scans script CONTENT at runtime, independent of filename or obfuscation. The STRONGEST detection method in the script. Requires Windows Defender to be running.

4. **Recycle Bin `$I` Metadata** — binary parsing of v1 (Vista/Win7) and v2 (Win8+) `$I` files to recover original file paths of deleted items. Scans ALL fixed drives. Limitation: most activators run as SYSTEM and self-destruct via Shift+Delete, completely bypassing the Recycle Bin.

5. **Security Audit Log** (Event ID 4660) — captures permanent file deletions including Shift+Delete. Requires "Audit File System" enabled in `secpol.msc` (disabled by default on client SKUs).

6. **VSS Shadow Copies** — system restore points and backup snapshots preserve file history, including files later permanently deleted. The script reports available snapshots for manual forensic analysis (not automated recovery).
