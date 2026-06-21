[CmdletBinding()]
param(
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Ten skrypt MUSI być uruchomiony jako Administrator, aby wyniki były wiarygodne."
    exit
}

$findings = New-Object System.Collections.Generic.List[object]
$stageStart = Get-Date
$stageCount = 0
$stageTotal = 7

function Write-Stage {
    param([Parameter(Mandatory=$true)][string]$Name)
    $script:stageCount++
    $elapsed = [math]::Round(((Get-Date) - $script:stageStart).TotalSeconds, 1)
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] [$stageCount/$stageTotal] $Name" -ForegroundColor Green
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet("Info", "Low", "Medium", "High", "Critical")][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation
    )

    $findings.Add([pscustomobject]@{
            Id             = $Id
            Severity       = $Severity
            Area           = $Area
            Evidence       = $Evidence
            Recommendation = $Recommendation
        })
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Convert-LicenseStatus {
    param([int]$Status)

    switch ($Status) {
        0 { "Unlicensed" }
        1 { "Licensed" }
        2 { "OOBGrace" }
        3 { "OOTGrace" }
        4 { "NonGenuineGrace" }
        5 { "Notification" }
        6 { "ExtendedGrace" }
        default { "Unknown($Status)" }
    }
}

function Get-OfficeFriendlyName {
    param([string]$Name, [string]$Description)

    # Map internal SKU tokens in the Name/Description to human-readable product names.
    $skuMap = [ordered]@{
        'O365BusinessPremium|BusinessPremium'                          = 'Microsoft 365 Business Premium'
        'O365Business(?!Premium)|Office365Business'                  = 'Microsoft 365 Apps for Business'
        'O365ProPlus|O365ProPlusR|MSOfficeProfessionalPlus365'       = 'Microsoft 365 Apps for Enterprise'
        'O365SmallBus'                                               = 'Microsoft 365 Business Basic'
        'O365EduCloud|O365Education'                                 = 'Microsoft 365 Education'
        'ProPlus2024|LTSC2024ProPlus'                                = 'Office LTSC Professional Plus 2024'
        'Standard2024|LTSC2024Standard'                              = 'Office LTSC Standard 2024'
        'ProPlus2021|LTSC2021ProPlus'                                = 'Office LTSC Professional Plus 2021'
        'Standard2021|LTSC2021Standard'                              = 'Office LTSC Standard 2021'
        'ProPlus2019'                                                = 'Office Professional Plus 2019'
        'Standard2019'                                               = 'Office Standard 2019'
        'HomeBusiness2019|Home.*Business.*2019'                      = 'Office Home & Business 2019'
        'HomeStudent2019|Home.*Student.*2019'                        = 'Office Home & Student 2019'
        'Professional2019'                                           = 'Office Professional 2019'
        'ProPlus(?!201)'                                             = 'Office Professional Plus 2016'
        'Standard(?!201)'                                            = 'Office Standard 2016'
        'HomeBusiness(?!201)|Home.*Business'                         = 'Office Home & Business 2016'
        'HomeStudent(?!201)|Home.*Student'                           = 'Office Home & Student 2016'
        'Professional(?!201)'                                        = 'Office Professional 2016'
        'OneNoteFree|OneNote.*Free'                                  = 'OneNote (Free)'
        'OneNote'                                                    = 'OneNote'
        'Visio.*Plan2|VisioPro'                                      = 'Visio Plan 2 / Professional'
        'Visio.*Plan1|VisioStd'                                      = 'Visio Plan 1 / Standard'
        'Project.*Plan5|ProjectPro'                                  = 'Project Plan 5 / Professional'
        'Project.*Plan3|ProjectStd'                                  = 'Project Plan 3 / Standard'
    }

    $combined = "$Name $Description"
    foreach ($pattern in $skuMap.Keys) {
        if ($combined -match $pattern) {
            return $skuMap[$pattern]
        }
    }

    # Fallback: strip internal noise and return a cleaner version of the raw name.
    $clean = $Name -replace '^Office \d+,\s*', '' -replace '_?(Grace|Subscription|Bypass|Free|Retail|Volume|R)$', '' -replace '_', ' '
    return $clean.Trim()
}

function Get-ChannelFromDescription {
    param([string]$Description)

    if ([string]::IsNullOrWhiteSpace($Description)) { return "Unknown" }
    if ($Description -match "RETAIL") { return "Retail" }
    if ($Description -match "OEM") { return "OEM" }
    if ($Description -match "MAK") { return "Volume:MAK" }
    if ($Description -match "KMSCLIENT") { return "Volume:KMSClient" }
    if ($Description -match "VOLUME_KMS") { return "Volume:KMS" }

    return "Other"
}

function Get-RiskLevel {
    param([System.Collections.Generic.List[object]]$InputFindings)

    $criticalCount = ($InputFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount     = ($InputFindings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount   = ($InputFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount      = ($InputFindings | Where-Object { $_.Severity -eq "Low" }).Count

    if ($criticalCount -ge 1) { return "Critical" }
    if ($highCount -ge 2) { return "High" }
    if ($highCount -eq 1 -and $mediumCount -ge 1) { return "High" }
    if ($highCount -eq 1) { return "Elevated" }
    if ($mediumCount -ge 2) { return "Elevated" }
    if ($mediumCount -eq 1 -or $lowCount -ge 2) { return "Moderate" }
    if ($lowCount -ge 1) { return "Low" }

    return "Minimal"
}

if (-not $AsJson) {
    Write-Host "--- Starting licensing audit (Windows + Office) ---" -ForegroundColor Cyan
}

# --- Kontekst użytkownika: wykrycie SYSTEM vs zalogowany użytkownik ---
# Skrypt wymaga Administratora, ale checki Office identity i vNext używają
# HKCU i %LOCALAPPDATA%. Gdy uruchomiony jako SYSTEM (RMM, SCCM, Intune),
# HKCU wskazuje na rejestr SYSTEM, a nie zalogowanego użytkownika!
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$isRunningAsSystem = $currentUser -eq "NT AUTHORITY\SYSTEM"

# Znajdź interaktywnego użytkownika przez explorer.exe (zawsze w sesji usera)
$interactiveUserName = $null
$interactiveUserProfile = $null
try {
    $explorerProc = Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($explorerProc -and $explorerProc.UserName) {
        $interactiveUserName = $explorerProc.UserName
        $samName = ($interactiveUserName -split '\\')[-1]
        $wmiUser = Get-CimInstance Win32_UserAccount -Filter "Name = '$samName'" -ErrorAction Stop |
            Select-Object -First 1
        if ($wmiUser -and $wmiUser.SID) {
            $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($wmiUser.SID)"
            $interactiveUserProfile = Get-ItemProperty -Path $profileKey -Name "ProfileImagePath" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty ProfileImagePath
        }
    }
}
catch { }

if ($isRunningAsSystem) {
    if ($interactiveUserProfile) {
        Write-Host "  [i] Running as SYSTEM. Targeting $interactiveUserName profile for user checks." -ForegroundColor DarkYellow
    }
    else {
        Write-Host "  [!] Running as SYSTEM, no interactive user detected. HKCU checks will likely be empty." -ForegroundColor Yellow
        Add-Finding -Id "RUNNING_AS_SYSTEM_NO_USER" -Severity "Medium" -Area "System" `
            -Evidence "Skrypt uruchomiony jako SYSTEM i nie wykryto aktywnego interaktywnego użytkownika. HKCU to rejestr SYSTEM, a nie użytkownika Office." `
            -Recommendation "Uruchom skrypt w kontekście zalogowanego użytkownika (RMM: opcja /user), aby sprawdzić tożsamość Office 365 i tokeny vNext."
    }
}

Write-Stage "Collecting licensing data (CIM/WMI)..."

$windowsAppId = "55c92734-d682-4d71-983e-d6ec3f16059f"
# Office 2013/2016/2019/2021/2024/Microsoft 365
$officeAppId   = "0ff1ce15-a989-479d-af46-f275c6370663"
# Office 2010 uses a different ApplicationId
$office2010AppId = "59a52881-a989-479d-af46-f275c6370663"
$officeIdentityPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity"
$officeIdentityProfilesPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities"

$allLic = @()
try {
    # WQL z podwójnym filtrem po stronie serwera CIM:
    # 1) ApplicationId — tylko Windows/Office, nie setki komponentów
    # 2) PartialProductKey IS NOT NULL — tylko aktywne licencje z kluczem
    # Bez filtrów zapytanie może trwać 30-120s na starszych maszynach.
    $licenseQuery = "SELECT * FROM SoftwareLicensingProduct WHERE (ApplicationId = '$windowsAppId' OR ApplicationId = '$officeAppId' OR ApplicationId = '$office2010AppId') AND PartialProductKey IS NOT NULL"
    $allLic = @(Get-CimInstance -Query $licenseQuery -ErrorAction Stop)
}
catch {
    Add-Finding -Id "CIM_READ_ERROR" -Severity "Medium" -Area "Licensing API" -Evidence "Cannot read SoftwareLicensingProduct: $($_.Exception.Message)" -Recommendation "Run script with Administrator rights and confirm WMI/CIM service health."
}

$windowsLic = @($allLic | Where-Object { $_.ApplicationId -eq $windowsAppId })
$officeLic   = @($allLic | Where-Object { $_.ApplicationId -in @($officeAppId, $office2010AppId) })

$winSummary = @($windowsLic | Select-Object Name, Description, PartialProductKey, LicenseStatus,
    @{Name = "LicenseStatusText"; Expression = { Convert-LicenseStatus $_.LicenseStatus } },
    @{Name = "Channel";           Expression = { Get-ChannelFromDescription $_.Description } })

$officeSummary = @($officeLic | Select-Object Name, Description, PartialProductKey, LicenseStatus,
    @{Name = "LicenseStatusText"; Expression = { Convert-LicenseStatus $_.LicenseStatus } },
    @{Name = "Channel";           Expression = { Get-ChannelFromDescription $_.Description } },
    @{Name = "FriendlyName";      Expression = { Get-OfficeFriendlyName $_.Name $_.Description } })

# Detect Office installations via Uninstall registry (catches versions not in SoftwareLicensingProduct,
# e.g. Click-to-Run without local SPP key, or older MSI installs).
$officeInstalled = [System.Collections.Generic.List[object]]::new()
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($uPath in $uninstallPaths) {
    if (-not (Test-Path $uPath)) { continue }
    Get-ChildItem -Path $uPath -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
            $isOfficeProduct = $p.Publisher -match 'Microsoft' -and $p.DisplayName -match `
                '(?i)Microsoft (365|Office|Visio|Project).*(365|2010|2013|2016|2019|2021|2024|Home|Business|Professional|Standard|Enterprise)'
            $isUpdateOrPack  = $p.DisplayName -match `
                '(?i)(Update|Hotfix|Security Update|Service Pack|MUI|Language Pack|Proof|Proofing Tools|\bKB\d{6,}\b)'
            if ($isOfficeProduct -and -not $isUpdateOrPack) {
                $officeInstalled.Add([pscustomobject]@{
                    DisplayName    = $p.DisplayName
                    DisplayVersion = $p.DisplayVersion
                    Architecture   = if ($uPath -match 'WOW6432') { '32-bit' } else { '64-bit' }
                    InstallDate    = $p.InstallDate
                    RegistrySource = $uPath
                })
            }
        } catch { Write-Debug "Office registry read skipped: $($_.Exception.Message)" }
    }
}

# Klasyfikacja: Microsoft 365 Apps (subskrypcyjne, bez klucza SPP) vs tradycyjny Office (wymaga klucza)
$m365Products = @($officeInstalled | Where-Object { $_.DisplayName -match '(?i)Microsoft 365' })
$isM365FromRegistry = $m365Products.Count -gt 0

$traditionalProducts = @($officeInstalled | Where-Object {
    $_.DisplayName -match '(?i)(Office|Visio|Project).*(Professional|Standard|Home|Enterprise|20\d{2}|LTSC)' -and
    $_.DisplayName -notmatch '(?i)Microsoft 365'
})
$hasTraditionalOffice = $traditionalProducts.Count -gt 0

# vNext licensing: M365 Apps używają tokenów użytkownika zamiast lokalnych kluczy SPP.
# Pliki .auth w %LOCALAPPDATA%\Microsoft\Office\16.0\Licensing potwierdzają aktywację.
# Gdy SYSTEM: używamy profilu interaktywnego użytkownika zamiast C:\Windows\System32\config\systemprofile.
$hasVNextTokens = $false
$vNextLicensePath = if ($isRunningAsSystem -and $interactiveUserProfile) {
    "$interactiveUserProfile\AppData\Local\Microsoft\Office\16.0\Licensing"
} else {
    "$env:LOCALAPPDATA\Microsoft\Office\16.0\Licensing"
}
if (Test-Path -Path $vNextLicensePath) {
    try {
        $authFiles = Get-ChildItem -Path $vNextLicensePath -Filter "*.auth" -ErrorAction Stop
        $hasVNextTokens = ($authFiles.Count -gt 0)
    }
    catch { Write-Debug "vNext licensing token check failed: $($_.Exception.Message)" }
}

$subscriptionEntries = @($officeSummary | Where-Object { $_.Description -match "TIMEBASED_SUB|SUB" -or $_.Name -match "O365|Microsoft 365|Subscription" })
$hasOffice365SubscriptionSku = $subscriptionEntries.Count -gt 0

$office365Identity = $null
if (Test-Path -Path $officeIdentityPath) {
    try {
        $identity = Get-ItemProperty -Path $officeIdentityPath -ErrorAction Stop
        $identityProfiles = @()

        if (Test-Path -Path $officeIdentityProfilesPath) {
            $profileKeys = Get-ChildItem -Path $officeIdentityProfilesPath -ErrorAction SilentlyContinue
            foreach ($key in $profileKeys) {
                try {
                    $p = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                    $identityProfiles += [pscustomobject]@{
                        ProfileKey      = $key.PSChildName
                        SignInName      = $p.SignInName
                        UserName        = $p.UserName
                        UserEmail       = $p.UserEmail
                        EmailAddress    = $p.EmailAddress
                        FederatedEmail  = $p.FederatedUserEmail
                        TenantId        = $p.TenantId
                    }
                }
                catch {
                    Write-Debug "Office identity profile key skipped: $($_.Exception.Message)"
                }
            }
        }

        $rootIdentityValues = @(
            $identity.SignInName,
            $identity.UserEmail,
            $identity.FederatedUserEmail,
            $identity.UserName
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $profileIdentityValues = @(
            $identityProfiles.SignInName,
            $identityProfiles.UserEmail,
            $identityProfiles.EmailAddress,
            $identityProfiles.FederatedEmail,
            $identityProfiles.UserName
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $allIdentityValues = @($rootIdentityValues + $profileIdentityValues | Select-Object -Unique)
        $hasSignedInIdentity = $allIdentityValues.Count -gt 0

        $identityProps = [pscustomobject]@{
            IdentityPath        = $officeIdentityPath
            SignInName          = $identity.SignInName
            UserName            = $identity.UserName
            UserEmail           = $identity.UserEmail
            FederatedUserEmail  = $identity.FederatedUserEmail
            TenantId            = $identity.TenantId
            ProfileCount        = $identityProfiles.Count
            Profiles            = $identityProfiles
            DetectedIdentities  = $allIdentityValues
            IsOffice365Account  = $hasSignedInIdentity
        }

        $office365Identity = $identityProps

        if ($identityProps.IsOffice365Account) {
            $identityCtxNote = if ($isRunningAsSystem) { " (UWAGA: odczytane z HKCU SYSTEM, nie użytkownika. Jeśli to konto SYSTEM ma identity Office — anomalia.)" } else { "" }
            Add-Finding -Id "OFFICE365_IDENTITY_PRESENT" -Severity "Info" -Area "Office 365" `
                -Evidence "User identity detected in HKCU Office identity profile.$identityCtxNote" `
                -Recommendation "Correlate with assigned Microsoft 365 license in Entra ID / M365 Admin Center."
        }
    }
    catch {
        $hkcErrorCtx = if ($isRunningAsSystem) { " (skrypt jako SYSTEM — HKCU to rejestr SYSTEM, nie użytkownika)" } else { "" }
        Add-Finding -Id "OFFICE365_IDENTITY_READ_ERROR" -Severity "Low" -Area "Office 365" `
            -Evidence "Could not read HKCU Office identity data: $($_.Exception.Message)$hkcErrorCtx" `
            -Recommendation "Run in user context with loaded profile to audit Microsoft 365 sign-in state."
    }
}

# If Identity key was empty, try alternative sign-in locations
if (-not $office365Identity -or -not $office365Identity.IsOffice365Account) {
    $altIdentity = $null
    $altSource = ""

    # Check 1: HKCU\...\SignIn (Office sign-in cache)
    $signInPath = "HKCU:\Software\Microsoft\Office\16.0\Common\SignIn"
    if (Test-Path $signInPath) {
        try {
            $signIn = Get-ItemProperty -Path $signInPath -ErrorAction Stop
            if ($signIn.SignInName) {
                $altIdentity = $signIn.SignInName
                $altSource = "SignIn key"
            } elseif ($signIn.LastUsedUserId) {
                $altIdentity = $signIn.LastUsedUserId
                $altSource = "SignIn key (LastUsedUserId)"
            }
        } catch {}
    }

    # Check 2: Office Registration subkeys
    if (-not $altIdentity) {
        $regPath = "HKCU:\Software\Microsoft\Office\16.0\Registration"
        if (Test-Path $regPath) {
            try {
                $regKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                foreach ($rk in $regKeys) {
                    $rp = Get-ItemProperty -Path $rk.PSPath -ErrorAction SilentlyContinue
                    if ($rp.UserEmail) {
                        $altIdentity = $rp.UserEmail
                        $altSource = "Registration key"
                        break
                    }
                }
            } catch {}
        }
    }

    # Check 3: HKCU\...\Common\Licensing (vNext tokens)
    if (-not $altIdentity) {
        $licPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing"
        if (Test-Path $licPath) {
            try {
                $licProps = Get-ItemProperty -Path $licPath -ErrorAction Stop
                if ($licProps.LicensingEmailAddress) {
                    $altIdentity = $licProps.LicensingEmailAddress
                    $altSource = "Licensing key"
                }
            } catch {}
        }
    }

    if ($altIdentity) {
        $office365Identity = [pscustomobject]@{
            IdentityPath        = $altSource
            SignInName          = $altIdentity
            UserName            = ""
            UserEmail           = ""
            FederatedUserEmail  = ""
            TenantId            = ""
            ProfileCount        = 0
            Profiles            = @()
            DetectedIdentities  = @($altIdentity)
            IsOffice365Account  = $true
        }
        Add-Finding -Id "OFFICE365_IDENTITY_PRESENT" -Severity "Info" -Area "Office 365" `
            -Evidence "User identity detected via $($altSource): $($altIdentity)" `
            -Recommendation "Correlate with assigned Microsoft 365 license in Entra ID / M365 Admin Center."
    }
}

$office365Signals = [pscustomobject]@{
    HasSubscriptionSku  = $hasOffice365SubscriptionSku
    SubscriptionSkuCount = $subscriptionEntries.Count
    HasIdentityProfile  = [bool]$office365Identity
    HasSignedInIdentity = [bool]($office365Identity -and $office365Identity.IsOffice365Account)
    IsM365FromRegistry  = $isM365FromRegistry
    HasTraditionalOffice = $hasTraditionalOffice
    HasVNextTokens      = $hasVNextTokens
    IsRunningAsSystem   = $isRunningAsSystem
    InteractiveUserName = if ($interactiveUserName) { $interactiveUserName } else { $null }
    IsSharedComputerActivation = $isSharedComputerActivation
}

if (-not $windowsLic) {
    Add-Finding -Id "WINDOWS_LICENSE_NOT_FOUND" -Severity "Medium" -Area "Windows" -Evidence "No Windows licensing product with PartialProductKey found in CIM." -Recommendation "Verify OS licensing service health and inspect slmgr /dlv manually."
}

# Shared Computer Activation (SCA): M365 na RDS/VDI/terminalach.
# W SCA tokeny są per-sesja, nie zostają trwale w HKCU — brak identity
# i tokenów vNext jest OCZEKIWANY. Nie można z tego wnioskować o braku licencji.
$isSharedComputerActivation = $false
try {
    $scaPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing",
        "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    )
    foreach ($scaPath in $scaPaths) {
        $scaVal = Get-ItemProperty -Path $scaPath -Name "SharedComputerLicensing" -ErrorAction SilentlyContinue
        if ($scaVal -and $scaVal.SharedComputerLicensing -eq 1) {
            $isSharedComputerActivation = $true
            break
        }
    }
}
catch { }

if (-not $officeLic) {
    # Nowoczesne Microsoft 365 Apps NIE UŻYWAJĄ lokalnych kluczy produktu (PartialProductKey).
    # Aktywacja opiera się na tokenie użytkownika (vNext) lub licencji urządzenia.
    # Brak zalogowanego użytkownika NIE JEST anomalią — SCA, device-based license
    # i licencje wolumenowe działają bez tożsamości HKCU.
    $userHasIdentity = $office365Identity -and $office365Identity.IsOffice365Account

    if ($isM365FromRegistry -and ($userHasIdentity -or $hasVNextTokens)) {
        # M365 + zalogowany użytkownik lub token vNext = normalna aktywacja subskrypcyjna.
        # Brak PartialProductKey w CIM jest OCZEKIWANY. Nie tworzymy findingu o braku klucza.
        $m365Evidence = "Microsoft 365 Apps: brak lokalnego klucza SPP (oczekiwane)."
        if ($userHasIdentity) { $m365Evidence += " Użytkownik zalogowany: $($office365Identity.SignInName)" }
        if ($hasVNextTokens) { $m365Evidence += " Tokeny vNext obecne." }
        Add-Finding -Id "OFFICE_M365_VNEXT_ACTIVATED" -Severity "Info" -Area "Office 365" `
            -Evidence $m365Evidence `
            -Recommendation "M365 używa aktywacji subskrypcyjnej — klucz SPP nie jest wymagany. Zweryfikuj przypisanie licencji w M365 Admin Center."
    }
    elseif ($isM365FromRegistry -and -not $userHasIdentity -and -not $hasVNextTokens) {
        # M365 bez identity i tokenów — NIE JEST automatycznie podejrzane.
        # Legalne scenariusze: Shared Computer Activation (RDS/VDI), device-based
        # license, licencja wolumenowa, użytkownik jeszcze się nie zalogował,
        # lub tokeny są w innym profilu (skrypt jako SYSTEM/Admin).
        $scaNote = if ($isSharedComputerActivation) { " Wykryto SharedComputerLicensing=1 — to wyjaśnia brak tożsamości HKCU." } else { "" }
        $ctxNote = if ($isRunningAsSystem) { " Skrypt jako SYSTEM — tokeny mogą być w profilu $interactiveUserName." } else { "" }
        Add-Finding -Id "OFFICE_M365_NO_SIGNIN" -Severity "Info" -Area "Office 365" `
            -Evidence "Microsoft 365 Apps wykryte w rejestrze, brak tożsamości HKCU i tokenów vNext.$scaNote$ctxNote Produkty: $(($m365Products.DisplayName | Select-Object -First 3) -join '; ')" `
            -Recommendation "To NIE jest anomalia. M365 może działać bez trwale zalogowanego użytkownika: Shared Computer Activation, device-based license, licencja wolumenowa. Jeśli aplikacje działają poprawnie — nie ma problemu."
    }
    elseif ($hasTraditionalOffice) {
        # Tradycyjny Office BEZ klucza SPP — to jest podejrzane
        Add-Finding -Id "OFFICE_LICENSE_NOT_FOUND" -Severity "Medium" -Area "Office" `
            -Evidence "Tradycyjny Office (wolumen/retail) wykryty w rejestrze, ale brak PartialProductKey w CIM. Produkty: $(($traditionalProducts.DisplayName | Select-Object -First 3) -join '; ')" `
            -Recommendation "Tradycyjny Office wymaga klucza produktu. Sprawdź stan aktywacji w aplikacji (Plik → Konto) i skoreluj z dokumentacją licencyjną."
    }
    elseif ($officeInstalled.Count -gt 0) {
        # Office w rejestrze, ale nie sklasyfikowany jako M365 ani tradycyjny
        Add-Finding -Id "OFFICE_LICENSE_NOT_FOUND" -Severity "Low" -Area "Office" `
            -Evidence "Produkty Office w rejestrze bez lokalnego klucza SPP: $(($officeInstalled.DisplayName | Select-Object -First 3) -join '; ')" `
            -Recommendation "Jeśli to Microsoft 365 Apps — zaloguj się (M365 nie używa kluczy). Jeśli tradycyjny Office — zweryfikuj klucz produktu."
    }
    else {
        # Office nie jest zainstalowany — informacja, nie anomalia
        Add-Finding -Id "OFFICE_NOT_INSTALLED" -Severity "Info" -Area "Office" `
            -Evidence "Nie wykryto instalacji Office ani w rejestrze, ani w CIM." `
            -Recommendation "Office nie jest zainstalowany na tym komputerze. Jeśli korzystasz z aplikacji Office — sprawdź ich źródło (Office Online, aplikacje PWA)."
    }
}

if ($office365Signals.HasSubscriptionSku) {
    Add-Finding -Id "OFFICE365_SUBSCRIPTION_SKU" -Severity "Info" -Area "Office 365" -Evidence "Detected Office subscription SKU(s) in licensing data (TIMEBASED_SUB / Subscription)." -Recommendation "Verify user assignment and sign-in state in Microsoft 365 admin center."
}

if ($office365Signals.HasSubscriptionSku -and -not $office365Signals.HasSignedInIdentity) {
    # Subskrypcyjny SKU w CIM + brak identity HKCU. NIE jest automatycznie podejrzane:
    # SCA, device-based license, SYSTEM context, lub użytkownik jeszcze się nie zalogował.
    $subCtxNote = if ($isSharedComputerActivation) { " SharedComputerLicensing=1 — SCA wyjaśnia brak identity." } elseif ($isRunningAsSystem) { " Skrypt jako SYSTEM — identity może być w profilu $interactiveUserName." } else { "" }
    Add-Finding -Id "OFFICE365_SUB_NO_SIGNIN" -Severity "Info" -Area "Office 365" `
        -Evidence "Subskrypcyjny SKU Office wykryty w CIM, ale brak zalogowanej tożsamości w HKCU.$subCtxNote" `
        -Recommendation "To NIE jest anomalia jeśli używasz Shared Computer Activation, device-based license lub licencji wolumenowej. Jeśli aplikacje Office działają — licencja jest prawidłowa."
}

# Do not classify GVLK as illegal by itself.
$kmsClientWindows = @($winSummary | Where-Object { $_.Channel -eq "Volume:KMSClient" })
$kmsClientOffice = @($officeSummary | Where-Object { $_.Channel -eq "Volume:KMSClient" -or $_.Channel -eq "Volume:KMS" })
if ($kmsClientWindows.Count -gt 0 -or $kmsClientOffice.Count -gt 0) {
    Add-Finding -Id "KMS_CHANNEL_PRESENT" -Severity "Info" -Area "Licensing Channel" -Evidence "Detected KMS channel products. This can be legitimate in Volume Licensing environments." -Recommendation "Validate against organization contract and KMS/ADBA deployment design."
}

# Check known Ohook indicator files.
$indicatorFiles = @(
    "C:\Windows\System32\sppcs.dll",
    "C:\Windows\SysWOW64\sppcs.dll"
)
foreach ($file in $indicatorFiles) {
    if (Test-Path -Path $file) {
        Add-Finding -Id "OHOOK_FILE_PRESENT" -Severity "High" -Area "MAS Ohook" -Evidence "Suspicious file present: $file" -Recommendation "Collect file hash, inspect signer, and compare against known-good baseline."
    }
}

Write-Stage "Scanning for activator artifacts (Ohook, KMS, slmgr)..."

# Ohook registry: MAS sets this value to suppress Office 365 license banner.
$ohookResiliencyPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency"
$heartbeatVal = Get-RegistryValue -Path $ohookResiliencyPath -Name "TimeOfLastHeartbeatFailure"
if ($heartbeatVal -eq "2040-01-01T00:00:00Z") {
    Add-Finding -Id "MAS_OHOOK_REGISTRY" -Severity "High" -Area "MAS Ohook" `
        -Evidence "HKCU Office Resiliency registry entry TimeOfLastHeartbeatFailure='$heartbeatVal' matches known MAS Ohook suppression value." `
        -Recommendation "Remove or correct the registry entry and reactivate Office legitimately."
}

# Online KMS (MAS): specific directory, command file and scheduled task left by MAS Online KMS method.
$onlineKMSDir = "C:\Program Files\Activation-Renewal"
if (Test-Path -Path $onlineKMSDir -PathType Container) {
    Add-Finding -Id "MAS_ONLINE_KMS_DIR" -Severity "High" -Area "MAS Online KMS" `
        -Evidence "MAS Online KMS directory present: $onlineKMSDir" `
        -Recommendation "Remove the directory, associated scheduled tasks, and reactivate Windows/Office legitimately."
}

foreach ($kmsFile in @("Activation_task.cmd", "Info.txt")) {
    $kmsFilePath = Join-Path $onlineKMSDir $kmsFile
    if (Test-Path -Path $kmsFilePath) {
        Add-Finding -Id "MAS_ONLINE_KMS_FILE" -Severity "High" -Area "MAS Online KMS" `
            -Evidence "MAS Online KMS file present: $kmsFilePath" `
            -Recommendation "Remove the file, associated scheduled tasks, and reactivate legitimately."
    }
}

try {
    $onlineKMSTask = Get-ScheduledTask -TaskName "Activation-Renewal" -ErrorAction SilentlyContinue
    if ($onlineKMSTask) {
        Add-Finding -Id "MAS_ONLINE_KMS_TASK" -Severity "High" -Area "MAS Online KMS" `
            -Evidence "MAS Online KMS scheduled task found: \Activation-Renewal" `
            -Recommendation "Delete the scheduled task and reactivate Windows/Office legitimately."
    }
}
catch {
    Write-Debug "Activation-Renewal task query failed: $($_.Exception.Message)"
    # Non-critical: task query failure is handled by the main scheduled task check below.
}

# Check authenticode signature of SppExtComObj.exe (legitimate file, but a tampered copy is a hard signal).
$sppExtPath = "$env:SystemRoot\System32\SppExtComObj.exe"
if (Test-Path -Path $sppExtPath) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $sppExtPath -ErrorAction Stop
        if ($sig.Status -ne "Valid") {
            Add-Finding -Id "SPPEXTCOMOBJ_INVALID_SIGNATURE" -Severity "High" -Area "File Indicators" `
                -Evidence "SppExtComObj.exe signature status: $($sig.Status). Expected: Valid (Microsoft)." `
                -Recommendation "Compare file hash against known-good baseline and investigate possible binary replacement."
        }
        elseif ($sig.SignerCertificate.Subject -notmatch "Microsoft") {
            Add-Finding -Id "SPPEXTCOMOBJ_UNEXPECTED_SIGNER" -Severity "High" -Area "File Indicators" `
                -Evidence "SppExtComObj.exe signed by unexpected publisher: $($sig.SignerCertificate.Subject)" `
                -Recommendation "File may have been replaced. Collect hash and escalate for forensic review."
        }
    }
    catch {
        Add-Finding -Id "SPPEXTCOMOBJ_SIGNATURE_ERROR" -Severity "Low" -Area "File Indicators" `
            -Evidence "Could not read authenticode signature of SppExtComObj.exe: $($_.Exception.Message)" `
            -Recommendation "Verify manually using Get-AuthenticodeSignature or sigcheck."
    }
}

# Check for KMS activator artifacts in ProgramData and common locations.
$programDataKmsGlob = @(
    "$env:ProgramData\KMS*",
    "$env:ProgramData\KMSAuto*",
    "$env:ProgramData\KMS_VL_ALL*",
    "$env:SystemRoot\System32\SppExtComObj*" # extra renamed copies
)
foreach ($glob in $programDataKmsGlob) {
    $matches = Get-Item -Path $glob -ErrorAction SilentlyContinue
    foreach ($match in $matches) {
        if ($match.FullName -ne $sppExtPath) {
            Add-Finding -Id "KMS_ARTIFACT_FOUND" -Severity "High" -Area "File Indicators" `
                -Evidence "KMS activator artifact found: $($match.FullName)" `
                -Recommendation "Inspect contents, remove unauthorized activator files, and validate licensing state."
        }
    }
}

# Check IFEO hooks for Office and Windows licensing services.
$ifeoTargets = @(
    "osppsvc.exe",
    "sppsvc.exe"
)

foreach ($target in $ifeoTargets) {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$target"
    if (Test-Path -Path $path) {
        $debugger = Get-RegistryValue -Path $path -Name "Debugger"
        $verifierDlls = Get-RegistryValue -Path $path -Name "VerifierDlls"
        $globalFlag = Get-RegistryValue -Path $path -Name "GlobalFlag"

        if (-not [string]::IsNullOrWhiteSpace($debugger)) {
            Add-Finding -Id "IFEO_DEBUGGER" -Severity "High" -Area "IFEO" -Evidence "$target has IFEO Debugger='$debugger'" -Recommendation "Investigate why process redirection is enabled for licensing service binaries."
        }

        if (-not [string]::IsNullOrWhiteSpace($verifierDlls)) {
            $severity = "Medium"
            if ($verifierDlls -match "sppcs\.dll") { $severity = "High" }
            Add-Finding -Id "IFEO_VERIFIER_DLLS" -Severity $severity -Area "IFEO" -Evidence "$target has IFEO VerifierDlls='$verifierDlls'" -Recommendation "Review verifier DLL chain and remove unauthorized hooks."
        }

        if ($null -ne $globalFlag -and "$globalFlag" -ne "") {
            Add-Finding -Id "IFEO_GLOBALFLAG" -Severity "Low" -Area "IFEO" -Evidence "$target has IFEO GlobalFlag='$globalFlag'" -Recommendation "Confirm GlobalFlag is expected by security tooling and not persistence abuse."
        }
    }
}

# KMS host checks (Windows + Office registry paths).
$kmsRegChecks = @(
    [pscustomobject]@{
        Area = "Windows"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
    },
    [pscustomobject]@{
        Area = "Office"
        Path = "HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform"
    }
)

foreach ($check in $kmsRegChecks) {
    $kmsHost = Get-RegistryValue -Path $check.Path -Name "KeyManagementServiceName"
    $kmsPort = Get-RegistryValue -Path $check.Path -Name "KeyManagementServicePort"

    if (-not [string]::IsNullOrWhiteSpace($kmsHost)) {
        $evidence = "$($check.Area) KMS host configured: $kmsHost"
        if ($kmsPort) { $evidence += ":$kmsPort" }

        if ($kmsHost -match "^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$") {
            Add-Finding -Id "KMS_LOCALHOST" -Severity "High" -Area "KMS" -Evidence $evidence -Recommendation "Validate if local host KMS is intentional. In most environments this is suspicious."
        }
        elseif ($kmsHost -match "kms|vlmcs") {
            Add-Finding -Id "KMS_HOST_PRESENT" -Severity "Info" -Area "KMS" -Evidence $evidence -Recommendation "Verify this host belongs to your organization and DNS resolves correctly."
        }
        else {
            Add-Finding -Id "KMS_CUSTOM_HOST" -Severity "Medium" -Area "KMS" -Evidence $evidence -Recommendation "Validate ownership of configured KMS host/IP and compare with CMDB."
        }
    }

    # Sprawdzenie niestandardowego portu nasłuchiwania KMS (domyślnie 1688 TCP).
    # KMS emulatory często używają alternatywnych portów by uniknąć konfliktu
    # z legalnym KMS lub by ukryć się przed skanerami sieciowymi.
    $kmsListeningPort = Get-RegistryValue -Path $check.Path -Name "KeyManagementServiceListeningPort"
    if ($kmsListeningPort -and [int]$kmsListeningPort -ne 1688) {
        Add-Finding -Id "KMS_NONSTANDARD_PORT" -Severity "High" -Area "KMS" `
            -Evidence "$($check.Area) KMS nasłuchuje na porcie $kmsListeningPort (standardowo 1688). Niestandardowy port to silny wskaźnik emulatora KMS." `
            -Recommendation "Sprawdź proces nasłuchujący na porcie $kmsListeningPort (netstat -ano). Jeśli to nieautoryzowany emulator KMS — zatrzymaj i usuń."
    }
}

# KMS DNS SRV: w domenie AD, legalny serwer KMS jest publikowany przez DNS
# jako _VLMCS._TCP.<domena>. Jeśli skonfigurowany host KMS NIE pasuje do
# rekordu SRV, może to wskazywać na zewnętrzny emulator KMS.
$kmsDnsMismatch = $false
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain -and $cs.Domain) {
        $kmsSrvRecord = "_VLMCS._TCP.$($cs.Domain)"
        try {
            $dnsResult = Resolve-DnsName -Name $kmsSrvRecord -Type SRV -ErrorAction Stop |
                Where-Object { $_.QueryType -eq 'SRV' } |
                Select-Object -First 1
            if ($dnsResult) {
                $advertisedKms = $dnsResult.NameTarget.TrimEnd('.')
                # Porównaj z hostem KMS w rejestrze (obie ścieżki)
                foreach ($check in $kmsRegChecks) {
                    $kmsHost = Get-RegistryValue -Path $check.Path -Name "KeyManagementServiceName"
                    if ($kmsHost -and -not [string]::IsNullOrWhiteSpace($kmsHost)) {
                        # Normalizuj: usuń port, porównaj hostname
                        $hostOnly = ($kmsHost -split ':')[0]
                        if ($hostOnly -notmatch [regex]::Escape($advertisedKms) -and
                            $advertisedKms -notmatch [regex]::Escape($hostOnly)) {
                            $kmsDnsMismatch = $true
                        }
                    }
                }
            } else {
                # Brak rekordu SRV KMS w domenie — to nie jest typowe dla AD z KMS
                # (może być ADBA, więc tylko Info)
            }
        }
        catch {
            Write-Debug "DNS KMS SRV query failed: $($_.Exception.Message)"
        }
    }
}
catch { Write-Debug "ComputerSystem domain check failed: $($_.Exception.Message)" }

if ($kmsDnsMismatch) {
    Add-Finding -Id "KMS_DNS_MISMATCH" -Severity "High" -Area "KMS" `
        -Evidence "Skonfigurowany host KMS NIE pasuje do rekordu SRV domeny ($kmsSrvRecord → $advertisedKms). KMS wskazuje na serwer spoza infrastruktury AD." `
        -Recommendation "Zweryfikuj czy host KMS należy do organizacji. Jeśli nie — może to być zewnętrzny emulator KMS używany przez MAS lub inny aktywator."
}

# slmgr output can provide extra hints, but strings are locale dependent.
try {
    $slmgrOutput = cscript //nologo C:\Windows\System32\slmgr.vbs /dlv 2>&1 | Out-String

    if ($slmgrOutput -match "2038") {
        Add-Finding -Id "SLMGR_2038_HINT" -Severity "Medium" -Area "slmgr" -Evidence "slmgr /dlv contains year 2038 marker. Could indicate KMS38-style activation behavior." -Recommendation "Cross-check activation renewal behavior and channel with official licensing records."
    }

    if ($slmgrOutput -match "Volume_KMSCLIENT" -and $slmgrOutput -notmatch "KMS machine name") {
        Add-Finding -Id "KMSCLIENT_NO_MACHINE_NAME" -Severity "Low" -Area "slmgr" -Evidence "KMS client channel seen but no explicit KMS machine name found in slmgr output." -Recommendation "Could be ADBA or transient state; verify activation source in domain environment."
    }
}
catch {
    Add-Finding -Id "SLMGR_READ_ERROR" -Severity "Low" -Area "slmgr" -Evidence "Unable to run slmgr /dlv: $($_.Exception.Message)" -Recommendation "Run script as Administrator to improve coverage."
}

# --- HWID / TSforge Detection ---
Write-Stage "Detecting HWID / TSforge activation..."

# HWID (Hardware ID) to najczęściej używana dziś metoda MAS do aktywacji Windows.
# Używa ClipSVC do wygenerowania biletu podpisanego kryptograficznie przez Microsoft
# — jest NIEROZRÓŻNIALNY od legalnej licencji cyfrowej na poziomie API i SPP store.
#
# OSTRZEŻENIE: HWID NIE MOŻNA wykryć przez porównanie daty modyfikacji plików SPP.
# LastWriteTime tokens.dat/data.dat/cache.dat zmienia się przy KAŻDEJ legalnej operacji:
# Windows Update, feature update, instalacji Office, odzyskiwaniu SPP, zmianie strefy.
# Timestampy w tej sekcji NIE SĄ samodzielnymi findingami — służą wyłącznie jako
# sygnał pomocniczy do korelacji z MOCNIEJSZYMI dowodami (GenuineTicket.xml,
# PowerShell event log, ślady forensyczne).
#
# Jedyne twarde dowody HWID/TSforge w tym skrypcie:
# - GenuineTicket.xml w ClipSVC (Check 4) — artefakt wstrzyknięcia biletu
# - Wpisy w PowerShell Operational log (sekcja Forensic Traces)
# - Ślady forensyczne plików aktywatorów (Recycle Bin, Prefetch, Security log)

$sppStorePath = "$env:SystemRoot\System32\spp\store\2.0"
$sppStoreFiles = @()
if (Test-Path -Path $sppStorePath) {
    try {
        $sppStoreFiles = @(Get-ChildItem -Path $sppStorePath -ErrorAction Stop)
    }
    catch {
        Add-Finding -Id "SPP_STORE_READ_ERROR" -Severity "Low" -Area "MAS HWID" `
            -Evidence "Nie można odczytać katalogu SPP store ($sppStorePath): $($_.Exception.Message)" `
            -Recommendation "Uruchom jako SYSTEM dla pełnego dostępu do SPP store."
    }
}

# Pobranie daty instalacji Windows do porównania osi czasu SPP
$windowsInstallDate = $null
$lastBootTime = $null
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $windowsInstallDate = $osInfo.InstallDate
    $lastBootTime = $osInfo.LastBootUpTime
}
catch {
    Write-Debug "Win32_OperatingSystem CIM query failed: $($_.Exception.Message)"
    Add-Finding -Id "OS_INFO_READ_ERROR" -Severity "Medium" -Area "System" `
        -Evidence "Nie można odczytać informacji o systemie operacyjnym (Win32_OperatingSystem): $($_.Exception.Message)" `
        -Recommendation "Sprawdź stan usługi CIM/WMI. Bez daty instalacji i uptime'u detekcja osi czasu SPP będzie ograniczona."
}

# --- Kontekst pomocniczy: upgrade Windows i instalacja Office ---
# Te dane pozwalają odróżnić naturalne modyfikacje SPP od wstrzyknięcia HWID.
# SPP store jest legalnie modyfikowany przy: upgrade Windows (7→10, 10→11),
# feature update (build upgrade), aktywacji Office, zmianie edycji, slmgr.

# Wykrycie upgrade'u Windows (np. 7→10, 10→11) — klucz istnieje tylko po upgrade
$isWindowsUpgraded = $false
$windowsUpgradeDate = $null
try {
    $setupKey = "HKLM:\SYSTEM\Setup"
    $sourceOsUpdated = Get-ItemProperty -Path $setupKey -Name "Source OS (Updated on)" -ErrorAction SilentlyContinue
    if ($sourceOsUpdated -and $sourceOsUpdated.'Source OS (Updated on)') {
        $rawDate = $sourceOsUpdated.'Source OS (Updated on)'
        try { $windowsUpgradeDate = Get-Date -Date $rawDate -ErrorAction Stop; $isWindowsUpgraded = $true } catch { Write-Debug "Source OS date parse failed: $($_.Exception.Message)" }
    }
}
catch { Write-Debug "Source OS upgrade detection skipped: $($_.Exception.Message)" }

# Druga ścieżka: MoSetup (Modern Setup) używany przy upgrade przez Windows Update
if (-not $isWindowsUpgraded) {
    try {
        $moSetup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MoSetup" -Name "UpgradeCodeDate" -ErrorAction SilentlyContinue
        if ($moSetup -and $moSetup.UpgradeCodeDate) {
            $isWindowsUpgraded = $true
        }
    }
    catch { Write-Debug "MoSetup upgrade detection skipped: $($_.Exception.Message)" }
}

# Data ostatniej instalacji Office — do korelacji z datą modyfikacji SPP
$officeInstallDates = @($officeInstalled | Where-Object { $_.InstallDate } | ForEach-Object {
        try { Get-Date $_.InstallDate -ErrorAction Stop } catch { $null }
    } | Where-Object { $_ -ne $null } | Sort-Object -Descending)
$latestOfficeInstallDate = if ($officeInstallDates.Count -gt 0) { $officeInstallDates[0] } else { $null }

# Check 1: tokens.dat — czas modyfikacji vs data instalacji Windows
# Trójstopniowa ocena: >365 dni (Medium), 90-365 dni (Low), <=90 dni (pominięte).
# Dodatkowo sprawdza legalne wyjaśnienia: upgrade Windows, instalacja Office, feature update.
$tokensDat = $sppStoreFiles | Where-Object { $_.Name -eq "tokens.dat" } | Select-Object -First 1
if ($tokensDat -and $windowsInstallDate) {
    $daysAfterInstall = [math]::Round(($tokensDat.LastWriteTime - $windowsInstallDate).TotalDays, 0)
    $tokensModDate = $tokensDat.LastWriteTime

    # Określenie czy istnieje legalne wyjaśnienie modyfikacji SPP
    $legitimateReason = ""

    # Wyjaśnienie A: upgrade Windows (7→10, 10→11) w pobliżu daty modyfikacji SPP
    if ($windowsUpgradeDate) {
        $daysFromUpgrade = [math]::Abs(($tokensModDate - $windowsUpgradeDate).TotalDays)
        if ($daysFromUpgrade -le 30) {
            $legitimateReason = "upgrade Windows (data upgrade'u: $($windowsUpgradeDate.ToString('yyyy-MM-dd')), różnica $([math]::Round($daysFromUpgrade,0)) dni od modyfikacji tokens.dat)"
        }
    }

    # Wyjaśnienie B: instalacja Office w pobliżu daty modyfikacji SPP
    if (-not $legitimateReason -and $latestOfficeInstallDate) {
        $daysFromOffice = [math]::Abs(($tokensModDate - $latestOfficeInstallDate).TotalDays)
        if ($daysFromOffice -le 14) {
            $legitimateReason = "instalacja Office (data: $($latestOfficeInstallDate.ToString('yyyy-MM-dd')), różnica $([math]::Round($daysFromOffice,0)) dni od modyfikacji tokens.dat)"
        }
    }

    # Wyjaśnienie C: feature update / upgrade wykryty po numerze buildu
    # Np. build >= 22000 (Win11) ale instalacja przed premierą Win11 (2021-10)
    if (-not $legitimateReason -and $osInfo) {
        try {
            $currentBuild = [int]$osInfo.BuildNumber
            if ($currentBuild -ge 22000 -and $windowsInstallDate -lt (Get-Date "2021-10-01")) {
                $legitimateReason = "prawdopodobny upgrade do Windows 11 (build $currentBuild, oryginalna instalacja $($windowsInstallDate.ToString('yyyy-MM')))"
            }
        }
        catch { Write-Debug "BuildNumber cast failed: $($_.Exception.Message)" }
    }

    # --- Ocena trójstopniowa ---
    # --- Ocena osi czasu SPP (tylko jako flag pomocniczy, NIE jako samodzielny finding) ---
    # Timestampy plików SPP zmieniają się przy każdej legalnej operacji systemowej.
    # Te dane NIE SĄ dowodem — służą wyłącznie do korelacji z twardymi sygnałami
    # (GenuineTicket.xml, PowerShell log, ślady forensyczne).
    $sppTimelineSuspicious = $false

    if ($daysAfterInstall -gt 365 -and -not $legitimateReason) {
        # >365 dni bez wyjaśnienia: słaby sygnał, tylko do korelacji
        $sppTimelineSuspicious = $true
    }

    # Check 2: tokens.dat zmodyfikowany podczas trwającej sesji (bez rebootu)
    # Modyfikacja SPP w trakcie sesji jest nietypowa, ale nadal możliwa legalnie
    # (naprawa sppsvc, instalacja roli/feature). Traktowane jako sygnał orientacyjny.
    $hoursSinceTokenMod = [math]::Round(((Get-Date) - $tokensModDate).TotalHours, 2)
    if ($hoursSinceTokenMod -lt 48 -and $lastBootTime) {
        $uptimeHours = [math]::Round(((Get-Date) - $lastBootTime).TotalHours, 2)
        if ($uptimeHours -gt 48 -and $hoursSinceTokenMod -lt $uptimeHours) {
            Add-Finding -Id "SPP_TOKENS_MOD_MID_SESSION" -Severity "Medium" -Area "MAS HWID" `
                -Evidence "tokens.dat zmodyfikowany $hoursSinceTokenMod godzin(y) temu, system działa od $uptimeHours godzin. Modyfikacja SPP w trakcie sesji (bez rebootu) — może być skutkiem ubocznym legalnych operacji (naprawa sppsvc, Windows Update), ale też charakterystyczna dla aktywacji HWID/TSforge." `
                -Recommendation "Słaby sygnał — NIE jest dowodem aktywacji. Skoreluj z twardymi wskaźnikami: GenuineTicket.xml, wpisy w PowerShell log, ślady plików aktywatorów."
            $sppTimelineSuspicious = $true
        }
    }
}

# Check 3: data.dat — synchronizacja modyfikacji z tokens.dat (tylko jako flag pomocniczy)
$dataDat = $sppStoreFiles | Where-Object { $_.Name -eq "data.dat" } | Select-Object -First 1
if ($dataDat -and $tokensDat) {
    $timeDiff = [math]::Abs(($dataDat.LastWriteTime - $tokensDat.LastWriteTime).TotalSeconds)
    if ($timeDiff -le 5) {
        $daysSinceMod = [math]::Round(((Get-Date) - $tokensDat.LastWriteTime).TotalDays, 0)
        if ($daysSinceMod -lt 30) {
            $sppTimelineSuspicious = $true
        }
    }
}

# Check 4: GenuineTicket.xml — pozostałość po HWID (ClipSVC normalnie sprząta po sobie)
$genuineTicketGlobs = @(
    "$env:ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket\GenuineTicket.xml",
    "$env:ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket\*.xml"
)
foreach ($gtGlob in $genuineTicketGlobs) {
    $gtFiles = @(Get-Item -Path $gtGlob -ErrorAction SilentlyContinue)
    foreach ($gtFile in $gtFiles) {
        Add-Finding -Id "HWID_GENUINE_TICKET" -Severity "High" -Area "MAS HWID" `
            -Evidence "Znaleziono pozostałość GenuineTicket.xml: $($gtFile.FullName) | LastWrite: $($gtFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
            -Recommendation "Ten plik jest tworzony przez aktywację HWID i nie powinien istnieć. Usuń plik i zbadaj historię aktywacji."
    }
}

# Check 5: Wskaźniki plikowe TSforge — DLL hooki podobne do Ohook, ale dla Windows SPP
$tsforgeIndicatorPaths = @(
    "$env:SystemRoot\System32\sppc.dll",
    "$env:SystemRoot\SysWOW64\sppc.dll",
    "$env:SystemRoot\System32\sppcext.dll",
    "$env:SystemRoot\SysWOW64\sppcext.dll"
)
foreach ($tsPath in $tsforgeIndicatorPaths) {
    if (Test-Path -Path $tsPath) {
        $suspicious = $false
        try {
            $tsSig = Get-AuthenticodeSignature -FilePath $tsPath -ErrorAction Stop
            if ($tsSig.Status -ne "Valid" -or $tsSig.SignerCertificate.Subject -notmatch "Microsoft") {
                $suspicious = $true
            }
        }
        catch {
            $suspicious = $true
        }

        if ($suspicious) {
            Add-Finding -Id "TSFORGE_FILE_PRESENT" -Severity "High" -Area "MAS TSforge" `
                -Evidence "Podejrzany DLL hook SPP obecny: $tsPath" `
                -Recommendation "Zbierz hash pliku, sprawdź podpis i porównaj ze znanym-dobrym wzorcem. TSforge używa DLL hooków do obejścia walidacji SPP."
        }
    }
}

# Check 6: Klucz OEM w firmware vs kanał Retail — HWID daje Retail, ale może brakować klucza OEM
try {
    $oemKey = (Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop).OA3xOriginalProductKey
}
catch {
    $oemKey = $null
}

$retailWinLic = @($winSummary | Where-Object { $_.Channel -eq "Retail" -and $_.LicenseStatusText -eq "Licensed" })
if ($retailWinLic.Count -gt 0 -and [string]::IsNullOrWhiteSpace($oemKey)) {
    Add-Finding -Id "HWID_RETAIL_NO_OEM_KEY" -Severity "Medium" -Area "MAS HWID" `
        -Evidence "Windows pokazuje kanał Retail i status Licensed, ale nie znaleziono klucza OEM w firmware (tabela MSDM). Urządzenia konsumenckie normalnie go posiadają." `
        -Recommendation "Jeśli to urządzenie konsumenckie (laptop/fabryczny PC), brak klucza OEM przy licencji Retail jest anomalią. Zweryfikuj źródło licencji."
}

# Check 7: cache.dat — spójność czasowa z tokens.dat (tylko jako flag pomocniczy)
$cacheDat = $sppStoreFiles | Where-Object { $_.Name -eq "cache.dat" } | Select-Object -First 1
if ($cacheDat -and $tokensDat) {
    $cacheTokenDiff = [math]::Abs(($cacheDat.LastWriteTime - $tokensDat.LastWriteTime).TotalSeconds)
    if ($cacheTokenDiff -le 10) {
        $daysSinceCache = [math]::Round(((Get-Date) - $cacheDat.LastWriteTime).TotalDays, 0)
        if ($daysSinceCache -lt 30) {
            $sppTimelineSuspicious = $true
        }
    }
}

# --- SPP Store Integrity Verification ---
Write-Stage "Verifying SPP Store integrity..."

# Porównanie hashu tokens.dat/data.dat z wzorcem Microsoft nie jest możliwe:
# zawartość tych plików jest unikalna dla każdej maszyny i zmienia się legalnie
# przy każdej aktywacji. Bilety HWID wstrzyknięte przez ClipSVC są podpisane
# kryptograficznie poprawnie — nie do odróżnienia na poziomie podpisu.
# Weryfikacja integralności opiera się zatem na metadanych systemu plików:
# ACL, Alternate Data Streams i podpisy cyfrowe binariów SPP.

# Check 8: ACL katalogu SPP store — domyślnie tylko SYSTEM i TrustedInstaller mają zapis

# SID-based check to avoid localization issues (Polish "ZARZĄDZANIE NT\SYSTEM" vs English "NT AUTHORITY\SYSTEM")
$wellKnownSafeSids = @('S-1-5-18', 'S-1-5-32-544')  # SYSTEM, Administrators
function Test-IsSafePrincipal {
    param($IdentityRef)
    try {
        $sid = $IdentityRef.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($sid -in $wellKnownSafeSids) { return $true }
        # TrustedInstaller and any NT SERVICE account (S-1-5-80-*)
        if ($sid -match '^S-1-5-80-') { return $true }
        return $false
    } catch { return $false }
}

if (Test-Path -Path $sppStorePath) {
    try {
        $sppAcl = Get-Acl -Path $sppStorePath -ErrorAction Stop
        $sppAccess = $sppAcl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|Modify|FullControl|Change' -and
            $_.AccessControlType -eq 'Allow' -and
            -not (Test-IsSafePrincipal $_.IdentityReference)
        }
        if ($sppAccess) {
            $grantedTo = ($sppAccess.IdentityReference | Select-Object -Unique) -join ', '
            Add-Finding -Id "SPP_STORE_ACL_RELAXED" -Severity "High" -Area "MAS HWID" `
                -Evidence "Katalog SPP store ($sppStorePath) ma nadpisane uprawnienia zapisu dla: $grantedTo. Domyślnie tylko SYSTEM i TrustedInstaller mają dostęp do zapisu." `
                -Recommendation "Przywróć domyślne uprawnienia NTFS dla katalogu SPP store. Rozszerzone uprawnienia umożliwiają nieautoryzowaną modyfikację bazy aktywacji."
        }
    }
    catch {
        Add-Finding -Id "SPP_ACL_READ_ERROR" -Severity "Low" -Area "MAS HWID" `
            -Evidence "Nie można odczytać ACL katalogu SPP store: $($_.Exception.Message)" `
            -Recommendation "Sprawdź uprawnienia ręcznie w Eksploratorze: Właściwości → Zabezpieczenia."
    }
}

# Check 9: ACL na kluczowych plikach SPP (tokens.dat, data.dat, cache.dat)
$sppKeyFiles = @($tokensDat, $dataDat, $cacheDat) | Where-Object { $_ -ne $null }
foreach ($sppFile in $sppKeyFiles) {
    try {
        $fileAcl = Get-Acl -Path $sppFile.FullName -ErrorAction Stop
        $fileAccess = $fileAcl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
            $_.AccessControlType -eq 'Allow' -and
            -not (Test-IsSafePrincipal $_.IdentityReference)
        }
        if ($fileAccess) {
            $grantedTo = ($fileAccess.IdentityReference | Select-Object -Unique) -join ', '
            Add-Finding -Id "SPP_FILE_ACL_RELAXED" -Severity "High" -Area "MAS HWID" `
                -Evidence "Plik SPP $($sppFile.Name) ma nadpisane uprawnienia zapisu dla: $grantedTo. Domyślnie tylko SYSTEM ma prawo zapisu." `
                -Recommendation "Przywróć domyślne ACL na plikach SPP store. Nieautoryzowany dostęp do zapisu umożliwia wstrzyknięcie biletu HWID."
        }
    }
    catch {
        Write-Debug "SPP file ACL read failed: $($_.Exception.Message)"
        # Błąd odczytu ACL na pojedynczym pliku — niekrytyczny.
    }
}

# Check 10: Alternate Data Streams (ADS) na plikach SPP store
# Niektóre aktywatory ukrywają dane lub kopie zapasowe w strumieniach NTFS.
foreach ($sppFile in $sppKeyFiles) {
    try {
        $streams = Get-Item -Path $sppFile.FullName -Stream * -ErrorAction Stop
        $nonDefaultStreams = $streams | Where-Object { $_.Stream -ne ':$DATA' }
        foreach ($ads in $nonDefaultStreams) {
            Add-Finding -Id "SPP_FILE_ADS_PRESENT" -Severity "High" -Area "MAS HWID" `
                -Evidence "Alternate Data Stream wykryty na $($sppFile.Name): '$($ads.Stream)' (rozmiar: $($ads.Length) B)" `
                -Recommendation "Pliki SPP store nie powinny zawierać alternatywnych strumieni NTFS. Zbadaj zawartość ADS (Get-Content -Stream) i usuń."
        }
    }
    catch {
        Write-Debug "SPP file ADS check failed: $($_.Exception.Message)"
        # Błąd odczytu ADS — niekrytyczny (może wystąpić na wolumenach nienależących do NTFS).
    }
}

# Check 11: Podpisy cyfrowe wszystkich binariów SPP w System32 i SysWOW64
# Rozszerza istniejący check SppExtComObj.exe na cały ekosystem SPP.
$sppBinaryGlobs = @(
    "$env:SystemRoot\System32\spp*.dll",
    "$env:SystemRoot\System32\spp*.exe",
    "$env:SystemRoot\SysWOW64\spp*.dll",
    "$env:SystemRoot\SysWOW64\spp*.exe"
)
foreach ($sppGlob in $sppBinaryGlobs) {
    $sppBinaries = @(Get-Item -Path $sppGlob -ErrorAction SilentlyContinue)
    foreach ($bin in $sppBinaries) {
        # SppExtComObj.exe — już sprawdzony wyżej
        if ($bin.Name -eq "SppExtComObj.exe") { continue }
        # DLL-i TSforge — już sprawdzone osobno
        if ($bin.Name -in @("sppc.dll", "sppcext.dll")) { continue }

        try {
            $sig = Get-AuthenticodeSignature -FilePath $bin.FullName -ErrorAction Stop
            if ($sig.Status -ne "Valid") {
                Add-Finding -Id "SPP_BINARY_INVALID_SIGNATURE" -Severity "High" -Area "MAS HWID" `
                    -Evidence "Podpis cyfrowy $($bin.Name) jest nieważny (status: $($sig.Status)). Oczekiwano Valid (Microsoft)." `
                    -Recommendation "Plik binarny SPP mógł zostać zastąpiony. Porównaj hash z czystą wersją Windows dla tej kompilacji i przeprowadź dochodzenie."
            }
            elseif ($sig.SignerCertificate.Subject -notmatch "Microsoft") {
                Add-Finding -Id "SPP_BINARY_UNEXPECTED_SIGNER" -Severity "High" -Area "MAS HWID" `
                    -Evidence "$($bin.Name) podpisany przez nieoczekiwanego wydawcę: $($sig.SignerCertificate.Subject)" `
                    -Recommendation "Plik SPP z nie-microsoftowym podpisem — prawdopodobna podmiana. Zbierz hash i eskalij do analizy forensiczej."
            }
        }
        catch {
            Write-Debug "SPP binary signature check failed: $($_.Exception.Message)"
            # Błąd odczytu podpisu pojedynczego pliku — niekrytyczny.
        }
    }
}

# --- Forensic Traces: detect deleted or previously-run activator tools ---
Write-Stage "Collecting forensic traces (Prefetch, PowerShell log, AMSI, VSS)..."

# UWAGA OGRANICZENIA:
# - Prefetch: tylko EXE (MAS .ps1/.cmd NIE tworzy wpisow). Regex lapa tylko
#   niezmienione nazwy plikow — trywialne do obejscia przez rename.
# - PowerShell log: przechwytuje wykonane skrypty przez Event ID 4103/4104.
#   Skuteczniejszy niz Prefetch, ale nadal omijalny przez obfuskacje.
# - Recycle Bin: wiekszosc aktywatorow uruchamia sie z uprawnieniami SYSTEM
#   i self-destruct przez Shift+Delete / del — NIE trafiaja do kosza.
# - Security log (4660): jedyne zrodlo wykrywajace Shift+Delete, ale wymaga
#   Audit File System wlaczonego w secpol.msc (domyslnie wylaczone na client SKU).
# - AMSI/Defender (ponizej): najlepsza metoda — przechwytuje tresc skryptu
#   niezaleznie od nazwy pliku. Wymaga dzialajacego Windows Defender.
#
# WNIOSEK: Te checki NIE sa wyczerpujace. Wykrywaja tylko slady pozostawione
# przez nieostroznych uzytkownikow lub stare/naiwne aktywatory.

# Prefetch files survive EXE deletion and record execution time.
# LIMITATIONS: Only EXE files (MAS .ps1/.cmd does NOT create Prefetch).
# Regex matches only well-known unchanged filenames — trivially bypassed by renaming.
# Detects only the clumsiest users and oldest activator EXE wrappers.
Write-Host "  [*] Scanning Prefetch..." -ForegroundColor DarkGray
$prefetchPath = "$env:SystemRoot\Prefetch"
$prefetchIndicatorRegex = '(?i)^(autokms|kmsauto|kms_?auto|kmspico|aact(64)?|heu_kms|kms_vl_all|vlmcsd|kmseldi|km_service)'
if (Test-Path -Path $prefetchPath) {
    try {
        $prefetchHits = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction Stop |
            Where-Object { $_.BaseName -match $prefetchIndicatorRegex }
        foreach ($pf in $prefetchHits) {
            Add-Finding -Id "PREFETCH_ACTIVATOR" -Severity "Medium" -Area "Forensic Traces" `
                -Evidence "Prefetch entry found (EXE was run, possibly deleted): $($pf.Name) | LastWrite: $($pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
                -Recommendation "This file proves the program was executed on this machine. Investigate activation history and validate current license state."
        }
    }
    catch {
        Add-Finding -Id "PREFETCH_READ_ERROR" -Severity "Low" -Area "Forensic Traces" `
            -Evidence "Could not read Prefetch directory: $($_.Exception.Message)" `
            -Recommendation "Verify Prefetch is enabled and script is running as Administrator."
    }
}

# PowerShell event logs (4103/4104): przechwytuje wykonane bloki skryptu.
# Lepiej niz Prefetch, bo dziala niezaleznie od nazwy pliku. Nadal omijalny
# przez obfuskacje, ale lapanie wzorcow BEHAWIORALNYCH (slmgr, ClipSVC, SPP)
# zamiast tylko nazw aktywatorow daje szersze pokrycie.
Write-Host "  [*] Searching PowerShell Operational log (up to 90 days)... (>najdluzej)" -ForegroundColor DarkGray
$psIndicatorRegex = '(?i)(Microsoft\.Activation\.Scripts|Activation-Renewal|Online_KMS|HWID_Activation|TSforge|MAS_AllInOne|\bohook\b|\bkmsauto\b|\bkmspico\b|\bheu_kms\b|\bvlmcsd\b|\bAAct\b|slmgr\s.*\/ipk|slmgr\s.*\/upk|ClipSVC|GenuineTicket|SoftwareLicensingProduct|SppExtComObj|tokens\.dat|\bHWID\b|TSforge\b|\bKMS38\b|sppsvc|osppsvc|spp\.dll|sppc\.dll|hook\.dll)'
try {
    $psOpLog = "Microsoft-Windows-PowerShell/Operational"
    if (Get-WinEvent -ListLog $psOpLog -ErrorAction SilentlyContinue) {
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $psOpLog
            ID        = 4103, 4104
            StartTime = (Get-Date).AddDays(-90)
        } -MaxEvents 5000 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match $psIndicatorRegex -and $_.ProcessId -ne $PID -and $_.Message -notmatch 'HWID_GENUINE_TICKET|POWERSHELL_LOG_ACTIVATOR|AMSI_ACTIVATOR_DETECTION|CORR_HWID|SPP_TOKENS_MOD_MID_SESSION' }

        foreach ($evt in $psEvents) {
            # Extract a snippet around the match for human-readable evidence
            $matchMatch = [regex]::Match($evt.Message, $psIndicatorRegex)
            $ctxStart = [Math]::Max(0, $matchMatch.Index - 80)
            $ctxLen   = [Math]::Min(240, $evt.Message.Length - $ctxStart)
            $snippet  = ($evt.Message.Substring($ctxStart, $ctxLen) -replace '\s+', ' ').Trim()

            Add-Finding -Id "POWERSHELL_LOG_ACTIVATOR" -Severity "High" -Area "Forensic Traces" `
                -Evidence "PowerShell event ID $($evt.Id) zawiera wzorzec aktywatora (marka lub zachowanie: slmgr/ClipSVC/SPP). TimeCreated: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Kontekst: ...$snippet..." `
                -Recommendation "PowerShell operational log przechwycil wykonanie skryptu aktywatora lub manipulacji SPP. Skoreluj timestamp ze zdarzeniami aktywacji i sesja uzytkownika."
        }
    }
}
catch {
    Add-Finding -Id "POWERSHELL_LOG_READ_ERROR" -Severity "Low" -Area "Forensic Traces" `
        -Evidence "Could not query PowerShell Operational log: $($_.Exception.Message)" `
        -Recommendation "Verify the PowerShell Operational log is enabled and the script runs as Administrator."
}

# AMSI / Windows Defender log: NAJLEPSZA metoda wykrywania skryptow aktywatorow.
# AMSI skanuje TRESC skryptu w runtime — niezaleznie od nazwy pliku, obfuskacji
# czy metody uruchomienia. Event ID 1116 (wykrycie) i 1117 (akcja) w dzienniku
# Windows Defender Operational przechwytuja to, co pominely pozostale checki.
# Wymaga dzialajacego Windows Defender (domyslnie wlaczony na client SKU).
Write-Host "  [*] Searching Defender/AMSI log..." -ForegroundColor DarkGray
$amsiIndicatorRegex = '(?i)(hacktool|activator|kms|ohook|hwid|tsforge|autokms|kmspico|aact|vlmcsd|sppc|malware|trojan)'
try {
    $defenderLog = "Microsoft-Windows-Windows Defender/Operational"
    if (Get-WinEvent -ListLog $defenderLog -ErrorAction SilentlyContinue) {
        $amsiEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $defenderLog
            ID        = 1116, 1117
            StartTime = (Get-Date).AddDays(-90)
        } -MaxEvents 2000 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match $amsiIndicatorRegex }

        foreach ($evt in $amsiEvents) {
            # AMSI events zawieraja nazwe wykrytego zagrozenia w Message
            $threatName = if ($evt.Message -match 'Threat Name:\s*(.+?)(\r|\n|$)') { $Matches[1].Trim() } else { "(unknown)" }
            Add-Finding -Id "AMSI_ACTIVATOR_DETECTION" -Severity "High" -Area "Forensic Traces" `
                -Evidence "AMSI/Defender Event ID $($evt.Id): wykryto zagrozenie '$threatName'. TimeCreated: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                -Recommendation "AMSI wykrylo skrypt aktywatora po TRESCI, nie nazwie pliku — to NAJMOCNIEJSZY sygnal w tej sekcji. Sprawdz pelna sciezke pliku i historie w Event Logu Defender."
        }
    }
}
catch {
    Write-Debug "AMSI/Defender log query failed: $($_.Exception.Message)"
    # Defender log niedostepny — moze byc wylaczony lub skrypt bez uprawnien.
    # Nie tworzymy findingu — brak logu nie jest anomalia.
}

# Recycle Bin: $I metadata files contain original path of deleted items (Windows Vista+).
# Binary format (v2, Windows 10): [8 version][8 size][8 FILETIME][4 pathLen][pathLen*2 Unicode path]
# Checked on ALL fixed drives (not just C:), since users may have deleted activator files from any volume.
# LIMITATION: Most activators run as SYSTEM and self-destruct via Shift+Delete / del,
# completely bypassing the Recycle Bin. This check catches only clumsy manual deletions.
Write-Host "  [*] Scanning Recycle Bin metadata..." -ForegroundColor DarkGray
$activatorPathRegex = '(?i)(autokms|kmsauto|kmspico|kms_vl_all|aact|ohook|sppcs\.dll|activation.renewal|mas_|heu_kms|vlmcsd)'

# Enumerate all fixed drives (type 3) for Recycle Bin search.
$fixedDrives = @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 3 })
if (-not $fixedDrives) { $fixedDrives = @([pscustomobject]@{ DeviceID = "C:" }) }

foreach ($drive in $fixedDrives) {
    $recycleBinRoot = "$($drive.DeviceID)\`$Recycle.Bin"
    if (-not (Test-Path -Path $recycleBinRoot)) { continue }

    try {
        $iFiles = Get-ChildItem -Path $recycleBinRoot -Recurse -Force -Filter "`$I*" -ErrorAction SilentlyContinue
        foreach ($iFile in $iFiles) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($iFile.FullName)
                if ($bytes.Length -ge 28) {
                    $version = [BitConverter]::ToInt64($bytes, 0)
                    if ($version -eq 2) {
                        # v2 (Win8+): path length at offset 24 (int32), path at offset 28 (Unicode)
                        $pathLen = [BitConverter]::ToInt32($bytes, 24)
                        $byteCount = $pathLen * 2
                        if ($pathLen -gt 0 -and ($byteCount + 28) -le $bytes.Length) {
                            $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $byteCount).TrimEnd([char]0)
                            if ($originalPath -match $activatorPathRegex) {
                                $deletedAt = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16)).ToString('yyyy-MM-dd HH:mm:ss')
                                Add-Finding -Id "RECYCLEBIN_ACTIVATOR" -Severity "Medium" -Area "Forensic Traces" `
                                    -Evidence "Usuniety plik aktywatora w Koszu ($($drive.DeviceID)): '$originalPath' | Usuniety: $deletedAt. UWAGA: wiekszosc aktywatorow omija Kosz przez Shift+Delete — ten slad zostawil tylko nieostrozny uzytkownik." `
                                    -Recommendation "Plik zostal usuniety, ale trafil do Kosza (nietypowe dla aktywatorow SYSTEM). Zweryfikuj obecny stan licencji — aktywator mogl dzialac przed usunieciem."
                            }
                        }
                    }
                    elseif ($version -eq 1) {
                        # v1 (Vista/Win7): fixed 260 UTF-16 chars at offset 24
                        if ($bytes.Length -ge 544) {
                            $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 24, 520).TrimEnd([char]0)
                            if ($originalPath -match $activatorPathRegex) {
                                $deletedAt = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16)).ToString('yyyy-MM-dd HH:mm:ss')
                                Add-Finding -Id "RECYCLEBIN_ACTIVATOR" -Severity "Medium" -Area "Forensic Traces" `
                                    -Evidence "Usuniety plik aktywatora w Koszu ($($drive.DeviceID)): '$originalPath' | Usuniety: $deletedAt. UWAGA: wiekszosc aktywatorow omija Kosz przez Shift+Delete — ten slad zostawil tylko nieostrozny uzytkownik." `
                                    -Recommendation "Plik zostal usuniety, ale trafil do Kosza (nietypowe dla aktywatorow SYSTEM). Zweryfikuj obecny stan licencji — aktywator mogl dzialac przed usunieciem."
                            }
                        }
                    }
                }
            }
            catch {
                Write-Debug "Recycle Bin metadata file skipped: $($_.Exception.Message)"
                # Skip unreadable $I files (locked or corrupt).
            }
        }
    }
    catch {
        Add-Finding -Id "RECYCLEBIN_READ_ERROR" -Severity "Low" -Area "Forensic Traces" `
            -Evidence "Could not enumerate Recycle Bin on $($drive.DeviceID): $($_.Exception.Message)" `
            -Recommendation "Run as Administrator to access all user Recycle Bin entries across all drives."
    }
}

# Security event log: if file audit policy is enabled, Event ID 4660 records
# file deletions INCLUDING Shift+Delete (which bypasses Recycle Bin entirely).
# Requires "Audit File System" or "Audit Object Access" in Local Security Policy
# (secpol.msc) — NOT enabled by default on client SKUs.
Write-Host "  [*] Searching Security log (Event 4660)..." -ForegroundColor DarkGray
try {
    $secLogName = "Security"
    if (Get-WinEvent -ListLog $secLogName -ErrorAction SilentlyContinue) {
        $secDelEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $secLogName
            ID        = 4660
            StartTime = (Get-Date).AddDays(-90)
        } -MaxEvents 2000 -ErrorAction SilentlyContinue

        foreach ($evt in $secDelEvents) {
            try {
                $xml = [xml]$evt.ToXml()
                [array]$nsData = $xml.Event.EventData.Data
                $objectName = ($nsData | Where-Object { $_.Name -eq "ObjectName" }).'#text'
                if ($objectName -and $objectName -match $activatorPathRegex) {
                    Add-Finding -Id "SECLOG_DELETION_AUDIT" -Severity "High" -Area "Forensic Traces" `
                        -Evidence "Security audit Event ID 4660 — activator file permanently deleted (Shift+Delete / direct erase): '$objectName' | TimeCreated: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" `
                        -Recommendation "Audit policy captured permanent deletion of activator file (bypassed Recycle Bin). Correlate deletion timestamp with user session activity."
                }
            }
            catch {
                Write-Debug "Security event XML parse failed: $($_.Exception.Message)"
                # Skip unparseable events.
            }
        }
    }
}
catch {
    Write-Debug "Security log query failed: $($_.Exception.Message)"
    # Security log may be inaccessible even as Administrator (requires SeSecurityPrivilege).
    # Expected on most consumer machines — not an error worth surfacing.
}

# VSS (Volume Shadow Copy): system restore points and backup snapshots preserve
# file history, including files later permanently deleted (Shift+Delete) or
# emptied from Recycle Bin. Deep forensic analysis can recover them.
Write-Host "  [*] Enumerating Volume Shadow Copies..." -ForegroundColor DarkGray
try {
    $vssCopies = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop)
    if ($vssCopies.Count -gt 0) {
        $oldestVss = ($vssCopies | Sort-Object InstallDate | Select-Object -First 1).InstallDate
        $newestVss = ($vssCopies | Sort-Object InstallDate | Select-Object -Last 1).InstallDate
        Add-Finding -Id "VSS_SHADOW_COPIES_PRESENT" -Severity "Info" -Area "Forensic Traces" `
            -Evidence "$($vssCopies.Count) Volume Shadow Copy snapshot(s) found spanning $($oldestVss.ToString('yyyy-MM-dd')) to $($newestVss.ToString('yyyy-MM-dd')). Snapshots may preserve deleted activator files predating Recycle Bin cleanup or permanent erasure." `
            -Recommendation "Mount shadow copies with 'mklink /D' or forensic tools (KAPE, Arsenal Image Mounter) to search for activator artifacts in historical file system snapshots."
    }
}
catch {
    Write-Debug "VSS shadow copy query failed: $($_.Exception.Message)"
    # VSS may be disabled or inaccessible. Not an error — just no shadow copies to check.
}

# --- End Forensic Traces ---

# Check suspicious scheduled tasks.
try {
    $taskIndicatorRegex = '(?i)(^|[^a-z0-9])(autokms|kmsauto|kmspico|heu_kms|vlmcs|aact|ohook|microsoft-activation-scripts|online_kms|kms_vl_all)([^a-z0-9]|$)'
    $taskMatches = Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskName -match $taskIndicatorRegex -or
        $_.TaskPath -match $taskIndicatorRegex
    }

    foreach ($task in $taskMatches) {
        Add-Finding -Id "SUSPICIOUS_TASK" -Severity "Medium" -Area "Scheduled Tasks" -Evidence "Task: $($task.TaskPath)$($task.TaskName) (nazwa pasuje do wzorca aktywatora)" -Recommendation "Inspect task actions, creator, and execution history."
    }

    # Behawioralna analiza zadań: szukaj PowerShell z -WindowStyle Hidden,
    # -ExecutionPolicy Bypass, -EncodedCommand (Base64) — wzorzec używany
    # przez MAS Online KMS i większość aktywatorów PowerShell.
    # Analizuje .Actions.Execute i .Actions.Arguments, nie tylko nazwę zadania.
    $behavioralTaskRegex = '(?i)(-WindowStyle\s+Hidden|-ExecutionPolicy\s+Bypass|-EncodedCommand\s+\S{10,}|Activation-Renewal|\\MAS\\|\bohook\b|\bHWID\b|\bTSforge\b|\bslmgr\b\s|/ipk\b|/upk\b|Massgravel|MicrosoftActivationScripts)'
    $allTasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($task in $allTasks) {
        try {
            $taskActions = $task.Actions
            $suspiciousAction = $false
            $actionDetail = ""
            foreach ($action in $taskActions) {
                $actionText = "$($action.Execute) $($action.Arguments)"
                if ($actionText -match $behavioralTaskRegex) {
                    $suspiciousAction = $true
                    $actionDetail = ($actionText -replace '\s+', ' ').Trim()
                    break
                }
            }
            if ($suspiciousAction) {
                # Sprawdź czy zadanie nie zostało już złapane przez nazwę
                $alreadyFound = $taskMatches | Where-Object { $_.TaskName -eq $task.TaskName -and $_.TaskPath -eq $task.TaskPath }
                if (-not $alreadyFound) {
                    Add-Finding -Id "SUSPICIOUS_TASK_BEHAVIOR" -Severity "High" -Area "Scheduled Tasks" `
                        -Evidence "Zadanie '$($task.TaskPath)$($task.TaskName)' ma podejrzane zachowanie: $actionDetail" `
                        -Recommendation "Zadanie uruchamia PowerShell z flagami typowymi dla aktywatorów (-Hidden, -Bypass, -EncodedCommand). Sprawdź akcję zadania i historię wykonania."
                }
            }
        }
        catch { Write-Debug "Task action check failed for $($task.TaskName): $($_.Exception.Message)" }
    }
}
catch {
    Add-Finding -Id "TASK_QUERY_ERROR" -Severity "Low" -Area "Scheduled Tasks" -Evidence "Could not query scheduled tasks: $($_.Exception.Message)" -Recommendation "Run with elevated privileges for full task visibility."
}

# Check suspicious services by name/display/path.
try {
    $serviceIndicatorRegex = '(?i)(^|[^a-z0-9])(autokms|kmsauto|kmspico|heu_kms|vlmcs|aact|ohook|sppcs|microsoft-activation-scripts)([^a-z0-9]|$)'
    $svcMatches = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
        $_.Name -match $serviceIndicatorRegex -or
        $_.DisplayName -match $serviceIndicatorRegex -or
        $_.PathName -match $serviceIndicatorRegex
    }

    foreach ($svc in $svcMatches) {
        Add-Finding -Id "SUSPICIOUS_SERVICE" -Severity "Medium" -Area "Services" -Evidence "Service: $($svc.Name), Path: $($svc.PathName)" -Recommendation "Validate service publisher and remove unauthorized activator services."
    }
}
catch {
    Add-Finding -Id "SERVICE_QUERY_ERROR" -Severity "Low" -Area "Services" -Evidence "Could not query services: $($_.Exception.Message)" -Recommendation "Run with elevated privileges for complete service inventory."
}

# --- Correlation Rule Engine ---
Write-Stage "Running correlation rule engine..."

# Runs AFTER all individual checks. Correlates multiple weak signals into
# high-confidence findings. Does not replace granular findings, only adds to them.
#
# UCZCIWE OGRANICZENIA — czego skrypt NIE wykryje:
# - MAS HWID po restarcie bez GenuineTicket.xml: kryptograficznie identyczny
#   z legalna licencja cyfrowa. Tylko slad wykonania skryptu (PowerShell log,
#   AMSI) moze go ujawnic. Timestampy SPP NIE sa dowodem.
# - MAS KMS38 / Online KMS ze zdalnym serwerem KMS w domenie: jesli emulator
#   dziala na zewnetrznym serwerze i publikuje sie przez DNS — nieodroznialny
#   od legalnego KMS enterprise bez analizy ruchu sieciowego.
# - Kazdy aktywator obfuskujacy nazwy plikow i nie tworzacy zadan harmonogramu:
#   ominie Prefetch i Recycle Bin. AMSI i PowerShell log (wzorce behawioralne)
#   sa jedyna obrona — wymagaja wlaczonego Defendera i Operational log.
# - TSforge w pamieci (in-memory driver): bez plikow DLL na dysku. Tylko AMSI
#   lub zaawansowana analiza forensicza (Volatility) moze go wykryc.

$foundIds = { param($id) $findings | Where-Object { $_.Id -eq $id } }

# RULE 1: IFEO hook + sppcs.dll present → near-certain Ohook installation
$ifeoHit   = $findings | Where-Object { $_.Id -in @("IFEO_DEBUGGER", "IFEO_VERIFIER_DLLS") }
$ohookFile = $findings | Where-Object { $_.Id -eq "OHOOK_FILE_PRESENT" }
if ($ifeoHit -and $ohookFile) {
    Add-Finding -Id "CORR_OHOOK_COMPLETE" -Severity "Critical" -Area "Correlation" `
        -Evidence "IFEO hook on licensing service ($($ifeoHit[0].Evidence)) combined with sppcs.dll present. Both artefacts of the same MAS Ohook method detected simultaneously." `
        -Recommendation "High-confidence Ohook activation detected. Remove sppcs.dll, IFEO keys, and reactivate Office with a legitimate license."
}

# RULE 2: Online KMS directory + renewal task both present → active Online KMS installation
$onlineKmsDir  = $findings | Where-Object { $_.Id -eq "MAS_ONLINE_KMS_DIR" }
$onlineKmsTask = $findings | Where-Object { $_.Id -eq "MAS_ONLINE_KMS_TASK" }
if ($onlineKmsDir -and $onlineKmsTask) {
    Add-Finding -Id "CORR_ONLINE_KMS_ACTIVE" -Severity "Critical" -Area "Correlation" `
        -Evidence "MAS Online KMS directory and renewal scheduled task both present. Activation infrastructure is complete and operational." `
        -Recommendation "Remove C:\Program Files\Activation-Renewal directory and the Activation-Renewal scheduled task, then reactivate legitimately."
}

# RULE 3: KMS on localhost/custom host + machine is NOT domain-joined → no legitimate KMS infrastructure
$kmsLocalhost = $findings | Where-Object { $_.Id -in @("KMS_LOCALHOST", "KMS_CUSTOM_HOST") }
if ($kmsLocalhost) {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $isDomainJoined = $cs.PartOfDomain
    }
    catch { $isDomainJoined = $false }

    if (-not $isDomainJoined) {
        Add-Finding -Id "CORR_KMS_HEADLESS" -Severity "Critical" -Area "Correlation" `
            -Evidence "KMS host configured ($($kmsLocalhost[0].Evidence)) on a standalone (non-domain) machine. No legitimate KMS infrastructure can explain this." `
            -Recommendation "Remove the KMS host registry entry and validate activation through official Microsoft channels."
    }
}

# RULE 4: Forensic activator trace + current KMS anomaly → consistent picture of past+present manipulation
$forensicTrace = $findings | Where-Object { $_.Id -in @("PREFETCH_ACTIVATOR", "RECYCLEBIN_ACTIVATOR", "POWERSHELL_LOG_ACTIVATOR", "SECLOG_DELETION_AUDIT", "AMSI_ACTIVATOR_DETECTION") }
$kmsAnomaly    = $findings | Where-Object { $_.Id -in @("KMS_LOCALHOST", "KMS_CUSTOM_HOST", "MAS_ONLINE_KMS_DIR", "MAS_ONLINE_KMS_TASK", "OHOOK_FILE_PRESENT", "MAS_OHOOK_REGISTRY") }
if ($forensicTrace -and $kmsAnomaly) {
    Add-Finding -Id "CORR_FORENSIC_MATCH" -Severity "Critical" -Area "Correlation" `
        -Evidence "Forensic traces of activator execution ($($forensicTrace[0].Evidence)) correlate with active licensing anomalies. Past and present indicators are consistent." `
        -Recommendation "Both historical execution evidence and current system state indicate unauthorized activation tooling. Full licensing remediation required."
}

# RULE 5: GenuineTicket.xml found → hard signal of HWID activation
# ClipSVC normally cleans up GenuineTicket.xml after processing. A leftover
# means the ticket was injected manually (HWID method) or cleanup failed.
# This is the SINGLE STRONGEST indicator of HWID activation.
$genuineTicketFinding = $findings | Where-Object { $_.Id -eq "HWID_GENUINE_TICKET" }
if ($genuineTicketFinding) {
    Add-Finding -Id "CORR_HWID_GENUINE_TICKET" -Severity "Critical" -Area "Correlation" `
        -Evidence "GenuineTicket.xml remnant found: $($genuineTicketFinding.Evidence). This file is a direct artefact of ClipSVC ticket injection used by HWID activation." `
        -Recommendation "Near-certain HWID activation detected. Remove the ticket file and investigate activation history."
}

# RULE 6: SPP mid-session modification + Retail channel without OEM key → orientacyjny sygnał HWID
# Oba sygnały są SŁABE indywidualnie — timestamp SPP zmienia się przy wielu legalnych
# operacjach, a brak klucza OEM jest normalny na PC składanych ręcznie. Razem dają
# orientacyjną wskazówkę, NIE dowód.
$sppMidSession = $findings | Where-Object { $_.Id -eq "SPP_TOKENS_MOD_MID_SESSION" }
$retailNoOem  = $findings | Where-Object { $_.Id -eq "HWID_RETAIL_NO_OEM_KEY" }
if ($sppMidSession -and $retailNoOem) {
    Add-Finding -Id "CORR_HWID_SPP_AND_RETAIL" -Severity "High" -Area "Correlation" `
        -Evidence "Modyfikacja SPP w trakcie sesji + Retail bez klucza OEM. Dwa niezależne, ale SŁABE sygnały — orientacyjna wskazówka, nie dowód HWID." `
        -Recommendation "Skoreluj z TWARDYMI dowodami: GenuineTicket.xml, wpisy PowerShell log, ślady plików aktywatorów. Same timestampy i kanał Retail NIE wystarczają do potwierdzenia."
}

# RULE 7: Twarde ślady forensyczne + anomalia osi czasu SPP → spójny obraz
# Łączy MOCNE dowody (PowerShell log, Recycle Bin, Security audit, Prefetch)
# ze SŁABYM sygnałem timestamp SPP. Daje to wysoki poziom pewności.
if ($forensicTrace -and $sppTimelineSuspicious) {
    Add-Finding -Id "CORR_HWID_FORENSIC_MATCH" -Severity "Critical" -Area "Correlation" `
        -Evidence "Twarde ślady forensyczne aktywatora ($($forensicTrace[0].Evidence)) + anomalia osi czasu SPP. Dowody historyczne i stan obecny tworzą spójny obraz." `
        -Recommendation "Połączenie śladów wykonania aktywatora z anomalią SPP daje wysoką pewność. Przeprowadź pełną remediację licencjonowania."
}

# RULE 8: TSforge DLL + anomalia osi czasu SPP → aktywne TSforge
$tsforgeFileFinding = $findings | Where-Object { $_.Id -eq "TSFORGE_FILE_PRESENT" }
if ($tsforgeFileFinding -and $sppTimelineSuspicious) {
    Add-Finding -Id "CORR_TSFORGE_ACTIVE" -Severity "Critical" -Area "Correlation" `
        -Evidence "DLL hook TSforge ($($tsforgeFileFinding.Evidence)) + anomalia osi czasu SPP. Oba artefakty aktywacji TSforge wykryte jednocześnie." `
        -Recommendation "Wysoka pewność aktywacji TSforge. Usuń DLL hooki i zweryfikuj aktywację Windows przez legalny kanał."
}

# RULE 9: SPP ACL relaxed + anomalia osi czasu SPP → naruszenie integralności
$sppAclHit = $findings | Where-Object { $_.Id -in @("SPP_STORE_ACL_RELAXED", "SPP_FILE_ACL_RELAXED") }
if ($sppAclHit -and $sppTimelineSuspicious) {
    Add-Finding -Id "CORR_SPP_ACL_TAMPER" -Severity "Critical" -Area "Correlation" `
        -Evidence "Uprawnienia SPP store zmienione ($($sppAclHit[0].Evidence)) + anomalia osi czasu SPP. Uprawnienia systemu plików zostały zmienione by umożliwić nieautoryzowaną aktywację." `
        -Recommendation "Przywróć domyślne ACL na katalogu i plikach SPP store, następnie zweryfikuj stan aktywacji przez oficjalne kanały."
}

# RULE 10: SPP ADS + anomalia osi czasu SPP → ukryte dane aktywatora
$sppAdsHit = $findings | Where-Object { $_.Id -eq "SPP_FILE_ADS_PRESENT" }
if ($sppAdsHit -and $sppTimelineSuspicious) {
    Add-Finding -Id "CORR_SPP_ADS_TAMPER" -Severity "Critical" -Area "Correlation" `
        -Evidence "Alternate Data Stream na pliku SPP ($($sppAdsHit.Evidence)) + anomalia osi czasu SPP. ADS to znana technika ukrywania ładunków aktywatorów." `
        -Recommendation "Zbadaj zawartość ADS na plikach SPP (Get-Content -Stream) i usuń nieautoryzowane strumienie. Zweryfikuj stan aktywacji."
}

# RULE 11: SPP binary invalid signature + anomalia osi czasu SPP → podmiana binariów
$sppSigHit = $findings | Where-Object { $_.Id -in @("SPP_BINARY_INVALID_SIGNATURE", "SPP_BINARY_UNEXPECTED_SIGNER") }
if ($sppSigHit -and $sppTimelineSuspicious) {
    Add-Finding -Id "CORR_SPP_BINARY_TAMPER" -Severity "Critical" -Area "Correlation" `
        -Evidence "Podpis binarny SPP nieprawidłowy ($($sppSigHit[0].Evidence)) + anomalia osi czasu SPP. Podmiana plików binarnych i naruszenie store wykryte razem." `
        -Recommendation "Zastąp naruszone pliki binarne SPP z czystego nośnika Windows i ponownie zweryfikuj aktywację. Eskalij do analizy forensiczej."
}

# --- End Correlation Rule Engine ---

$risk = Get-RiskLevel -InputFindings $findings

Write-Stage "Generating report..."

$report = [pscustomobject]@{
    GeneratedAtUtc  = (Get-Date).ToUniversalTime().ToString("s") + "Z"
    ComputerName    = $env:COMPUTERNAME
    RiskLevel       = $risk
    WindowsLicenses = $winSummary
    OfficeLicenses    = $officeSummary
    OfficeInstalled   = $officeInstalled
    Office365Signals = $office365Signals
    Office365Identity = $office365Identity
    Findings        = $findings
    Disclaimer      = "This script detects anomalies and tampering indicators. It cannot provide a 100% legal determination on its own."
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 6
    return
}

Write-Host ""
Write-Host "================ LICENSE AUDIT REPORT ================" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "Timestamp (UTC): $($report.GeneratedAtUtc)"
Write-Host "Computer: $($report.ComputerName)"
Write-Host "Risk level: $($report.RiskLevel)"
Write-Host ""

Write-Host "Windows licensing entries:" -ForegroundColor Cyan
if ($winSummary.Count -eq 0) {
    Write-Host "  (none)"
}
else {
    foreach ($item in $winSummary) {
        Write-Host "  - Name: $($item.Name)"
        Write-Host "    Channel: $($item.Channel)"
        Write-Host "    Status: $($item.LicenseStatusText)"
        Write-Host "    Partial key: $($item.PartialProductKey)"
    }
}

Write-Host ""
Write-Host "Office licensing entries (SPP):" -ForegroundColor Cyan
if ($officeSummary.Count -eq 0) {
    Write-Host "  (none or not licensed via local product key)"
}
else {
    foreach ($item in $officeSummary) {
        Write-Host "  - $($item.FriendlyName)" -ForegroundColor White
        Write-Host "    Channel: $($item.Channel)"
        Write-Host "    Status:  $($item.LicenseStatusText)"
        Write-Host "    Partial key: $($item.PartialProductKey)"
        Write-Host "    Raw name: $($item.Name)"
    }
}

Write-Host ""
Write-Host "Installed Office products (registry):" -ForegroundColor Cyan
if ($officeInstalled.Count -eq 0) {
    Write-Host "  (none found in Uninstall registry)"
}
else {
    foreach ($item in $officeInstalled) {
        Write-Host "  - $($item.DisplayName) v$($item.DisplayVersion) [$($item.Architecture)]"
        if ($item.InstallDate) { Write-Host "    Installed: $($item.InstallDate)" }
    }
}

Write-Host ""
Write-Host "Office 365 identity (HKCU):" -ForegroundColor Cyan
if ($null -eq $office365Identity) {
    Write-Host "  (not found in current user profile)"
}
else {
    Write-Host "  - Identity path: $($office365Identity.IdentityPath)"
    Write-Host "    SignInName: $($office365Identity.SignInName)"
    Write-Host "    UserName: $($office365Identity.UserName)"
    Write-Host "    UserEmail: $($office365Identity.UserEmail)"
    Write-Host "    FederatedUserEmail: $($office365Identity.FederatedUserEmail)"
    Write-Host "    TenantId: $($office365Identity.TenantId)"
    Write-Host "    IsOffice365Account: $($office365Identity.IsOffice365Account)"
}

Write-Host ""
Write-Host "Office 365 signals:" -ForegroundColor Cyan
Write-Host "  - HasSubscriptionSku: $($office365Signals.HasSubscriptionSku)"
Write-Host "    SubscriptionSkuCount: $($office365Signals.SubscriptionSkuCount)"
Write-Host "    HasIdentityProfile: $($office365Signals.HasIdentityProfile)"
Write-Host "    HasSignedInIdentity: $($office365Signals.HasSignedInIdentity)"
Write-Host "    IsM365FromRegistry: $($office365Signals.IsM365FromRegistry)"
Write-Host "    HasTraditionalOffice: $($office365Signals.HasTraditionalOffice)"
Write-Host "    HasVNextTokens: $($office365Signals.HasVNextTokens)"
Write-Host "    IsRunningAsSystem: $($office365Signals.IsRunningAsSystem)"
Write-Host "    InteractiveUserName: $($office365Signals.InteractiveUserName)"
Write-Host "    IsSharedComputerActivation: $($office365Signals.IsSharedComputerActivation)"

Write-Host ""
Write-Host "Findings:" -ForegroundColor Yellow
if ($findings.Count -eq 0) {
    Write-Host "  No anomalies detected by current checks."
}
else {
    foreach ($f in $findings) {
        Write-Host "  [$($f.Severity)] [$($f.Area)] $($f.Evidence)"
        Write-Host "     Recommendation: $($f.Recommendation)"
    }
}

Write-Host ""
Write-Host "Disclaimer: $($report.Disclaimer)" -ForegroundColor DarkYellow
Write-Host "======================================================"
