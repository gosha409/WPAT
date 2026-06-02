<# 
.SYNOPSIS
  Version: 2026-06-02-v12-layout-logic
  Read-only Windows persistence audit based on https://persistence-info.github.io/

.DESCRIPTION
  Checks the persistence locations listed by persistence-info.github.io as of 2026-06-02.
  The script does not create, modify, delete, enable, or disable anything.
  It inventories full evidence by default and exports JSON + CSV, enriched triage CSV files, category CSV files, dangerous-only CSV, and highlighted HTML.

.NOTES
  Run from an elevated PowerShell session for HKLM/service/LSA visibility.
  User hive registry checks are limited to currently loaded hives under HKEY_USERS.
  File checks enumerate local profile directories under C:\Users when accessible.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "."
)

$ErrorActionPreference = "Continue"
Write-Host "persistence_info_audit.ps1 version: 2026-06-02"

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Errors = New-Object System.Collections.Generic.List[object]

function Initialize-RegistryDrives {
    foreach ($drive in @(
        @{ Name = "HKU";  Root = "HKEY_USERS" },
        @{ Name = "HKCR"; Root = "HKEY_CLASSES_ROOT" }
    )) {
        if (-not (Get-PSDrive -Name $drive.Name -ErrorAction SilentlyContinue)) {
            try {
                New-PSDrive -Name $drive.Name -PSProvider Registry -Root $drive.Root -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning "Cannot create registry PSDrive $($drive.Name): $($_.Exception.Message)"
            }
        }
    }
}

function Add-AuditError {
    param(
        [string]$Mechanism,
        [string]$Location,
        [string]$ErrorText
    )
    $script:Errors.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString("o")
        Mechanism = $Mechanism
        Location = $Location
        Error = $ErrorText
    }) | Out-Null
}

function Normalize-Data {
    param([object]$Data)
    if ($null -eq $Data) { return "" }
    if ($Data -is [array]) { return (($Data | ForEach-Object { [string]$_ }) -join "; ") }
    return [string]$Data
}

function Expand-EnvSafe {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    try { return [Environment]::ExpandEnvironmentVariables($Value) } catch { return $Value }
}

function Get-CommandCandidate {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return "" }

    $s = (Expand-EnvSafe $CommandLine).Trim()

    # Composite registry values are often not executable paths.
    if ($s -match '[\|\?*<>]') { return "" }

    if ($s.StartsWith('"')) {
        if ($s -match '^"([^"]+\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|hta|sys|cpl))"') { return $matches[1] }
        return ""
    }

    if ($s -match '^([A-Za-z]:\\[^\r\n]+?\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|hta|sys|cpl))(\s|$|,|;)') {
        return $matches[1]
    }

    if ($s -match '^(\\\\[^\r\n]+?\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|hta|sys|cpl))(\s|$|,|;)') {
        return $matches[1]
    }

    # Bare DLL/EXE reference such as localspl.dll, ifmon.dll, msv1_0.dll.
    if ($s -match '^([A-Za-z0-9_\.\-]+\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|hta|sys|cpl))(\s|$|,|;)') {
        return $matches[1]
    }

    # LSA/auth package names commonly omit .dll, for example scecli or msv1_0.
    if ($s -match '^[A-Za-z0-9_\.-]+$') { return $s }

    return ""
}

function Test-AuditPathCandidate {
    param([string]$PathCandidate)

    if ([string]::IsNullOrWhiteSpace($PathCandidate)) { return $false }

    if ($PathCandidate -match '[<>"|*?]') { return $false }
    if ($PathCandidate -match '^\{[0-9A-Fa-f-]{36}\}$') { return $false }
    if ($PathCandidate -match '^[A-Za-z]:.*[A-Za-z]:') { return $false }

    if ($PathCandidate.Length -ge 3 -and $PathCandidate[1] -eq ':' -and ($PathCandidate[2] -eq '\' -or $PathCandidate[2] -eq '/')) {
        return $true
    }

    if ($PathCandidate.StartsWith('\\')) { return $true }

    return $false
}

function Test-BareExecutableName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '^[A-Za-z0-9_\.\-]+\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|hta|sys|cpl)$')
}

function Resolve-AuditCandidatePath {
    param(
        [string]$Candidate,
        [string]$Mechanism = "",
        [string]$Name = "",
        [string]$RegistryPath = ""
    )

    $result = [ordered]@{
        Candidate = $Candidate
        ResolvedPath = $Candidate
        Resolution = ""
    }

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $result }

    $candidateExpanded = Expand-EnvSafe $Candidate
    $result.Candidate = $candidateExpanded
    $result.ResolvedPath = $candidateExpanded

    if (Test-AuditPathCandidate -PathCandidate $candidateExpanded) {
        $result.Resolution = "absolute"
        return $result
    }

    $bare = $candidateExpanded.Trim()
    $isBareExecutable = Test-BareExecutableName -Value $bare
    $tryNames = New-Object System.Collections.Generic.List[string]

    if ($isBareExecutable) {
        $tryNames.Add($bare) | Out-Null
    }

    # Contextual DLL expansion for common Windows persistence locations that store DLL names without paths.
    if (($Mechanism -match 'Password Filter|Authentication Packages|LSA Extension') -and ($bare -match '^[A-Za-z0-9_\.-]+$')) {
        if ($bare -notmatch '(?i)\.dll$') { $tryNames.Add("$bare.dll") | Out-Null }
        else { $tryNames.Add($bare) | Out-Null }
    }

    if (($Mechanism -match 'Print Monitor|Netsh extension DLL|Autodial DLL|ServerLevelPluginDll') -and ($bare -match '^[A-Za-z0-9_\.-]+$')) {
        if ($bare -notmatch '(?i)\.(dll|exe|sys)$') { $tryNames.Add("$bare.dll") | Out-Null }
        else { $tryNames.Add($bare) | Out-Null }
    }

    if ($tryNames.Count -eq 0) { return $result }

    $searchDirs = New-Object System.Collections.Generic.List[string]
    if ($env:WINDIR) {
        $searchDirs.Add((Join-Path $env:WINDIR "System32")) | Out-Null
        $searchDirs.Add((Join-Path $env:WINDIR "SysWOW64")) | Out-Null
        $searchDirs.Add($env:WINDIR) | Out-Null
    }
    if ($env:SystemRoot -and $env:SystemRoot -ne $env:WINDIR) {
        $searchDirs.Add((Join-Path $env:SystemRoot "System32")) | Out-Null
        $searchDirs.Add((Join-Path $env:SystemRoot "SysWOW64")) | Out-Null
        $searchDirs.Add($env:SystemRoot) | Out-Null
    }

    foreach ($nameCandidate in ($tryNames | Select-Object -Unique)) {
        foreach ($dir in ($searchDirs | Select-Object -Unique)) {
            if ([string]::IsNullOrWhiteSpace($dir)) { continue }
            $p = Join-Path $dir $nameCandidate
            try {
                if (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction Stop) {
                    $result.ResolvedPath = $p
                    $result.Resolution = "resolved_bare_name_to_$dir"
                    return $result
                }
            } catch {}
        }
    }

    return $result
}

function Test-PathWritableByNonAdmin {
    param([string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($FilePath)) { return $null }
try {
        $acl = Get-Acl -LiteralPath $FilePath -ErrorAction Stop

        $riskyIdentityPatterns = @(
            'Everyone',
            'BUILTIN\\Users',
            'NT AUTHORITY\\Authenticated Users',
            'Authenticated Users',
            '\\Users$',
            'INTERACTIVE'
        )

        $writeMasks = @(
            [System.Security.AccessControl.FileSystemRights]::Write,
            [System.Security.AccessControl.FileSystemRights]::WriteData,
            [System.Security.AccessControl.FileSystemRights]::AppendData,
            [System.Security.AccessControl.FileSystemRights]::CreateFiles,
            [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
            [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
            [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
            [System.Security.AccessControl.FileSystemRights]::TakeOwnership
        )

        foreach ($ace in $acl.Access) {
            if ([string]$ace.AccessControlType -ne "Allow") { continue }

            $identity = [string]$ace.IdentityReference
            $isRiskyIdentity = $false

            foreach ($pat in $riskyIdentityPatterns) {
                if ($identity -match $pat) {
                    $isRiskyIdentity = $true
                    break
                }
            }

            if (-not $isRiskyIdentity) { continue }

            $rights = [int64]$ace.FileSystemRights

            foreach ($mask in $writeMasks) {
                if (($rights -band [int64]$mask) -ne 0) {
                    return $true
                }
            }
        }

        return $false
    } catch {
        return $null
    }
}

function Get-FileZoneId {
    param([string]$FilePath)

    try {
        $adsPath = "$FilePath`:Zone.Identifier"
        if (Test-Path -LiteralPath $adsPath -ErrorAction SilentlyContinue) {
            $zoneRaw = Get-Content -LiteralPath $adsPath -ErrorAction SilentlyContinue | Out-String
            if ($zoneRaw -match 'ZoneId\s*=\s*(\d+)') {
                return $matches[1]
            }
            return "Present"
        }
    } catch {}

    return ""
}

function Get-FileEvidence {
    param(
        [string]$CommandOrPath,
        [string]$Mechanism = "",
        [string]$Name = "",
        [string]$RegistryPath = ""
    )

    $candidate = Get-CommandCandidate $CommandOrPath
    $resolved = Resolve-AuditCandidatePath -Candidate $candidate -Mechanism $Mechanism -Name $Name -RegistryPath $RegistryPath
    $candidatePath = [string]$resolved.ResolvedPath

    $empty = @{
        Candidate = $candidatePath
        OriginalCandidate = [string]$resolved.Candidate
        CandidateResolution = [string]$resolved.Resolution
        Exists = $null
        Signature = ""
        Publisher = ""
        SHA256 = ""
        FileOwner = ""
        CreationTimeUtc = ""
        LastWriteTimeUtc = ""
        CompanyName = ""
        ProductName = ""
        OriginalFilename = ""
        FileDescription = ""
        ZoneId = ""
        WritableByNonAdmin = $null
    }

    if ([string]::IsNullOrWhiteSpace($candidatePath)) {
        $empty.Candidate = ""
        return $empty
    }

    if (-not (Test-AuditPathCandidate -PathCandidate $candidatePath)) {
        return $empty
    }

    try {
        $exists = Test-Path -LiteralPath $candidatePath -PathType Leaf -ErrorAction Stop
        $empty.Exists = $exists

        if (-not $exists) {
            return $empty
        }

        try {
            $hash = Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256 -ErrorAction Stop
            $empty.SHA256 = [string]$hash.Hash
        } catch {}

        try {
            $item = Get-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
            $empty.CreationTimeUtc = $item.CreationTimeUtc.ToString("o")
            $empty.LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("o")
        } catch {}

        try {
            $acl = Get-Acl -LiteralPath $candidatePath -ErrorAction Stop
            $empty.FileOwner = [string]$acl.Owner
        } catch {}

        try {
            $empty.WritableByNonAdmin = Test-PathWritableByNonAdmin -FilePath $candidatePath
        } catch {}

        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $candidatePath -ErrorAction SilentlyContinue
            if ($sig) {
                $empty.Signature = [string]$sig.Status
                if ($sig.SignerCertificate) {
                    $empty.Publisher = [string]$sig.SignerCertificate.Subject
                }
            }
        } catch {}

        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($candidatePath)
            if ($vi) {
                $empty.CompanyName = [string]$vi.CompanyName
                $empty.ProductName = [string]$vi.ProductName
                $empty.OriginalFilename = [string]$vi.OriginalFilename
                $empty.FileDescription = [string]$vi.FileDescription
            }
        } catch {}

        try {
            $empty.ZoneId = Get-FileZoneId -FilePath $candidatePath
        } catch {}

        return $empty
    } catch {
        $empty.Exists = $null
        return $empty
    }
}

function S {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [string]$Value
}

function ConvertTo-HtmlSafe {
    param([object]$Value)
    return [System.Security.SecurityElement]::Escape((S $Value))
}

function Get-ObjectPropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) { return "" }

    $prop = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $prop) { return "" }
    return $prop.Value
}

function Has-Any {
    param(
        [string]$Text,
        [string[]]$Patterns
    )

    foreach ($p in $Patterns) {
        if ($Text -match $p) { return $true }
    }

    return $false
}

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [string]$Reason
    )

    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        $Reasons.Add($Reason) | Out-Null
    }
}

function Get-SafeFileName {
    param([string]$Name)

    $safe = $Name -replace '^\d+\s+', ''
    $safe = $safe -replace '[\\/:\*\?"<>\|]+', '_'
    $safe = $safe -replace '\s+', '_'
    $safe = $safe -replace '_+', '_'
    $safe = $safe.Trim('_')

    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = "Other"
    }

    return $safe
}

function Get-MechanismFamily {
    param([string]$Mechanism)

    switch -Regex ($Mechanism) {
        'Password Filter|Authentication Packages|LSA Extension|Winlogon Notification Package|MPNotify|Print Monitor|Boot Verification Program|Windows Platform Binary Table|ServerLevelPluginDll|Autodial DLL|Netsh extension DLL' {
            return "Critical OS / LSASS / Boot / Spooler"
        }
        'Image File Execution Options|Monitoring Silent Process Exit|AeDebug|WER Debugger|File Extension Hijacking|Recycle Bin COM Extension Handler|HKCU cmd.exe AutoRun' {
            return "Execution hijack / debugger / association"
        }
        'Windows Services|Task Scheduler|Desired State Configuration' {
            return "Services / scheduled / configuration enforcement"
        }
        'HKCU Run and RunOnce|Startup Folder|User Init Mpr Logon Script|HKCU Load|PowerShell Profiles|Screen Saver|Windows Terminal Profile|Keyboard Shortcut|TS Initial Program|RDP WDS Startup Programs' {
            return "User logon / interactive session / RDP"
        }
        'AMSI Providers|GPO Client-side Extension|Disk Cleanup Handler|Filter Handlers for Windows Search|IFilter|hhctrl.ocx|\.chm helper DLL|Code Signing DLL|Explorer tools|TelemetryController|Credential Manager DLL' {
            return "COM / shell / provider extension"
        }
        default {
            return "Other"
        }
    }
}

function Get-Group {
    param([string]$Mechanism)

    if ([string]::IsNullOrWhiteSpace($Mechanism)) { return "Unknown" }
    return $Mechanism
}

function Get-BaseMechanismScore {
    param([string]$Mechanism)

    switch -Regex ($Mechanism) {
        'Password Filter|Authentication Packages|LSA Extension|Winlogon Notification Package|MPNotify|Print Monitor|Boot Verification Program|Windows Platform Binary Table|ServerLevelPluginDll|Autodial DLL|Netsh extension DLL' { return 22 }
        'Image File Execution Options|Monitoring Silent Process Exit|AeDebug|WER Debugger|File Extension Hijacking|Recycle Bin COM Extension Handler|HKCU cmd.exe AutoRun' { return 24 }
        'Task Scheduler|Windows Services|Desired State Configuration' { return 12 }
        'HKCU Run and RunOnce|Startup Folder|User Init Mpr Logon Script|HKCU Load|PowerShell Profiles|Screen Saver|Windows Terminal Profile|Keyboard Shortcut|TS Initial Program|RDP WDS Startup Programs' { return 14 }
        'AMSI Providers|GPO Client-side Extension|Credential Manager DLL' { return 12 }
        'Disk Cleanup Handler|Filter Handlers for Windows Search|IFilter|hhctrl.ocx|\.chm helper DLL|Code Signing DLL|Explorer tools|TelemetryController' { return 5 }
        default { return 3 }
    }
}

function Get-Verdict {
    param([int]$Score)

    if ($Score -ge 75) { return "Critical" }
    if ($Score -ge 45) { return "High" }
    if ($Score -ge 30) { return "Medium" }

    return "Low"
}

function Get-VerdictRank {
    param([string]$Verdict)

    switch -Regex (S $Verdict) {
        '^Critical$' { return 1 }
        '^High$' { return 2 }
        '^Medium$' { return 3 }
        default { return 4 }
    }
}

function Test-ReviewQueueVerdict {
    param([string]$Verdict)

    return ((S $Verdict) -match '^(Critical|High|Medium)$')
}

function Test-LooksLikeExecutableRef {
    param([string]$Text)

    return ($Text -match '(?i)\.(exe|dll|ocx|scr|ps1|bat|cmd|vbs|js|jse|hta|sys|cpl)(\s|$|"|''|,|;)') 
}

function Test-MicrosoftTrustedFile {
    param([pscustomobject]$Row)

    $candidate = S $Row.CandidatePath
    $sig = S $Row.SignatureStatus
    $signer = S $Row.Signer
    $company = S $Row.CompanyName
    $writable = S $Row.WritableByNonAdmin
    $exists = S $Row.CandidateExists

    if ($exists -notmatch '(?i)^True$') { return $false }
    if ($sig -ne "Valid") { return $false }
    if (($signer -notmatch '(?i)Microsoft') -and ($company -notmatch '(?i)Microsoft')) { return $false }
    if ($writable -match '(?i)^True$') { return $false }

    if ($candidate -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') { return $true }
    if ($candidate -match '(?i)\\Program Files( \(x86\))?\\Windows Defender\\') { return $true }
    if ($candidate -match '(?i)\\ProgramData\\Microsoft\\Windows Defender\\') { return $true }

    return $false
}

function Test-SystemDirectoryFile {
    param([string]$CandidatePath)

    return ((S $CandidatePath) -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\')
}

function Test-UserWritablePathString {
    param([string]$CandidatePath)

    $p = S $CandidatePath
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    if ($p -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\Downloads\\|\\Desktop\\|\\Public\\') { return $true }

    # ProgramData is noisy; treat as suspicious only when it is not a Microsoft-trusted Defender/platform path.
    if ($p -match '(?i)\\ProgramData\\' -and $p -notmatch '(?i)\\ProgramData\\Microsoft\\Windows Defender\\') { return $true }
    return $false
}

function Test-LolBinReference {
    param([string]$Text)

    return (Has-Any -Text (S $Text) -Patterns @(
        '(?i)(^|[\\\s"''])powershell(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])pwsh(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])mshta(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])rundll32(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])regsvr32(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])wscript(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])cscript(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])wmic(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])bitsadmin(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])certutil(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])msiexec(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])cmd(\.exe)?\s+/c\b',
        '(?i)(^|[\\\s"''])forfiles(\.exe)?(\s|$|"|'')',
        '(?i)(^|[\\\s"''])schtasks(\.exe)?(\s|$|"|'')'
    ))
}

function Test-ScriptObfuscationOrNetworkRetrieval {
    param([string]$Text)

    return (Has-Any -Text (S $Text) -Patterns @(
        '(?i)-enc(odedcommand)?\b',
        '(?i)\bIEX\b|Invoke-Expression',
        '(?i)DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b',
        '(?i)System\.Net\.WebClient|New-Object\s+Net\.WebClient',
        '(?i)FromBase64String',
        '(?i)System\.Reflection|Add-Type',
        '(?i)-nop\b|-noprofile\b|-w\s+hidden|-windowstyle\s+hidden',
        '(?i)https?://'
    ))
}

function Get-MechanismDescription {
    param([string]$Mechanism)

    $common = "Scoring is evidence-based. A mechanism is not dangerous by itself. Severity increases when the entry resolves to an executable file that is unsigned, has a non-valid signature, is outside the expected system or Program Files location, is writable by non-admin identities, points into user profile, Temp, Downloads, Public or ProgramData staging paths, launches script hosts or LOLBins, contains encoded PowerShell or network download patterns, references a missing binary, or appears newly introduced compared with a baseline. Signed Microsoft components in System32, SysWOW64, WinSxS or known Defender paths are downgraded unless another suspicious signal is present."

    switch -Regex ($Mechanism) {
        '^Code Signing DLL$' { return "Cryptography, OID and SIP provider registrations can affect trust and code-signing decisions. Criticality logic: custom provider DLLs, non-Microsoft providers, missing files, writable paths, unsigned binaries, non-valid signatures, or drift from the baseline are review-worthy. Built-in Microsoft values and pure function-name metadata are normally inventory only. $common" }
        '^IFilter$' { return "IFilter entries map file types to COM filter DLLs used by indexing and search components. Criticality logic: resolved InprocServer32 DLLs outside expected locations, unsigned or writable DLLs, user-writable paths, and non-Microsoft filters for high-volume file types are stronger signals. GUID-only mapping rows are context; the resolved DLL row is the primary evidence. $common" }
        '^Windows Services$' { return "Windows service ImagePath and ServiceDll values can run as SYSTEM or privileged service accounts. Criticality logic: Auto, Boot or System start services are important, but they become suspicious mainly when the binary is unsigned, missing, writable, in a user/staging path, or uses script hosts and LOLBINs. Valid third-party services in Program Files are usually Medium until baselined. $common" }
        '^Filter Handlers for Windows Search$' { return "PersistentHandler mappings connect file extensions to COM handlers and IFilters. Criticality logic: the mapping itself is context; review escalates when the resolved COM DLL is custom, unsigned, writable, outside Program Files or Windows system directories, or appears in an unusual user-specific class hive. $common" }
        '^Task Scheduler$' { return "Scheduled task actions are common persistence points. Criticality logic: hidden non-Microsoft tasks, tasks executing from user profile, Temp, Downloads, Public, ProgramData staging paths, script hosts, encoded PowerShell, network retrieval, missing binaries, or unexpected SYSTEM tasks move into review queue. Built-in hidden Microsoft Windows tasks without an executable action are low-signal inventory and should not be elevated only because Hidden=True. $common" }
        '^Disk Cleanup Handler$' { return "Disk Cleanup handler entries can invoke COM handlers or configured paths during cleanup operations. Criticality logic: GUID or metadata values are context; review focuses on resolved DLLs or executable paths that are unsigned, user-writable, non-Microsoft, missing, or outside expected system locations. $common" }
        '^GPO Client-side Extension$' { return "Group Policy client-side extensions are loaded during policy processing and can run in privileged contexts. Criticality logic: custom CSE DLLs, non-System32 paths, unsigned DLLs, user-writable paths or new CLSIDs are high-signal. Built-in Microsoft extensions are baseline candidates. $common" }
        '^TelemetryController$' { return "TelemetryController entries describe compatibility telemetry commands. Criticality logic: suspicious command paths, script hosts, network retrieval, missing executables or user-writable paths are review signals. Numeric state/result metadata is inventory context. $common" }
        '^Netsh extension DLL$' { return "Netsh helper DLL registration loads extension DLLs into netsh contexts. Criticality logic: built-in Microsoft System32 helpers are normally low; custom, unsigned, writable, missing or non-System32 helpers are high risk. $common" }
        '^Credential Manager DLL$' { return "Network Provider and credential manager DLL settings can load provider DLLs during logon or network authentication flows. Criticality logic: ProviderPath is the primary file evidence; Name, Class and ProviderOrder are context unless the related DLL is unexpected, unsigned or writable. $common" }
        '^Print Monitor$' { return "Print monitor DLLs can be loaded by the print subsystem. Criticality logic: built-in Microsoft monitor DLLs in System32 are expected; custom monitor DLLs, unsigned binaries, writable paths or non-System32 locations require immediate review. $common" }
        '^Windows Terminal Profile$' { return "Windows Terminal profiles are user configuration entries. Criticality logic: default built-in shells such as signed Microsoft PowerShell are low signal; review escalates for custom command lines, script arguments, encoded commands, network retrieval, or start-on-login behaviour tied to a suspicious profile. $common" }
        '^AMSI Providers$' { return "AMSI provider COM registrations can intercept scanning flows. Criticality logic: review custom providers, non-Microsoft providers, unsigned DLLs, missing files, writable paths and unexpected CLSIDs. Provider CLSID rows are context; resolved InprocServer32 rows are primary evidence. $common" }
        '^Authentication Packages$' { return "LSASS authentication packages are sensitive because they are loaded into LSASS. Criticality logic: built-in Microsoft packages such as msv1_0 are expected; custom package names, non-System32 paths, unsigned DLLs or writable locations are critical. $common" }
        '^Password Filter$' { return "Password filter packages are loaded by LSA during password operations. Criticality logic: built-in scecli is expected; additional custom packages, missing DLLs, unsigned DLLs or non-System32 paths are critical. $common" }
        '^LSA Extension$' { return "LSA extension DLLs are loaded by LSASS. Criticality logic: any custom or non-System32 DLL, unsigned DLL, missing file, writable path or newly introduced entry is critical. Built-in signed Microsoft LSASS components are downgraded. $common" }
        '^Autodial DLL$' { return "Winsock AutodialDLL points to a helper loaded by networking components. Criticality logic: built-in signed rasadhlp.dll in System32 is expected; custom, unsigned, writable or non-System32 DLLs are high risk. $common" }
        '^Startup Folder$' { return "Startup folders launch items during user logon. Criticality logic: scripts, shortcuts to user-writable payloads, LOLBIN chains, network retrieval, unsigned payloads and writable targets are review signals. $common" }
        '^TS Initial Program$' { return "RDP initial program settings can force a program at session start. Criticality logic: non-standard executable paths, script hosts, user-writable paths, missing binaries and network retrieval patterns are suspicious. $common" }
        '^RDP WDS Startup Programs$' { return "RDP WDS startup program settings can launch processes when RDP sessions initialize. Criticality logic: custom paths, scripts, missing binaries or user-writable locations are review signals. $common" }
        '^Desired State Configuration$' { return "DSC Local Configuration Manager can enforce configuration as SYSTEM. Criticality logic: pull mode, frequent correction, suspicious MOF content or unexpected configuration files are review signals. This collector inventories LCM state and MOF presence; content review may still be required. $common" }
        default { return "This mechanism is a persistence-info location. Criticality logic: review rises when a concrete executable or DLL reference is custom, unsigned, writable, missing, outside expected system/vendor locations, launches script hosts or LOLBINs, includes encoded/network retrieval patterns, or appears as drift from baseline. Pure registry metadata, GUID-only rows and trusted Microsoft system components are lower-signal context unless paired with another suspicious indicator. $common" }
    }
}

function Score-Finding {
    param([pscustomobject]$Row)

    $mechanism = S $Row.Mechanism
    $risk = S $Row.Risk
    $data = S $Row.Data
    $path = S $Row.Path
    $name = S $Row.Name
    $candidate = S $Row.CandidatePath
    $sig = S $Row.SignatureStatus
    $signer = S $Row.Signer
    $hidden = S $Row.Hidden
    $startMode = S $Row.StartMode
    $zoneId = S $Row.ZoneId
    $writableByNonAdmin = S $Row.WritableByNonAdmin
    $companyName = S $Row.CompanyName
    $exists = S $Row.CandidateExists

    $commandText = "$data $candidate"
    $reasons = New-Object System.Collections.Generic.List[string]
    $score = 0
    $signalCount = 0

    $group = Get-Group -Mechanism $mechanism
    $family = Get-MechanismFamily -Mechanism $mechanism
    $score += Get-BaseMechanismScore -Mechanism $mechanism
    Add-Reason $reasons "mechanism=$mechanism"
    Add-Reason $reasons "family=$family"

    $isTrustedMicrosoft = Test-MicrosoftTrustedFile -Row $Row
    $isSystemPath = Test-SystemDirectoryFile -CandidatePath $candidate
    $isExecutableRef = Test-LooksLikeExecutableRef -Text $commandText
    $isUserWritablePath = Test-UserWritablePathString -CandidatePath $candidate
    $hasLolBin = Test-LolBinReference -Text $commandText
    $hasScriptNetwork = Test-ScriptObfuscationOrNetworkRetrieval -Text $commandText
    $isMicrosoftWindowsTask = (($mechanism -eq "Task Scheduler") -and ($path -match '^\\Microsoft\\Windows\\'))
    $isTaskWithoutActionPath = (($mechanism -eq "Task Scheduler") -and [string]::IsNullOrWhiteSpace($candidate) -and [string]::IsNullOrWhiteSpace($data))
    $isTrustedThirdPartyProgramFiles = (($exists -match '(?i)^True$') -and ($sig -eq "Valid") -and (-not $isTrustedMicrosoft) -and ($candidate -match '(?i)^C:\\Program Files( \(x86\))?\\') -and ($writableByNonAdmin -notmatch '(?i)^True$'))

    if ($risk -eq "High") {
        if ($isTrustedMicrosoft) {
            $score += 3
            Add-Reason $reasons "collector_risk=High_but_trusted_microsoft_file"
        } elseif ($isMicrosoftWindowsTask -and $isTaskWithoutActionPath) {
            $score += 1
            Add-Reason $reasons "collector_risk=High_but_builtin_microsoft_task_without_action_path"
        } elseif ($isTrustedThirdPartyProgramFiles) {
            $score += 6
            Add-Reason $reasons "collector_risk=High_but_signed_third_party_program_files"
        } else {
            $score += 12
            Add-Reason $reasons "collector_risk=High"
        }
    } elseif ($risk -eq "Review") {
        $score += 2
    }

    # Not every registry value in a sensitive key is executable evidence.
    if (($mechanism -match 'Credential Manager DLL') -and ($name -notmatch '(?i)^ProviderPath$')) {
        $score = [Math]::Min($score, 18)
        Add-Reason $reasons "non_executable_network_provider_metadata_value"
        return [pscustomobject]@{
            Score = $score
            Verdict = Get-Verdict -Score $score
            Group = $group
            Family = $family
            Reasons = ($reasons | Select-Object -Unique) -join "; "
        }
    }

    if ($hidden -match '(?i)^true$') {
        if ($isMicrosoftWindowsTask -and $isTaskWithoutActionPath) {
            Add-Reason $reasons "hidden_builtin_microsoft_task_without_action_path_low_signal"
        } elseif ($isMicrosoftWindowsTask -and $isTrustedMicrosoft) {
            $score += 2
            Add-Reason $reasons "hidden_microsoft_windows_task_low_signal"
        } elseif ($isTrustedThirdPartyProgramFiles) {
            $score += 6
            $signalCount++
            Add-Reason $reasons "hidden_signed_third_party_task_review_signal"
        } else {
            $score += 15
            $signalCount++
            Add-Reason $reasons "hidden_task_or_hidden_execution"
        }
    }

    if ($startMode -match '(?i)^(Auto|Boot|System)$') {
        if ($isTrustedMicrosoft) {
            $score += 2
            Add-Reason $reasons "auto_boot_system_start_trusted_microsoft"
        } else {
            $score += 8
            $signalCount++
            Add-Reason $reasons "auto_boot_system_start"
        }
    }

    if ($isUserWritablePath) {
        if ($isTrustedMicrosoft) {
            $score += 2
            Add-Reason $reasons "writable_or_staging_path_but_trusted_microsoft_file"
        } else {
            $score += 25
            $signalCount++
            Add-Reason $reasons "path_in_user_writable_or_staging_location"
        }
    }

    if ($candidate -match '(?i)\\Windows\\Temp\\|\\Temp\\|\\Downloads\\') {
        $score += 20
        $signalCount++
        Add-Reason $reasons "temp_or_downloads_path"
    }

    if ($candidate -match '^(?i)\\\\') {
        $score += 20
        $signalCount++
        Add-Reason $reasons "unc_network_path"
    }

    if ($isExecutableRef -and $sig -and $sig -ne "Valid") {
        $score += 25
        $signalCount++
        Add-Reason $reasons "non_valid_authenticode_signature"
    }

    if ($isExecutableRef -and [string]::IsNullOrWhiteSpace($signer) -and $exists -match '(?i)^True$' -and $candidate -match '^[A-Za-z]:\\') {
        $score += 12
        $signalCount++
        Add-Reason $reasons "no_signer_for_existing_executable_ref"
    }

    if ($signer -and $signer -notmatch '(?i)Microsoft|Windows|DigiCert|GlobalSign|Sectigo|COMODO|Entrust|Google|Mozilla|Intel|NVIDIA|AMD|Adobe|Oracle|VMware|Citrix|Dell|HP|Lenovo|Cisco|Broadcom|Realtek') {
        $score += 10
        $signalCount++
        Add-Reason $reasons "non_common_publisher_review"
    }

    if ($hasLolBin) {
        if (($mechanism -match 'Image File Execution Options|Monitoring Silent Process Exit|AeDebug|WER Debugger|HKCU Run and RunOnce|Startup Folder|User Init Mpr Logon Script|HKCU cmd.exe AutoRun|PowerShell Profiles') -or $hasScriptNetwork -or (-not $isTrustedMicrosoft)) {
            $score += 20
            $signalCount++
            Add-Reason $reasons "lolbin_or_script_host_reference"
        } else {
            Add-Reason $reasons "lolbin_reference_trusted_context_low_signal"
        }
    }

    if ($hasScriptNetwork) {
        $score += 35
        $signalCount++
        Add-Reason $reasons "script_obfuscation_or_network_retrieval"
    }

    if (($data -match '(?i)\.tmp\\|\\temp\\|\.dat(\s|$)|\.log(\s|$)|\.txt(\s|$)') -and (Test-LooksLikeExecutableRef -Text $data)) {
        $score += 15
        $signalCount++
        Add-Reason $reasons "suspicious_extension_or_staging_combo"
    }

    if (($mechanism -match 'Image File Execution Options|Monitoring Silent Process Exit|AeDebug|WER Debugger') -and ($hasLolBin -or $hasScriptNetwork)) {
        $score += 25
        $signalCount++
        Add-Reason $reasons "debugger_hijack_to_script_or_lolbin"
    }

    if ($mechanism -match 'Password Filter|Authentication Packages|LSA Extension') {
        if ($candidate -and (-not $isSystemPath)) {
            $score += 30
            $signalCount++
            Add-Reason $reasons "lsa_related_path_outside_system_directory"
        } elseif ($isTrustedMicrosoft) {
            Add-Reason $reasons "trusted_microsoft_lsa_component"
        }
    }

    if ($mechanism -match 'Print Monitor|Netsh extension DLL|Autodial DLL|ServerLevelPluginDll') {
        if ($candidate -and (-not $isSystemPath) -and (-not $isTrustedMicrosoft)) {
            $score += 25
            $signalCount++
            Add-Reason $reasons "system_dll_load_path_outside_system_directory"
        } elseif ($isTrustedMicrosoft) {
            Add-Reason $reasons "trusted_microsoft_system_dll_component"
        }
    }

    if (($mechanism -match 'Startup Folder|PowerShell Profiles|Windows Terminal Profile|HKCU Run and RunOnce|User Init Mpr Logon Script|HKCU cmd.exe AutoRun') -and ($hasLolBin -or $hasScriptNetwork)) {
        if ($isTrustedMicrosoft -and (-not $hasScriptNetwork)) {
            $score += 2
            Add-Reason $reasons "user_autostart_trusted_builtin_shell_low_signal"
        } else {
            $score += 20
            $signalCount++
            Add-Reason $reasons "user_autostart_uses_script_or_network_pattern"
        }
    }

    if ($candidate -and $exists -match '(?i)^False$' -and $isExecutableRef) {
        $score += 8
        $signalCount++
        Add-Reason $reasons "candidate_path_not_found_now"
    }

    if ($writableByNonAdmin -match '(?i)^True$') {
        $score += 25
        $signalCount++
        Add-Reason $reasons "candidate_writable_by_non_admin_identity"
    }

    if ($zoneId -match '^[34]$') {
        $score += 15
        $signalCount++
        Add-Reason $reasons "mark_of_the_web_zone_$zoneId"
    }

    if ($isExecutableRef -and $isSystemPath -and $signer -and $signer -notmatch '(?i)Microsoft') {
        $score += 20
        $signalCount++
        Add-Reason $reasons "non_microsoft_signed_binary_in_system_directory_reference"
    }

    if ($mechanism -match 'Windows Services' -and $isUserWritablePath -and (-not $isTrustedMicrosoft)) {
        $score += 20
        $signalCount++
        Add-Reason $reasons "service_points_to_writable_or_staging_location"
    }

    # Strong false-positive reduction: signed Microsoft file, trusted location, not writable, and no real suspicious signal.
    if ($isTrustedMicrosoft -and $signalCount -eq 0) {
        $cap = 22
        if ($mechanism -match 'Password Filter|Authentication Packages|LSA Extension|Print Monitor|Netsh extension DLL|Autodial DLL|ServerLevelPluginDll') { $cap = 28 }
        if ($score -gt $cap) { $score = $cap }
        Add-Reason $reasons "trusted_microsoft_signed_system_component_downgrade"
    }

    # Empty/non-executable records from Microsoft task metadata should not become dangerous by mechanism or Hidden=True alone.
    if ($isMicrosoftWindowsTask -and $isTaskWithoutActionPath) {
        if ($score -gt 18) { $score = 18 }
        Add-Reason $reasons "microsoft_windows_task_without_action_path_low_signal"
    } elseif (([string]::IsNullOrWhiteSpace($candidate)) -and ($path -match '^\\Microsoft\\Windows\\') -and ($signalCount -eq 0)) {
        if ($score -gt 25) { $score = 25 }
        Add-Reason $reasons "microsoft_windows_task_without_action_path_low_signal"
    }

    return [pscustomobject]@{
        Score = $score
        Verdict = Get-Verdict -Score $score
        Group = $group
        Family = $family
        Reasons = ($reasons | Select-Object -Unique) -join "; "
    }
}

function Get-EvidenceType {
    param([pscustomobject]$Row)

    $candidate = S $Row.CandidatePath
    $exists = S $Row.CandidateExists
    $name = S $Row.Name
    $data = S $Row.Data

    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
        if ($exists -match '(?i)^True$') { return "ResolvedFile" }
        if ($exists -match '(?i)^False$') { return "MissingFileReference" }
        if (Test-AuditPathCandidate -PathCandidate $candidate) { return "UnverifiedFileReference" }
        return "NonFilesystemCandidate"
    }

    if ($data -match '^\{[0-9A-Fa-f-]{36}\}$') { return "CLSIDOrGUID" }
    if ($name -match '(?i)^(Name|Class|State|Author|Hidden|StartMode|StartName|DisplayName|ConfigurationMode|RefreshMode)$') { return "MetadataValue" }
    if ([string]::IsNullOrWhiteSpace($data)) { return "EmptyOrKeyOnlyValue" }

    return "RegistryOrConfigValue"
}

function Get-EnrichmentStatus {
    param([pscustomobject]$Row)

    $candidate = S $Row.CandidatePath
    $exists = S $Row.CandidateExists
    $sha = S $Row.SHA256
    $sig = S $Row.SignatureStatus

    if (-not [string]::IsNullOrWhiteSpace($sha)) { return "file_enriched_hash_signature_metadata" }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return "not_a_file_reference" }
    if (-not (Test-AuditPathCandidate -PathCandidate $candidate)) { return "candidate_not_filesystem_path" }
    if ($exists -match '(?i)^False$') { return "filesystem_path_not_found" }
    if ($exists -match '(?i)^True$' -and [string]::IsNullOrWhiteSpace($sha)) { return "file_found_hash_unavailable" }
    if ([string]::IsNullOrWhiteSpace($exists)) { return "filesystem_check_not_applicable_or_failed" }

    return "unknown"
}

function Get-NoHashReason {
    param([pscustomobject]$Row)

    $sha = S $Row.SHA256
    if (-not [string]::IsNullOrWhiteSpace($sha)) { return "" }

    $candidate = S $Row.CandidatePath
    $exists = S $Row.CandidateExists
    $data = S $Row.Data

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ($data -match '^\{[0-9A-Fa-f-]{36}\}$') { return "value_is_guid_or_clsid_not_file" }
        if ([string]::IsNullOrWhiteSpace($data)) { return "empty_value_or_key_inventory" }
        return "value_did_not_resolve_to_file_path"
    }

    if (-not (Test-AuditPathCandidate -PathCandidate $candidate)) { return "candidate_is_not_filesystem_path" }
    if ($exists -match '(?i)^False$') { return "file_not_found_at_candidate_path" }
    if ($exists -match '(?i)^True$') { return "hash_collection_failed_or_access_denied" }

    return "path_check_failed_or_not_applicable"
}

function Get-RecommendedAction {
    param([pscustomobject]$Row)

    $verdict = S $Row.Verdict
    $mechanism = S $Row.Mechanism
    $evidence = S $Row.EvidenceType
    $reasons = S $Row.Reasons

    if ($verdict -eq "Critical") { return "Inspect immediately: validate owner/change source, verify hash/signature, collect process/registry telemetry, and consider containment if unknown." }
    if ($verdict -eq "High") { return "Prioritize review: confirm expected software/vendor, compare against baseline, verify signer/hash/path ACLs, and investigate recent changes." }
    if ($verdict -eq "Medium") { return "Review after High/Critical: validate whether this entry is expected; baseline or allowlist only after confirming path, signer, and business need." }

    if ($evidence -match 'MetadataValue|CLSIDOrGUID|RegistryOrConfigValue') { return "Inventory context: not directly hashable; review only if the related resolved DLL/EXE or mapping is unexpected." }
    if ($reasons -match 'trusted_microsoft') { return "Likely expected Microsoft component; keep for baseline/drift monitoring." }

    return "Low priority baseline candidate."
}

function Add-ComputedTriageMetadata {
    param([pscustomobject]$Row)

    $row | Add-Member -NotePropertyName EvidenceType -NotePropertyValue (Get-EvidenceType -Row $Row) -Force
    $row | Add-Member -NotePropertyName EnrichmentStatus -NotePropertyValue (Get-EnrichmentStatus -Row $Row) -Force
    $row | Add-Member -NotePropertyName NoHashReason -NotePropertyValue (Get-NoHashReason -Row $Row) -Force
    $row | Add-Member -NotePropertyName IsTrustedMicrosoft -NotePropertyValue (Test-MicrosoftTrustedFile -Row $Row) -Force
    $row | Add-Member -NotePropertyName IsSystemPath -NotePropertyValue (Test-SystemDirectoryFile -CandidatePath (S $Row.CandidatePath)) -Force
    $row | Add-Member -NotePropertyName IsExecutableRef -NotePropertyValue (Test-LooksLikeExecutableRef -Text ("{0} {1}" -f (S $Row.Data), (S $Row.CandidatePath))) -Force
    $row | Add-Member -NotePropertyName IsUserWritablePath -NotePropertyValue (Test-UserWritablePathString -CandidatePath (S $Row.CandidatePath)) -Force
    $row | Add-Member -NotePropertyName HasLolBin -NotePropertyValue (Test-LolBinReference -Text ("{0} {1}" -f (S $Row.Data), (S $Row.CandidatePath))) -Force
    $row | Add-Member -NotePropertyName HasScriptNetwork -NotePropertyValue (Test-ScriptObfuscationOrNetworkRetrieval -Text ("{0} {1}" -f (S $Row.Data), (S $Row.CandidatePath))) -Force
    $row | Add-Member -NotePropertyName RecommendedAction -NotePropertyValue (Get-RecommendedAction -Row $Row) -Force

    return $Row
}

function Add-Finding {
    param(
        [string]$Mechanism,
        [string]$Category,
        [string]$Location,
        [string]$Path,
        [string]$Name = "",
        [object]$Data = "",
        [string]$UserSid = "",
        [string]$UserProfile = "",
        [string]$Risk = "Review",
        [string]$Notes = "",
        [hashtable]$Extra = @{}
    )

    $dataText = Normalize-Data $Data
    $file = Get-FileEvidence -CommandOrPath $dataText -Mechanism $Mechanism -Name $Name -RegistryPath $Path

    $row = [ordered]@{
        Timestamp = (Get-Date).ToString("o")
        Mechanism = $Mechanism
        Category = $Category
        Location = $Location
        Path = $Path
        Name = $Name
        Data = $dataText
        UserSid = $UserSid
        UserProfile = $UserProfile
        CandidatePath = $file.Candidate
        OriginalCandidate = $file.OriginalCandidate
        CandidateResolution = $file.CandidateResolution
        CandidateExists = $file.Exists
        SHA256 = $file.SHA256
        SignatureStatus = $file.Signature
        Signer = $file.Publisher
        FileOwner = $file.FileOwner
        WritableByNonAdmin = $file.WritableByNonAdmin
        CreationTimeUtc = $file.CreationTimeUtc
        LastWriteTimeUtc = $file.LastWriteTimeUtc
        CompanyName = $file.CompanyName
        ProductName = $file.ProductName
        OriginalFilename = $file.OriginalFilename
        FileDescription = $file.FileDescription
        ZoneId = $file.ZoneId
        Risk = $Risk
        Notes = $Notes
    }

    foreach ($k in $Extra.Keys) { $row[$k] = $Extra[$k] }

    $scoreInput = [pscustomobject]$row
    $triage = Score-Finding -Row $scoreInput

    $row["Group"] = $triage.Group
    $row["Family"] = $triage.Family
    $row["Score"] = $triage.Score
    $row["Verdict"] = $triage.Verdict
    $row["Reasons"] = $triage.Reasons

    $finalRow = Add-ComputedTriageMetadata -Row ([pscustomobject]$row)
    $script:Findings.Add($finalRow) | Out-Null
}

function Get-RegistryValueNames {
    param([string]$Path)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $key.GetValueNames()
    } catch {
        return @()
    }
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $regName = $Name
        if ($Name -eq "(default)") { $regName = "" }
        return $key.GetValue($regName, $null, "DoNotExpandEnvironmentNames")
    } catch {
        return $null
    }
}

function Add-RegistryValues {
    param(
        [string]$Mechanism,
        [string]$Category,
        [string]$Location,
        [string]$Path,
        [string[]]$Names = @(),
        [string]$UserSid = "",
        [string]$UserProfile = "",
        [string]$Risk = "Review",
        [string]$Notes = ""
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $valueNames = @()
        if ($Names.Count -gt 0) {
            $valueNames = $Names
        } else {
            $valueNames = $key.GetValueNames()
            if ($valueNames.Count -eq 0) { $valueNames = @("(key exists)") }
        }

        foreach ($vn in $valueNames) {
            if ($vn -eq "(key exists)") {
                Add-Finding -Mechanism $Mechanism -Category $Category -Location $Location -Path $Path -Name "" -Data "" -UserSid $UserSid -UserProfile $UserProfile -Risk $Risk -Notes "Registry key exists; no values present."
                continue
            }
            $regName = $vn
            if ($vn -eq "(default)") { $regName = "" }
            $value = $key.GetValue($regName, $null, "DoNotExpandEnvironmentNames")
            if ($null -ne $value) {
                $displayName = if ($regName -eq "") { "(default)" } else { $regName }
                Add-Finding -Mechanism $Mechanism -Category $Category -Location $Location -Path $Path -Name $displayName -Data $value -UserSid $UserSid -UserProfile $UserProfile -Risk $Risk -Notes $Notes
            }
        }
    } catch {
        Add-AuditError -Mechanism $Mechanism -Location $Path -ErrorText $_.Exception.Message
    }
}

function Add-RegistrySubkeyValues {
    param(
        [string]$Mechanism,
        [string]$Category,
        [string]$Location,
        [string]$BasePath,
        [string[]]$Names = @(),
        [string]$Risk = "Review",
        [string]$Notes = ""
    )

    if (-not (Test-Path -LiteralPath $BasePath)) { return }
    try {
        Get-ChildItem -LiteralPath $BasePath -ErrorAction Stop | ForEach-Object {
            Add-RegistryValues -Mechanism $Mechanism -Category $Category -Location $Location -Path $_.PSPath -Names $Names -Risk $Risk -Notes $Notes
        }
    } catch {
        Add-AuditError -Mechanism $Mechanism -Location $BasePath -ErrorText $_.Exception.Message
    }
}

function Resolve-ClsidInproc {
    param(
        [string]$Clsid,
        [string]$UserSid = ""
    )
    if ([string]::IsNullOrWhiteSpace($Clsid)) { return @() }
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    if ($UserSid) {
        $candidatePaths.Add("HKU:\$UserSid\Software\Classes\CLSID\$Clsid\InprocServer32") | Out-Null
    }
    foreach ($p in @(
        "HKLM:\SOFTWARE\Classes\CLSID\$Clsid\InprocServer32",
        "HKCR:\CLSID\$Clsid\InprocServer32"
    )) { $candidatePaths.Add($p) | Out-Null }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $candidatePaths) {
        if (Test-Path -LiteralPath $p) {
            $v = Get-RegistryValue -Path $p -Name "(default)"
            if ($null -ne $v) {
                $out.Add([pscustomobject]@{ Path = $p; Value = $v }) | Out-Null
            }
        }
    }
    return $out
}

Initialize-RegistryDrives

$profiles = @()
try {
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -and ($_.LocalPath -match '^[A-Za-z]:\\') }
} catch {}
$profileBySid = @{}
foreach ($p in $profiles) { $profileBySid[$p.SID] = $p.LocalPath }

$loadedUserSids = @()
try {
    $loadedUserSids = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
        ForEach-Object { $_.PSChildName }
} catch {}

# 1. HKCU Run and RunOnce
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    foreach ($sub in @(
        "Software\Microsoft\Windows\CurrentVersion\Run",
        "Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )) {
        Add-RegistryValues -Mechanism "HKCU Run and RunOnce registry keys" -Category "Registry/UserLogon" -Location "HKCU\$sub" -Path "HKU:\$sid\$sub" -UserSid $sid -UserProfile $profile -Risk "Review" -Notes "Runs at user logon. Commonly legitimate; verify command owner, signer, and path."
    }
}

# 2. Task Scheduler
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tasks) {
        $actions = @($t.Actions)
        foreach ($a in $actions) {
            $data = (($a.Execute, $a.Arguments) | Where-Object { $_ }) -join " "
            $risk = if ($t.Settings.Hidden) { "High" } else { "Review" }
            Add-Finding -Mechanism "Task Scheduler" -Category "ScheduledTask" -Location "Task Scheduler API" -Path ($t.TaskPath + $t.TaskName) -Name "Action" -Data $data -Risk $risk -Notes "Scheduled task action." -Extra @{
                State = [string]$t.State
                Author = [string]$t.Author
                Hidden = [string]$t.Settings.Hidden
            }
        }
    }
} catch {
    Add-AuditError -Mechanism "Task Scheduler" -Location "Task Scheduler API" -ErrorText $_.Exception.Message
    $taskRoot = Join-Path $env:WINDIR "System32\Tasks"
    if (Test-Path -LiteralPath $taskRoot) {
        Get-ChildItem -LiteralPath $taskRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Mechanism "Task Scheduler" -Category "ScheduledTask/FileFallback" -Location $taskRoot -Path $_.FullName -Name "TaskFile" -Data $_.FullName -Risk "Review" -Notes "Fallback task file inventory because ScheduledTasks API was unavailable."
        }
    }
}

# 3. Image File Execution Options - Debugger
$ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path -LiteralPath $ifeo) {
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Image File Execution Options key" -Category "Registry/ImageHijack" -Location "HKLM\...\Image File Execution Options\<image>\Debugger" -Path $_.PSPath -Names @("Debugger") -Risk "High" -Notes "Debugger value causes image execution redirection."
    }
}

# 4. Windows Services
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
    foreach ($svc in $services) {
        Add-Finding -Mechanism "Windows Services" -Category "Service" -Location "HKLM\SYSTEM\CurrentControlSet\Services" -Path $svc.Name -Name "ImagePath" -Data $svc.PathName -Risk "Review" -Notes "Service executable." -Extra @{
            DisplayName = [string]$svc.DisplayName
            StartMode = [string]$svc.StartMode
            State = [string]$svc.State
            StartName = [string]$svc.StartName
        }
    }
} catch {
    Add-AuditError -Mechanism "Windows Services" -Location "Win32_Service" -ErrorText $_.Exception.Message
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Windows Services" -Category "ServiceDll" -Location "HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll" -Path (Join-Path $_.PSPath "Parameters") -Names @("ServiceDll") -Risk "Review" -Notes "Service DLL loaded by svchost or service host."
    }
}

# 5. AeDebug
Add-RegistryValues -Mechanism "AeDebug" -Category "Registry/Debugger" -Location "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Names @("Debugger","Auto") -Risk "High" -Notes "Crash debugger configuration."

# 6. WER Debugger
Add-RegistryValues -Mechanism "WER Debugger" -Category "Registry/Debugger" -Location "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs" -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Hangs" -Names @("Debugger") -Risk "High" -Notes "Debugger invoked for hung applications."

# 7. Natural Language Development Platform 6 DLLs
$langBase = "HKLM:\System\CurrentControlSet\Control\ContentIndex\Language"
if (Test-Path $langBase) {
    Get-ChildItem -LiteralPath $langBase -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Natural Language Development Platform 6 DLLs" -Category "Registry/DLLLoad" -Location "HKLM\System\CurrentControlSet\Control\ContentIndex\Language\<language>\DLLOverridePath" -Path $_.PSPath -Names @("DLLOverridePath") -Risk "High" -Notes "SearchIndexer language DLL override."
    }
}

# 8. GPO Client-side Extension
$gpo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions"
if (Test-Path $gpo) {
    Get-ChildItem -LiteralPath $gpo -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "GPO Client-side Extension" -Category "Registry/DLLLoad" -Location "HKLM\...\Winlogon\GPExtensions\<CLSID>" -Path $_.PSPath -Names @("DllName","ProcessGroupPolicy","ProcessGroupPolicyEx","GenerateGroupPolicy","NoGPOListChanges") -Risk "Review" -Notes "Group Policy client-side extension registration."
    }
}

# 9. Filter Handlers for Windows Search
# 35. IFilter (same registry surface; emitted separately where handler COM DLLs are resolved)
$classesRoots = @("HKLM:\SOFTWARE\Classes")
foreach ($sid in $loadedUserSids) { $classesRoots += "HKU:\$sid\Software\Classes" }
foreach ($root in $classesRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like ".*" } |
        ForEach-Object {
            $extPath = $_.PSPath
            $phPath = Join-Path $extPath "PersistentHandler"
            if (Test-Path -LiteralPath $phPath) {
                $ph = Get-RegistryValue -Path $phPath -Name "(default)"
                if ($ph) {
                    Add-Finding -Mechanism "Filter Handlers for Windows Search" -Category "Registry/COM" -Location "$root\<extension>\PersistentHandler" -Path $phPath -Name "(default)" -Data $ph -Risk "Review" -Notes "Persistent handler CLSID for indexed file extension."
                    $ifilterKey = "$root\CLSID\$ph\PersistentAddinsRegistered\{89BCB740-6119-101A-BCB7-00DD010655AF}"
                    $ifilterClsid = Get-RegistryValue -Path $ifilterKey -Name "(default)"
                    if ($ifilterClsid) {
                        Add-Finding -Mechanism "IFilter" -Category "Registry/COM" -Location "$root\CLSID\<PersistentHandler>\PersistentAddinsRegistered\IFilter" -Path $ifilterKey -Name "(default)" -Data $ifilterClsid -Risk "Review" -Notes "IFilter implementation CLSID."
                        foreach ($res in Resolve-ClsidInproc -Clsid $ifilterClsid) {
                            Add-Finding -Mechanism "IFilter" -Category "Registry/COM" -Location "CLSID InprocServer32" -Path $res.Path -Name "(default)" -Data $res.Value -Risk "Review" -Notes "IFilter DLL path."
                        }
                    }
                }
            }
        }
}

# 10. Disk Cleanup Handler
$volCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
if (Test-Path $volCaches) {
    Get-ChildItem -LiteralPath $volCaches -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Disk Cleanup Handler" -Category "Registry/COM" -Location "HKLM\...\Explorer\VolumeCaches\<handler>" -Path $_.PSPath -Risk "Review" -Notes "Disk Cleanup handler configuration. GUID values should be resolved to CLSID InprocServer32."
        foreach ($name in Get-RegistryValueNames $_.PSPath) {
            $v = Normalize-Data (Get-RegistryValue -Path $_.PSPath -Name $name)
            if ($v -match '^\{[0-9A-Fa-f-]{36}\}$') {
                foreach ($res in Resolve-ClsidInproc -Clsid $v) {
                    Add-Finding -Mechanism "Disk Cleanup Handler" -Category "Registry/COM" -Location "Resolved CLSID InprocServer32" -Path $res.Path -Name "(default)" -Data $res.Value -Risk "Review" -Notes "Resolved Disk Cleanup handler COM DLL."
                }
            }
        }
    }
}

# 11. .chm helper DLL
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism ".chm helper DLL" -Category "Registry/DLLLoad" -Location "HKCU\Software\Microsoft\HtmlHelp Author" -Path "HKU:\$sid\Software\Microsoft\HtmlHelp Author" -UserSid $sid -UserProfile $profile -Risk "High" -Notes "DLL loaded when old CHM help content is opened."
}

# 12. hhctrl.ocx
Add-RegistryValues -Mechanism "hhctrl.ocx" -Category "Registry/COM" -Location "HKCR\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32" -Path "HKCR:\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32" -Names @("(default)") -Risk "High" -Notes "HTML Help control InprocServer32. Verify it points to the expected signed Microsoft hhctrl.ocx."

# 13. AMSI Providers
$amsi = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
if (Test-Path $amsi) {
    Get-ChildItem -LiteralPath $amsi -ErrorAction SilentlyContinue | ForEach-Object {
        $clsid = $_.PSChildName
        Add-Finding -Mechanism "AMSI Providers" -Category "Registry/COM" -Location "HKLM\SOFTWARE\Microsoft\AMSI\Providers\<CLSID>" -Path $_.PSPath -Name "ProviderCLSID" -Data $clsid -Risk "Review" -Notes "Registered AMSI provider."
        foreach ($res in Resolve-ClsidInproc -Clsid $clsid) {
            Add-Finding -Mechanism "AMSI Providers" -Category "Registry/COM" -Location "Resolved CLSID InprocServer32" -Path $res.Path -Name "(default)" -Data $res.Value -Risk "Review" -Notes "AMSI provider COM DLL."
        }
    }
}

# 14. ServerLevelPluginDll
Add-RegistryValues -Mechanism "ServerLevelPluginDll" -Category "Registry/DLLLoad" -Location "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Names @("ServerLevelPluginDll") -Risk "High" -Notes "DNS Server plugin DLL. Relevant only when DNS Server role is installed."

# 15. Password Filter
Add-RegistryValues -Mechanism "Password Filter" -Category "Registry/LSA" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Names @("Notification Packages") -Risk "High" -Notes "LSA password filter packages. Review non-default DLL names."

# 16. Credential Manager DLL / Network Provider
Add-RegistryValues -Mechanism "Credential Manager DLL" -Category "Registry/NetworkProvider" -Location "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Names @("ProviderOrder") -Risk "Review" -Notes "Network provider order."
$svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
if (Test-Path $svcRoot) {
    Get-ChildItem -LiteralPath $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $np = Join-Path $_.PSPath "NetworkProvider"
        Add-RegistryValues -Mechanism "Credential Manager DLL" -Category "Registry/NetworkProvider" -Location "HKLM\SYSTEM\CurrentControlSet\Services\<service>\NetworkProvider" -Path $np -Names @("ProviderPath","Name","Class") -Risk "High" -Notes "Network provider DLL can be loaded during logon."
    }
}

# 17. Authentication Packages
Add-RegistryValues -Mechanism "Authentication Packages" -Category "Registry/LSA" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Names @("Authentication Packages") -Risk "High" -Notes "LSASS authentication packages. Review non-default entries."

# 18. Code Signing DLL
foreach ($base in @(
    "HKLM:\SOFTWARE\Microsoft\Cryptography\Providers",
    "HKLM:\SOFTWARE\Microsoft\Cryptography\OID"
)) {
    if (Test-Path $base) {
        Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $names = Get-RegistryValueNames $_.PSPath
            foreach ($n in $names) {
                $v = Normalize-Data (Get-RegistryValue -Path $_.PSPath -Name $n)
                if ($n -match '(?i)dll|image|provider|func|path' -or $v -match '(?i)\.dll|\.ocx|\.exe') {
                    Add-Finding -Mechanism "Code Signing DLL" -Category "Registry/CryptoProvider" -Location $base -Path $_.PSPath -Name $n -Data $v -Risk "Review" -Notes "Cryptography provider/OID registration value. Review custom SIP/trust providers."
                }
            }
        }
    }
}

# 19. HKCU cmd.exe AutoRun
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism "HKCU cmd.exe AutoRun" -Category "Registry/Shell" -Location "HKCU\Software\Microsoft\Command Processor\AutoRun" -Path "HKU:\$sid\Software\Microsoft\Command Processor" -Names @("AutoRun") -UserSid $sid -UserProfile $profile -Risk "High" -Notes "Executed every time cmd.exe starts for this user."
}

# 20. LSA Extension
Add-RegistryValues -Mechanism "LSA Extension" -Category "Registry/LSA" -Location "HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\Extensions" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv" -Names @("Extensions") -Risk "High" -Notes "DLLs loaded by lsass.exe through LSA extension config."

# 21. Winlogon Notification Package
$notify = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
if (Test-Path $notify) {
    Get-ChildItem -LiteralPath $notify -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Winlogon Notification Package" -Category "Registry/Winlogon" -Location "HKLM\...\Winlogon\Notify\<package>" -Path $_.PSPath -Names @("DLLName","Asynchronous","Impersonate","Logon","Logoff","Startup","Shutdown","StartScreenSaver","StopScreenSaver","Lock","Unlock") -Risk "High" -Notes "Winlogon notification package DLL/event mapping."
    }
}

# 22. Print Monitor
$monitors = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
if (Test-Path $monitors) {
    Get-ChildItem -LiteralPath $monitors -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Print Monitor" -Category "Registry/DLLLoad" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<monitor>" -Path $_.PSPath -Names @("Driver") -Risk "High" -Notes "Print monitor DLL loaded by print spooler."
    }
}

# 23. HKCU Load
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism "HKCU Load" -Category "Registry/UserLogon" -Location "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load" -Path "HKU:\$sid\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Names @("Load") -UserSid $sid -UserProfile $profile -Risk "High" -Notes "Legacy user logon autostart value. Rare on modern Windows."
}

# 24. MPNotify
Add-RegistryValues -Mechanism "MPNotify" -Category "Registry/Winlogon" -Location "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\mpnotify" -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Names @("mpnotify") -Risk "High" -Notes "Executed by winlogon during logon and terminated after timeout."

# 25. Windows Platform Binary Table
$wpbtFile = Join-Path $env:WINDIR "System32\wpbbin.exe"
if (Test-Path -LiteralPath $wpbtFile) {
    Add-Finding -Mechanism "Windows Platform Binary Table" -Category "Firmware/Boot" -Location "UEFI WPBT -> %SystemRoot%\System32\wpbbin.exe" -Path $wpbtFile -Name "wpbbin.exe" -Data $wpbtFile -Risk "High" -Notes "wpbbin.exe exists. Confirm firmware source and signature."
}
Add-RegistryValues -Mechanism "Windows Platform Binary Table" -Category "Firmware/Boot" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\DisableWpbtExecution" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Names @("DisableWpbtExecution") -Risk "Info" -Notes "Value 1 disables WPBT execution. Absence does not prove compromise."

# 26. Explorer tools
$myComputer = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer"
if (Test-Path $myComputer) {
    Add-RegistrySubkeyValues -Mechanism "Explorer tools" -Category "Registry/UserInitiated" -Location "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\<tool>" -BasePath $myComputer -Names @("BackupPath","cleanuppath","DefragPath") -Risk "Review" -Notes "Explorer utility path mapping."
}

# 27. Windows Terminal Profile
$terminalPatterns = @(
    "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
    "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe"
)
foreach ($p in $profiles) {
    foreach ($pkg in $terminalPatterns) {
        $settings = Join-Path $p.LocalPath "AppData\Local\Packages\$pkg\LocalState\settings.json"
        if (Test-Path -LiteralPath $settings) {
            try {
                $jsonRaw = Get-Content -LiteralPath $settings -Raw -ErrorAction Stop
                $json = $jsonRaw | ConvertFrom-Json -ErrorAction Stop
                $defaultProfile = [string]$json.defaultProfile
                $startOnLogin = [string]$json.startOnUserLogin
                Add-Finding -Mechanism "Windows Terminal Profile" -Category "File/Profile" -Location "%LOCALAPPDATA%\Packages\$pkg\LocalState\settings.json" -Path $settings -Name "settings.json" -Data "defaultProfile=$defaultProfile; startOnUserLogin=$startOnLogin" -UserSid $p.SID -UserProfile $p.LocalPath -Risk "Review" -Notes "Windows Terminal settings. Review default profile and commandline values."
                if ($json.profiles -and $json.profiles.list) {
                    foreach ($prof in $json.profiles.list) {
                        $cmd = [string]$prof.commandline
                        if ($cmd) {
                            Add-Finding -Mechanism "Windows Terminal Profile" -Category "File/Profile" -Location "Windows Terminal profile commandline" -Path $settings -Name ([string]$prof.name) -Data $cmd -UserSid $p.SID -UserProfile $p.LocalPath -Risk "Review" -Notes "Custom profile commandline."
                        }
                    }
                }
            } catch {
                Add-AuditError -Mechanism "Windows Terminal Profile" -Location $settings -ErrorText $_.Exception.Message
            }
        }
    }
}

# 28. Startup Folder
$startupRel = "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
foreach ($p in $profiles) {
    $dir = Join-Path $p.LocalPath $startupRel
    if (Test-Path -LiteralPath $dir) {
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Mechanism "Startup Folder" -Category "File/UserLogon" -Location "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" -Path $_.FullName -Name $_.Name -Data $_.FullName -UserSid $p.SID -UserProfile $p.LocalPath -Risk "Review" -Notes "File launched from Startup folder at user logon."
        }
    }
}
$commonStartup = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path -LiteralPath $commonStartup) {
    Get-ChildItem -LiteralPath $commonStartup -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -Mechanism "Startup Folder" -Category "File/UserLogon" -Location "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" -Path $_.FullName -Name $_.Name -Data $_.FullName -Risk "Review" -Notes "Common Startup folder item. Added as an adjacent defensive check."
    }
}

# 29. User Init Mpr Logon Script
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism "User Init Mpr Logon Script" -Category "Registry/UserLogon" -Location "HKCU\Environment\UserInitMprLogonScript" -Path "HKU:\$sid\Environment" -Names @("UserInitMprLogonScript") -UserSid $sid -UserProfile $profile -Risk "High" -Notes "User logon script through HKCU Environment."
}

# 30. Autodial DLL
Add-RegistryValues -Mechanism "Autodial DLL" -Category "Registry/DLLLoad" -Location "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters" -Names @("AutodialDLL") -Risk "High" -Notes "Winsock Autodial DLL."

# 31. .NET Startup Hooks
Add-RegistryValues -Mechanism ".NET Startup Hooks" -Category "Environment" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\DOTNET_STARTUP_HOOKS" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Names @("DOTNET_STARTUP_HOOKS") -Risk "High" -Notes ".NET runtime startup hook loaded before Main in .NET apps."
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism ".NET Startup Hooks" -Category "Environment" -Location "HKCU\Environment\DOTNET_STARTUP_HOOKS" -Path "HKU:\$sid\Environment" -Names @("DOTNET_STARTUP_HOOKS") -UserSid $sid -UserProfile $profile -Risk "High" -Notes "Per-user .NET startup hook."
}

# 32. PowerShell Profiles
$psProfileRelatives = @(
    "Documents\WindowsPowerShell\Profile.ps1",
    "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    "Documents\PowerShell\Profile.ps1",
    "Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
)
foreach ($p in $profiles) {
    foreach ($rel in $psProfileRelatives) {
        $f = Join-Path $p.LocalPath $rel
        if (Test-Path -LiteralPath $f) {
            Add-Finding -Mechanism "PowerShell Profiles" -Category "File/Profile" -Location "`$Home\$rel" -Path $f -Name (Split-Path $f -Leaf) -Data $f -UserSid $p.SID -UserProfile $p.LocalPath -Risk "Review" -Notes "PowerShell profile runs when PowerShell starts unless -NoProfile is used."
        }
    }
}
foreach ($psInstallRoot in @($PSHOME, (Join-Path $env:ProgramFiles "PowerShell\7"))) {
    if (-not $psInstallRoot) { continue }
    foreach ($name in @("Profile.ps1","Microsoft.PowerShell_profile.ps1")) {
        $f = Join-Path $psInstallRoot $name
        if (Test-Path -LiteralPath $f) {
            Add-Finding -Mechanism "PowerShell Profiles" -Category "File/Profile" -Location "`$PSHOME\$name" -Path $f -Name $name -Data $f -Risk "Review" -Notes "All-users PowerShell profile."
        }
    }
}

# 33. TS Initial Program
foreach ($regPath in @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
)) {
    Add-RegistryValues -Mechanism "TS Initial Program" -Category "Registry/RDP" -Location $regPath -Path $regPath -Names @("fInheritInitialProgram","InitialProgram","WorkDirectory") -Risk "Review" -Notes "Initial program on RDP session when inherited/enabled."
}
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism "TS Initial Program" -Category "Registry/RDP" -Location "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Path "HKU:\$sid\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Names @("fInheritInitialProgram","InitialProgram","WorkDirectory") -UserSid $sid -UserProfile $profile -Risk "Review" -Notes "Per-user RDP initial program policy."
}

# 34. RDP WDS Startup Programs
Add-RegistryValues -Mechanism "RDP WDS Startup Programs" -Category "Registry/RDP" -Location "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" -Names @("StartupPrograms") -Risk "High" -Notes "Server-side programs launched after RDP session connection."

# 36. Recycle Bin COM Extension Handler
foreach ($rb in @(
    "HKCR:\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell",
    "HKLM:\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell"
)) {
    if (Test-Path $rb) {
        Get-ChildItem -LiteralPath $rb -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -ieq "command" } |
            ForEach-Object {
                Add-RegistryValues -Mechanism "Recycle Bin COM Extension Handler" -Category "Registry/COMVerb" -Location "$rb\<verb>\command" -Path $_.PSPath -Names @("(default)") -Risk "High" -Notes "Recycle Bin shell verb command."
            }
    }
}

# 37. TelemetryController
$telemetry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"
if (Test-Path $telemetry) {
    Get-ChildItem -LiteralPath $telemetry -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "TelemetryController" -Category "Registry/SystemTask" -Location "HKLM\...\AppCompatFlags\TelemetryController\<entry>" -Path $_.PSPath -Risk "Review" -Notes "CompatTelRunner telemetry controller command configuration."
    }
}

# 38. Monitoring Silent Process Exit
$spe = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
if (Test-Path $spe) {
    Get-ChildItem -LiteralPath $spe -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Monitoring Silent Process Exit" -Category "Registry/ProcessMonitor" -Location "HKLM\...\SilentProcessExit\<image>" -Path $_.PSPath -Names @("ReportingMode","MonitorProcess") -Risk "High" -Notes "MonitorProcess runs when configured monitored process exits."
    }
}
if (Test-Path $ifeo) {
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $gf = Get-RegistryValue -Path $_.PSPath -Name "GlobalFlag"
        if ($null -ne $gf) {
            $isMonitor = $false
            try { $isMonitor = (([int]$gf -band 512) -eq 512) } catch {}
            if ($isMonitor -or $true) {
                Add-Finding -Mechanism "Monitoring Silent Process Exit" -Category "Registry/ProcessMonitor" -Location "HKLM\...\Image File Execution Options\<image>\GlobalFlag" -Path $_.PSPath -Name "GlobalFlag" -Data $gf -Risk "High" -Notes "GlobalFlag contains FLG_MONITOR_SILENT_PROCESS_EXIT when bit 512 is set."
            }
        }
    }
}

# 39. Desired State Configuration
try {
    if (Get-Command Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue) {
        $lcm = Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue
        if ($lcm) {
            Add-Finding -Mechanism "Desired State Configuration" -Category "PowerShell/DSC" -Location "DSC Local Configuration Manager" -Path "LCM" -Name "ConfigurationMode" -Data $lcm.ConfigurationMode -Risk "Review" -Notes "DSC LCM can enforce configuration and run as SYSTEM." -Extra @{
                ActionAfterReboot = [string]$lcm.ActionAfterReboot
                ConfigurationModeFrequencyMins = [string]$lcm.ConfigurationModeFrequencyMins
                RefreshMode = [string]$lcm.RefreshMode
            }
        }
    }
    $dscDir = Join-Path $env:WINDIR "System32\Configuration"
    if (Test-Path -LiteralPath $dscDir) {
        Get-ChildItem -LiteralPath $dscDir -Filter "*.mof" -File -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Mechanism "Desired State Configuration" -Category "PowerShell/DSC" -Location "%WINDIR%\System32\Configuration\*.mof" -Path $_.FullName -Name $_.Name -Data $_.FullName -Risk "Review" -Notes "DSC MOF configuration file present."
        }
    }
} catch {
    Add-AuditError -Mechanism "Desired State Configuration" -Location "DSC" -ErrorText $_.Exception.Message
}

# 40. Screen Saver
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    Add-RegistryValues -Mechanism "Screen Saver" -Category "Registry/UserSession" -Location "HKCU\Control Panel\Desktop" -Path "HKU:\$sid\Control Panel\Desktop" -Names @("SCRNSAVE.EXE","ScreenSaveActive","ScreenSaverIsSecure","ScreenSaveTimeOut") -UserSid $sid -UserProfile $profile -Risk "Review" -Notes "Screensaver executable and activation settings."
}

# 41. Netsh extension DLL
Add-RegistryValues -Mechanism "Netsh extension DLL" -Category "Registry/DLLLoad" -Location "HKLM\SOFTWARE\Microsoft\NetSh" -Path "HKLM:\SOFTWARE\Microsoft\NetSh" -Risk "High" -Notes "Netsh helper DLL values."
if (Test-Path "HKLM:\SOFTWARE\Microsoft\NetSh") {
    Get-ChildItem -LiteralPath "HKLM:\SOFTWARE\Microsoft\NetSh" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-RegistryValues -Mechanism "Netsh extension DLL" -Category "Registry/DLLLoad" -Location "HKLM\SOFTWARE\Microsoft\NetSh\<subkey>" -Path $_.PSPath -Risk "High" -Notes "Netsh helper subkey."
    }
}

# 42. Boot Verification Program
Add-RegistryValues -Mechanism "Boot Verification Program" -Category "Registry/Boot" -Location "HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram\ImagePath" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BootVerificationProgram" -Names @("ImagePath") -Risk "High" -Notes "Service Control Manager launches ImagePath at boot verification."

# 43. File Extension Hijacking
foreach ($sid in $loadedUserSids) {
    $profile = $profileBySid[$sid]
    foreach ($path in @(
        "HKU:\$sid\Software\Classes\txtfile\shell\open\command",
        "HKU:\$sid\txtfile\shell\open\command"
    )) {
        Add-RegistryValues -Mechanism "File Extension Hijacking" -Category "Registry/FileAssociation" -Location "HKCU\txtfile\shell\open\command / HKCU\Software\Classes\txtfile\shell\open\command" -Path $path -Names @("(default)") -UserSid $sid -UserProfile $profile -Risk "High" -Notes "User-level txtfile open command override."
    }
}
Add-RegistryValues -Mechanism "File Extension Hijacking" -Category "Registry/FileAssociation" -Location "HKCR\txtfile\shell\open\command" -Path "HKCR:\txtfile\shell\open\command" -Names @("(default)") -Risk "Review" -Notes "Merged class open command for txtfile."

# 44. Keyboard Shortcut
try {
    $wsh = New-Object -ComObject WScript.Shell
    $lnkRoots = New-Object System.Collections.Generic.List[string]
    foreach ($p in $profiles) {
        foreach ($rel in @("Desktop","AppData\Roaming\Microsoft\Windows\Start Menu")) {
            $d = Join-Path $p.LocalPath $rel
            if (Test-Path -LiteralPath $d) { $lnkRoots.Add($d) | Out-Null }
        }
    }
    foreach ($root in $lnkRoots | Select-Object -Unique) {
        Get-ChildItem -LiteralPath $root -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $sc = $wsh.CreateShortcut($_.FullName)
                if ($sc.Hotkey) {
                    Add-Finding -Mechanism "Keyboard Shortcut" -Category "File/LNK" -Location "`$Home\Desktop / `$env:APPDATA\Microsoft\Windows\Start Menu" -Path $_.FullName -Name "Hotkey" -Data $sc.TargetPath -Risk "Review" -Notes "Shortcut has a hotkey. Pressing it launches target." -Extra @{
                        Hotkey = [string]$sc.Hotkey
                        Arguments = [string]$sc.Arguments
                        WorkingDirectory = [string]$sc.WorkingDirectory
                    }
                }
            } catch {}
        }
    }
} catch {
    Add-AuditError -Mechanism "Keyboard Shortcut" -Location "WScript.Shell" -ErrorText $_.Exception.Message
}

function Get-RowArray {
    param($Rows)

    $list = New-Object System.Collections.ArrayList

    if ($null -eq $Rows) {
        return @()
    }

    foreach ($item in $Rows) {
        if ($null -eq $item) { continue }

        $typeName = $item.GetType().FullName

        # Flatten only real collection containers. Do not flatten strings or PSCustomObject rows.
        if (($item -is [System.Collections.IEnumerable]) -and
            (-not ($item -is [string])) -and
            ($typeName -match '^System\.Collections')) {
            foreach ($nested in $item) {
                if ($null -ne $nested) { [void]$list.Add($nested) }
            }
        } else {
            [void]$list.Add($item)
        }
    }

    return @($list.ToArray())
}

function Get-ScoreInt {
    param($Row)

    try {
        return [int](Get-ObjectPropertyValue -Object $Row -PropertyName "Score")
    } catch {
        return 0
    }
}

function New-SortWrapper {
    param(
        $Row,
        [string]$Mode = "Default"
    )

    $score = Get-ScoreInt -Row $Row
    $inverseScore = 999999999 - $score

    if ($Mode -eq "Score") {
        $verdictRank = Get-VerdictRank -Verdict (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Verdict"))
        $key = "{0:D2}|{1:D9}|{2}|{3}|{4}|{5}" -f `
            $verdictRank,
            $inverseScore,
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Group")),
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Mechanism")),
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Path")),
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Name"))
    } else {
        $verdictRank = Get-VerdictRank -Verdict (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Verdict"))
        $key = "{0}|{1:D2}|{2:D9}|{3}|{4}|{5}" -f `
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Group")),
            $verdictRank,
            $inverseScore,
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Mechanism")),
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Path")),
            (S (Get-ObjectPropertyValue -Object $Row -PropertyName "Name"))
    }

    return [pscustomobject]@{
        SortKey = $key
        Row = $Row
    }
}

function Sort-FindingsDefault {
    param($Rows)

    $wrappers = New-Object System.Collections.ArrayList

    foreach ($r in (Get-RowArray -Rows $Rows)) {
        if ($null -eq $r) { continue }
        [void]$wrappers.Add((New-SortWrapper -Row $r -Mode "Default"))
    }

    $result = New-Object System.Collections.ArrayList
    foreach ($w in ($wrappers | Sort-Object -Property SortKey)) {
        [void]$result.Add($w.Row)
    }

    return @($result.ToArray())
}

function Sort-FindingsByScore {
    param($Rows)

    $wrappers = New-Object System.Collections.ArrayList

    foreach ($r in (Get-RowArray -Rows $Rows)) {
        if ($null -eq $r) { continue }
        [void]$wrappers.Add((New-SortWrapper -Row $r -Mode "Score"))
    }

    $result = New-Object System.Collections.ArrayList
    foreach ($w in ($wrappers | Sort-Object -Property SortKey)) {
        [void]$result.Add($w.Row)
    }

    return @($result.ToArray())
}

$script:SourceMechanisms = @(
    "HKCU Run and RunOnce registry keys",
    "Task Scheduler",
    "Image File Execution Options key",
    "Windows Services",
    "AeDebug",
    "WER Debugger",
    "Natural Language Development Platform 6 DLLs",
    "GPO Client-side Extension",
    "Filter Handlers for Windows Search",
    "Disk Cleanup Handler",
    ".chm helper DLL",
    "hhctrl.ocx",
    "AMSI Providers",
    "ServerLevelPluginDll",
    "Password Filter",
    "Credential Manager DLL",
    "Authentication Packages",
    "Code Signing DLL",
    "HKCU cmd.exe AutoRun",
    "LSA Extension",
    "Winlogon Notification Package",
    "Print Monitor",
    "HKCU Load",
    "MPNotify",
    "Windows Platform Binary Table",
    "Explorer tools",
    "Windows Terminal Profile",
    "Startup Folder",
    "User Init Mpr Logon Script",
    "Autodial DLL",
    ".NET Startup Hooks",
    "PowerShell Profiles",
    "TS Initial Program",
    "RDP WDS Startup Programs",
    "IFilter",
    "Recycle Bin COM Extension Handler",
    "TelemetryController",
    "Monitoring Silent Process Exit",
    "Desired State Configuration",
    "Screen Saver",
    "Netsh extension DLL",
    "Boot Verification Program",
    "File Extension Hijacking",
    "Keyboard Shortcut"
)
$script:ImplementedMechanisms = @(
    "HKCU Run and RunOnce registry keys",
    "Task Scheduler",
    "Image File Execution Options key",
    "Windows Services",
    "AeDebug",
    "WER Debugger",
    "Natural Language Development Platform 6 DLLs",
    "GPO Client-side Extension",
    "Filter Handlers for Windows Search",
    "Disk Cleanup Handler",
    ".chm helper DLL",
    "hhctrl.ocx",
    "AMSI Providers",
    "ServerLevelPluginDll",
    "Password Filter",
    "Credential Manager DLL",
    "Authentication Packages",
    "Code Signing DLL",
    "HKCU cmd.exe AutoRun",
    "LSA Extension",
    "Winlogon Notification Package",
    "Print Monitor",
    "HKCU Load",
    "MPNotify",
    "Windows Platform Binary Table",
    "Explorer tools",
    "Windows Terminal Profile",
    "Startup Folder",
    "User Init Mpr Logon Script",
    "Autodial DLL",
    ".NET Startup Hooks",
    "PowerShell Profiles",
    "TS Initial Program",
    "RDP WDS Startup Programs",
    "IFilter",
    "Recycle Bin COM Extension Handler",
    "TelemetryController",
    "Monitoring Silent Process Exit",
    "Desired State Configuration",
    "Screen Saver",
    "Netsh extension DLL",
    "Boot Verification Program",
    "File Extension Hijacking",
    "Keyboard Shortcut"
)

function Test-MechanismImplemented {
    param([string]$Mechanism)

    foreach ($m in @($script:ImplementedMechanisms)) {
        if ((S $m) -eq (S $Mechanism)) { return $true }
    }
    return $false
}

function Get-CoverageRows {
    param($Rows)

    $counts = @{}
    foreach ($r in @(Get-RowArray -Rows $Rows)) {
        $m = S $r.Mechanism
        if ([string]::IsNullOrWhiteSpace($m)) { continue }
        if (-not $counts.ContainsKey($m)) { $counts[$m] = 0 }
        $counts[$m] = [int]$counts[$m] + 1
    }

    $out = New-Object System.Collections.ArrayList
    foreach ($m in @($script:SourceMechanisms | Sort-Object)) {
        $implemented = Test-MechanismImplemented -Mechanism $m
        $observed = 0
        if ($counts.ContainsKey($m)) { $observed = [int]$counts[$m] }
        $coverageStatus = if ($implemented) { "Implemented" } else { "Missing" }

        [void]$out.Add([pscustomobject]@{
            Source = "persistence-info.github.io README"
            Mechanism = $m
            Implemented = $implemented
            ObservedRows = $observed
            CoverageStatus = $coverageStatus
            Notes = "Implemented means collector has a read-only check for this persistence-info location. ObservedRows can be 0 when the host has no matching artifact."
        })
    }
    return @($out)
}

function Export-FullCsv {
    param(
        $Rows,
        [string]$Path
    )

    $rowArray = Get-RowArray -Rows $Rows
    $props = New-Object System.Collections.ArrayList

    foreach ($r in $rowArray) {
        if ($null -eq $r) { continue }
        foreach ($p in $r.PSObject.Properties.Name) {
            $propName = [string]$p
            if (-not $props.Contains($propName)) {
                [void]$props.Add($propName)
            }
        }
    }

    if ($props.Count -eq 0) {
        if ($script:DefaultExportColumns -and $script:DefaultExportColumns.Count -gt 0) {
            $header = ($script:DefaultExportColumns | ForEach-Object { '"' + ([string]$_).Replace('"','""') + '"' }) -join ","
            Set-Content -LiteralPath $Path -Value $header -Encoding UTF8
        } else {
            Set-Content -LiteralPath $Path -Value "" -Encoding UTF8
        }
        return
    }

    $normalized = New-Object System.Collections.ArrayList

    foreach ($r in $rowArray) {
        if ($null -eq $r) { continue }
        $h = [ordered]@{}
        foreach ($p in $props) {
            $h[[string]$p] = S (Get-ObjectPropertyValue -Object $r -PropertyName ([string]$p))
        }
        [void]$normalized.Add([pscustomobject]$h)
    }

    if ($normalized.Count -eq 0) {
        if ($script:DefaultExportColumns -and $script:DefaultExportColumns.Count -gt 0) {
            $header = ($script:DefaultExportColumns | ForEach-Object { '"' + ([string]$_).Replace('"','""') + '"' }) -join ","
            Set-Content -LiteralPath $Path -Value $header -Encoding UTF8
        } else {
            Set-Content -LiteralPath $Path -Value "" -Encoding UTF8
        }
        return
    }

    $normalized | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Get-SummaryRows {
    param($Rows)

    $map = @{}

    foreach ($r in (Get-RowArray -Rows $Rows)) {
        if ($null -eq $r) { continue }

        $group = S (Get-ObjectPropertyValue -Object $r -PropertyName "Group")
        $verdict = S (Get-ObjectPropertyValue -Object $r -PropertyName "Verdict")
        $key = "$group`t$verdict"

        if (-not $map.ContainsKey($key)) {
            $map[$key] = [pscustomobject]@{
                Group = $group
                Verdict = $verdict
                Count = 0
            }
        }

        $map[$key].Count = [int]$map[$key].Count + 1
    }

    $wrappers = New-Object System.Collections.ArrayList
    foreach ($row in $map.Values) {
        $key = "{0}|{1}" -f (S $row.Group), (S $row.Verdict)
        [void]$wrappers.Add([pscustomobject]@{ SortKey = $key; Row = $row })
    }

    $result = New-Object System.Collections.ArrayList
    foreach ($w in ($wrappers | Sort-Object -Property SortKey)) {
        [void]$result.Add($w.Row)
    }

    return @($result.ToArray())
}

function Get-CountRowsByProperty {
    param(
        $Rows,
        [string]$PropertyName
    )

    $map = @{}

    foreach ($r in (Get-RowArray -Rows $Rows)) {
        if ($null -eq $r) { continue }
        $value = S (Get-ObjectPropertyValue -Object $r -PropertyName $PropertyName)
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "(empty)" }

        if (-not $map.ContainsKey($value)) {
            $map[$value] = [pscustomobject]@{
                Count = 0
                Name = $value
            }
        }

        $map[$value].Count = [int]$map[$value].Count + 1
    }

    $wrappers = New-Object System.Collections.ArrayList
    foreach ($row in $map.Values) {
        $inverseCount = 999999999 - [int]$row.Count
        $sortKey = "{0:D9}|{1}" -f $inverseCount, (S $row.Name)
        [void]$wrappers.Add([pscustomobject]@{ SortKey = $sortKey; Row = $row })
    }

    $result = New-Object System.Collections.ArrayList
    foreach ($w in ($wrappers | Sort-Object -Property SortKey)) {
        [void]$result.Add($w.Row)
    }

    return @($result.ToArray())
}

function Get-GroupedFindingMap {
    param(
        $Rows,
        [string]$PropertyName
    )

    $map = @{}

    foreach ($r in (Get-RowArray -Rows $Rows)) {
        if ($null -eq $r) { continue }
        $value = S (Get-ObjectPropertyValue -Object $r -PropertyName $PropertyName)
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "99 Other" }

        if (-not $map.ContainsKey($value)) {
            $map[$value] = New-Object System.Collections.ArrayList
        }

        [void]$map[$value].Add($r)
    }

    return $map
}

function Get-HtmlColumnWidth {
    param([string]$ColumnName)

    switch -Regex (S $ColumnName) {
        '^(Score)$' { return 64 }
        '^(Verdict|Risk)$' { return 90 }
        '^(Group|Family|Mechanism|Category|Location|EvidenceType|EnrichmentStatus|NoHashReason|CandidateResolution)$' { return 170 }
        '^(Path|Data|CandidatePath|OriginalCandidate|Signer|Reasons|RecommendedAction)$' { return 360 }
        '^(SHA256)$' { return 330 }
        '^(Name|UserSid|UserProfile|FileOwner|CompanyName|ProductName|OriginalFilename|FileDescription|DisplayName|Author|StartName)$' { return 220 }
        '^(Timestamp|CreationTimeUtc|LastWriteTimeUtc)$' { return 210 }
        '^(CandidateExists|WritableByNonAdmin|IsTrustedMicrosoft|IsSystemPath|IsExecutableRef|IsUserWritablePath|HasLolBin|HasScriptNetwork|Hidden|State|StartMode|ZoneId)$' { return 110 }
        default { return 160 }
    }
}

function Get-HtmlColumnCssClass {
    param([string]$ColumnName)

    $safe = (S $ColumnName) -replace '[^A-Za-z0-9_-]', '-'
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "col" }
    return "col-$safe"
}

function New-HtmlTable {
    param(
        $Rows,
        [string[]]$Columns,
        [switch]$HighlightDangerous
    )

    $rowArray = Get-RowArray -Rows $Rows

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<div class="table-wrap">')
    [void]$sb.AppendLine('<table class="report-table">')
    [void]$sb.AppendLine('<colgroup>')
    foreach ($c in $Columns) {
        $width = Get-HtmlColumnWidth -ColumnName $c
        $className = Get-HtmlColumnCssClass -ColumnName $c
        [void]$sb.AppendLine(('<col class="{0}" style="width:{1}px; min-width:{1}px;">' -f (ConvertTo-HtmlSafe $className), $width))
    }
    [void]$sb.AppendLine('</colgroup>')
    [void]$sb.AppendLine('<thead><tr>')

    foreach ($c in $Columns) {
        $className = Get-HtmlColumnCssClass -ColumnName $c
        [void]$sb.AppendLine(('<th class="{0}" title="{1}"><span class="th-label">{1}</span><span class="col-resizer" title="Drag to resize column"></span></th>' -f (ConvertTo-HtmlSafe $className), (ConvertTo-HtmlSafe $c)))
    }

    [void]$sb.AppendLine('</tr></thead>')
    [void]$sb.AppendLine('<tbody>')

    foreach ($r in $rowArray) {
        $verdict = S (Get-ObjectPropertyValue -Object $r -PropertyName "Verdict")
        $class = ""

        if ($HighlightDangerous) {
            if ($verdict -eq "Critical") { $class = " class=""critical""" }
            elseif ($verdict -eq "High") { $class = " class=""high""" }
            elseif ($verdict -eq "Medium") { $class = " class=""medium""" }
        }

        [void]$sb.AppendLine("<tr$class>")

        foreach ($c in $Columns) {
            $cell = Get-ObjectPropertyValue -Object $r -PropertyName $c
            $className = Get-HtmlColumnCssClass -ColumnName $c
            [void]$sb.AppendLine(('<td class="{0}" title="{1}">{1}</td>' -f (ConvertTo-HtmlSafe $className), (ConvertTo-HtmlSafe $cell)))
        }

        [void]$sb.AppendLine('</tr>')
    }

    [void]$sb.AppendLine('</tbody></table></div>')
    return $sb.ToString()
}


try {
    $script:ExportStep = "prepare output directory"
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $script:ExportStep = "prepare paths"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $jsonPath = Join-Path $OutputDirectory "persistence-info-audit-$stamp.json"
    $csvPath = Join-Path $OutputDirectory "persistence-info-audit-$stamp.csv"
    $errPath = Join-Path $OutputDirectory "persistence-info-audit-errors-$stamp.json"

    $triageDir = Join-Path $OutputDirectory "triage-$stamp"
    $categoryDir = Join-Path $triageDir "categories"

    New-Item -ItemType Directory -Path $triageDir -Force | Out-Null
    New-Item -ItemType Directory -Path $categoryDir -Force | Out-Null

    $script:ExportStep = "sort findings"
    $sortedFindings = Sort-FindingsDefault -Rows $script:Findings.ToArray()

    $script:ExportStep = "select review queue findings"
    $dangerousSource = @()
    foreach ($f in @($sortedFindings)) {
        if (Test-ReviewQueueVerdict -Verdict (S $f.Verdict)) {
            $dangerousSource += $f
        }
    }
    $dangerousFindings = Sort-FindingsByScore -Rows $dangerousSource

    $script:ExportStep = "build summary rows"
    $summaryRows = Get-SummaryRows -Rows $sortedFindings

    $script:ExportStep = "initialize export columns"
    $columns = @(
        "Score",
        "Verdict",
        "Group",
        "Family",
        "Mechanism",
        "Risk",
        "EvidenceType",
        "EnrichmentStatus",
        "NoHashReason",
        "Path",
        "Name",
        "Data",
        "CandidatePath",
        "OriginalCandidate",
        "CandidateResolution",
        "CandidateExists",
        "SHA256",
        "SignatureStatus",
        "Signer",
        "FileOwner",
        "WritableByNonAdmin",
        "ZoneId",
        "CompanyName",
        "ProductName",
        "OriginalFilename",
        "FileDescription",
        "IsTrustedMicrosoft",
        "IsSystemPath",
        "IsExecutableRef",
        "IsUserWritablePath",
        "HasLolBin",
        "HasScriptNetwork",
        "Reasons",
        "RecommendedAction"
    )
    $script:DefaultExportColumns = $columns

    $triageAllCsv = Join-Path $triageDir "persistence-info-triage-all.csv"
    $triageDangerousCsv = Join-Path $triageDir "persistence-info-triage-dangerous.csv"
    $triageReviewCsv = Join-Path $triageDir "persistence-info-triage-reviewqueue.csv"
    $triageSummaryCsv = Join-Path $triageDir "persistence-info-triage-summary.csv"
    $coverageCsv = Join-Path $triageDir "persistence-info-coverage.csv"
    $htmlPath = Join-Path $triageDir "persistence-info-triage-highlighted.html"

    $script:ExportStep = "write raw json"
    $sortedFindings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $script:ExportStep = "write raw csv"
    Export-FullCsv -Rows $sortedFindings -Path $csvPath

    $script:ExportStep = "write errors json"
    $script:Errors | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $errPath -Encoding UTF8

    $script:ExportStep = "write triage all csv"
    Export-FullCsv -Rows $sortedFindings -Path $triageAllCsv

    $script:ExportStep = "write review queue csv"
    Export-FullCsv -Rows $dangerousFindings -Path $triageReviewCsv

    $script:ExportStep = "write compatibility dangerous csv"
    Export-FullCsv -Rows $dangerousFindings -Path $triageDangerousCsv

    $script:ExportStep = "write summary csv"
    Export-FullCsv -Rows $summaryRows -Path $triageSummaryCsv

    $script:ExportStep = "write coverage csv"
    $coverageRows = Get-CoverageRows -Rows $sortedFindings
    Export-FullCsv -Rows $coverageRows -Path $coverageCsv

    $script:ExportStep = "write category csv files"
    $categoryFiles = New-Object System.Collections.Generic.List[object]
    $findingGroups = Get-GroupedFindingMap -Rows $sortedFindings -PropertyName "Group"

    $categoryIndex = 0
    foreach ($groupName in @($findingGroups.Keys | Sort-Object)) {
        $categoryIndex++
        $safe = Get-SafeFileName -Name $groupName
        $prefix = "{0:D2}" -f $categoryIndex

        $fileName = "{0}_{1}.csv" -f $prefix, $safe
        $filePath = Join-Path $categoryDir $fileName

        $groupRows = Sort-FindingsByScore -Rows $findingGroups[$groupName].ToArray()
        Export-FullCsv -Rows $groupRows -Path $filePath

        $categoryFiles.Add([pscustomobject]@{
            Group = $groupName
            Count = [int]$findingGroups[$groupName].Count
            File = $filePath
        }) | Out-Null
    }

    # columns are initialized before CSV exports

    $script:ExportStep = "build html tables"
    $summaryHtml = New-HtmlTable -Rows $summaryRows -Columns @("Group", "Verdict", "Count")
    $coverageHtml = New-HtmlTable -Rows $coverageRows -Columns @("Mechanism", "Implemented", "ObservedRows", "CoverageStatus", "Notes")
    $categoryHtml = New-HtmlTable -Rows $categoryFiles.ToArray() -Columns @("Group", "Count", "File")
    $dangerousTop = @($dangerousFindings | Select-Object -First 500)
    $dangerousHtml = New-HtmlTable -Rows $dangerousTop -Columns $columns -HighlightDangerous
    $reviewQueueHtml = '<details class="review-queue-block"><summary>Review queue findings: Medium/High/Critical - ' + (S $dangerousFindings.Count) + '</summary>' + $dangerousHtml + '</details>'
    $coverageSpoilerHtml = '<details class="coverage-block"><summary>Coverage check: persistence-info mechanisms - ' + (S $coverageRows.Count) + '</summary>' + $coverageHtml + '</details>' 

    $categorySections = New-Object System.Text.StringBuilder
    $htmlGroups = Get-GroupedFindingMap -Rows $sortedFindings -PropertyName "Group"
    foreach ($groupName in @($htmlGroups.Keys | Sort-Object)) {
        $groupRows = Sort-FindingsByScore -Rows $htmlGroups[$groupName].ToArray()
        $groupCount = [int]$htmlGroups[$groupName].Count
        $groupReview = 0
        foreach ($gr in @($groupRows)) {
            if (Test-ReviewQueueVerdict -Verdict (S $gr.Verdict)) { $groupReview++ }
        }

        $description = Get-MechanismDescription -Mechanism $groupName
        [void]$categorySections.AppendLine('<details class="category-block">')
        [void]$categorySections.AppendLine(('<summary>{0} - rows: {1}, review queue: {2}</summary>' -f (ConvertTo-HtmlSafe $groupName), $groupCount, $groupReview))
        [void]$categorySections.AppendLine(('<p class="category-description"><b>Criticality logic:</b> {0}</p>' -f (ConvertTo-HtmlSafe $description)))

        foreach ($riskLevel in @("Critical", "High", "Medium", "Low")) {
            $riskRowsSource = New-Object System.Collections.ArrayList
            foreach ($rr in @($groupRows)) {
                if ((S $rr.Verdict) -eq $riskLevel) { [void]$riskRowsSource.Add($rr) }
            }

            $riskRows = Sort-FindingsByScore -Rows $riskRowsSource.ToArray()
            $riskRowsArray = Get-RowArray -Rows $riskRows
            $riskCount = [int]$riskRowsArray.Count
            if ($riskCount -eq 0) { continue }

            $riskOpen = ""
            if ($riskLevel -eq "Critical" -or $riskLevel -eq "High" -or $riskLevel -eq "Medium") { $riskOpen = " open" }
            $riskClass = (S $riskLevel).ToLowerInvariant()

            [void]$categorySections.AppendLine(('<details class="risk-block {0}"{1}>' -f (ConvertTo-HtmlSafe $riskClass), $riskOpen))
            [void]$categorySections.AppendLine(('<summary>{0} - {1}</summary>' -f (ConvertTo-HtmlSafe $riskLevel), $riskCount))
            [void]$categorySections.AppendLine((New-HtmlTable -Rows $riskRowsArray -Columns $columns -HighlightDangerous))
            [void]$categorySections.AppendLine('</details>')
        }

        [void]$categorySections.AppendLine('</details>')
    }
    $categoriesHtml = $categorySections.ToString()

    $css = @"
<style>
:root {
  --score-width: 64px;
  --small-width: 90px;
  --medium-width: 170px;
  --large-width: 360px;
}
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
h1, h2 { font-weight: 600; }
.meta { margin-bottom: 18px; color: #333; }
.legend span { display: inline-block; padding: 4px 8px; border: 1px solid #ccc; margin-right: 8px; }
.table-wrap { width: 100%; max-width: 100%; overflow: auto; border: 1px solid #ddd; margin-bottom: 24px; }
table.report-table { border-collapse: collapse; width: max-content; min-width: 100%; font-size: 12px; table-layout: fixed; }
table.report-table th, table.report-table td { border: 1px solid #ccc; padding: 5px 7px; vertical-align: top; }
table.report-table th { background: #eee; text-align: left; position: sticky; top: 0; z-index: 2; user-select: none; }
table.report-table td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
table.report-table td.col-Path,
table.report-table td.col-Data,
table.report-table td.col-CandidatePath,
table.report-table td.col-OriginalCandidate,
table.report-table td.col-Signer,
table.report-table td.col-Reasons,
table.report-table td.col-RecommendedAction {
  white-space: normal;
  line-height: 1.35;
}
table.report-table td:hover { outline: 1px solid #666; background: #fff; white-space: normal; overflow: visible; position: relative; z-index: 3; }
.th-label { display: inline-block; padding-right: 8px; }
.col-resizer { position: absolute; top: 0; right: 0; width: 7px; height: 100%; cursor: col-resize; border-right: 2px solid transparent; }
.col-resizer:hover { border-right-color: #555; }
.critical { background: #ffd6d6; }
.high { background: #ffe8c2; }
.medium { background: #fff7cf; }
.legend span { display: inline-block; padding: 4px 8px; border: 1px solid #ccc; margin-right: 8px; }
details.category-block { margin: 12px 0; border: 1px solid #bbb; padding: 8px 10px; border-radius: 4px; }
details.category-block > summary { cursor: pointer; font-weight: 600; font-size: 15px; }
details.risk-block { margin: 10px 0 10px 18px; border-left: 4px solid #bbb; padding-left: 10px; }
details.risk-block > summary { cursor: pointer; font-weight: 600; }
details.risk-block.critical { border-left-color: #cc0000; }
details.risk-block.high { border-left-color: #d98200; }
details.risk-block.medium { border-left-color: #c7a300; }
details.risk-block.low { border-left-color: #888; }
.category-description { margin: 10px 0 12px 0; color: #333; max-width: 1400px; line-height: 1.45; }
details.review-queue-block, details.coverage-block { margin: 12px 0; border: 1px solid #999; padding: 8px 10px; border-radius: 4px; }
details.review-queue-block > summary, details.coverage-block > summary { cursor: pointer; font-weight: 600; font-size: 15px; }
</style>
"@


    $scriptJs = @"
<script>
(function () {
  function initResizableTables() {
    document.querySelectorAll("table.report-table").forEach(function (table) {
      var cols = table.querySelectorAll("colgroup col");
      table.querySelectorAll("th").forEach(function (th, index) {
        var handle = th.querySelector(".col-resizer");
        if (!handle || !cols[index]) { return; }

        handle.addEventListener("mousedown", function (event) {
          event.preventDefault();
          var startX = event.pageX;
          var startWidth = cols[index].getBoundingClientRect().width;

          function onMove(moveEvent) {
            var nextWidth = Math.max(50, startWidth + (moveEvent.pageX - startX));
            cols[index].style.width = nextWidth + "px";
            cols[index].style.minWidth = nextWidth + "px";
          }

          function onUp() {
            document.removeEventListener("mousemove", onMove);
            document.removeEventListener("mouseup", onUp);
          }

          document.addEventListener("mousemove", onMove);
          document.addEventListener("mouseup", onUp);
        });
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initResizableTables);
  } else {
    initResizableTables();
  }
})();
</script>
"@

    $html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Persistence-info v12 mechanism grouped audit report</title>
$css
</head>
<body>
<h1>Persistence-info v12 mechanism grouped audit report</h1>
<div class="meta">
Generated: $(Get-Date -Format o)<br>
Rows: $($sortedFindings.Count)<br>
Review queue rows: $($dangerousFindings.Count)<br>
Output directory: $(ConvertTo-HtmlSafe $OutputDirectory)<br>
Triage directory: $(ConvertTo-HtmlSafe $triageDir)
</div>

<div class="legend">
<span class="critical">Critical</span>
<span class="high">High</span>
<span class="medium">Medium</span>
</div>

<h2>Summary by group and verdict</h2>
$summaryHtml

<h2>Coverage</h2>
$coverageSpoilerHtml

<h2>Category files</h2>
$categoryHtml

<h2>Review queue</h2>
$reviewQueueHtml

<h2>All findings grouped by mechanism</h2>
$categoriesHtml
$scriptJs
</body>
</html>
"@

    $script:ExportStep = "write html"
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

    Write-Host ""
    Write-Host "Persistence-info audit complete."
    Write-Host "Findings:       $($script:Findings.Count)"
    Write-Host "Review queue:   $($dangerousFindings.Count)"
    Write-Host "Errors:         $($script:Errors.Count)"
    Write-Host "JSON:           $jsonPath"
    Write-Host "CSV:            $csvPath"
    Write-Host "Errors:         $errPath"
    Write-Host "Triage all:     $triageAllCsv"
    Write-Host "Review CSV:     $triageReviewCsv"
    Write-Host "Compat CSV:     $triageDangerousCsv"
    Write-Host "Summary CSV:    $triageSummaryCsv"
    Write-Host "Coverage CSV:   $coverageCsv"
    Write-Host "Category dir:   $categoryDir"
    Write-Host "HTML report:    $htmlPath"
    Write-Host ""

    $script:ExportStep = "console verdict summary"
    Get-CountRowsByProperty -Rows $sortedFindings -PropertyName "Verdict" |
        Format-Table -AutoSize

    $script:ExportStep = "console group summary"
    Get-CountRowsByProperty -Rows $sortedFindings -PropertyName "Group" |
        Format-Table -AutoSize
} catch {
    $lineNo = ""
    $lineText = ""

    if ($_.InvocationInfo) {
        $lineNo = [string]$_.InvocationInfo.ScriptLineNumber
        $lineText = [string]$_.InvocationInfo.Line
    }

    $msg = "Export failed at step '$script:ExportStep': $($_.Exception.Message)"
    if ($lineNo) { $msg += "`nLine: $lineNo" }
    if ($lineText) { $msg += "`nCommand: $lineText" }

    Write-Error $msg
}

