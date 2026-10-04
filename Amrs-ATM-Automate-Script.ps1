<#
.SYNOPSIS
    Amr's ATM Automate Script - v2.0
    NCR Personas / APTRA ATM security assessment automation (Windows).

.DESCRIPTION
    Single-file PowerShell collector for AUTHORISED ATM penetration tests.
    Runs 15 phases, writes a verbose human log, a machine-readable findings
    JSON/CSV, and (optionally) crackable Radmin hash lines.

    Phases
      1  Host context & NCR/APTRA software inventory
      2  Local users & administrators
      3  ATM service accounts (sstauto et al) & auto-logon
      4  UAC / elevation misconfiguration
      5  Credential hunting (registry, files, vaults, unattend)
      6  eJournal & camera archives (cardholder data at rest)
      7  Radmin Server hash extraction (v2 + v3, hashcat-ready)
      8  XFS registry, service-provider DLL integrity & trace config
      9  XFS API direct interaction (P/Invoke, bitness-aware)
      10 Application whitelisting & endpoint security posture
      11 Kiosk / lockdown breakout posture
      12 Local privilege-escalation surface
      13 Disk encryption & boot integrity
      14 Removable media & device control
      15 Network exposure

.PARAMETER OutputDir
    Where to write results. Defaults to ".\Amrs Output" next to the script,
    falling back to %TEMP% if that is not writable (e.g. read-only USB).

.PARAMETER Phases
    Which phases to run, e.g. -Phases 7,8,9. Default: all.

.PARAMETER NoRedact
    Write secrets and PANs to the log UNMASKED. Off by default: on a live
    ATM the output file would otherwise become cardholder data itself.

.PARAMETER Fast
    Skip the deep recursive filesystem scans in phases 5 and 6.

.PARAMETER SkipXfsApi
    Do not touch the XFS API at all (phase 9 becomes registry-only). Use on an
    in-service ATM, or where Add-Type would trip application whitelisting.

.PARAMETER ProveCdmLock
    SAFE impact proof: WFSLock the Cash Dispenser, log the result, WFSUnlock.
    Demonstrates exclusive control of the dispenser WITHOUT dispensing cash.
    Requires a typed confirmation unless -Force is also supplied.

.PARAMETER Relaunch32
    Re-execute this script under 32-bit PowerShell. XFS on ATMs is almost
    always 32-bit, and a 64-bit process cannot P/Invoke a 32-bit msxfs.dll.

.PARAMETER AllowNonAdmin
    Run without local administrator. Useful and encouraged: it shows what a
    kiosk-level or terminal-user attacker can actually reach.

.EXAMPLE
    .\Amrs-ATM-Automate-Script.ps1
    Full assessment, secrets masked, results under '.\Amrs Output\Run_<ts>'.

.EXAMPLE
    .\Amrs-ATM-Automate-Script.ps1 -Phases 7,8,9 -Relaunch32
    Radmin + XFS only, re-executed in 32-bit PowerShell so msxfs.dll loads.

.EXAMPLE
    .\Amrs-ATM-Automate-Script.ps1 -AllowNonAdmin -Phases 11,12
    What a kiosk-level attacker sees: lockdown posture and privesc surface.

.NOTES
    Author  : Amr Kadry
    Target  : NCR Personas / APTRA ATMs (Windows Embedded / IoT / 7 / 10)
    Version : 2.0

    AUTHORISED TESTING ONLY. Read-only by design: this script never dispenses
    cash, never writes to an XFS device, and never changes system configuration.
#>

[CmdletBinding()]
param(
    [string]   $OutputDir,
    [int[]]    $Phases = (1..15),
    [switch]   $NoRedact,
    [switch]   $Fast,
    [switch]   $SkipXfsApi,
    [switch]   $ProveCdmLock,
    [switch]   $Relaunch32,
    [switch]   $AllowNonAdmin,
    [switch]   $Force,
    [int]      $MaxScanSeconds = 180,
    [int]      $MaxScanFiles   = 20000
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'   # progress bars are painfully slow on ATM-class CPUs
$script:ExitCode       = 0

# ============================================================
#  BITNESS RELAUNCH (before anything else touches the system)
# ============================================================

$script:SelfPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Definition }

if ($Relaunch32 -and [Environment]::Is64BitProcess) {
    $ps32 = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps32) {
        Write-Host '[*] Relaunching under 32-bit PowerShell for XFS compatibility...' -ForegroundColor Cyan
        $fwd = @()
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Key -eq 'Relaunch32') { continue }
            if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $fwd += "-$($kv.Key)" } }
            elseif ($kv.Value -is [array]) { $fwd += "-$($kv.Key)"; $fwd += ($kv.Value -join ',') }
            else { $fwd += "-$($kv.Key)"; $fwd += "$($kv.Value)" }
        }
        & $ps32 -NoProfile -ExecutionPolicy Bypass -File $script:SelfPath @fwd
        exit $LASTEXITCODE
    }
    Write-Host "[!] 32-bit PowerShell not found at $ps32 - continuing in the current process." -ForegroundColor Yellow
}

# ============================================================
#  OUTPUT SETUP
# ============================================================

$ScriptDir = Split-Path -Parent $script:SelfPath
$Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

function Test-Writable {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $Path (".w" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        [IO.File]::WriteAllText($probe, 'x')
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

if (-not $OutputDir) { $OutputDir = Join-Path $ScriptDir 'Amrs Output' }
if (-not (Test-Writable $OutputDir)) {
    $fallback = Join-Path $env:TEMP "AmrsATM_$Timestamp"
    Write-Host "[!] '$OutputDir' is not writable - falling back to $fallback" -ForegroundColor Yellow
    $OutputDir = $fallback
    if (-not (Test-Writable $OutputDir)) { throw 'No writable output directory available.' }
}

$RunDir     = Join-Path $OutputDir "Run_$Timestamp"
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
$LogFile    = Join-Path $RunDir 'ATM-Assessment.log'
$JsonFile   = Join-Path $RunDir 'findings.json'
$CsvFile    = Join-Path $RunDir 'findings.csv'
$RadminReg  = Join-Path $RunDir 'Radmin-Registry.reg'
$RadminHash = Join-Path $RunDir 'Radmin-hashes.txt'
$BlobDir    = Join-Path $RunDir 'blobs'

# The output directory will hold credentials and possibly PANs. Lock it down to
# the current user + Administrators, and break inheritance from the parent.
try {
    $acl = Get-Acl $RunDir
    $acl.SetAccessRuleProtection($true, $false)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -Path $RunDir -AclObject $acl -ErrorAction Stop
} catch { }

# ============================================================
#  LOGGING
# ============================================================

# StreamWriter rather than Add-Content: Add-Content reopens the file per line,
# which costs minutes over a run this verbose. UTF-8 so the box-drawing and
# arrow characters below survive (the v1 log mangled them under ANSI).
$script:Writer = New-Object System.IO.StreamWriter($LogFile, $false, (New-Object System.Text.UTF8Encoding($true)))
$script:Writer.AutoFlush = $true

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.PadRight(8), $Message
    $colour = switch ($Level) {
        'CRITICAL' { 'Red' }
        'HIGH'     { 'Red' }
        'WARNING'  { 'Yellow' }
        'SUCCESS'  { 'Green' }
        'SECTION'  { 'Cyan' }
        'VERBOSE'  { 'DarkGray' }
        'ERROR'    { 'Magenta' }
        default    { 'Gray' }
    }
    Write-Host $line -ForegroundColor $colour
    $script:Writer.WriteLine($line)
}

function Write-Banner {
    param([string]$Title)
    $sep = '=' * 72
    $txt = "`r`n$sep`r`n  $Title`r`n$sep"
    Write-Host $txt -ForegroundColor Cyan
    $script:Writer.WriteLine($txt)
}

function Write-SubBanner {
    param([string]$Title)
    $txt = "`r`n  --- $Title " + ('-' * [Math]::Max(0, 60 - $Title.Length))
    Write-Host $txt -ForegroundColor DarkCyan
    $script:Writer.WriteLine($txt)
}

# ============================================================
#  FINDINGS MODEL
# ============================================================

$script:Findings = New-Object System.Collections.ArrayList
$script:Phase    = 0

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Asset = $env:COMPUTERNAME,
        [string]$Detail,
        [string]$Evidence,
        [string]$Impact,
        [string]$Remediation,
        [string]$Ref
    )
    $null = $script:Findings.Add([pscustomobject]@{
        Severity    = $Severity
        Phase       = $script:Phase
        Title       = $Title
        Asset       = $Asset
        Detail      = $Detail
        Evidence    = $Evidence
        Impact      = $Impact
        Remediation = $Remediation
        Ref         = $Ref
        Observed    = (Get-Date -Format 's')
    })
    $lvl = switch ($Severity) {
        'CRITICAL' { 'CRITICAL' }
        'HIGH'     { 'HIGH' }
        'MEDIUM'   { 'WARNING' }
        default    { 'INFO' }
    }
    Write-Log ('[FINDING/{0}] {1}' -f $Severity, $Title) $lvl
    if ($Detail)   { Write-Log ('    ' + $Detail) 'VERBOSE' }
    if ($Evidence) { Write-Log ('    evidence: ' + $Evidence) 'VERBOSE' }
}

# ============================================================
#  REDACTION  (default ON - the log must not itself become CHD)
# ============================================================

function Test-Luhn {
    param([string]$Digits)
    if ($Digits -notmatch '^\d{12,19}$') { return $false }
    $sum = 0
    $alt = $false
    for ($i = $Digits.Length - 1; $i -ge 0; $i--) {
        $d = [int]::Parse($Digits[$i])
        if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }
        $sum += $d
        $alt = -not $alt
    }
    return ($sum % 10 -eq 0)
}

function Protect-Pan {
    # Luhn-validate before masking, so random 16-digit IDs are not reported as
    # card numbers. v1 flagged any 16 digits and wrote them to disk in full.
    param([string]$Text)
    if ($NoRedact) { return $Text }
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return [regex]::Replace($Text, '(?<!\d)(\d[\d \-]{10,22}\d)(?!\d)', {
        param($m)
        $raw = $m.Groups[1].Value
        $d = ($raw -replace '[^\d]', '')
        if (Test-Luhn $d) {
            return $d.Substring(0, 6) + ('*' * ($d.Length - 10)) + $d.Substring($d.Length - 4) + '[PAN-MASKED]'
        }
        return $raw
    })
}

function Protect-Secret {
    param([string]$Text)
    if ($NoRedact) { return $Text }
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = Protect-Pan $Text
    # Mask the value side of password-ish assignments; keep the key name visible
    # so the finding is still actionable.
    $t = [regex]::Replace($t,
        '(?i)((?:pass(?:word|wd)?|pwd|secret|apikey|api_key|token|credential)\s*[:=]\s*)(\x22|\x27)?([^\s\x22\x27,;<>]{1,200})',
        { param($m) $m.Groups[1].Value + $m.Groups[2].Value + ('<REDACTED:' + $m.Groups[3].Value.Length + 'ch>') })
    # ISO/IEC 7813 track 2
    $t = [regex]::Replace($t, ';\d{12,19}=\d{4,}\?', ';<TRACK2-MASKED>?')
    return $t
}

function Show-Secret {
    # Display form for a recovered secret: length plus a short SHA-1, so the
    # same password can be correlated across a fleet without storing plaintext.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '(empty)' }
    if ($NoRedact) { return $Value }
    $sha = [Security.Cryptography.SHA1]::Create()
    try {
        $h = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally { $sha.Dispose() }
    return '<REDACTED len=' + $Value.Length + ' sha1=' + $h.Substring(0, 16) + '>'
}

# ============================================================
#  COMPAT HELPERS  (WES7 / POSReady ATMs may only have PS 2.0)
# ============================================================

$script:PSMajor = $PSVersionTable.PSVersion.Major

function Test-Cmd {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-Wmi {
    param([string]$Class, [string]$Filter)
    if (Test-Cmd 'Get-CimInstance') {
        if ($Filter) { Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction SilentlyContinue }
        else { Get-CimInstance -ClassName $Class -ErrorAction SilentlyContinue }
    } else {
        if ($Filter) { Get-WmiObject -Class $Class -Filter $Filter -ErrorAction SilentlyContinue }
        else { Get-WmiObject -Class $Class -ErrorAction SilentlyContinue }
    }
}

function Get-OsInfo {
    if (-not $script:OsCache) { $script:OsCache = Get-Wmi 'Win32_OperatingSystem' }
    return $script:OsCache
}

function Get-CsInfo {
    if (-not $script:CsCache) { $script:CsCache = Get-Wmi 'Win32_ComputerSystem' }
    return $script:CsCache
}

function Get-RegValue {
    # Null-safe single value read; returns $null when the key or value is absent.
    param([string]$Path, [string]$Name)
    try {
        $k = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -eq $k) { return $null }
        return $k.$Name
    } catch { return $null }
}

function Get-RegValues {
    param([string]$Path)
    try {
        $p = Get-ItemProperty -Path $Path -ErrorAction Stop
        return @($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' })
    } catch { return @() }
}

function Format-Hex {
    param([byte[]]$Bytes, [int]$Max = 0)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    $b = if ($Max -gt 0 -and $Bytes.Length -gt $Max) { $Bytes[0..($Max - 1)] } else { $Bytes }
    $s = ($b | ForEach-Object { $_.ToString('X2') }) -join ''
    if ($Max -gt 0 -and $Bytes.Length -gt $Max) { $s += '...(+' + ($Bytes.Length - $Max) + 'B)' }
    return $s
}

function Save-Blob {
    # Persist binary evidence in full. v1 only hex-dumped the first 48-64 bytes,
    # which is not enough to parse or crack anything offline.
    param([byte[]]$Bytes, [string]$Name)
    if (-not (Test-Path $BlobDir)) { New-Item -ItemType Directory -Path $BlobDir -Force | Out-Null }
    $p = Join-Path $BlobDir (($Name -replace '[^\w\.\-]', '_') + '.bin')
    [IO.File]::WriteAllBytes($p, $Bytes)
    return $p
}

function Get-PeMachineType {
    # Reads the PE COFF Machine field. Needed because 64-bit PowerShell cannot
    # P/Invoke a 32-bit msxfs.dll - the usual reason phase 9 silently "fails".
    param([string]$Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $br = New-Object IO.BinaryReader($fs)
            if ($br.ReadUInt16() -ne 0x5A4D) { return 'NOT-PE' }
            $fs.Position = 0x3C
            $peOff = $br.ReadUInt32()
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { return 'NOT-PE' }
            switch ($br.ReadUInt16()) {
                0x014C  { return 'x86' }
                0x8664  { return 'x64' }
                0x01C4  { return 'ARM' }
                0xAA64  { return 'ARM64' }
                default { return 'UNKNOWN' }
            }
        } finally { $fs.Dispose() }
    } catch { return 'ERROR' }
}

function Get-WeakAcl {
    # Allow-ACEs granting write-equivalent rights to a non-administrative
    # principal. On an ATM this is the whole game: a terminal-level account
    # that can write an XFS service-provider DLL owns the cash dispenser.
    param([string]$Path)
    $weak = @()
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $id = "$($ace.IdentityReference)"
            $isLowPriv = $id -match '(?i)^(Everyone|BUILTIN\\Users|NT AUTHORITY\\(Authenticated Users|INTERACTIVE)|.*\\(Users|Everyone))$' -or $id -match '(?i)sstauto|kiosk|operator'
            if (-not $isLowPriv) { continue }
            if ("$($ace.FileSystemRights)" -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions|CreateFiles|Delete') {
                $weak += ('{0} = {1}' -f $id, $ace.FileSystemRights)
            }
        }
    } catch { }
    return $weak
}

function Get-FileTrust {
    param([string]$Path)
    $sig = 'unchecked'
    $signer = ''
    try {
        if (Test-Cmd 'Get-AuthenticodeSignature') {
            $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
            $sig = "$($s.Status)"
            if ($s.SignerCertificate) { $signer = "$($s.SignerCertificate.Subject)" }
        }
    } catch { }
    return [pscustomobject]@{
        Path      = $Path
        Machine   = (Get-PeMachineType $Path)
        Signature = $sig
        Signer    = $signer
        WeakAcl   = (Get-WeakAcl $Path)
    }
}

function Get-BoundedFiles {
    # Recursive enumeration under a wall-clock and file-count budget. v1 walked
    # each search root once per file pattern (10 full recursive walks), which on
    # an Atom-class ATM could run for the better part of an hour.
    param(
        [string]$Path,
        [string[]]$Extensions,
        [int]$MaxFiles = 5000,
        [int]$MaxSeconds = 60,
        [long]$MaxBytes = 5MB
    )
    $sw  = [Diagnostics.Stopwatch]::StartNew()
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($f in (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { Write-Log "    (time budget reached scanning $Path)" 'VERBOSE'; break }
            if ($out.Count -ge $MaxFiles) { Write-Log "    (file cap reached scanning $Path)" 'VERBOSE'; break }
            if ($f.PSIsContainer) { continue }
            if ($Extensions -and ($Extensions -notcontains $f.Extension.ToLower())) { continue }
            if ($f.Length -gt $MaxBytes) { continue }
            $null = $out.Add($f)
        }
    } catch { }
    return $out
}

function Invoke-Phase {
    # Every phase is isolated: one broken check can no longer abort the run.
    param([int]$Number, [string]$Title, [scriptblock]$Body)
    if ($Phases -notcontains $Number) { Write-Log "Phase $Number ($Title) skipped by -Phases" 'VERBOSE'; return }
    $script:Phase = $Number
    Write-Banner ('PHASE {0} : {1}' -f $Number, $Title)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Body }
    catch {
        Write-Log "Phase $Number aborted: $($_.Exception.Message)" 'ERROR'
        Write-Log "$($_.ScriptStackTrace)" 'VERBOSE'
        $script:ExitCode = 2
    }
    Write-Log ('Phase {0} finished in {1:N1}s' -f $Number, $sw.Elapsed.TotalSeconds) 'VERBOSE'
}


# ============================================================
#  PREFLIGHT
# ============================================================

$header = @"
###############################################################
#                                                             #
#   Amr's ATM Automate Script  v2.0                           #
#   NCR Personas / APTRA security assessment                  #
#                                                             #
#   Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
#   Host      : $env:COMPUTERNAME
#   User      : $env:USERDOMAIN\$env:USERNAME
#   Process   : $(if([Environment]::Is64BitProcess){'64-bit'}else{'32-bit'}) PowerShell $($PSVersionTable.PSVersion)
#   Redaction : $(if($NoRedact){'OFF  <-- output will contain plaintext secrets'}else{'ON (PAN/secret masked)'})
#                                                             #
#   AUTHORISED TESTING ONLY                                   #
###############################################################
"@
Write-Host $header -ForegroundColor Green
$script:Writer.WriteLine($header)

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$script:IsAdmin  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:IsSystem = $identity.IsSystem

if (-not $script:IsAdmin -and -not $AllowNonAdmin) {
    Write-Log 'Not running as local Administrator. Many checks will be incomplete.' 'WARNING'
    Write-Log 'Re-run elevated, or pass -AllowNonAdmin to deliberately assess the low-privilege view.' 'WARNING'
    $script:Writer.Flush(); $script:Writer.Dispose()
    exit 1
}

Write-Log "Output directory : $RunDir"
Write-Log "Administrator    : $script:IsAdmin" $(if ($script:IsAdmin) { 'SUCCESS' } else { 'WARNING' })
Write-Log "SYSTEM           : $script:IsSystem"
Write-Log "Language mode    : $($ExecutionContext.SessionState.LanguageMode)"
Write-Log "Phases selected  : $($Phases -join ',')"
if ($Fast) { Write-Log 'Fast mode: deep filesystem scans will be skipped.' 'WARNING' }

# Language mode is checked up front, not in the last phase: it decides whether
# the XFS P/Invoke in phase 9 can run at all.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Log "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) - Add-Type and Win32 calls are blocked, phase 9 will degrade to registry only." 'WARNING'
}

# ============================================================
#  PHASE 1 : HOST CONTEXT & NCR SOFTWARE INVENTORY
# ============================================================

Invoke-Phase 1 'HOST CONTEXT & NCR SOFTWARE INVENTORY' {

    $os = Get-OsInfo
    $cs = Get-CsInfo

    $sysInfo = [ordered]@{
        'Hostname'      = $env:COMPUTERNAME
        'OS'            = $os.Caption
        'OS Version'    = $os.Version
        'OS Build'      = $os.BuildNumber
        'Architecture'  = $os.OSArchitecture
        'Install Date'  = $os.InstallDate
        'Last Boot'     = $os.LastBootUpTime
        'Manufacturer'  = $cs.Manufacturer
        'Model'         = $cs.Model
        'Domain'        = $cs.Domain
        'PartOfDomain'  = $cs.PartOfDomain
        'Workgroup'     = $cs.Workgroup
        'Current User'  = "$env:USERDOMAIN\$env:USERNAME"
        'TimeZone'      = (Get-Wmi 'Win32_TimeZone').Caption
    }
    foreach ($k in $sysInfo.Keys) { Write-Log ('  {0,-14} : {1}' -f $k, $sysInfo[$k]) }

    # --- Patch currency. ATMs are notoriously years behind. ---
    Write-SubBanner 'Patch Level'
    try {
        $hf = Get-Wmi 'Win32_QuickFixEngineering' | Where-Object { $_.InstalledOn } |
              Sort-Object { [datetime]$_.InstalledOn } -Descending
        $count = @($hf).Count
        Write-Log "  Hotfixes recorded : $count"
        if ($count -gt 0) {
            $newest = [datetime]$hf[0].InstalledOn
            $ageDays = [int]((Get-Date) - $newest).TotalDays
            Write-Log ("  Most recent patch : {0:yyyy-MM-dd} ({1} days ago)  [{2}]" -f $newest, $ageDays, $hf[0].HotFixID)
            foreach ($h in ($hf | Select-Object -First 10)) {
                Write-Log ('    {0}  {1:yyyy-MM-dd}' -f $h.HotFixID, [datetime]$h.InstalledOn) 'VERBOSE'
            }
            if ($ageDays -gt 180) {
                Add-Finding -Severity 'HIGH' -Title 'ATM is significantly behind on security patches' `
                    -Detail "Most recent hotfix installed $ageDays days ago ($($hf[0].HotFixID))." `
                    -Evidence ('newest={0:yyyy-MM-dd} total={1}' -f $newest, $count) `
                    -Impact 'Public exploits for patched local and remote vulnerabilities remain viable against the terminal.' `
                    -Remediation 'Bring the ATM into the managed patch cycle; agree a maintenance window with the operations team.' `
                    -Ref 'CWE-1104'
            }
        } else {
            Write-Log '  No hotfix data available (common on Embedded images using offline servicing).' 'WARNING'
        }
    } catch { Write-Log "  Patch enumeration failed: $($_.Exception.Message)" 'VERBOSE' }

    # Unsupported OS build check
    $caption = "$($os.Caption)"
    if ($caption -match '(?i)XP|Embedded Standard 2009|POSReady|Windows 7|Server 2008') {
        Add-Finding -Severity 'HIGH' -Title 'ATM runs an operating system past end of support' `
            -Detail $caption `
            -Evidence "$caption build $($os.BuildNumber)" `
            -Impact 'No vendor security updates; known kernel and driver vulnerabilities are permanently unpatched.' `
            -Remediation 'Migrate to a supported Windows 10 IoT Enterprise LTSC image, or document a compensating isolation control.' `
            -Ref 'CWE-1104'
    }

    # --- NCR / ATM software footprint ---
    Write-SubBanner 'ATM Software Footprint (filesystem)'
    $ncrPaths = @(
        'C:\Program Files\NCR', 'C:\Program Files (x86)\NCR',
        'C:\Program Files\NCR\APTRA', 'C:\Program Files (x86)\NCR\APTRA',
        'C:\NCR', 'C:\APTRA', 'C:\WOSA\XFS', 'C:\XFS',
        'C:\Program Files\Common Files\XFS', 'C:\Program Files (x86)\Common Files\XFS',
        'C:\Program Files\Diebold', 'C:\Program Files (x86)\Wincor Nixdorf',
        'C:\Program Files (x86)\KAL', 'C:\Program Files\Phoenix'
    )
    foreach ($p in $ncrPaths) {
        if (Test-Path $p) {
            Write-Log "  [FOUND] $p" 'SUCCESS'
            foreach ($item in (Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 20)) {
                Write-Log ('      {0}   {1}' -f $item.Name, $item.LastWriteTime) 'VERBOSE'
            }
            $weak = Get-WeakAcl $p
            if ($weak) {
                Add-Finding -Severity 'CRITICAL' -Title 'ATM application directory is writable by a non-administrative principal' `
                    -Detail "$p grants write access to: $($weak -join '; ')" `
                    -Evidence ($weak -join '; ') `
                    -Impact 'A terminal-level or kiosk account can replace ATM application and XFS binaries, which leads to full control of the dispenser and card reader.' `
                    -Remediation 'Restrict the directory tree to SYSTEM and Administrators; remove Users/Everyone write ACEs.' `
                    -Ref 'CWE-732'
            }
        } else {
            Write-Log "  [absent] $p" 'VERBOSE'
        }
    }

    Write-SubBanner 'Installed ATM / Remote-Access Software (registry)'
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $interesting = 'NCR|APTRA|Edge|XFS|Solidcore|McAfee|Radmin|Phoenix|Vista ATM|Diebold|Wincor|KAL|TeamViewer|VNC|AnyDesk|LogMeIn|Kaseya|ScreenConnect|Dameware'
    foreach ($rk in $uninstallKeys) {
        Get-ItemProperty $rk -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match $interesting } |
            ForEach-Object {
                Write-Log ('  [installed] {0}  v{1}  ({2})' -f $_.DisplayName, $_.DisplayVersion, $_.Publisher) 'SUCCESS'
                if ($_.DisplayName -match 'TeamViewer|VNC|AnyDesk|LogMeIn|Kaseya|ScreenConnect|Dameware|Radmin') {
                    Add-Finding -Severity 'MEDIUM' -Title "Third-party remote-access software installed: $($_.DisplayName)" `
                        -Detail "Version $($_.DisplayVersion). Remote-control software on an ATM widens the remote attack surface and is frequently the jackpotting entry point." `
                        -Evidence "$($_.DisplayName) v$($_.DisplayVersion)" `
                        -Impact 'An attacker who recovers or cracks the remote-access credential gains interactive control of the terminal.' `
                        -Remediation 'Remove unused remote-access agents; where required, restrict to a management VLAN with per-host unique credentials and MFA.' `
                        -Ref 'CWE-1393'
                }
            }
    }

    # --- Which process owns the ATM application, and as whom ---
    Write-SubBanner 'ATM Application Processes'
    $atmProcPattern = 'aptra|ncr|edge|xfs|sst|dispenser|cashdisp|journal|vista|probase|kal'
    foreach ($proc in (Get-Wmi 'Win32_Process' | Where-Object { $_.Name -match $atmProcPattern })) {
        $owner = ''
        try {
            if ($proc.GetOwner) { $o = $proc.GetOwner(); $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
        Write-Log ('  PID {0,-6} {1,-28} user={2}' -f $proc.ProcessId, $proc.Name, $owner)
        Write-Log ('      cmdline: {0}' -f (Protect-Secret "$($proc.CommandLine)")) 'VERBOSE'
    }
}

# ============================================================
#  PHASE 2 : LOCAL USERS & ADMINISTRATORS
# ============================================================

Invoke-Phase 2 'LOCAL USERS & ADMINISTRATORS' {

    Write-SubBanner 'Local Users'
    $users = @()
    if (Test-Cmd 'Get-LocalUser') {
        $users = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($u in $users) {
            $status = if ($u.Enabled) { 'ENABLED' } else { 'disabled' }
            $last   = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'never' }
            Write-Log ('  {0,-24} {1,-9} lastLogon={2}' -f $u.Name, $status, $last)
            Write-Log ('      pwdSet={0} pwdRequired={1} pwdExpires={2} sid={3}' -f $u.PasswordLastSet, $u.PasswordRequired, $u.PasswordExpires, $u.SID) 'VERBOSE'

            if ($u.Enabled -and -not $u.PasswordRequired) {
                # UF_PASSWD_NOTREQD only means a blank password is permitted, not
                # that the account has one. Confirm by hand before reporting.
                Add-Finding -Severity 'HIGH' -Title "Enabled local account '$($u.Name)' permits a blank password" `
                    -Detail 'The UF_PASSWD_NOTREQD flag is set, so this account may authenticate with an empty password. Verify with a logon attempt before reporting - the flag alone does not prove the password is blank.' `
                    -Evidence "$($u.Name) SID=$($u.SID)" `
                    -Impact 'Anyone with console or network access to the terminal can authenticate as this account without a credential.' `
                    -Remediation 'Set a unique strong password, or disable the account if unused.' `
                    -Ref 'CWE-258'
            }
            if ($u.Enabled -and $u.PasswordExpires -eq $null -and $u.PasswordLastSet) {
                Write-Log '      note: password set to never expire' 'VERBOSE'
            }
        }
    } else {
        Write-Log '  Get-LocalUser unavailable (PS 2.0) - using WMI' 'VERBOSE'
        foreach ($u in (Get-Wmi 'Win32_UserAccount' -Filter 'LocalAccount=True')) {
            Write-Log ('  {0,-24} disabled={1} lockout={2} sid={3}' -f $u.Name, $u.Disabled, $u.Lockout, $u.SID)
        }
    }

    Write-SubBanner 'Administrators Group'
    $admins = @()
    if (Test-Cmd 'Get-LocalGroupMember') {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
        foreach ($m in $admins) {
            Write-Log ('  [admin] {0,-34} type={1} source={2}' -f $m.Name, $m.ObjectClass, $m.PrincipalSource)
        }
    } else {
        foreach ($line in (net localgroup Administrators 2>&1)) { Write-Log "  $line" 'VERBOSE' }
    }

    # More than a couple of local admins on a kiosk appliance is an issue in itself.
    $localAdminCount = @($admins | Where-Object { $_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User' }).Count
    if ($localAdminCount -gt 2) {
        Add-Finding -Severity 'MEDIUM' -Title "Excessive local administrators on the terminal ($localAdminCount)" `
            -Detail (($admins | ForEach-Object { $_.Name }) -join ', ') `
            -Evidence "count=$localAdminCount" `
            -Impact 'Each additional administrative account is another credential that, if reused across the fleet, compromises every ATM.' `
            -Remediation 'Reduce to the minimum required; use per-host unique passwords (LAPS or the vendor equivalent).' `
            -Ref 'CWE-269'
    }

    Write-SubBanner 'Password Policy'
    foreach ($line in (net accounts 2>&1)) { Write-Log "  $line" }

    Write-SubBanner 'Built-in Administrator Status'
    $builtin = $users | Where-Object { "$($_.SID)" -match '-500$' }
    if ($builtin) {
        Write-Log ('  {0} (SID -500) enabled={1}' -f $builtin.Name, $builtin.Enabled)
        if ($builtin.Enabled -and $builtin.Name -eq 'Administrator') {
            Add-Finding -Severity 'LOW' -Title 'Built-in Administrator account is enabled and not renamed' `
                -Detail 'RID 500 account is enabled under its default name.' `
                -Evidence "$($builtin.Name) SID=$($builtin.SID)" `
                -Impact 'Provides a known, non-lockout-protected target for offline and online password attacks.' `
                -Remediation 'Rename and disable the built-in Administrator; use named administrative accounts.' `
                -Ref 'CWE-1392'
        }
    }
}

# ============================================================
#  PHASE 3 : ATM SERVICE ACCOUNTS & AUTO-LOGON
# ============================================================

Invoke-Phase 3 'ATM SERVICE ACCOUNTS & AUTO-LOGON' {

    # v1 only looked for 'sstauto'. The equivalent account is named differently
    # across vendors and site builds, so probe the whole family.
    $candidates = @('sstauto', 'ncruser', 'ncr', 'atmuser', 'atm', 'sst', 'kiosk', 'operator', 'edgeuser', 'aptra')
    $svcAccounts = @()

    if (Test-Cmd 'Get-LocalUser') {
        $all = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($c in $candidates) {
            $hit = $all | Where-Object { $_.Name -eq $c }
            if ($hit) { $svcAccounts += $hit }
        }
        # Also catch site-specific naming
        $svcAccounts += $all | Where-Object { $_.Description -match '(?i)auto|kiosk|terminal|unattended|service' }
        $svcAccounts = $svcAccounts | Sort-Object Name -Unique
    }

    if (-not $svcAccounts) {
        Write-Log '  No ATM/kiosk service account matched the known naming patterns.' 'INFO'
    }

    foreach ($sa in $svcAccounts) {
        Write-SubBanner "Service account: $($sa.Name)"
        Write-Log ('  enabled={0} pwdRequired={1} pwdLastSet={2} lastLogon={3}' -f $sa.Enabled, $sa.PasswordRequired, $sa.PasswordLastSet, $sa.LastLogon)
        Write-Log ('  description: {0}' -f $sa.Description) 'VERBOSE'
        Write-Log ('  sid        : {0}' -f $sa.SID) 'VERBOSE'

        # Group memberships - exact SID comparison, not a substring match
        $inGroups = @()
        if (Test-Cmd 'Get-LocalGroup') {
            foreach ($g in (Get-LocalGroup -ErrorAction SilentlyContinue)) {
                try {
                    $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop
                    if ($members | Where-Object { "$($_.SID)" -eq "$($sa.SID)" }) { $inGroups += $g.Name }
                } catch { }
            }
        }
        if ($inGroups) { Write-Log ('  groups: {0}' -f ($inGroups -join ', ')) 'WARNING' }

        if ($inGroups -contains 'Administrators' -and $sa.Enabled) {
            Add-Finding -Severity 'CRITICAL' -Title "ATM auto-logon account '$($sa.Name)' is a local administrator" `
                -Detail "Account is enabled and a member of: $($inGroups -join ', ')." `
                -Evidence "$($sa.Name) SID=$($sa.SID) groups=$($inGroups -join ',')" `
                -Impact 'The unattended session that the ATM boots into already holds administrative rights, so any kiosk breakout is an immediate full compromise of the terminal - no privilege escalation step required.' `
                -Remediation 'Run the ATM application under a least-privilege account; grant only the specific rights the XFS stack requires.' `
                -Ref 'CWE-250'
        }
    }

    # --- Auto-logon ---
    Write-SubBanner 'Winlogon Auto-Logon Configuration'
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $wl) {
        $p = Get-ItemProperty $wl -ErrorAction SilentlyContinue   # read once, not four times
        Write-Log ('  AutoAdminLogon     : {0}' -f $p.AutoAdminLogon)
        Write-Log ('  DefaultUserName    : {0}' -f $p.DefaultUserName)
        Write-Log ('  DefaultDomainName  : {0}' -f $p.DefaultDomainName)
        Write-Log ('  AutoLogonCount     : {0}' -f $p.AutoLogonCount) 'VERBOSE'
        Write-Log ('  ForceAutoLogon     : {0}' -f $p.ForceAutoLogon) 'VERBOSE'

        if ($p.DefaultPassword) {
            Add-Finding -Severity 'CRITICAL' -Title 'Auto-logon password stored in cleartext in the registry' `
                -Detail "HKLM\...\Winlogon\DefaultPassword is set for $($p.DefaultDomainName)\$($p.DefaultUserName)." `
                -Evidence ("DefaultUserName={0} DefaultPassword={1}" -f $p.DefaultUserName, (Show-Secret "$($p.DefaultPassword)")) `
                -Impact 'Any account that can read HKLM recovers the interactive ATM account password. If that password is reused across the estate, one terminal compromises the fleet.' `
                -Remediation 'Remove DefaultPassword and use the LSA secret path (sysinternals Autologon) or, preferably, an account with no interactive password at all. Rotate the password estate-wide.' `
                -Ref 'CWE-256'
        } else {
            Write-Log '  DefaultPassword    : not present' 'VERBOSE'
        }

        # Autologon can also be stashed as an LSA secret (DefaultPassword in LSA).
        if ($p.AutoAdminLogon -eq '1' -and -not $p.DefaultPassword) {
            Write-Log '  AutoAdminLogon enabled with no registry password: credential is likely an LSA secret (recoverable as SYSTEM).' 'WARNING'
            Add-Finding -Severity 'MEDIUM' -Title 'Unattended auto-logon enabled (credential held as an LSA secret)' `
                -Detail 'AutoAdminLogon=1 with no DefaultPassword value, so the credential is stored in the LSA secret DefaultPassword.' `
                -Evidence 'AutoAdminLogon=1, DefaultPassword absent' `
                -Impact 'The credential is recoverable by any SYSTEM-level code on the terminal, and the terminal boots into an interactive session with no authentication.' `
                -Remediation 'Accept only with a least-privilege ATM account plus full-disk encryption and physical controls on the top box.' `
                -Ref 'CWE-256'
        }
    }
}

# ============================================================
#  PHASE 4 : UAC / ELEVATION MISCONFIGURATION
# ============================================================

Invoke-Phase 4 'UAC / ELEVATION MISCONFIGURATION' {

    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (-not (Test-Path $uacKey)) {
        Write-Log 'UAC policy key missing - unusual configuration.' 'WARNING'
        return
    }
    $u = Get-ItemProperty $uacKey -ErrorAction SilentlyContinue

    $checks = @(
        @{ Name = 'EnableLUA';                   Desc = 'UAC master switch' }
        @{ Name = 'ConsentPromptBehaviorAdmin';  Desc = 'Admin elevation prompt (0=silent elevate, 1=creds, 2=consent, 5=consent for non-Windows)' }
        @{ Name = 'ConsentPromptBehaviorUser';   Desc = 'Standard user elevation prompt (0=auto-deny)' }
        @{ Name = 'PromptOnSecureDesktop';       Desc = 'Prompt on the secure desktop' }
        @{ Name = 'EnableInstallerDetection';    Desc = 'Installer detection' }
        @{ Name = 'ValidateAdminCodeSignatures'; Desc = 'Only elevate signed and validated binaries' }
        @{ Name = 'EnableSecureUIAPaths';        Desc = 'UIAccess integrity enforcement' }
        @{ Name = 'EnableVirtualization';        Desc = 'File and registry virtualisation' }
        @{ Name = 'FilterAdministratorToken';    Desc = 'Admin Approval Mode for RID 500' }
        @{ Name = 'LocalAccountTokenFilterPolicy'; Desc = 'Remote UAC token filtering (1 = disabled, enables remote admin)' }
    )

    foreach ($c in $checks) {
        $v = $u.($c.Name)
        if ($null -eq $v) { Write-Log ('  {0,-32} : not set (OS default applies)' -f $c.Name) 'VERBOSE'; continue }
        Write-Log ('  {0,-32} : {1}   {2}' -f $c.Name, $v, $c.Desc)
    }

    if ($u.EnableLUA -eq 0) {
        Add-Finding -Severity 'HIGH' -Title 'UAC is disabled (EnableLUA = 0)' `
            -Detail 'With EnableLUA=0 every member of Administrators runs with a full token and no elevation boundary exists.' `
            -Evidence 'EnableLUA=0' `
            -Impact 'Any code running as the ATM account, if that account is administrative, executes with full administrative rights with no prompt and no audit trail.' `
            -Remediation 'Set EnableLUA=1 and ConsentPromptBehaviorAdmin=2; validate the ATM application still starts.' `
            -Ref 'CWE-250'
    }
    if ($u.ConsentPromptBehaviorAdmin -eq 0 -and $u.EnableLUA -ne 0) {
        Add-Finding -Severity 'MEDIUM' -Title 'Administrators elevate silently (ConsentPromptBehaviorAdmin = 0)' `
            -Detail 'Elevation is granted without a consent or credential prompt.' `
            -Evidence 'ConsentPromptBehaviorAdmin=0' `
            -Impact 'Malicious code in an administrative session elevates with no user interaction.' `
            -Remediation 'Set ConsentPromptBehaviorAdmin=2 (consent on the secure desktop).' `
            -Ref 'CWE-250'
    }
    if ($u.LocalAccountTokenFilterPolicy -eq 1) {
        Add-Finding -Severity 'MEDIUM' -Title 'Remote UAC filtering disabled (LocalAccountTokenFilterPolicy = 1)' `
            -Detail 'Local administrative accounts receive a full token over the network.' `
            -Evidence 'LocalAccountTokenFilterPolicy=1' `
            -Impact 'A recovered local admin hash or password is directly usable for remote administration (pass-the-hash to the ATM).' `
            -Remediation 'Remove the value so remote logons for local accounts are token-filtered.' `
            -Ref 'CWE-269'
    }

    Write-SubBanner 'AlwaysInstallElevated'
    $aieU = Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieM = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    Write-Log "  HKCU=$aieU  HKLM=$aieM"
    if ($aieU -eq 1 -and $aieM -eq 1) {
        Add-Finding -Severity 'HIGH' -Title 'AlwaysInstallElevated enabled in both hives' `
            -Detail 'Any user can install an MSI package as SYSTEM.' `
            -Evidence 'HKCU=1 HKLM=1' `
            -Impact 'Direct, reliable local privilege escalation to SYSTEM from the kiosk account using a crafted MSI - no exploit needed.' `
            -Remediation 'Set both values to 0 or remove them via Group Policy.' `
            -Ref 'CWE-269'
    }

    Write-SubBanner 'Auto-Elevating Binaries Present'
    $bypassBins = @('fodhelper.exe', 'computerdefaults.exe', 'sdclt.exe', 'eventvwr.exe', 'mmc.exe',
                    'cmstp.exe', 'wsreset.exe', 'slui.exe', 'DismHost.exe', 'CompMgmtLauncher.exe')
    $present = @()
    foreach ($b in $bypassBins) {
        $f = Get-Command $b -ErrorAction SilentlyContinue
        if ($f) { $present += $b; Write-Log ('  [present] {0,-24} {1}' -f $b, $f.Source) 'VERBOSE' }
    }
    if ($present) {
        Write-Log ('  {0} known auto-elevating binaries reachable.' -f $present.Count) 'INFO'
        Write-Log '  (Informational on its own - only exploitable combined with EnableLUA=1 + ConsentPromptBehaviorAdmin=0/5 and an admin-group session.)' 'VERBOSE'
    }
}


# ============================================================
#  PHASE 5 : CREDENTIAL HUNTING
# ============================================================

Invoke-Phase 5 'CREDENTIAL HUNTING' {

    Write-SubBanner 'Stored Credentials (cmdkey / Credential Manager)'
    foreach ($line in (cmdkey /list 2>&1)) {
        if ("$line" -match 'Target:|Type:|User:|Local machine') { Write-Log ('  ' + "$line".Trim()) }
    }
    if (Test-Cmd 'vaultcmd') {
        foreach ($line in (vaultcmd /listcreds:"Windows Credentials" /all 2>&1)) { Write-Log ('  ' + "$line".Trim()) 'VERBOSE' }
    }

    Write-SubBanner 'Wi-Fi Profile Keys'
    try {
        $names = netsh wlan show profiles 2>&1 | Select-String 'All User Profile' | ForEach-Object { ("$_" -split ':', 2)[-1].Trim() }
        foreach ($n in $names) {
            $k = netsh wlan show profile name="$n" key=clear 2>&1 | Select-String 'Key Content'
            if ($k) {
                $key = ("$k" -split ':', 2)[-1].Trim()
                Add-Finding -Severity 'MEDIUM' -Title "Wireless pre-shared key recoverable from the ATM: '$n'" `
                    -Detail 'netsh wlan show profile key=clear returns the PSK to any administrator.' `
                    -Evidence ("SSID={0} key={1}" -f $n, (Show-Secret $key)) `
                    -Impact 'Grants an attacker who compromises one terminal access to the wireless network the ATM estate sits on.' `
                    -Remediation 'Use 802.1X with per-device certificates rather than a shared PSK, or wire the terminal.' `
                    -Ref 'CWE-522'
            }
        }
    } catch { Write-Log '  Wireless enumeration unavailable.' 'VERBOSE' }

    Write-SubBanner 'Known Credential Registry Locations'
    $credRegPaths = @(
        'HKLM:\SOFTWARE\RealVNC\WinVNC4', 'HKLM:\SOFTWARE\RealVNC\vncserver',
        'HKLM:\SOFTWARE\WOW6432Node\RealVNC\WinVNC4',
        'HKLM:\SOFTWARE\TightVNC\Server', 'HKLM:\SOFTWARE\WOW6432Node\TightVNC\Server',
        'HKLM:\SOFTWARE\ORL\WinVNC3\Default', 'HKCU:\SOFTWARE\ORL\WinVNC3\Default',
        'HKLM:\SOFTWARE\TeamViewer', 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer',
        'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
        'HKLM:\SOFTWARE\NCR\APTRA', 'HKLM:\SOFTWARE\NCR\Platform', 'HKLM:\SOFTWARE\NCR',
        'HKLM:\SOFTWARE\WOW6432Node\NCR',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'
    )
    foreach ($rp in $credRegPaths) {
        if (-not (Test-Path $rp)) { continue }
        Write-Log "  [key] $rp" 'VERBOSE'
        foreach ($v in (Get-RegValues $rp)) {
            if ($v.Name -notmatch '(?i)pass|pwd|secret|key|cred|auth|token|community|vnc') { continue }
            $display = if ($v.Value -is [byte[]]) { '[binary ' + $v.Value.Length + 'B] ' + (Format-Hex $v.Value 32) } else { Show-Secret "$($v.Value)" }
            Add-Finding -Severity 'HIGH' -Title "Credential material in registry: $rp -> $($v.Name)" `
                -Detail 'A credential-bearing registry value is readable at this path.' `
                -Evidence "$($v.Name) = $display" `
                -Impact 'Recoverable by any account with read access to the hive; VNC and SNMP values in particular are trivially reversible or directly reusable.' `
                -Remediation 'Remove the stored credential, or move the product to a credential store with per-host unique secrets.' `
                -Ref 'CWE-256'
            if ($v.Value -is [byte[]]) { $null = Save-Blob $v.Value ("reg_" + ($rp -replace '[:\\]', '_') + "_" + $v.Name) }
        }
    }

    Write-SubBanner 'Unattended Install / Provisioning Artefacts'
    $unattend = @(
        'C:\unattend.xml', 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml',
        'C:\Windows\system32\sysprep\unattend.xml', 'C:\Windows\system32\sysprep\Panther\unattend.xml',
        'C:\sysprep.inf', 'C:\sysprep\sysprep.xml', 'C:\Windows\Panther\setupinfo',
        'C:\Windows\debug\NetSetup.log', 'C:\Windows\Panther\UnattendGC\setupact.log'
    )
    foreach ($f in $unattend) {
        if (-not (Test-Path $f)) { continue }
        $hits = Get-Content $f -ErrorAction SilentlyContinue | Select-String 'Password|AdminPassword|UserAccounts|PlainText'
        if ($hits) {
            Add-Finding -Severity 'HIGH' -Title "Provisioning file retains credential material: $f" `
                -Detail 'Deployment artefact left on the terminal after imaging.' `
                -Evidence (($hits | Select-Object -First 5 | ForEach-Object { Protect-Secret "$($_.Line)".Trim() }) -join ' | ') `
                -Impact 'Image-build credentials are usually identical across the whole ATM estate, so recovering one yields fleet-wide access.' `
                -Remediation 'Delete provisioning artefacts as a final imaging step and rotate any credential they contained.' `
                -Ref 'CWE-522'
        } else {
            Write-Log "  [present, no credential strings] $f" 'VERBOSE'
        }
    }

    if ($Fast) { Write-Log '  Skipping deep configuration-file scan (-Fast).' 'WARNING'; return }

    Write-SubBanner 'Configuration File Credential Scan'
    $searchPaths = @(
        "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
        'C:\NCR', 'C:\APTRA', 'C:\Program Files\NCR', 'C:\Program Files (x86)\NCR',
        'C:\WOSA', 'C:\XFS', 'C:\temp', 'C:\Temp', 'C:\inetpub', 'C:\Scripts', 'C:\Install'
    )
    $exts = @('.ini', '.cfg', '.conf', '.config', '.xml', '.txt', '.log', '.bak', '.old', '.properties', '.json', '.ps1', '.bat', '.cmd', '.vbs')

    # The key must be followed by a separator and a real-looking value. Matching
    # the bare word "password" (as v1 did) flags every piece of documentation,
    # source comment and API reference on the disk - in testing that produced
    # over two hundred findings on a single host, which buries the real ones.
    $credPattern = '(?i)\b(password|passwd|pwd|secret|apikey|api_key|accesskey|access_key|connectionstring|privatekey)\b\s*[:=]\s*["'']?[^\s"''<>$%{},;]{4,}'
    $placeholder = '(?i)[:=]\s*["'']?(\$|%|\{|<|\[|null\b|changeme|xxx+|\*\*\*|your[_-]?|example|placeholder|todo)'
    # Developer and framework trees generate noise without ATM relevance.
    $excludeDir  = '(?i)\\(node_modules|\.git|\.svn|packages|site-packages|dist-info|obj|\.vs|\.nuget|AppData\\Local\\(Temp|Microsoft)|WinSxS)\\'
    $perRoot     = [int]($MaxScanSeconds / [Math]::Max(1, $searchPaths.Count))
    $maxPerRoot  = 25

    foreach ($sp in $searchPaths) {
        if (-not (Test-Path $sp)) { continue }
        Write-Log "  scanning $sp ..." 'VERBOSE'
        $reported = 0
        $suppressed = 0
        # One bounded walk per root, filtering by extension in-pass. v1 did a
        # separate full recursive walk for each of ten wildcard patterns.
        foreach ($f in (Get-BoundedFiles -Path $sp -Extensions $exts -MaxFiles $MaxScanFiles -MaxSeconds ([Math]::Max(10, $perRoot)))) {
            if ($f.FullName -match $excludeDir) { continue }
            try {
                $content = Get-Content $f.FullName -ErrorAction SilentlyContinue -TotalCount 800
                if (-not $content) { continue }
                $hits = @($content | Select-String -Pattern $credPattern | Where-Object { "$($_.Line)" -notmatch $placeholder })
                if (-not $hits) { continue }
                if ($reported -ge $maxPerRoot) {
                    $suppressed++
                    Write-Log ('    [suppressed] {0}' -f $f.FullName) 'VERBOSE'
                    continue
                }
                $reported++
                $ev = ($hits | Select-Object -First 4 | ForEach-Object { 'L' + $_.LineNumber + ': ' + (Protect-Secret "$($_.Line)".Trim()) }) -join ' | '
                Add-Finding -Severity 'MEDIUM' -Title "Possible credential in configuration file: $($f.Name)" `
                    -Detail $f.FullName `
                    -Evidence $ev `
                    -Impact 'Credentials in on-disk configuration are readable by anyone who reaches the filesystem, including after a disk-theft or offline-boot attack.' `
                    -Remediation 'Move secrets to DPAPI-protected or vendor-managed storage and remove the plaintext copies.' `
                    -Ref 'CWE-256'
            } catch { }
        }
        if ($suppressed -gt 0) {
            Write-Log ("  {0} further matching files under {1} were suppressed (cap {2} per root) - see VERBOSE lines." -f $suppressed, $sp, $maxPerRoot) 'WARNING'
        }
    }
}

# ============================================================
#  PHASE 6 : eJOURNAL & CAMERA ARCHIVES (CARDHOLDER DATA AT REST)
# ============================================================

Invoke-Phase 6 'eJOURNAL & CAMERA ARCHIVES' {

    Write-SubBanner 'eJournal Discovery'
    $ejPaths = @(
        'C:\NCR\eJournal', 'C:\NCR\Journal', 'C:\Program Files\NCR\eJournal',
        'C:\Program Files (x86)\NCR\eJournal', 'C:\APTRA\eJournal', 'C:\NCR\APTRA\eJournal',
        'C:\Users\sstauto\AppData\Local\NCR\eJournal', 'D:\eJournal', 'E:\eJournal',
        'C:\NCR\EJ', 'C:\ProgramData\NCR\eJournal'
    )
    $ejReg = @('HKLM:\SOFTWARE\NCR\eJournal', 'HKLM:\SOFTWARE\WOW6432Node\NCR\eJournal', 'HKLM:\SOFTWARE\NCR\APTRA\eJournal')
    foreach ($r in $ejReg) {
        if (-not (Test-Path $r)) { continue }
        Write-Log "  [registry] $r" 'VERBOSE'
        foreach ($v in (Get-RegValues $r)) {
            Write-Log ('      {0} = {1}' -f $v.Name, $v.Value) 'VERBOSE'
            if ($v.Name -match '(?i)path|dir|folder|location|archive|backup' -and "$($v.Value)") { $ejPaths += "$($v.Value)" }
        }
    }

    foreach ($p in ($ejPaths | Select-Object -Unique)) {
        if (-not (Test-Path $p)) { continue }
        Write-Log "  [found] eJournal directory: $p" 'SUCCESS'

        $weak = Get-WeakAcl $p
        if ($weak) {
            Add-Finding -Severity 'HIGH' -Title 'Electronic journal directory is readable or writable by a low-privilege principal' `
                -Detail "$p : $($weak -join '; ')" `
                -Evidence ($weak -join '; ') `
                -Impact 'The electronic journal records transaction detail and, on many builds, masked or unmasked card data. Write access additionally allows an attacker to erase the forensic record of a cash-out.' `
                -Remediation 'Restrict the journal tree to SYSTEM, Administrators and the ATM service account only.' `
                -Ref 'CWE-732'
        }

        $files = Get-BoundedFiles -Path $p -MaxFiles 5000 -MaxSeconds 45 -MaxBytes 50MB
        $size  = ($files | Measure-Object -Property Length -Sum).Sum
        Write-Log ('      files={0} total={1:N2} MB' -f @($files).Count, ($size / 1MB))

        if (-not $Fast) {
            $samples = $files | Where-Object { $_.Extension -match '(?i)\.(ej|jrn|log|txt|xml|dat|csv)$' } | Select-Object -First 25
            foreach ($s in $samples) {
                try {
                    $c = Get-Content $s.FullName -TotalCount 200 -ErrorAction SilentlyContinue
                    if (-not $c) { continue }
                    # Luhn-validated PAN detection: far fewer false positives than
                    # v1's "any 16 digits", and the evidence below is masked.
                    $panLines = @()
                    foreach ($line in $c) {
                        foreach ($m in [regex]::Matches("$line", '(?<!\d)(\d[\d \-]{10,22}\d)(?!\d)')) {
                            $d = ($m.Groups[1].Value -replace '[^\d]', '')
                            if (Test-Luhn $d) { $panLines += "$line"; break }
                        }
                    }
                    $track2 = $c | Select-String ';\d{12,19}=\d{4,}\?'
                    if ($panLines -or $track2) {
                        Add-Finding -Severity 'CRITICAL' -Title 'Unmasked cardholder data found in the electronic journal' `
                            -Detail "$($s.FullName) contains Luhn-valid primary account numbers$(if($track2){' and ISO 7813 track 2 data'}) in cleartext." `
                            -Evidence (($panLines | Select-Object -First 3 | ForEach-Object { Protect-Pan ("$_".Trim()) }) -join ' | ') `
                            -Impact 'Cardholder data at rest in cleartext on the terminal. A disk theft, offline boot, or any filesystem read reproduces card numbers for cloning and card-not-present fraud. This is a direct PCI DSS requirement 3 failure.' `
                            -Remediation 'Enable PAN truncation or masking in the journal configuration, encrypt the journal at rest, and purge historical journals holding full PANs.' `
                            -Ref 'CWE-312 / PCI DSS 3.4'
                    }
                } catch { }
            }
        }

        foreach ($bd in (Get-ChildItem -Path $p -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)backup|archive|old|bak' })) {
            Write-Log ('      [archive dir] {0}  modified {1}' -f $bd.FullName, $bd.LastWriteTime) 'WARNING'
        }
    }

    Write-SubBanner 'Camera / Surveillance Archive Discovery'
    $camPaths = @(
        'C:\NCR\Camera', 'C:\NCR\CameraImages', 'C:\NCR\Surveillance', 'C:\NCR\CameraArchive',
        'C:\Program Files\NCR\Camera', 'C:\APTRA\Camera', 'C:\NCR\APTRA\ImageArchive',
        'D:\Camera', 'D:\CameraBackup', 'E:\Camera', 'C:\ProgramData\NCR\Camera'
    )
    foreach ($r in @('HKLM:\SOFTWARE\NCR\Camera', 'HKLM:\SOFTWARE\WOW6432Node\NCR\Camera', 'HKLM:\SOFTWARE\NCR\APTRA\Camera', 'HKLM:\SOFTWARE\NCR\ImageArchive')) {
        if (-not (Test-Path $r)) { continue }
        foreach ($v in (Get-RegValues $r)) {
            Write-Log ('      {0} = {1}' -f $v.Name, $v.Value) 'VERBOSE'
            if ($v.Name -match '(?i)path|dir|folder|location|archive|backup|image' -and "$($v.Value)") { $camPaths += "$($v.Value)" }
        }
    }

    foreach ($p in ($camPaths | Select-Object -Unique)) {
        if (-not (Test-Path $p)) { continue }
        Write-Log "  [found] camera archive: $p" 'SUCCESS'
        $files = Get-BoundedFiles -Path $p -MaxFiles 5000 -MaxSeconds 30 -MaxBytes 100MB
        $imgs  = $files | Where-Object { $_.Extension -match '(?i)\.(jpg|jpeg|png|bmp|tif|tiff|avi|mp4|mkv)$' }
        Write-Log ('      files={0} images/video={1}' -f @($files).Count, @($imgs).Count)

        $weak = Get-WeakAcl $p
        if (@($imgs).Count -gt 0) {
            $sev = if ($weak) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding -Severity $sev -Title 'Surveillance imagery stored unencrypted on the ATM' `
                -Detail "$p holds $(@($imgs).Count) image or video files in cleartext$(if($weak){" and grants low-privilege access: $($weak -join '; ')"})." `
                -Evidence (($imgs | Select-Object -First 3 | ForEach-Object { $_.FullName }) -join ' | ') `
                -Impact 'Customer face imagery correlated with transaction timestamps is biometric and personal data. Write access also lets an attacker delete the footage covering a cash-out.' `
                -Remediation 'Encrypt the archive at rest, restrict ACLs to SYSTEM and Administrators, and enforce a short retention period.' `
                -Ref 'CWE-312'
        }
    }

    Write-SubBanner 'SMB Shares Exposing Journal / Camera / NCR Paths'
    if (Test-Cmd 'Get-SmbShare') {
        foreach ($sh in (Get-SmbShare -ErrorAction SilentlyContinue)) {
            if ("$($sh.Path)" -notmatch '(?i)journal|camera|surveillance|image|backup|NCR|APTRA') { continue }
            $acc = Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue |
                   ForEach-Object { "$($_.AccountName)=$($_.AccessControlType):$($_.AccessRight)" }
            Add-Finding -Severity 'HIGH' -Title "SMB share exposes ATM data: $($sh.Name)" `
                -Detail "$($sh.Name) -> $($sh.Path). Share permissions: $($acc -join '; ')" `
                -Evidence "$($sh.Name)=$($sh.Path) [$($acc -join '; ')]" `
                -Impact 'Journal, camera or application data is reachable over the network, extending a single-terminal compromise to anyone on the ATM VLAN.' `
                -Remediation 'Remove the share; if operationally required, restrict to named service accounts and require SMB signing and encryption.' `
                -Ref 'CWE-732'
        }
    } else {
        foreach ($line in (net share 2>&1)) { Write-Log "  $line" 'VERBOSE' }
    }
}

# ============================================================
#  PHASE 7 : RADMIN SERVER HASH EXTRACTION
# ============================================================

Invoke-Phase 7 'RADMIN SERVER HASH EXTRACTION' {

    $hashLines = New-Object System.Collections.ArrayList
    $radminFound = $false

    # v1 only looked at v3.0. Radmin 2.x is still common on older ATM images and
    # its hash is a straight MD5, which is dramatically easier to crack.
    $v2Paths = @(
        'HKLM:\SOFTWARE\Radmin\v2.0\Server\Parameters',
        'HKLM:\SOFTWARE\WOW6432Node\Radmin\v2.0\Server\Parameters'
    )
    $v3Paths = @(
        'HKLM:\SOFTWARE\Radmin\v3.0\Server\Parameters',
        'HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters',
        'HKLM:\SOFTWARE\Radmin\v3.0\Server\Parameters\Radmin Security',
        'HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security'
    )

    function Read-RadminTlv {
        # Bounds-safe TLV walk. v1 sliced $data[($o+4)..($o+3+$len)], which for a
        # zero length produces a reversed two-element range in PowerShell, and had
        # no end-of-buffer check at all, so a bad length silently yielded garbage.
        param([byte[]]$Data, [string]$Label)
        $out = [ordered]@{ Username = ''; Salt = $null; Verifier = $null; Modulus = $null; Generator = '' }
        $o = 0
        $guard = 0
        while ($o + 4 -le $Data.Length) {
            if (++$guard -gt 512) { Write-Log '      (TLV guard tripped - stopping)' 'VERBOSE'; break }
            $type = [BitConverter]::ToUInt16($Data, $o)
            $len  = [BitConverter]::ToUInt16($Data, $o + 2)
            $o += 4
            if ($len -eq 0) { Write-Log ('      TLV type {0}: zero length' -f $type) 'VERBOSE'; continue }
            if ($o + $len -gt $Data.Length) {
                Write-Log ('      TLV type {0}: declared length {1} exceeds buffer ({2} bytes left) - truncated record' -f $type, $len, ($Data.Length - $o)) 'VERBOSE'
                break
            }
            $val = New-Object byte[] $len
            [Array]::Copy($Data, $o, $val, 0, $len)
            $o += $len

            switch ($type) {
                16 {
                    $u = [Text.Encoding]::Unicode.GetString($val).TrimEnd([char]0)
                    $out.Username = $u
                    Write-Log ('      TLV 16 username : {0}' -f $u) 'WARNING'
                }
                48 { $out.Modulus = $val;  Write-Log ('      TLV 48 modulus  : {0}B {1}' -f $len, (Format-Hex $val 24)) 'VERBOSE' }
                64 {
                    $out.Generator = if ($len -le 8) { (Format-Hex $val) } else { '?' }
                    Write-Log ('      TLV 64 generator: {0}' -f $out.Generator) 'VERBOSE'
                }
                80 { $out.Salt = $val;     Write-Log ('      TLV 80 salt     : {0}B {1}' -f $len, (Format-Hex $val)) 'WARNING' }
                96 { $out.Verifier = $val; Write-Log ('      TLV 96 verifier : {0}B {1}' -f $len, (Format-Hex $val 32)) 'WARNING' }
                default { Write-Log ('      TLV {0,-5} : {1}B {2}' -f $type, $len, (Format-Hex $val 16)) 'VERBOSE' }
            }
        }
        return [pscustomobject]$out
    }

    # ---------- Radmin 2.x ----------
    foreach ($p in $v2Paths) {
        if (-not (Test-Path $p)) { continue }
        $radminFound = $true
        Write-SubBanner "Radmin 2.x: $p"
        foreach ($v in (Get-RegValues $p)) {
            if ($v.Value -isnot [byte[]]) { Write-Log ('  {0} = {1}' -f $v.Name, $v.Value) 'VERBOSE'; continue }
            $blob = Save-Blob $v.Value ("radmin2_" + $v.Name)
            Write-Log ('  {0} = [binary {1}B] saved to {2}' -f $v.Name, $v.Value.Length, $blob) 'WARNING'
            Write-Log ('      hex: {0}' -f (Format-Hex $v.Value)) 'VERBOSE'
            # Radmin 2 stores a raw MD5 of the password (null-padded input).
            if ($v.Value.Length -ge 16) {
                $md5 = Format-Hex ($v.Value[0..15])
                $null = $hashLines.Add("# Radmin 2.x  (hashcat -m 9900)   source=$p\$($v.Name)")
                $null = $hashLines.Add($md5.ToLower())
            }
        }
        Add-Finding -Severity 'HIGH' -Title 'Radmin 2.x password hash extractable from the registry' `
            -Detail "Radmin 2 keeps an unsalted MD5 of the remote-access password under $p. Hash written to $RadminHash for offline cracking (hashcat -m 9900)." `
            -Evidence "$p" `
            -Impact 'Unsalted MD5 with no iteration count cracks fast. The recovered password usually grants interactive remote control of the terminal, and is commonly identical across the estate.' `
            -Remediation 'Retire Radmin 2.x. If remote access is required use a current version with Radmin Security, per-host unique passwords, and IP restrictions.' `
            -Ref 'CWE-916'
    }

    # ---------- Radmin 3.x ----------
    foreach ($p in $v3Paths) {
        if (-not (Test-Path $p)) { continue }
        $radminFound = $true
        Write-SubBanner "Radmin 3.x: $p"

        $targets = @($p)
        foreach ($sk in (Get-ChildItem $p -ErrorAction SilentlyContinue)) { $targets += "$($sk.PSPath)" }

        foreach ($t in $targets) {
            foreach ($v in (Get-RegValues $t)) {
                if ($v.Value -isnot [byte[]]) {
                    Write-Log ('  {0} = {1}' -f $v.Name, $v.Value) 'VERBOSE'
                    continue
                }
                $name = (($t -replace '.*Radmin', 'Radmin') -replace '[:\\ ]', '_') + '_' + $v.Name
                $blob = Save-Blob $v.Value $name
                Write-Log ('  {0}\{1} = [binary {2}B] saved to {3}' -f (Split-Path $t -Leaf), $v.Name, $v.Value.Length, $blob) 'WARNING'

                $tlv = Read-RadminTlv -Data $v.Value -Label $name
                if ($tlv.Salt -and $tlv.Verifier) {
                    $u = if ($tlv.Username) { $tlv.Username } else { 'unknown' }
                    $null = $hashLines.Add("# Radmin 3.x SRP  user=$u  source=$t\$($v.Name)")
                    $null = $hashLines.Add("# hashcat -m 29200 ; VERIFY field order against 'hashcat --example-hashes -m 29200' before cracking")
                    $null = $hashLines.Add('$radmin3$' + (Format-Hex $tlv.Salt).ToLower() + '$' + (Format-Hex $tlv.Verifier).ToLower())

                    Add-Finding -Severity 'HIGH' -Title "Radmin 3 SRP verifier extractable for user '$u'" `
                        -Detail "Salt ($($tlv.Salt.Length)B) and verifier ($($tlv.Verifier.Length)B) recovered from $t. Full blob preserved at $blob; candidate hashcat line written to $RadminHash." `
                        -Evidence "user=$u salt=$(Format-Hex $tlv.Salt) verifierLen=$($tlv.Verifier.Length)" `
                        -Impact 'The verifier permits offline password recovery. A recovered Radmin password grants interactive remote control of the ATM, and these passwords are routinely shared across an estate.' `
                        -Remediation 'Rotate Radmin passwords to long per-host unique values, restrict Radmin to a management VLAN with IP filtering, and prefer Windows-authentication mode over Radmin Security.' `
                        -Ref 'CWE-916'
                }
            }
        }
    }

    if (-not $radminFound) {
        Write-Log '  Radmin Server not present (checked v2.0 and v3.0, both native and WOW6432Node).' 'INFO'
        return
    }

    # ---------- .reg export ----------
    Write-SubBanner 'Registry Export'
    $script:Writer.Flush()
    $regHeaderWritten = $false
    foreach ($exportPath in @('HKLM\SOFTWARE\Radmin', 'HKLM\SOFTWARE\WOW6432Node\Radmin')) {
        $tmp = Join-Path $env:TEMP ('radmin_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.reg')
        $null = & reg.exe export $exportPath $tmp /y 2>&1
        if (-not (Test-Path $tmp)) { Write-Log "  [skip] $exportPath (absent or access denied)" 'VERBOSE'; continue }
        $content = Get-Content $tmp -Raw -ErrorAction SilentlyContinue
        if (-not $regHeaderWritten) {
            Set-Content -Path $RadminReg -Value "Windows Registry Editor Version 5.00`r`n; Amr's ATM Automate Script - Radmin export`r`n; host=$env:COMPUTERNAME date=$(Get-Date -Format 's')`r`n" -Encoding ASCII
            $regHeaderWritten = $true
        }
        Add-Content -Path $RadminReg -Value ($content -replace 'Windows Registry Editor Version 5\.00\r?\n', '') -Encoding Unicode
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Write-Log "  [exported] $exportPath" 'SUCCESS'
    }

    if ($hashLines.Count -gt 0) {
        Set-Content -Path $RadminHash -Value $hashLines -Encoding ASCII
        Write-Log "  Hash candidates written to: $RadminHash" 'SUCCESS'
    }
}


# ============================================================
#  XFS SHARED HELPERS
# ============================================================

# CEN XFS service classes. The registry stores 'class' as a NAME on most
# implementations (e.g. "CDM") and as a NUMBER on others. v1 assumed numeric
# only, so [int]$class silently produced 0 and every CDM-specific check -
# including the entire cash-dispenser path - was skipped.
$script:XfsClasses = @(
    @{ Num = 1;  Name = 'PTR'; Label = 'Printer' }
    @{ Num = 2;  Name = 'IDC'; Label = 'Identification Card Unit (card reader)' }
    @{ Num = 3;  Name = 'CDM'; Label = 'Cash Dispenser Module' }
    @{ Num = 4;  Name = 'PIN'; Label = 'PIN Keypad / EPP' }
    @{ Num = 5;  Name = 'CHK'; Label = 'Check Reader' }
    @{ Num = 6;  Name = 'DEP'; Label = 'Depository' }
    @{ Num = 7;  Name = 'TTU'; Label = 'Text Terminal Unit' }
    @{ Num = 8;  Name = 'SIU'; Label = 'Sensors and Indicators Unit' }
    @{ Num = 9;  Name = 'VDM'; Label = 'Vendor Dependent Mode' }
    @{ Num = 10; Name = 'CAM'; Label = 'Camera' }
    @{ Num = 11; Name = 'ALM'; Label = 'Alarm' }
    @{ Num = 12; Name = 'CEU'; Label = 'Card Embossing Unit' }
    @{ Num = 13; Name = 'CIM'; Label = 'Cash-In Module' }
    @{ Num = 14; Name = 'CRD'; Label = 'Card Dispenser' }
    @{ Num = 15; Name = 'BCR'; Label = 'Barcode Reader' }
    @{ Num = 16; Name = 'IPM'; Label = 'Item Processing Module' }
)

function Resolve-XfsClass {
    param($Raw)
    $s = "$Raw".Trim()
    if ($s -match '^\d+$') {
        $hit = $script:XfsClasses | Where-Object { $_.Num -eq [int]$s }
    } else {
        $hit = $script:XfsClasses | Where-Object { $_.Name -eq $s.ToUpper() }
    }
    if ($hit) { return [pscustomobject]@{ Num = $hit.Num; Name = $hit.Name; Label = $hit.Label } }
    return [pscustomobject]@{ Num = 0; Name = $s; Label = "unrecognised ('$s')" }
}

function Get-XfsErrorName {
    # Per CEN XFS xfsapi.h. v1's table was incorrect (it mapped -26 to
    # "NO_SUCH_DEVICE", which is actually WFS_ERR_INVALID_TIMER).
    param([int]$Code)
    $map = @{
        0 = 'WFS_SUCCESS'; -1 = 'ALREADY_STARTED'; -2 = 'API_VER_TOO_HIGH'; -3 = 'API_VER_TOO_LOW'
        -4 = 'CANCELED'; -5 = 'CFG_CHANGED_PROP'; -6 = 'CFG_INVALID_CONTEXT'; -7 = 'CFG_INVALID_HKEY'
        -8 = 'CFG_INVALID_NAME'; -9 = 'DEV_NOT_READY'; -10 = 'HARDWARE_ERROR'; -11 = 'INTERNAL_ERROR'
        -12 = 'INVALID_ADDRESS'; -13 = 'INVALID_APP_HANDLE'; -14 = 'INVALID_BUFFER'; -15 = 'INVALID_CATEGORY'
        -16 = 'INVALID_COMMAND'; -17 = 'INVALID_EVENT_CLASS'; -18 = 'INVALID_HSERVICE'; -19 = 'INVALID_HPROVIDER'
        -20 = 'INVALID_HWND'; -21 = 'INVALID_HWNDREG'; -22 = 'INVALID_POINTER'; -23 = 'INVALID_REQ_ID'
        -24 = 'INVALID_RESULT'; -25 = 'INVALID_SERVPROV'; -26 = 'INVALID_TIMER'; -27 = 'INVALID_TRACELEVEL'
        -28 = 'LOCKED'; -29 = 'NO_BLOCKING_CALL'; -30 = 'NO_SERVPROV'; -31 = 'NO_SUCH_THREAD'
        -32 = 'NO_TIMER'; -33 = 'NOT_LOCKED'; -34 = 'NOT_STARTED'; -35 = 'NOT_REGISTERED'
        -36 = 'OP_IN_PROGRESS'; -37 = 'OUT_OF_MEMORY'; -38 = 'SERVICE_NOT_STARTED'; -39 = 'SPI_VER_TOO_HIGH'
        -40 = 'SPI_VER_TOO_LOW'; -41 = 'SRVC_VER_TOO_HIGH'; -42 = 'SRVC_VER_TOO_LOW'; -43 = 'TIMEOUT'
        -44 = 'UNSUPP_CATEGORY'; -45 = 'UNSUPP_COMMAND'; -46 = 'VERSION_ERROR_IN_SRVC'; -47 = 'INVALID_DATA'
        -48 = 'SOFTWARE_ERROR'; -49 = 'CONNECTION_LOST'; -50 = 'USER_ERROR'; -51 = 'UNSUPP_DATA'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return "UNKNOWN($Code)"
}

$script:XfsDllPath      = $null
$script:LogicalServices = @()

# ============================================================
#  PHASE 8 : XFS REGISTRY, SP INTEGRITY & TRACE CONFIGURATION
# ============================================================

Invoke-Phase 8 'XFS REGISTRY, SERVICE-PROVIDER INTEGRITY & TRACING' {

    Write-SubBanner 'XFS Manager Binary'
    $dllCandidates = @(
        (Join-Path $env:SystemRoot 'System32\msxfs.dll'),
        (Join-Path $env:SystemRoot 'SysWOW64\msxfs.dll'),
        'C:\Program Files\Common Files\XFS\msxfs.dll',
        'C:\Program Files (x86)\Common Files\XFS\msxfs.dll',
        'C:\WOSA\XFS\msxfs.dll', 'C:\XFS\msxfs.dll'
    )
    foreach ($d in $dllCandidates) {
        if (-not (Test-Path $d)) { continue }
        $t = Get-FileTrust $d
        Write-Log ('  [found] {0}' -f $d) 'SUCCESS'
        Write-Log ('      arch={0} signature={1} signer={2}' -f $t.Machine, $t.Signature, $t.Signer)
        if (-not $script:XfsDllPath) { $script:XfsDllPath = $d }
        if ($t.WeakAcl) {
            Add-Finding -Severity 'CRITICAL' -Title 'XFS Manager (msxfs.dll) is writable by a non-administrative principal' `
                -Detail "$d : $($t.WeakAcl -join '; ')" `
                -Evidence ($t.WeakAcl -join '; ') `
                -Impact 'Replacing the XFS Manager intercepts every call between the ATM application and the cash dispenser, card reader and PIN pad. This is a complete terminal compromise: unauthorised dispense and card data capture, with no exploit required.' `
                -Remediation 'Restrict msxfs.dll to SYSTEM and Administrators (read and execute for everyone else).' `
                -Ref 'CWE-732'
        }
    }
    if (-not $script:XfsDllPath) {
        # v1 fell back to a full C:\ recursive search, which can run for a very
        # long time on an ATM disk. Bound it to the plausible roots.
        Write-Log '  msxfs.dll not in the standard locations - searching likely roots...' 'WARNING'
        foreach ($root in @($env:SystemRoot, 'C:\Program Files', 'C:\Program Files (x86)', 'C:\NCR', 'C:\WOSA', 'C:\XFS')) {
            if (-not (Test-Path $root)) { continue }
            $hit = Get-ChildItem -Path $root -Filter 'msxfs.dll' -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { $script:XfsDllPath = $hit.FullName; Write-Log "  [found] $($hit.FullName)" 'SUCCESS'; break }
        }
    }
    if (-not $script:XfsDllPath) {
        Write-Log '  No XFS Manager present. This host is probably not an ATM core, or XFS is vendor-relocated.' 'WARNING'
    }

    Write-SubBanner 'XFS Service Providers'
    $spRoots = @('HKLM:\SOFTWARE\XFS\SERVICE_PROVIDERS', 'HKLM:\SOFTWARE\WOW6432Node\XFS\SERVICE_PROVIDERS')
    $spSeen  = @{}
    foreach ($root in $spRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($sp in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $props   = Get-ItemProperty $sp.PSPath -ErrorAction SilentlyContinue
            $dllname = "$($props.dllname)"
            if (-not $dllname) { continue }
            Write-Log ('  [SP] {0}' -f $sp.PSChildName) 'SUCCESS'
            Write-Log ('      dllname={0}' -f $dllname) 'VERBOSE'

            # Resolve dllname (often bare, resolved via the loader search path)
            # to a real file so its trust and ACL can actually be checked.
            $resolved = $null
            if (Test-Path $dllname) { $resolved = (Resolve-Path $dllname).Path }
            else {
                foreach ($dir in @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'),
                                   'C:\Program Files\Common Files\XFS', 'C:\Program Files (x86)\Common Files\XFS',
                                   'C:\WOSA\XFS', 'C:\XFS', 'C:\Program Files\NCR', 'C:\Program Files (x86)\NCR')) {
                    $try = Join-Path $dir (Split-Path $dllname -Leaf)
                    if (Test-Path $try) { $resolved = $try; break }
                }
            }
            if (-not $resolved) { Write-Log '      (DLL not located on disk - cannot assess integrity)' 'WARNING'; continue }
            if ($spSeen.ContainsKey($resolved.ToLower())) { continue }
            $spSeen[$resolved.ToLower()] = $true

            $t = Get-FileTrust $resolved
            Write-Log ('      path={0}' -f $t.Path) 'VERBOSE'
            Write-Log ('      arch={0} signature={1}' -f $t.Machine, $t.Signature) 'VERBOSE'
            if ($t.Signer) { Write-Log ('      signer={0}' -f $t.Signer) 'VERBOSE' }

            if ($t.WeakAcl) {
                Add-Finding -Severity 'CRITICAL' -Title "XFS service-provider DLL is writable by a non-administrative principal: $($sp.PSChildName)" `
                    -Detail "$($t.Path) : $($t.WeakAcl -join '; ')" `
                    -Evidence "$($t.Path) [$($t.WeakAcl -join '; ')]" `
                    -Impact 'The service-provider DLL is the software that drives the physical device. Write access to a CDM provider means an attacker can issue dispense commands directly; for an IDC or PIN provider it means card track data and PIN block capture.' `
                    -Remediation 'Restrict all XFS service-provider binaries to SYSTEM and Administrators, and enable application whitelisting in enforce mode.' `
                    -Ref 'CWE-732'
            }
            if ($t.Signature -match 'NotSigned|UnknownError|HashMismatch|NotTrusted') {
                Add-Finding -Severity 'MEDIUM' -Title "XFS service-provider DLL is unsigned or untrusted: $($sp.PSChildName)" `
                    -Detail "$($t.Path) signature status: $($t.Signature)" `
                    -Evidence "$($t.Path) sig=$($t.Signature)" `
                    -Impact 'Without a valid signature, tampering with the device driver layer cannot be detected by signature-based whitelisting.' `
                    -Remediation 'Require signed service-provider binaries and enforce signature validation in the whitelisting product.' `
                    -Ref 'CWE-347'
            }
        }
    }

    Write-SubBanner 'XFS Logical Services'
    foreach ($root in @('HKLM:\SOFTWARE\XFS\LOGICAL_SERVICES', 'HKLM:\SOFTWARE\WOW6432Node\XFS\LOGICAL_SERVICES')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($ls in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $p   = Get-ItemProperty $ls.PSPath -ErrorAction SilentlyContinue
            $cls = Resolve-XfsClass $p.class
            $obj = [pscustomobject]@{
                Name     = $ls.PSChildName
                Provider = "$($p.provider)"
                ClassNum = $cls.Num
                ClassName= $cls.Name
                Label    = $cls.Label
            }
            $script:LogicalServices += $obj
            Write-Log ('  [LS] {0,-22} provider={1,-22} class={2} ({3})' -f $obj.Name, $obj.Provider, $obj.ClassName, $obj.Label) 'SUCCESS'
            if ($cls.Num -eq 3) { Write-Log '       >>> CASH DISPENSER MODULE' 'CRITICAL' }
            if ($cls.Num -eq 4) { Write-Log '       >>> PIN KEYPAD / EPP' 'WARNING' }
            if ($cls.Num -eq 2) { Write-Log '       >>> CARD READER' 'WARNING' }
        }
    }
    Write-Log ('  {0} logical services enumerated.' -f @($script:LogicalServices).Count)

    Write-SubBanner 'XFS Tracing Configuration'
    # XFS trace files can contain card track data and PIN-pad traffic. Tracing
    # left enabled on a production ATM is cardholder data written to disk.
    $traceHits = @()
    foreach ($root in @('HKLM:\SOFTWARE\XFS', 'HKLM:\SOFTWARE\WOW6432Node\XFS')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in (Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | Select-Object -First 400)) {
            foreach ($v in (Get-RegValues "$($k.PSPath)")) {
                if ($v.Name -notmatch '(?i)trace|log(file|path|level)?$|debug') { continue }
                if ("$($v.Value)" -in @('', '0')) { continue }
                $traceHits += ('{0}\{1} = {2}' -f $k.PSChildName, $v.Name, $v.Value)
                Write-Log ('  {0}\{1} = {2}' -f $k.PSChildName, $v.Name, $v.Value) 'WARNING'
            }
        }
    }
    if ($traceHits) {
        Add-Finding -Severity 'HIGH' -Title 'XFS tracing or debug logging appears to be enabled' `
            -Detail (($traceHits | Select-Object -First 10) -join '; ') `
            -Evidence (($traceHits | Select-Object -First 6) -join ' | ') `
            -Impact 'XFS traces record the command and data stream between the application and the card reader and PIN pad, which can include full track data. Enabled tracing turns the terminal disk into a cardholder-data store.' `
            -Remediation 'Disable XFS tracing on production terminals, purge existing trace files, and gate tracing behind a maintenance mode.' `
            -Ref 'CWE-532'
    }

    # Existing trace/log files in the usual places
    foreach ($d in @('C:\XFS', 'C:\WOSA\XFS', 'C:\NCR\Trace', 'C:\NCR\Logs', (Join-Path $env:SystemRoot 'Temp'))) {
        if (-not (Test-Path $d)) { continue }
        $tf = Get-ChildItem -Path $d -Include '*.log', '*.trc', '*.trace' -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($f in $tf) { Write-Log ('  [trace file] {0}  {1:N0} KB  {2}' -f $f.FullName, ($f.Length / 1KB), $f.LastWriteTime) 'VERBOSE' }
    }
}

# ============================================================
#  PHASE 9 : XFS API DIRECT INTERACTION
# ============================================================

Invoke-Phase 9 'XFS API DIRECT INTERACTION' {

    if ($SkipXfsApi) { Write-Log 'Skipped by -SkipXfsApi.' 'WARNING'; return }
    if (-not $script:XfsDllPath) { Write-Log 'No msxfs.dll located in phase 8 - nothing to call.' 'WARNING'; return }
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Log "PowerShell language mode is $($ExecutionContext.SessionState.LanguageMode); Add-Type is blocked, so the API cannot be reached from here." 'WARNING'
        return
    }

    # ---- Bitness gate. This is why phase 9 usually fails on a modern host: XFS
    # ---- on ATMs is 32-bit, and a 64-bit process cannot load a 32-bit DLL.
    $arch = Get-PeMachineType $script:XfsDllPath
    $procBits = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
    Write-Log "  msxfs.dll architecture : $arch"
    Write-Log "  PowerShell process     : $procBits"
    if (($arch -eq 'x86' -and $procBits -eq 'x64') -or ($arch -eq 'x64' -and $procBits -eq 'x86')) {
        Write-Log '  ARCHITECTURE MISMATCH - the P/Invoke would fail with BadImageFormatException.' 'CRITICAL'
        Write-Log "  Re-run:  powershell -ExecutionPolicy Bypass -File `"$script:SelfPath`" -Relaunch32 -Phases 8,9" 'CRITICAL'
        Add-Finding -Severity 'INFO' -Title 'XFS API not exercised: PowerShell/msxfs.dll architecture mismatch' `
            -Detail "msxfs.dll is $arch, the assessing process is $procBits. Re-run with -Relaunch32." `
            -Evidence "dll=$arch process=$procBits" `
            -Impact 'Coverage gap only - the XFS device layer was not tested interactively.' `
            -Remediation 'Not a defect in the terminal; re-run the assessment in a matching-architecture host process.'
        return
    }

    $xfsCode = @'
using System;
using System.Runtime.InteropServices;

public class XfsApi
{
    // dwVersionsRequired packs a RANGE: low word = lowest acceptable version,
    // high word = highest. Each word is (minor << 8) | major, so 3.00 = 0x0003
    // and 3.30 = 0x1E03. v1 passed 0x00000A03, i.e. lowest=3.10 highest=0.00,
    // an inverted range that makes WFSStartUp fail on a conforming manager.
    public const uint VERSIONS_3_00_TO_3_30 = 0x1E030003;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct WFSVERSION
    {
        public ushort wVersion;
        public ushort wLowVersion;
        public ushort wHighVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WFSRESULT
    {
        public uint   RequestID;
        public ushort hService;
        public long   tsTimestamp1;
        public long   tsTimestamp2;
        public int    hResult;
        public uint   dwCommandCode;
        public IntPtr lpBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WFSCDMSTATUS
    {
        public ushort fwDevice;
        public ushort fwSafeDoor;
        public ushort fwDispenser;
        public ushort fwIntermediateStacker;
        public IntPtr lppPositions;
        public IntPtr lpszExtra;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WFSCDMCAPS
    {
        public ushort wClass;
        public ushort fwType;
        public ushort wMaxDispenseItems;
        public int    bCompound;
        public int    bShutter;
        public int    bShutterControl;
        public ushort fwRetractAreas;
        public ushort fwRetractTransportActions;
        public ushort fwRetractStackerActions;
        public int    bSafeDoor;
        public int    bCashBox;
        public int    bIntermediateStacker;
        public int    bItemsTakenSensor;
        public ushort fwPositions;
        public ushort fwMoveItems;
        public ushort fwExchangeType;
        public IntPtr lpszExtra;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WFSCDMCUINFO
    {
        public ushort usCount;
        public IntPtr lppList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct WFSCDMCASHUNIT
    {
        public ushort usNumber;
        public ushort usType;
        public IntPtr lpszCashUnitName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 5)] public string cUnitID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 3)] public string cCurrencyID;
        public uint   ulValues;
        public uint   ulInitialCount;
        public uint   ulCount;
        public uint   ulRejectCount;
        public uint   ulMinimum;
        public uint   ulMaximum;
        public int    bAppLock;
        public ushort usStatus;
        public ushort usNumPhysicalCUs;
        public IntPtr lppPhysical;
    }

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSStartUp(uint dwVersionsRequired, ref WFSVERSION lpWFSVersion);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSOpen(string lpszLogicalName, IntPtr hApp, string lpszAppID,
        uint dwTraceLevel, uint dwTimeOut, uint dwSrvcVersionsRequired,
        ref WFSVERSION lpSrvcVersion, ref WFSVERSION lpSPIVersion, ref ushort lphService);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSGetInfo(ushort hService, uint dwCategory, IntPtr lpQueryDetails,
        uint dwTimeOut, ref IntPtr lppResult);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSClose(ushort hService);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSCleanUp();

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSFreeResult(IntPtr lpResult);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSLock(ushort hService, uint dwTimeOut, ref IntPtr lppResult);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSUnlock(ushort hService);

    public static string DeviceState(ushort s)
    {
        switch (s)
        {
            case 0: return "ONLINE";
            case 1: return "OFFLINE";
            case 2: return "POWEROFF";
            case 3: return "NODEVICE";
            case 4: return "HWERROR";
            case 5: return "USERERROR";
            case 6: return "BUSY";
            case 7: return "FRAUDATTEMPT";
            case 8: return "POTENTIALFRAUD";
            default: return "UNKNOWN(" + s + ")";
        }
    }
}
'@

    try { Add-Type -TypeDefinition $xfsCode -ErrorAction Stop; Write-Log '  XFS interop types compiled.' 'SUCCESS' }
    catch {
        Write-Log "  Add-Type failed: $($_.Exception.Message)" 'ERROR'
        Write-Log '  Application whitelisting (e.g. Solidcore) commonly blocks the compiler that Add-Type invokes.' 'WARNING'
        return
    }

    $ver = New-Object XfsApi+WFSVERSION
    $versions = [XfsApi]::VERSIONS_3_00_TO_3_30

    Write-SubBanner 'WFSStartUp'
    $hr = 0
    try { $hr = [XfsApi]::WFSStartUp($versions, [ref]$ver) }
    catch [System.BadImageFormatException] {
        Write-Log '  BadImageFormatException - architecture mismatch. Re-run with -Relaunch32.' 'CRITICAL'
        return
    }
    catch {
        Write-Log "  WFSStartUp threw: $($_.Exception.Message)" 'ERROR'
        return
    }

    if ($hr -ne 0 -and $hr -ne -1) {   # -1 = ALREADY_STARTED, which is fine
        Write-Log ('  WFSStartUp failed: {0}' -f (Get-XfsErrorName $hr)) 'WARNING'
        foreach ($s in (Get-Service -Name 'XFS*', 'MSXFS*' -ErrorAction SilentlyContinue)) {
            Write-Log ('    service {0} = {1}' -f $s.Name, $s.Status)
        }
        return
    }
    Write-Log ('  WFSStartUp OK ({0})' -f (Get-XfsErrorName $hr)) 'SUCCESS'
    Write-Log ('    manager version 0x{0:X4} (range 0x{1:X4}-0x{2:X4})' -f $ver.wVersion, $ver.wLowVersion, $ver.wHighVersion)
    Write-Log ('    description : {0}' -f $ver.szDescription)
    Write-Log ('    status      : {0}' -f $ver.szSystemStatus) 'VERBOSE'

    $openedAny = $false
    $cdmOpened = @()

    foreach ($ls in $script:LogicalServices) {
        Write-SubBanner ("WFSOpen " + $ls.Name + "  [" + $ls.ClassName + "]")
        $sv = New-Object XfsApi+WFSVERSION
        $sp = New-Object XfsApi+WFSVERSION
        [ushort]$h = 0

        $hrOpen = [XfsApi]::WFSOpen($ls.Name, [IntPtr]::Zero, 'ATMAssessment', 0, 15000, $versions, [ref]$sv, [ref]$sp, [ref]$h)
        if ($hrOpen -ne 0) {
            Write-Log ('  open failed: {0}' -f (Get-XfsErrorName $hrOpen)) 'WARNING'
            continue
        }
        $openedAny = $true
        Write-Log ('  opened, hService={0}' -f $h) 'SUCCESS'
        Write-Log ('    SP  : 0x{0:X4}  {1}' -f $sv.wVersion, $sv.szDescription) 'VERBOSE'
        Write-Log ('    SPI : 0x{0:X4}' -f $sp.wVersion) 'VERBOSE'

        try {
            # Status category is always (class * 100) + 1 across the CEN classes.
            $statusCat = [uint32](($ls.ClassNum * 100) + 1)
            if ($ls.ClassNum -gt 0) {
                $pRes = [IntPtr]::Zero
                $hrI = [XfsApi]::WFSGetInfo($h, $statusCat, [IntPtr]::Zero, 15000, [ref]$pRes)
                if ($hrI -eq 0 -and $pRes -ne [IntPtr]::Zero) {
                    $res = [Runtime.InteropServices.Marshal]::PtrToStructure($pRes, [Type][XfsApi+WFSRESULT])
                    Write-Log ('  status query OK (category {0})' -f $statusCat) 'SUCCESS'
                    if ($ls.ClassNum -eq 3 -and $res.lpBuffer -ne [IntPtr]::Zero) {
                        $st = [Runtime.InteropServices.Marshal]::PtrToStructure($res.lpBuffer, [Type][XfsApi+WFSCDMSTATUS])
                        Write-Log ('    device    : {0}' -f [XfsApi]::DeviceState($st.fwDevice)) $(if ($st.fwDevice -eq 0) { 'SUCCESS' } else { 'WARNING' })
                        Write-Log ('    safe door : {0}' -f $st.fwSafeDoor)
                        Write-Log ('    dispenser : {0}' -f $st.fwDispenser)
                        Write-Log ('    stacker   : {0}' -f $st.fwIntermediateStacker)
                        if ($st.lpszExtra -ne [IntPtr]::Zero) {
                            $extra = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($st.lpszExtra)
                            Write-Log ('    extra     : {0}' -f $extra) 'VERBOSE'
                        }
                        if ($st.fwDevice -in @(7, 8)) {
                            Write-Log '    device reports a fraud-attempt state' 'CRITICAL'
                        }
                    }
                    [void][XfsApi]::WFSFreeResult($pRes)
                } else {
                    Write-Log ('  status query failed: {0}' -f (Get-XfsErrorName $hrI)) 'WARNING'
                }
            }

            if ($ls.ClassNum -eq 3) {
                $cdmOpened += $ls.Name

                # --- Capabilities (WFS_INF_CDM_CAPABILITIES = 302) ---
                $pCaps = [IntPtr]::Zero
                if ([XfsApi]::WFSGetInfo($h, 302, [IntPtr]::Zero, 15000, [ref]$pCaps) -eq 0 -and $pCaps -ne [IntPtr]::Zero) {
                    $r = [Runtime.InteropServices.Marshal]::PtrToStructure($pCaps, [Type][XfsApi+WFSRESULT])
                    if ($r.lpBuffer -ne [IntPtr]::Zero) {
                        $c = [Runtime.InteropServices.Marshal]::PtrToStructure($r.lpBuffer, [Type][XfsApi+WFSCDMCAPS])
                        Write-Log '  CDM capabilities:' 'SUCCESS'
                        Write-Log ('    maxDispenseItems={0} shutter={1} shutterControl={2} safeDoor={3}' -f $c.wMaxDispenseItems, $c.bShutter, $c.bShutterControl, $c.bSafeDoor)
                        Write-Log ('    cashBox={0} intermediateStacker={1} itemsTakenSensor={2}' -f $c.bCashBox, $c.bIntermediateStacker, $c.bItemsTakenSensor) 'VERBOSE'
                        Write-Log ('    positions=0x{0:X4} moveItems=0x{1:X4} retractAreas=0x{2:X4}' -f $c.fwPositions, $c.fwMoveItems, $c.fwRetractAreas) 'VERBOSE'
                        if ($c.lpszExtra -ne [IntPtr]::Zero) {
                            Write-Log ('    extra: {0}' -f [Runtime.InteropServices.Marshal]::PtrToStringAnsi($c.lpszExtra)) 'VERBOSE'
                        }
                    }
                    [void][XfsApi]::WFSFreeResult($pCaps)
                }

                # --- Cash unit inventory (WFS_INF_CDM_CASH_UNIT_INFO = 303) ---
                # v1 only logged "raw data available". Parsing it is what turns
                # phase 9 into evidence: it proves the assessing process can read
                # live cassette currency and note counts.
                $pCu = [IntPtr]::Zero
                if ([XfsApi]::WFSGetInfo($h, 303, [IntPtr]::Zero, 15000, [ref]$pCu) -eq 0 -and $pCu -ne [IntPtr]::Zero) {
                    try {
                        $r = [Runtime.InteropServices.Marshal]::PtrToStructure($pCu, [Type][XfsApi+WFSRESULT])
                        if ($r.lpBuffer -ne [IntPtr]::Zero) {
                            $info = [Runtime.InteropServices.Marshal]::PtrToStructure($r.lpBuffer, [Type][XfsApi+WFSCDMCUINFO])
                            Write-Log ('  cash units reported: {0}' -f $info.usCount) 'SUCCESS'
                            $ptrSize = [IntPtr]::Size
                            $totalNotes = 0
                            $detail = @()
                            for ($i = 0; $i -lt [int]$info.usCount; $i++) {
                                $slot = [IntPtr]::Add($info.lppList, $i * $ptrSize)
                                $cuPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($slot)
                                if ($cuPtr -eq [IntPtr]::Zero) { continue }
                                $cu = [Runtime.InteropServices.Marshal]::PtrToStructure($cuPtr, [Type][XfsApi+WFSCDMCASHUNIT])
                                $nm = ''
                                if ($cu.lpszCashUnitName -ne [IntPtr]::Zero) { $nm = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($cu.lpszCashUnitName) }
                                Write-Log ('    CU {0}: id={1} name={2} currency={3} denom={4} count={5} reject={6} status={7}' -f `
                                    $cu.usNumber, $cu.cUnitID, $nm, $cu.cCurrencyID, $cu.ulValues, $cu.ulCount, $cu.ulRejectCount, $cu.usStatus)
                                $totalNotes += [int]$cu.ulCount
                                $detail += ('{0}:{1}x{2}{3}' -f $cu.cUnitID, $cu.ulCount, $cu.ulValues, $cu.cCurrencyID)
                            }
                            if ($totalNotes -gt 0) {
                                Add-Finding -Severity 'CRITICAL' -Title 'Cash dispenser inventory readable by an unprivileged local XFS client' `
                                    -Detail "A non-ATM application process opened the CDM logical service '$($ls.Name)' and read live cassette currency and note counts ($totalNotes notes across $($info.usCount) units). The XFS layer applied no authentication or application identity check." `
                                    -Evidence ($detail -join ' ') `
                                    -Impact 'Any code able to run on the terminal can talk to the cash dispenser through the XFS Manager. Reading the inventory is the reconnaissance step of a jackpotting attack; the same interface accepts WFS_CMD_CDM_DISPENSE. This is the core precondition for every known ATM cash-out malware family (Ploutus, Cutlet Maker, FASTCash).' `
                                    -Remediation 'Enforce application whitelisting in enforce (not observe) mode so only the signed ATM application can load msxfs.dll; restrict the XFS registry tree and service-provider binaries; ensure the ATM application holds a persistent WFSLock on the dispenser so rogue clients cannot acquire it.' `
                                    -Ref 'CWE-306'
                            }
                        }
                    } catch { Write-Log "    (cash unit parse failed: $($_.Exception.Message))" 'VERBOSE' }
                    [void][XfsApi]::WFSFreeResult($pCu)
                }

                # --- Currency exponent (306) and mix types (307) ---
                foreach ($cat in @(306, 307)) {
                    $pp = [IntPtr]::Zero
                    $rc = [XfsApi]::WFSGetInfo($h, [uint32]$cat, [IntPtr]::Zero, 15000, [ref]$pp)
                    Write-Log ('  category {0} -> {1}' -f $cat, (Get-XfsErrorName $rc)) 'VERBOSE'
                    if ($pp -ne [IntPtr]::Zero) { [void][XfsApi]::WFSFreeResult($pp) }
                }

                # --- Optional, explicitly opt-in: prove exclusive device control ---
                if ($ProveCdmLock) {
                    $go = $Force
                    if (-not $go) {
                        Write-Host ''
                        Write-Host "  About to WFSLock the cash dispenser '$($ls.Name)'." -ForegroundColor Yellow
                        Write-Host '  This takes EXCLUSIVE control of the dispenser for a moment and will' -ForegroundColor Yellow
                        Write-Host '  interrupt live transactions. No cash is dispensed. Type LOCK to proceed:' -ForegroundColor Yellow
                        $go = ((Read-Host '  >') -eq 'LOCK')
                    }
                    if ($go) {
                        $pLock = [IntPtr]::Zero
                        $hrL = [XfsApi]::WFSLock($h, 10000, [ref]$pLock)
                        if ($pLock -ne [IntPtr]::Zero) { [void][XfsApi]::WFSFreeResult($pLock) }
                        if ($hrL -eq 0) {
                            [void][XfsApi]::WFSUnlock($h)
                            Add-Finding -Severity 'CRITICAL' -Title 'Arbitrary local process can acquire an exclusive lock on the cash dispenser' `
                                -Detail "WFSLock on '$($ls.Name)' succeeded from an ad-hoc PowerShell process, which was then released immediately. No cash was dispensed." `
                                -Evidence "WFSLock('$($ls.Name)') = WFS_SUCCESS, WFSUnlock issued" `
                                -Impact 'Holding the lock is the step immediately before WFS_CMD_CDM_DISPENSE. A process that can lock the dispenser can dispense from it, and can simultaneously deny service to the legitimate ATM application.' `
                                -Remediation 'Keep the dispenser locked by the ATM application for the life of the session, and enforce application whitelisting so no other process can load the XFS Manager.' `
                                -Ref 'CWE-306'
                        } else {
                            Write-Log ('  WFSLock denied: {0} (the ATM application most likely holds the lock - a good sign)' -f (Get-XfsErrorName $hrL)) 'SUCCESS'
                        }
                    } else {
                        Write-Log '  Lock proof declined by operator.' 'INFO'
                    }
                }
            }
        } finally {
            [void][XfsApi]::WFSClose($h)
            Write-Log '  closed.' 'VERBOSE'
        }
    }

    if ($openedAny -and -not $cdmOpened) {
        Write-Log '  Logical services were opened, but no CDM service was reachable.' 'INFO'
    }
    if ($openedAny) {
        Add-Finding -Severity 'HIGH' -Title 'XFS Manager accepts connections from an arbitrary local application' `
            -Detail "WFSStartUp and WFSOpen succeeded from an ad-hoc PowerShell process using the application id 'ATMAssessment'. Services opened: $(@($script:LogicalServices | ForEach-Object { $_.Name }) -join ', ')." `
            -Evidence "WFSStartUp=OK, opened=$(@($cdmOpened).Count) CDM service(s)" `
            -Impact 'CEN XFS performs no caller authentication. The only practical control is application whitelisting, so any gap in whitelisting enforcement exposes the cash dispenser, card reader and PIN pad directly to local code.' `
            -Remediation 'Treat application whitelisting in enforce mode as the primary ATM control and verify it blocks unsigned interpreters and compilers; audit the updater and exception lists.' `
            -Ref 'CWE-306'
    }

    [void][XfsApi]::WFSCleanUp()
    Write-Log '  WFSCleanUp issued.' 'VERBOSE'
}


# ============================================================
#  PHASE 10 : APPLICATION WHITELISTING & ENDPOINT SECURITY
# ============================================================

Invoke-Phase 10 'APPLICATION WHITELISTING & ENDPOINT SECURITY' {

    Write-SubBanner 'Security and Remote-Access Services'
    $services = @(
        @{ Name = 'McAfee Solidcore';      Svc = 'scsrvc';           Kind = 'whitelist' }
        @{ Name = 'McAfee Agent';          Svc = 'masvc';            Kind = 'mgmt' }
        @{ Name = 'McAfee VirusScan';      Svc = 'McShield';         Kind = 'av' }
        @{ Name = 'Windows Defender';      Svc = 'WinDefend';        Kind = 'av' }
        @{ Name = 'Windows Firewall';      Svc = 'mpssvc';           Kind = 'fw' }
        @{ Name = 'Symantec Endpoint';     Svc = 'SepMasterService'; Kind = 'av' }
        @{ Name = 'Trend Micro';           Svc = 'TmListen';         Kind = 'av' }
        @{ Name = 'CrowdStrike Falcon';    Svc = 'CSFalconService';  Kind = 'edr' }
        @{ Name = 'Phoenix Vista ATM';     Svc = 'VistaATM';         Kind = 'atm' }
        @{ Name = 'Radmin Server';         Svc = 'RServer3';         Kind = 'remote' }
        @{ Name = 'RDP (TermService)';     Svc = 'TermService';      Kind = 'remote' }
        @{ Name = 'VNC Server';            Svc = 'vncserver';        Kind = 'remote' }
        @{ Name = 'TeamViewer';            Svc = 'TeamViewer';       Kind = 'remote' }
        @{ Name = 'AppLocker (AppIDSvc)';  Svc = 'AppIDSvc';         Kind = 'whitelist' }
        @{ Name = 'Keyboard Filter';       Svc = 'MsKeyboardFilter'; Kind = 'kiosk' }
        @{ Name = 'Shell Launcher';        Svc = 'ShellHWDetection'; Kind = 'kiosk' }
    )
    $whitelistActive = $false
    foreach ($s in $services) {
        $svc = Get-Service -Name $s.Svc -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Log ('  {0,-22} : not installed' -f $s.Name) 'VERBOSE'; continue }
        $running = ($svc.Status -eq 'Running')
        $lvl = if ($s.Kind -eq 'remote' -and $running) { 'WARNING' } elseif ($running) { 'SUCCESS' } else { 'WARNING' }
        Write-Log ('  {0,-22} : {1,-8} startType={2}' -f $s.Name, $svc.Status, $svc.StartType) $lvl
        if ($s.Kind -eq 'whitelist' -and $running) { $whitelistActive = $true }
        if ($s.Kind -eq 'av' -and -not $running) {
            Add-Finding -Severity 'MEDIUM' -Title "$($s.Name) is installed but not running" `
                -Detail "Service $($s.Svc) status is $($svc.Status) (start type $($svc.StartType))." `
                -Evidence "$($s.Svc)=$($svc.Status)" `
                -Impact 'The terminal has no active malware detection, so commodity ATM malware runs unimpeded.' `
                -Remediation 'Start the service and set it to automatic; investigate why it stopped.' `
                -Ref 'CWE-693'
        }
    }

    Write-SubBanner 'McAfee Solidcore Detail'
    $sadmin = Get-Command 'sadmin' -ErrorAction SilentlyContinue
    if (-not $sadmin) {
        foreach ($p in @('C:\Program Files\McAfee\Solidcore\sadmin.exe', 'C:\Program Files (x86)\McAfee\Solidcore\sadmin.exe')) {
            if (Test-Path $p) { $sadmin = Get-Item $p; break }
        }
    }
    if ($sadmin) {
        $exe = if ($sadmin.Source) { $sadmin.Source } else { $sadmin.FullName }
        Write-Log "  sadmin: $exe"
        $statusOut = @()
        try { $statusOut = & $exe status 2>&1 } catch { Write-Log "  sadmin status failed: $($_.Exception.Message)" 'WARNING' }
        foreach ($line in $statusOut) { Write-Log ('    ' + "$line") }

        $joined = ($statusOut -join ' ')
        if ($joined -match '(?i)\[Observe\]|Observe mode|observe-mode') {
            Add-Finding -Severity 'CRITICAL' -Title 'Application whitelisting is in Observe mode, not Enforce' `
                -Detail 'McAfee Solidcore reports Observe (monitor-only) mode, so unauthorised binaries are logged but still permitted to execute.' `
                -Evidence (($statusOut | Select-String -Pattern '(?i)mode' | Select-Object -First 3 | ForEach-Object { "$_".Trim() }) -join ' | ') `
                -Impact 'Whitelisting is the single control that stops ATM cash-out malware reaching the XFS layer. In Observe mode that control does not actually block anything, so arbitrary code - including a jackpotting toolkit - executes freely.' `
                -Remediation 'Move Solidcore to Enable/Enforce mode after a solidification pass, and verify with sadmin status that the enforcement state survives reboot.' `
                -Ref 'CWE-693'
        } elseif ($joined -match '(?i)disabled') {
            Add-Finding -Severity 'CRITICAL' -Title 'Application whitelisting is disabled' `
                -Detail 'McAfee Solidcore is installed but reports a disabled state.' `
                -Evidence ($joined.Substring(0, [Math]::Min(300, $joined.Length))) `
                -Impact 'Any executable can run on the terminal, which removes the primary barrier between a kiosk breakout and the cash dispenser.' `
                -Remediation 'Re-enable and solidify; investigate how and when it was disabled.' `
                -Ref 'CWE-693'
        }

        # Updaters are the usual whitelisting bypass: an overly broad updater
        # lets anything it launches execute, whitelisting notwithstanding.
        foreach ($sub in @(@('updaters', 'list'), @('config', 'show'), @('features', 'list'))) {
            try {
                $o = & $exe $sub[0] $sub[1] 2>&1
                Write-Log ("  sadmin $($sub -join ' '):") 'VERBOSE'
                foreach ($line in ($o | Select-Object -First 60)) { Write-Log ('    ' + "$line") 'VERBOSE' }
                if ($sub[0] -eq 'updaters') {
                    $risky = $o | Select-String -Pattern '(?i)cmd\.exe|powershell|wscript|cscript|rundll32|mshta|regsvr32|msiexec|python|java\.exe'
                    if ($risky) {
                        Add-Finding -Severity 'HIGH' -Title 'Solidcore updater list contains a general-purpose interpreter' `
                            -Detail 'An updater is trusted to install and launch arbitrary content, so whitelisting no longer constrains anything it executes.' `
                            -Evidence (($risky | Select-Object -First 5 | ForEach-Object { "$_".Trim() }) -join ' | ') `
                            -Impact 'An attacker who can invoke the trusted updater executes arbitrary code with whitelisting bypassed, reaching the XFS layer.' `
                            -Remediation 'Remove interpreters from the updater list; scope updaters to specific signed vendor binaries.' `
                            -Ref 'CWE-693'
                    }
                }
            } catch { }
        }
    } else {
        Write-Log '  sadmin not found.' 'VERBOSE'
    }

    Write-SubBanner 'AppLocker / WDAC / SRP'
    $appLockerConfigured = $false
    if (Test-Cmd 'Get-AppLockerPolicy') {
        try {
            $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
            $ruleCount = 0
            foreach ($c in $pol.RuleCollections) {
                Write-Log ('  AppLocker {0,-18} rules={1} enforcement={2}' -f $c.RuleCollectionType, $c.Count, $c.EnforcementMode)
                $ruleCount += $c.Count
                if ($c.Count -gt 0 -and $c.EnforcementMode -eq 'AuditOnly') {
                    Add-Finding -Severity 'HIGH' -Title "AppLocker $($c.RuleCollectionType) rules are audit-only" `
                        -Detail "Enforcement mode is AuditOnly with $($c.Count) rules configured." `
                        -Evidence "$($c.RuleCollectionType)=AuditOnly rules=$($c.Count)" `
                        -Impact 'Rules are evaluated and logged but never block, so the whitelist provides no protection against untrusted executables.' `
                        -Remediation 'Switch the collection to Enabled (enforce) once the audit log is clean.' `
                        -Ref 'CWE-693'
                }
            }
            if ($ruleCount -gt 0) { $appLockerConfigured = $true }
        } catch { Write-Log "  AppLocker policy query failed: $($_.Exception.Message)" 'VERBOSE' }
    }
    $srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    if (Test-Path $srp) {
        Write-Log ('  SRP DefaultLevel = {0} (262144 = unrestricted, 0 = disallowed)' -f (Get-RegValue $srp 'DefaultLevel'))
    }
    $wdac = Join-Path $env:SystemRoot 'System32\CodeIntegrity\SIPolicy.p7b'
    Write-Log ('  WDAC policy file present: {0}' -f (Test-Path $wdac))

    if (-not $whitelistActive -and -not $appLockerConfigured -and -not (Test-Path $wdac)) {
        Add-Finding -Severity 'CRITICAL' -Title 'No application whitelisting is active on the terminal' `
            -Detail 'Neither Solidcore, AppLocker, WDAC nor SRP was found in an enforcing configuration.' `
            -Evidence 'solidcore=inactive applocker=unconfigured wdac=absent' `
            -Impact 'Application whitelisting is the control that ATM security guidance (and PCI) relies on to stop unauthorised code reaching the XFS cash-dispenser interface. Without it, any code an attacker lands on the terminal can dispense cash.' `
            -Remediation 'Deploy and enforce an application whitelisting product on every terminal; verify enforcement state as part of the health check.' `
            -Ref 'CWE-693'
    }

    Write-SubBanner 'PowerShell Posture'
    $lm = $ExecutionContext.SessionState.LanguageMode
    Write-Log "  LanguageMode : $lm"
    Write-Log ('  Version      : {0}' -f $PSVersionTable.PSVersion)
    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $tr  = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
    Write-Log "  ScriptBlockLogging=$sbl  Transcription=$tr"
    if ($lm -eq 'FullLanguage') {
        Add-Finding -Severity 'MEDIUM' -Title 'PowerShell runs in FullLanguage mode on the ATM' `
            -Detail 'Full language mode permits Add-Type, reflection and direct Win32 P/Invoke, which is how this assessment reached the XFS API.' `
            -Evidence "LanguageMode=$lm ScriptBlockLogging=$sbl" `
            -Impact 'A scripting host with unrestricted language mode gives an attacker in-memory access to the XFS device layer without dropping a binary, which also sidesteps file-based whitelisting.' `
            -Remediation 'Constrain PowerShell with WDAC or AppLocker so it runs in ConstrainedLanguage, or remove the PowerShell feature from the ATM image. Enable script-block logging and transcription.' `
            -Ref 'CWE-250'
    }
    if (-not $sbl) {
        Add-Finding -Severity 'LOW' -Title 'PowerShell script-block logging is not enabled' `
            -Detail 'No EnableScriptBlockLogging policy value found.' `
            -Evidence 'EnableScriptBlockLogging absent' `
            -Impact 'Script-based attacks against the terminal leave little forensic record.' `
            -Remediation 'Enable script-block logging and transcription, and forward the logs off the terminal.' `
            -Ref 'CWE-778'
    }
}

# ============================================================
#  PHASE 11 : KIOSK / LOCKDOWN BREAKOUT POSTURE
# ============================================================

Invoke-Phase 11 'KIOSK / LOCKDOWN BREAKOUT POSTURE' {

    # An ATM is a kiosk. This phase assesses, from inside the OS, the controls
    # that an operator at the fascia would be probing from the outside - the
    # shell, the keyboard filter, the accessibility dialogs, safe mode and the
    # Explorer-dependent escape routes. Technique taxonomy follows
    # github.com/ikarus23/kiosk-mode-breakout.

    Write-SubBanner 'Shell Replacement / Assigned Access'
    $wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell    = Get-RegValue $wlKey 'Shell'
    $userinit = Get-RegValue $wlKey 'Userinit'
    Write-Log "  HKLM Shell    : $shell"
    Write-Log "  HKLM Userinit : $userinit"
    $userShell = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell'
    if ($userShell) { Write-Log "  HKCU Shell    : $userShell" }

    $explorerIsShell = ("$shell" -match '(?i)explorer\.exe' -and -not $userShell)
    $explorerRunning = [bool](Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)
    Write-Log "  explorer.exe running: $explorerRunning"

    if ($explorerIsShell -or $explorerRunning) {
        Add-Finding -Severity 'HIGH' -Title 'Windows Explorer shell is active on the ATM' `
            -Detail "Winlogon Shell = '$shell'; explorer.exe running = $explorerRunning." `
            -Evidence "Shell=$shell explorerRunning=$explorerRunning" `
            -Impact 'With Explorer as the shell, the whole family of shell-dependent kiosk escapes becomes available at the fascia: Win+R, Win+E, Win+D, the taskbar, drag-and-drop, AutoPlay and the corner hot-zones. Any keyboard attached to the top box or exposed USB port then reaches a file browser and a command prompt.' `
            -Remediation 'Replace the shell with the ATM application itself (Shell Launcher on Windows IoT Enterprise, or Winlogon Shell set to the ATM executable) so no Explorer surface exists.' `
            -Ref 'CWE-1188'
    } else {
        Write-Log '  Custom shell in place and Explorer not running - the strongest single kiosk control.' 'SUCCESS'
    }

    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')) {
        if (-not (Test-Path $k)) { continue }
        foreach ($v in (Get-RegValues $k)) { Write-Log ('  {0}\{1} = {2}' -f (Split-Path $k -Leaf), $v.Name, $v.Value) 'VERBOSE' }
    }
    $lockdown = @{
        'DisableTaskMgr'        = (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableTaskMgr')
        'DisableCMD'            = (Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableCMD')
        'NoRun'                 = (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoRun')
        'NoWinKeys'             = (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoWinKeys')
        'NoDrives'              = (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDrives')
        'DisableLockWorkstation'= (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableLockWorkstation')
        'DisableChangePassword' = (Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableChangePassword')
    }
    $missing = @()
    foreach ($k in $lockdown.Keys) {
        Write-Log ('  {0,-24} = {1}' -f $k, $(if ($null -eq $lockdown[$k]) { 'not set' } else { $lockdown[$k] }))
        if ($lockdown[$k] -ne 1) { $missing += $k }
    }
    if ($missing.Count -ge 5) {
        Add-Finding -Severity 'MEDIUM' -Title 'Interactive lockdown policies are largely unset on the ATM session' `
            -Detail "Not enforced: $($missing -join ', ')." `
            -Evidence ($missing -join ',') `
            -Impact 'Once an attacker reaches any window on the terminal, Task Manager, the Run dialog and the Windows key shortcuts are all available to launch a command prompt.' `
            -Remediation 'Apply a kiosk GPO or local policy to the ATM account: DisableTaskMgr, NoRun, NoWinKeys, DisableCMD, DisableLockWorkstation.' `
            -Ref 'CWE-1188'
    }

    Write-SubBanner 'Keyboard Filter (Windows Embedded / IoT)'
    $kfRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Embedded\KeyboardFilter'
    $kfSvc  = Get-Service -Name 'MsKeyboardFilter' -ErrorAction SilentlyContinue
    if ($kfSvc) { Write-Log ('  MsKeyboardFilter service: {0} (start {1})' -f $kfSvc.Status, $kfSvc.StartType) }
    else { Write-Log '  MsKeyboardFilter service not present.' 'WARNING' }

    if (Test-Path $kfRoot) {
        $enabled = @(); $disabled = @()
        foreach ($sub in (Get-ChildItem $kfRoot -Recurse -ErrorAction SilentlyContinue | Select-Object -First 300)) {
            foreach ($v in (Get-RegValues "$($sub.PSPath)")) {
                if ($v.Name -notmatch '(?i)enabled') { continue }
                if ("$($v.Value)" -eq '1') { $enabled += $sub.PSChildName } else { $disabled += $sub.PSChildName }
            }
        }
        Write-Log ('  filters enabled : {0}' -f (($enabled | Select-Object -Unique) -join ', '))
        Write-Log ('  filters disabled: {0}' -f (($disabled | Select-Object -Unique) -join ', ')) 'VERBOSE'

        # The escapes that matter most if unfiltered.
        $critical = @('Ctrl+Alt+Del', 'Ctrl+Shift+Esc', 'Win+R', 'Win+E', 'Win+U', 'Win+X', 'Alt+Tab', 'Alt+F4', 'Win+D', 'Win+L', 'Win+Tab', 'Shift+F10')
        $unfiltered = $critical | Where-Object { ($enabled | Select-Object -Unique) -notcontains $_ }
        if ($unfiltered) {
            Add-Finding -Severity 'HIGH' -Title 'Keyboard Filter does not block the primary kiosk-escape shortcuts' `
                -Detail "Not filtered: $($unfiltered -join ', ')." `
                -Evidence ($unfiltered -join ',') `
                -Impact 'A keyboard plugged into an exposed USB port, or an attached service keyboard, reaches Task Manager or the Run dialog directly and from there a command prompt on the ATM.' `
                -Remediation 'Add the missing shortcuts to the Keyboard Filter custom and predefined key lists, and verify with a physical keyboard at the fascia.' `
                -Ref 'CWE-1188'
        }
    } else {
        Add-Finding -Severity 'HIGH' -Title 'No Windows Keyboard Filter configuration present' `
            -Detail "$kfRoot does not exist, so no Embedded/IoT keyboard filtering is configured." `
            -Evidence 'KeyboardFilter registry root absent' `
            -Impact 'Every Windows keyboard shortcut is live at the fascia. On an ATM with any reachable USB port or service keyboard, this is a direct route out of the kiosk application.' `
            -Remediation 'Enable the Keyboard Filter feature on the Windows IoT Enterprise image and block the shortcut set, or physically remove and disable all operator-reachable USB ports.' `
            -Ref 'CWE-1188'
    }

    Write-SubBanner 'Accessibility Escape Routes (sticky keys, on-screen keyboard, magnifier)'
    # The sticky-keys dialog at the logon screen is one of the most reliable
    # kiosk escapes: enabling it lets Ctrl, Alt and Del be pressed sequentially,
    # which most keyboard filters do not intercept.
    $accessKeys = @{
        'StickyKeys Flags'   = (Get-RegValue 'HKCU:\Control Panel\Accessibility\StickyKeys' 'Flags')
        'ToggleKeys Flags'   = (Get-RegValue 'HKCU:\Control Panel\Accessibility\ToggleKeys' 'Flags')
        'Keyboard Response'  = (Get-RegValue 'HKCU:\Control Panel\Accessibility\Keyboard Response' 'Flags')
        'MouseKeys Flags'    = (Get-RegValue 'HKCU:\Control Panel\Accessibility\MouseKeys' 'Flags')
        'HighContrast Flags' = (Get-RegValue 'HKCU:\Control Panel\Accessibility\HighContrast' 'Flags')
    }
    foreach ($k in $accessKeys.Keys) { Write-Log ('  {0,-20} = {1}  (hotkey active when bit 0x04 set)' -f $k, $accessKeys[$k]) }

    $atBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
    foreach ($b in $atBinaries) {
        $p = Join-Path $env:SystemRoot "System32\$b"
        if (-not (Test-Path $p)) { Write-Log ('  {0,-18} absent (good - removed from the image)' -f $b) 'SUCCESS'; continue }
        $weak = Get-WeakAcl $p
        Write-Log ('  {0,-18} present{1}' -f $b, $(if ($weak) { "  WEAK ACL: $($weak -join '; ')" } else { '' })) $(if ($weak) { 'CRITICAL' } else { 'INFO' })
        if ($weak) {
            Add-Finding -Severity 'CRITICAL' -Title "Accessibility binary $b is writable by a non-administrative principal" `
                -Detail "$p : $($weak -join '; ')" `
                -Evidence "$p [$($weak -join '; ')]" `
                -Impact 'Replacing an accessibility binary yields a SYSTEM-level command prompt from the logon screen - the classic sticky-keys backdoor - requiring only physical access to the fascia keyboard.' `
                -Remediation 'Restore default ACLs on the System32 accessibility binaries (SYSTEM and Administrators only, TrustedInstaller owner).' `
                -Ref 'CWE-732'
        }
        # IFEO debugger hijack on the same binaries
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b"
        $dbg = Get-RegValue $ifeo 'Debugger'
        if ($dbg) {
            Add-Finding -Severity 'CRITICAL' -Title "Image File Execution Options debugger set on $b" `
                -Detail "$ifeo\Debugger = $dbg" `
                -Evidence "$b -> $dbg" `
                -Impact 'An IFEO debugger on an accessibility binary executes the named program instead, from the logon screen, as SYSTEM. This is a persistent backdoor and may indicate the terminal is already compromised.' `
                -Remediation 'Remove the Debugger value, investigate how it was set, and treat the terminal as compromised until proven otherwise.' `
                -Ref 'CWE-506'
        }
    }
    $utilmanAvail = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ShowLogonOptions'
    Write-Log ('  Logon-screen ease-of-access button available: {0}' -f $(if ($null -eq $utilmanAvail) { 'default (yes)' } else { $utilmanAvail }))

    Write-SubBanner 'Safe Mode / Recovery Availability'
    # Two hard power cycles normally drop a Windows box into the recovery
    # environment, which is a reliable kiosk escape unless the boot status
    # policy suppresses it and recovery is disabled.
    if ($script:IsAdmin) {
        $bcd = & bcdedit.exe /enum '{current}' 2>&1
        foreach ($line in $bcd) { Write-Log ('  ' + "$line".Trim()) 'VERBOSE' }
        $bcdText = ($bcd -join ' ')
        $policy = if ($bcdText -match '(?i)bootstatuspolicy\s+(\S+)') { $Matches[1] } else { 'not set (default: DisplayAllFailures)' }
        $recovery = if ($bcdText -match '(?i)recoveryenabled\s+(\S+)') { $Matches[1] } else { 'not set (default: Yes)' }
        Write-Log "  bootstatuspolicy = $policy"
        Write-Log "  recoveryenabled  = $recovery"
        if ($policy -notmatch '(?i)IgnoreAllFailures' -or $recovery -notmatch '(?i)No') {
            Add-Finding -Severity 'HIGH' -Title 'Windows recovery environment is reachable from the ATM fascia' `
                -Detail "bootstatuspolicy = $policy, recoveryenabled = $recovery. Repeated hard power cycles will present the recovery or advanced boot options." `
                -Evidence "bootstatuspolicy=$policy recoveryenabled=$recovery" `
                -Impact 'Anyone who can cut power to the terminal twice reaches advanced boot options: safe mode with a command prompt, and the option to boot alternative media. Safe mode also disables the keyboard filter and, where no local admin is enabled, activates the built-in Administrator.' `
                -Remediation 'Set bootstatuspolicy to IgnoreAllFailures and recoveryenabled to No, protect the UEFI configuration with a password, and rely on full-disk encryption so an alternative boot yields nothing.' `
                -Ref 'CWE-1188'
        }
    } else {
        Write-Log '  bcdedit requires administrator - recovery posture not assessed.' 'WARNING'
    }

    Write-SubBanner 'AutoPlay / AutoRun'
    $noDriveType = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    $noAutorun   = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun'
    Write-Log ('  NoDriveTypeAutoRun = {0} (0xFF disables all)  NoAutorun = {1}' -f $noDriveType, $noAutorun)
    if ($null -eq $noDriveType -or [int]$noDriveType -ne 255) {
        Add-Finding -Severity 'MEDIUM' -Title 'AutoPlay is not fully disabled' `
            -Detail "NoDriveTypeAutoRun = $noDriveType (0xFF / 255 disables AutoPlay on every drive type)." `
            -Evidence "NoDriveTypeAutoRun=$noDriveType" `
            -Impact 'AutoPlay and the drive-repair prompts that Windows raises for removable media are a documented kiosk-escape route: the resulting dialogs contain links and buttons that reach Explorer and the system settings.' `
            -Remediation 'Set NoDriveTypeAutoRun to 0xFF and NoAutorun to 1 by policy.' `
            -Ref 'CWE-1188'
    }

    Write-SubBanner 'Browser / Embedded Web Surfaces'
    # A kiosk front end rendered in a browser or Electron shell brings its own
    # escapes: developer tools, print and save dialogs, view-source, downloads.
    $browsers = @(
        @{ N = 'Microsoft Edge';  P = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' }
        @{ N = 'Google Chrome';   P = 'C:\Program Files\Google\Chrome\Application\chrome.exe' }
        @{ N = 'Internet Explorer'; P = 'C:\Program Files\Internet Explorer\iexplore.exe' }
        @{ N = 'Firefox';         P = 'C:\Program Files\Mozilla Firefox\firefox.exe' }
    )
    $found = @()
    foreach ($b in $browsers) { if (Test-Path $b.P) { $found += $b.N; Write-Log ('  [present] {0}' -f $b.N) } }
    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)msedge|chrome|iexplore|firefox|electron|cefsharp' })) {
        Write-Log ('  [running] {0} (PID {1})' -f $proc.ProcessName, $proc.Id) 'WARNING'
        $found += $proc.ProcessName
    }
    if ($found) {
        Add-Finding -Severity 'MEDIUM' -Title 'Web browser or embedded web runtime present on the ATM' `
            -Detail "Detected: $(($found | Select-Object -Unique) -join ', ')." `
            -Evidence (($found | Select-Object -Unique) -join ',') `
            -Impact 'A browser or Chromium-embedded front end adds its own escape surface at the fascia: developer tools, Ctrl+P and Ctrl+S dialogs, view-source, the downloads folder, and file:// and shell: URI handlers that reach the filesystem and a command prompt.' `
            -Remediation 'Remove browsers from the ATM image where not required. Where a web front end is required, disable developer tools, printing, downloads and context menus, and allowlist navigation to the application origin only.' `
            -Ref 'CWE-1188'
    }

    Write-SubBanner 'On-Screen Keyboard & Touch Input'
    $tabTip = Join-Path $env:ProgramFiles 'Common Files\microsoft shared\ink\TabTip.exe'
    Write-Log ('  osk.exe present    : {0}' -f (Test-Path (Join-Path $env:SystemRoot 'System32\osk.exe')))
    Write-Log ('  TabTip.exe present : {0}' -f (Test-Path $tabTip))
    $touch = Get-Wmi 'Win32_PnPEntity' | Where-Object { "$($_.Name)" -match '(?i)touch screen|touch panel|HID-compliant touch' }
    if ($touch) { foreach ($t in $touch) { Write-Log ('  touch device: {0}' -f $t.Name) } }
}

# ============================================================
#  PHASE 12 : LOCAL PRIVILEGE-ESCALATION SURFACE
# ============================================================

Invoke-Phase 12 'LOCAL PRIVILEGE-ESCALATION SURFACE' {

    Write-SubBanner 'Current Token Privileges'
    foreach ($line in (whoami /priv 2>&1)) {
        $l = "$line"
        if ($l -match '(?i)SeImpersonate|SeAssignPrimaryToken|SeBackup|SeRestore|SeDebug|SeTakeOwnership|SeLoadDriver|SeTcb|SeCreateToken') {
            Write-Log ('  ' + $l.Trim()) 'WARNING'
        } elseif ($l.Trim()) { Write-Log ('  ' + $l.Trim()) 'VERBOSE' }
    }

    Write-SubBanner 'Unquoted Service Paths'
    foreach ($s in (Get-Wmi 'Win32_Service')) {
        $pn = "$($s.PathName)"
        if (-not $pn -or $pn.StartsWith('"')) { continue }
        # Only a space in the path before the .exe is exploitable
        $exePart = if ($pn -match '(?i)^(.*?\.exe)') { $Matches[1] } else { $pn }
        if ($exePart -notmatch ' ') { continue }
        if ($exePart -match '(?i)^[A-Z]:\\Windows\\') { continue }
        Add-Finding -Severity 'MEDIUM' -Title "Unquoted service image path: $($s.Name)" `
            -Detail "$($s.Name) -> $pn (startMode $($s.StartMode), account $($s.StartName))" `
            -Evidence $pn `
            -Impact 'If any parent directory of the path is writable, an attacker plants a binary that Windows executes as the service account on next start - a local escalation to SYSTEM on a terminal that reboots regularly.' `
            -Remediation 'Quote the ImagePath value for the service.' `
            -Ref 'CWE-428'
    }

    Write-SubBanner 'Weak Service Binary ACLs'
    $checked = @{}
    foreach ($s in (Get-Wmi 'Win32_Service')) {
        $pn = "$($s.PathName)"
        if (-not $pn) { continue }
        $exe = if ($pn -match '(?i)"([^"]+\.exe)"') { $Matches[1] } elseif ($pn -match '(?i)^([A-Z]:\\[^ ]+\.exe)') { $Matches[1] } else { $null }
        if (-not $exe -or -not (Test-Path $exe)) { continue }
        if ($checked.ContainsKey($exe.ToLower())) { continue }
        $checked[$exe.ToLower()] = $true
        if ($exe -match '(?i)^[A-Z]:\\Windows\\') { continue }
        $weak = Get-WeakAcl $exe
        if (-not $weak) { continue }
        Add-Finding -Severity 'HIGH' -Title "Service binary writable by a non-administrative principal: $($s.Name)" `
            -Detail "$exe : $($weak -join '; ') (service account $($s.StartName))" `
            -Evidence "$exe [$($weak -join '; ')]" `
            -Impact 'Overwriting the binary yields code execution as the service account, typically SYSTEM, on the next service start or terminal reboot.' `
            -Remediation 'Restrict the binary and its directory to SYSTEM and Administrators.' `
            -Ref 'CWE-732'
    }

    Write-SubBanner 'Writable Directories on PATH'
    foreach ($d in ($env:PATH -split ';' | Where-Object { $_ })) {
        if (-not (Test-Path $d)) { continue }
        $weak = Get-WeakAcl $d
        if (-not $weak) { continue }
        Add-Finding -Severity 'MEDIUM' -Title "Writable directory on the system PATH: $d" `
            -Detail "$d : $($weak -join '; ')" `
            -Evidence "$d [$($weak -join '; ')]" `
            -Impact 'Allows binary planting and DLL search-order hijacking against any process that resolves a name through PATH, including scheduled administrative tasks.' `
            -Remediation 'Remove the entry from PATH or restrict write access to administrators.' `
            -Ref 'CWE-426'
    }

    Write-SubBanner 'Scheduled Tasks Running as SYSTEM'
    if (Test-Cmd 'Get-ScheduledTask') {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ("$($t.Principal.UserId)" -notmatch '(?i)SYSTEM|LOCALSERVICE|NETWORKSERVICE') { continue }
            $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
            if ($t.TaskPath -match '(?i)^\\Microsoft\\Windows\\') { continue }
            Write-Log ('  [{0}] {1}{2} -> {3}' -f $t.Principal.UserId, $t.TaskPath, $t.TaskName, $actions) 'VERBOSE'
            foreach ($a in $t.Actions) {
                $exe = "$($a.Execute)" -replace '"', ''
                if (-not $exe -or -not (Test-Path $exe -ErrorAction SilentlyContinue)) { continue }
                $weak = Get-WeakAcl $exe
                if ($weak) {
                    Add-Finding -Severity 'HIGH' -Title "Scheduled task binary writable by a low-privilege principal: $($t.TaskName)" `
                        -Detail "$exe runs as $($t.Principal.UserId). ACL: $($weak -join '; ')" `
                        -Evidence "$exe [$($weak -join '; ')]" `
                        -Impact 'Replacing the binary gives code execution as SYSTEM at the next scheduled run.' `
                        -Remediation 'Restrict the task binary to SYSTEM and Administrators.' `
                        -Ref 'CWE-732'
                }
            }
        }
    } else {
        foreach ($line in (schtasks /query /fo LIST /v 2>&1 | Select-String 'TaskName|Run As User' | Select-Object -First 80)) { Write-Log ('  ' + "$line".Trim()) 'VERBOSE' }
    }

    Write-SubBanner 'Credential Exposure in LSASS'
    $wdigest  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $runAsPPL = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $credGuard = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags'
    Write-Log "  WDigest UseLogonCredential = $wdigest   LSA RunAsPPL = $runAsPPL   LsaCfgFlags = $credGuard"
    if ($wdigest -eq 1) {
        Add-Finding -Severity 'HIGH' -Title 'WDigest cleartext credential caching is enabled' `
            -Detail 'UseLogonCredential = 1 causes LSASS to retain the cleartext password of interactive sessions.' `
            -Evidence 'UseLogonCredential=1' `
            -Impact 'Any SYSTEM-level code dumps the ATM service account password in cleartext. Because that account is normally identical across the estate, one terminal yields fleet-wide credentials.' `
            -Remediation 'Set UseLogonCredential to 0 and reboot.' `
            -Ref 'CWE-522'
    }
    if ($null -eq $runAsPPL -or $runAsPPL -eq 0) {
        Add-Finding -Severity 'MEDIUM' -Title 'LSA protection (RunAsPPL) is not enabled' `
            -Detail 'LSASS does not run as a protected process.' `
            -Evidence "RunAsPPL=$runAsPPL" `
            -Impact 'LSASS memory can be read directly by administrative code, exposing cached credentials and Kerberos material for the auto-logon account.' `
            -Remediation 'Set RunAsPPL=1; validate the ATM application and peripheral drivers still function.' `
            -Ref 'CWE-522'
    }

    Write-SubBanner 'Registry Hive Backups & Shadow Copies'
    foreach ($p in @("$env:SystemRoot\repair\SAM", "$env:SystemRoot\System32\config\RegBack\SAM",
                     "$env:SystemRoot\repair\SYSTEM", "$env:SystemRoot\System32\config\RegBack\SYSTEM")) {
        if (-not (Test-Path $p)) { continue }
        $f = Get-Item $p -ErrorAction SilentlyContinue
        if ($f.Length -eq 0) { Write-Log "  [empty] $p" 'VERBOSE'; continue }
        $weak = Get-WeakAcl $p
        Add-Finding -Severity $(if ($weak) { 'HIGH' } else { 'MEDIUM' }) -Title "Registry hive backup present: $(Split-Path $p -Leaf)" `
            -Detail "$p ($([int]($f.Length / 1KB)) KB)$(if ($weak) { ". Weak ACL: $($weak -join '; ')" })" `
            -Evidence "$p size=$($f.Length)$(if ($weak) { " acl=$($weak -join '; ')" })" `
            -Impact 'SAM and SYSTEM backups allow offline extraction of every local password hash, including the ATM service and administrator accounts.' `
            -Remediation 'Remove stale hive backups; ensure ACLs permit SYSTEM and Administrators only.' `
            -Ref 'CWE-522'
    }
    if ($script:IsAdmin) {
        $shadows = & vssadmin.exe list shadows 2>&1 | Select-String 'Shadow Copy Volume|Creation Time' | Select-Object -First 20
        if ($shadows) { foreach ($l in $shadows) { Write-Log ('  ' + "$l".Trim()) 'VERBOSE' } }
        else { Write-Log '  No volume shadow copies present.' 'VERBOSE' }
    }
}


# ============================================================
#  PHASE 13 : DISK ENCRYPTION & BOOT INTEGRITY
# ============================================================

Invoke-Phase 13 'DISK ENCRYPTION & BOOT INTEGRITY' {

    # On an ATM the top box is often reachable with a common key, and the hard
    # disk is the softest target in the whole machine: pull it, mount it offline,
    # read the journal, dump the SAM, implant a malicious XFS provider, put it
    # back. Full-disk encryption is what breaks that chain.

    Write-SubBanner 'BitLocker'
    $encrypted = $false
    if (Test-Cmd 'Get-BitLockerVolume') {
        try {
            foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
                Write-Log ('  {0} status={1} method={2} protection={3} percent={4}' -f $v.MountPoint, $v.VolumeStatus, $v.EncryptionMethod, $v.ProtectionStatus, $v.EncryptionPercentage)
                foreach ($kp in $v.KeyProtector) { Write-Log ('      protector: {0}' -f $kp.KeyProtectorType) 'VERBOSE' }
                if ($v.MountPoint -eq $env:SystemDrive -and $v.ProtectionStatus -eq 'On') { $encrypted = $true }
            }
        } catch { Write-Log "  BitLocker query failed: $($_.Exception.Message)" 'VERBOSE' }
    } else {
        $mb = Get-Wmi 'Win32_EncryptableVolume'
        if ($mb) {
            foreach ($v in $mb) { Write-Log ('  {0} protectionStatus={1}' -f $v.DriveLetter, $v.ProtectionStatus); if ($v.ProtectionStatus -eq 1) { $encrypted = $true } }
        } else {
            Write-Log '  No BitLocker WMI provider - feature absent from this image.' 'WARNING'
        }
    }
    # Third-party FDE
    $thirdPartyFde = @()
    foreach ($n in @('McAfee Drive Encryption', 'Symantec Endpoint Encryption', 'Sophos SafeGuard', 'CheckPoint FDE', 'WinMagic SecureDoc')) {
        $hit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
               Where-Object { "$($_.DisplayName)" -like "*$n*" }
        if ($hit) { $thirdPartyFde += $n; $encrypted = $true; Write-Log "  [present] $n" 'SUCCESS' }
    }

    if (-not $encrypted) {
        Add-Finding -Severity 'CRITICAL' -Title 'ATM system drive is not encrypted at rest' `
            -Detail 'No active BitLocker protection and no third-party full-disk encryption product detected on the system volume.' `
            -Evidence "bitlocker=off thirdParty=$(if ($thirdPartyFde) { $thirdPartyFde -join ',' } else { 'none' })" `
            -Impact 'Physical access to the top box - which across an estate is frequently gated by a single common key - lets an attacker remove the disk or boot external media and then read the electronic journal and camera archive, extract every local password hash offline, and write a malicious XFS service provider back to disk. The implanted provider survives reboot and drives the cash dispenser directly. This single control defeats the entire offline branch of ATM attack paths.' `
            -Remediation 'Enable BitLocker with a TPM-plus-PIN or TPM-plus-startup-key protector on every terminal, suppress the recovery environment, and protect the UEFI configuration with a password so boot order cannot be changed.' `
            -Ref 'CWE-311'
    }

    Write-SubBanner 'TPM'
    if (Test-Cmd 'Get-Tpm') {
        try {
            $t = Get-Tpm -ErrorAction Stop
            Write-Log ('  present={0} ready={1} enabled={2} activated={3} owned={4}' -f $t.TpmPresent, $t.TpmReady, $t.TpmEnabled, $t.TpmActivated, $t.TpmOwned)
            if (-not $t.TpmPresent) {
                Add-Finding -Severity 'MEDIUM' -Title 'No TPM available on the terminal' `
                    -Detail 'Get-Tpm reports no TPM present.' -Evidence 'TpmPresent=False' `
                    -Impact 'Measured boot and TPM-sealed disk encryption keys are unavailable, so any encryption must rely on a startup secret that is in practice shared across the estate.' `
                    -Remediation 'Specify TPM 2.0 for terminal refreshes; in the interim use a startup key on removable media held under dual control.' `
                    -Ref 'CWE-311'
            }
        } catch { Write-Log "  TPM query failed: $($_.Exception.Message)" 'VERBOSE' }
    }

    Write-SubBanner 'Secure Boot / Firmware'
    try {
        if (Test-Cmd 'Confirm-SecureBootUEFI') {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            Write-Log "  Secure Boot enabled: $sb" $(if ($sb) { 'SUCCESS' } else { 'WARNING' })
            if (-not $sb) {
                Add-Finding -Severity 'MEDIUM' -Title 'Secure Boot is disabled' `
                    -Detail 'Confirm-SecureBootUEFI returned False.' -Evidence 'SecureBoot=False' `
                    -Impact 'Unsigned bootloaders and bootkits can load, and alternative boot media is not rejected by firmware.' `
                    -Remediation 'Enable Secure Boot and set a UEFI administrator password.' `
                    -Ref 'CWE-1326'
            }
        }
    } catch { Write-Log '  Secure Boot state unavailable (legacy BIOS boot).' 'WARNING' }
    $bios = Get-Wmi 'Win32_BIOS'
    if ($bios) { Write-Log ('  BIOS: {0} {1} {2}' -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.ReleaseDate) }

    Write-SubBanner 'Hibernation / Crash Dumps (memory on disk)'
    $hib = Join-Path $env:SystemDrive 'hiberfil.sys'
    if (Test-Path $hib) {
        $f = Get-Item $hib -Force -ErrorAction SilentlyContinue
        Add-Finding -Severity 'LOW' -Title 'Hibernation file present on an unencrypted-capable volume' `
            -Detail "$hib ($([int]($f.Length / 1MB)) MB) contains a snapshot of physical memory." `
            -Evidence "$hib size=$($f.Length)" `
            -Impact 'Memory contents - potentially including PIN block material, keys and credentials - are written to disk and recoverable offline.' `
            -Remediation 'Disable hibernation on terminals (powercfg /h off).' `
            -Ref 'CWE-311'
    }
    $cd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' 'CrashDumpEnabled'
    Write-Log ('  CrashDumpEnabled = {0} (0=none, 1=complete, 2=kernel, 3=small)' -f $cd)
}

# ============================================================
#  PHASE 14 : REMOVABLE MEDIA & DEVICE CONTROL
# ============================================================

Invoke-Phase 14 'REMOVABLE MEDIA & DEVICE CONTROL' {

    # USB is the primary physical vector at the fascia and in the top box: a
    # keyboard for kiosk escape, mass storage for payload delivery, a network
    # adapter to bypass the managed interface, or a device that triggers a
    # Windows co-driver download and its attendant dialogs.

    Write-SubBanner 'USB Storage Policy'
    $usbStorStart = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'
    $denyAll      = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' 'Deny_All'
    $writeProtect = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' 'WriteProtect'
    Write-Log ('  USBSTOR Start = {0} (3 = enabled on demand, 4 = disabled)' -f $usbStorStart)
    Write-Log ('  RemovableStorageDevices Deny_All = {0}' -f $denyAll)
    Write-Log ('  StorageDevicePolicies WriteProtect = {0}' -f $writeProtect)

    if ($usbStorStart -ne 4 -and $denyAll -ne 1) {
        Add-Finding -Severity 'HIGH' -Title 'USB mass storage is not disabled on the terminal' `
            -Detail "USBSTOR Start = $usbStorStart and no Deny_All removable-storage policy is present." `
            -Evidence "USBSTOR.Start=$usbStorStart Deny_All=$denyAll" `
            -Impact 'A USB stick in a fascia or top-box port delivers tooling onto the terminal, and the AutoPlay and drive-repair dialogs Windows raises for removable media are themselves a documented kiosk-escape route.' `
            -Remediation 'Set USBSTOR Start to 4 and apply a Deny_All removable-storage policy; where a port is needed for service, allowlist specific device instance IDs.' `
            -Ref 'CWE-1299'
    }

    Write-SubBanner 'Device Installation Restrictions'
    $diRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
    $denyUnspecified = Get-RegValue $diRoot 'DenyUnspecified'
    $allowAdminOverride = Get-RegValue $diRoot 'AllowAdminInstall'
    Write-Log ('  DenyUnspecified = {0}  AllowAdminInstall = {1}' -f $denyUnspecified, $allowAdminOverride)
    if ($denyUnspecified -ne 1) {
        Add-Finding -Severity 'HIGH' -Title 'Any new device class may be installed on the terminal' `
            -Detail 'No DenyUnspecified device-installation restriction is in force, so Windows will install drivers for arbitrary newly attached hardware.' `
            -Evidence "DenyUnspecified=$denyUnspecified" `
            -Impact 'An attacker at the fascia attaches a USB HID device that presents as a keyboard (or a mouse-class device that emits keystrokes, bypassing simple class filters) and drives the kiosk-escape shortcuts directly. A USB network adapter likewise creates an unmanaged interface that sidesteps the terminal network controls.' `
            -Remediation 'Apply device installation restrictions: deny all device classes by default and allowlist only the device instance IDs the ATM hardware requires.' `
            -Ref 'CWE-1299'
    }

    Write-SubBanner 'Driver Co-Installer / Metadata Download'
    # Windows fetching a vendor "co-driver" on device insertion produces exactly
    # the kind of popup an attacker at the fascia can escape through.
    $searchOrder = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig'
    $metadata    = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' 'PreventDeviceMetadataFromNetwork'
    $dontSearchWU = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' 'DontSearchWindowsUpdate'
    Write-Log ('  SearchOrderConfig = {0} (0 = do not search Windows Update)' -f $searchOrder)
    Write-Log ('  PreventDeviceMetadataFromNetwork = {0}' -f $metadata)
    Write-Log ('  DontSearchWindowsUpdate = {0}' -f $dontSearchWU)
    if ($searchOrder -ne 0 -and $dontSearchWU -ne 1) {
        Add-Finding -Severity 'MEDIUM' -Title 'Terminal will fetch device drivers and metadata from the network on device insertion' `
            -Detail "SearchOrderConfig = $searchOrder, DontSearchWindowsUpdate = $dontSearchWU, PreventDeviceMetadataFromNetwork = $metadata." `
            -Evidence "SearchOrderConfig=$searchOrder DontSearchWindowsUpdate=$dontSearchWU" `
            -Impact 'Attaching a recognised consumer device (for example an emulated gaming mouse) triggers a driver or companion-software download and its installation dialogs. Those dialogs - including any UAC prompt - are a known route out of a kiosk session.' `
            -Remediation 'Set SearchOrderConfig to 0, DontSearchWindowsUpdate to 1 and PreventDeviceMetadataFromNetwork to 1.' `
            -Ref 'CWE-1188'
    }

    Write-SubBanner 'Attached Device Inventory'
    $pnp = Get-Wmi 'Win32_PnPEntity'
    foreach ($d in ($pnp | Where-Object { "$($_.PNPDeviceID)" -match '^USB' } | Select-Object -First 60)) {
        Write-Log ('  [USB] {0,-46} {1}' -f ("$($d.Name)".Substring(0, [Math]::Min(46, "$($d.Name)".Length))), $d.PNPDeviceID) 'VERBOSE'
    }
    $hidKeyboards = $pnp | Where-Object { "$($_.PNPClass)" -eq 'Keyboard' }
    $hidMice      = $pnp | Where-Object { "$($_.PNPClass)" -eq 'Mouse' }
    Write-Log ('  keyboards attached: {0}   pointing devices: {1}' -f @($hidKeyboards).Count, @($hidMice).Count)
    foreach ($k in $hidKeyboards) { Write-Log ('    keyboard: {0}  {1}' -f $k.Name, $k.PNPDeviceID) }
    if (@($hidKeyboards).Count -gt 0) {
        Add-Finding -Severity 'LOW' -Title 'A keyboard device is currently attached to the ATM' `
            -Detail (($hidKeyboards | ForEach-Object { "$($_.Name) [$($_.PNPDeviceID)]" }) -join ' | ') `
            -Evidence "count=$(@($hidKeyboards).Count)" `
            -Impact 'A permanently attached keyboard removes the hardest prerequisite for a kiosk escape. Confirm whether the port is operator-reachable without opening the safe.' `
            -Remediation 'Remove service keyboards after maintenance; disable or physically block operator-reachable USB ports.' `
            -Ref 'CWE-1188'
    }

    # XFS peripheral comms path - tells you whether a jackpotting cable attack
    # against the dispenser is physically plausible.
    Write-SubBanner 'ATM Peripheral Interfaces'
    foreach ($d in ($pnp | Where-Object { "$($_.Name)" -match '(?i)dispenser|card reader|smart card|pin ?pad|encrypt|journal|NCR|USB Serial|COM\d' } | Select-Object -First 40)) {
        Write-Log ('  {0,-46} {1}' -f $d.Name, $d.PNPDeviceID)
    }
    foreach ($p in (Get-Wmi 'Win32_SerialPort')) { Write-Log ('  [serial] {0} {1}' -f $p.DeviceID, $p.Description) 'VERBOSE' }
}

# ============================================================
#  PHASE 15 : NETWORK EXPOSURE
# ============================================================

Invoke-Phase 15 'NETWORK EXPOSURE' {

    Write-SubBanner 'Interfaces'
    foreach ($n in (Get-Wmi 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True')) {
        Write-Log ('  {0}' -f $n.Description)
        Write-Log ('      ip={0} mask={1} gw={2} dns={3} dhcp={4}' -f ($n.IPAddress -join ','), ($n.IPSubnet -join ','), ($n.DefaultIPGateway -join ','), ($n.DNSServerSearchOrder -join ','), $n.DHCPEnabled)
    }

    Write-SubBanner 'Firewall Profiles'
    if (Test-Cmd 'Get-NetFirewallProfile') {
        foreach ($fw in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            Write-Log ('  {0,-10} enabled={1} inbound={2} outbound={3}' -f $fw.Name, $fw.Enabled, $fw.DefaultInboundAction, $fw.DefaultOutboundAction) $(if ($fw.Enabled) { 'SUCCESS' } else { 'WARNING' })
            if (-not $fw.Enabled) {
                Add-Finding -Severity 'HIGH' -Title "Windows Firewall disabled on the $($fw.Name) profile" `
                    -Detail "Profile $($fw.Name) is disabled." -Evidence "$($fw.Name)=disabled" `
                    -Impact 'Every listening service on the terminal is reachable from the ATM network segment, so one compromised terminal or a network tap in the top box can attack the rest of the estate laterally.' `
                    -Remediation 'Enable the firewall on all profiles with a default-deny inbound rule and an explicit allowlist for management traffic.' `
                    -Ref 'CWE-1327'
            }
        }
    } else {
        foreach ($line in (netsh advfirewall show allprofiles 2>&1 | Select-String 'Profile Settings|State')) { Write-Log ('  ' + "$line".Trim()) }
    }

    Write-SubBanner 'Listening Ports'
    $risky = @{ 21 = 'FTP'; 23 = 'Telnet'; 135 = 'RPC'; 139 = 'NetBIOS'; 445 = 'SMB'; 3389 = 'RDP';
                4899 = 'Radmin'; 5800 = 'VNC-HTTP'; 5900 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM-TLS'; 1433 = 'MSSQL' }
    if (Test-Cmd 'Get-NetTCPConnection') {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort
        foreach ($l in $listeners) {
            $pname = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Log ('  {0,-16}:{1,-6} pid={2,-6} {3}' -f $l.LocalAddress, $l.LocalPort, $l.OwningProcess, $pname) 'VERBOSE'
        }
        foreach ($port in $risky.Keys) {
            $hit = $listeners | Where-Object { $_.LocalPort -eq $port -and "$($_.LocalAddress)" -in @('0.0.0.0', '::', '[::]') }
            if (-not $hit) { continue }
            $pname = (Get-Process -Id $hit[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
            $sev = if ($port -in @(23, 21, 4899, 5900, 3389)) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding -Severity $sev -Title "$($risky[$port]) listening on all interfaces (tcp/$port)" `
                -Detail "Process $pname (pid $($hit[0].OwningProcess)) is bound to 0.0.0.0:$port." `
                -Evidence "0.0.0.0:$port pid=$($hit[0].OwningProcess) proc=$pname" `
                -Impact 'Remote administrative and file-sharing services on an ATM are the standard lateral-movement path across an estate, and are directly reachable by anyone who taps the network cable inside the top box.' `
                -Remediation 'Bind the service to the management interface only, restrict with host firewall rules to the management subnet, or remove it.' `
                -Ref 'CWE-1327'
        }
    } else {
        foreach ($line in (netstat -ano 2>&1 | Select-String 'LISTENING' | Select-Object -First 80)) { Write-Log ('  ' + "$line".Trim()) 'VERBOSE' }
    }

    Write-SubBanner 'RDP Configuration'
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny  = Get-RegValue $tsKey 'fDenyTSConnections'
    $nla   = Get-RegValue "$tsKey\WinStations\RDP-Tcp" 'UserAuthentication'
    $secLayer = Get-RegValue "$tsKey\WinStations\RDP-Tcp" 'SecurityLayer'
    Write-Log "  fDenyTSConnections=$deny  UserAuthentication(NLA)=$nla  SecurityLayer=$secLayer"
    if ($deny -eq 0) {
        $sev = if ($nla -ne 1) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding -Severity $sev -Title "RDP is enabled on the ATM$(if ($nla -ne 1) { ' without Network Level Authentication' })" `
            -Detail "fDenyTSConnections = 0, UserAuthentication = $nla, SecurityLayer = $secLayer." `
            -Evidence "fDenyTSConnections=0 NLA=$nla" `
            -Impact 'Interactive remote access to a cash-handling terminal. Without NLA the logon screen is exposed pre-authentication, which also exposes the accessibility escape routes assessed in phase 11.' `
            -Remediation 'Disable RDP on terminals, or require NLA, restrict by host firewall to a management jump host, and enforce per-host unique credentials.' `
            -Ref 'CWE-1327'
    }

    Write-SubBanner 'SMB & Name Resolution'
    if (Test-Cmd 'Get-SmbServerConfiguration') {
        $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smb) {
            Write-Log ('  SMB1 enabled={0} signingRequired={1} encryptData={2}' -f $smb.EnableSMB1Protocol, $smb.RequireSecuritySignature, $smb.EncryptData)
            if ($smb.EnableSMB1Protocol) {
                Add-Finding -Severity 'HIGH' -Title 'SMBv1 is enabled on the terminal' `
                    -Detail 'EnableSMB1Protocol is true.' -Evidence 'SMB1=enabled' `
                    -Impact 'SMBv1 carries known remote code execution vulnerabilities and no modern integrity protection, and is the path wormable malware has historically taken across ATM estates.' `
                    -Remediation 'Disable SMBv1 and require SMB signing.' -Ref 'CWE-1104'
            }
            if (-not $smb.RequireSecuritySignature) {
                Add-Finding -Severity 'MEDIUM' -Title 'SMB signing is not required' `
                    -Detail 'RequireSecuritySignature is false.' -Evidence 'SMBSigning=optional' `
                    -Impact 'Permits SMB relay from the ATM network segment to authenticate as the terminal against other hosts.' `
                    -Remediation 'Require SMB signing on clients and servers across the estate.' -Ref 'CWE-300'
            }
        }
    }
    $llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $nbt = Get-Wmi 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True' | ForEach-Object { $_.TcpipNetbiosOptions }
    Write-Log "  LLMNR EnableMulticast=$llmnr   NetBIOS options=$($nbt -join ',')"
    if ($llmnr -ne 0) {
        $llmnrState = if ($null -eq $llmnr) { 'not set, so LLMNR is enabled by default' } else { "EnableMulticast = $llmnr (0 disables it)" }
        Add-Finding -Severity 'MEDIUM' -Title 'LLMNR is not disabled' `
            -Detail $llmnrState -Evidence "EnableMulticast=$(if ($null -eq $llmnr) { 'absent' } else { $llmnr })" `
            -Impact 'An attacker on the ATM segment poisons name resolution and captures or relays the terminal machine and service account authentication.' `
            -Remediation 'Disable LLMNR and NetBIOS over TCP/IP by policy.' -Ref 'CWE-300'
    }

    Write-SubBanner 'Named Pipes'
    # XFS service providers and ATM middleware frequently expose named pipes. A
    # weak pipe ACL is an alternative route to the device layer that does not
    # require loading msxfs.dll at all.
    try {
        $pipes = [IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { Split-Path $_ -Leaf }
        Write-Log ('  {0} named pipes present.' -f @($pipes).Count)
        foreach ($p in ($pipes | Where-Object { $_ -match '(?i)xfs|ncr|aptra|cdm|idc|pin|dispenser|atm|journal|sst' })) {
            Write-Log ('  [interesting] \\.\pipe\{0}' -f $p) 'WARNING'
            Add-Finding -Severity 'LOW' -Title "ATM-related named pipe exposed: \\.\pipe\$p" `
                -Detail 'An ATM or XFS component exposes a named pipe in the local namespace.' `
                -Evidence "\\.\pipe\$p" `
                -Impact 'If the pipe ACL permits a low-privilege principal, it offers a route to the device layer that bypasses msxfs.dll entirely and therefore any whitelisting focused on that DLL. Enumerate the pipe DACL and protocol to confirm.' `
                -Remediation 'Restrict pipe DACLs to the ATM service account, and authenticate the client at the protocol level.' `
                -Ref 'CWE-732'
        }
    } catch { Write-Log '  Named pipe enumeration failed.' 'VERBOSE' }

    Write-SubBanner 'Proxy & Time Source'
    $proxy = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer'
    Write-Log ('  ProxyServer = {0}' -f $(if ($proxy) { $proxy } else { 'none' }))
    foreach ($line in (w32tm /query /source 2>&1)) { Write-Log ('  time source: ' + "$line".Trim()) }

    if (-not $Fast) {
        Write-SubBanner 'Outbound Internet Reachability (segmentation test)'
        # An ATM that can reach the open internet can also reach an attacker's
        # command-and-control, and can download a payload after a kiosk escape.
        $reached = @()
        foreach ($t in @(@('1.1.1.1', 443), @('8.8.8.8', 53))) {
            try {
                $c = New-Object Net.Sockets.TcpClient
                $iar = $c.BeginConnect($t[0], $t[1], $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $c.Connected) { $reached += "$($t[0]):$($t[1])" }
                $c.Close()
            } catch { }
        }
        if ($reached) {
            Write-Log ('  outbound reachable: {0}' -f ($reached -join ', ')) 'WARNING'
            Add-Finding -Severity 'MEDIUM' -Title 'Terminal has direct outbound internet connectivity' `
                -Detail "Direct TCP connections succeeded to: $($reached -join ', ')." `
                -Evidence ($reached -join ',') `
                -Impact 'The ATM segment is not egress-restricted, so an attacker who lands code on the terminal can retrieve tooling and establish an outbound command-and-control channel that bypasses inbound firewall controls.' `
                -Remediation 'Restrict the ATM VLAN to the specific switch, host and processor endpoints required; deny all other egress at the firewall and proxy.' `
                -Ref 'CWE-1327'
        } else {
            Write-Log '  No direct outbound connectivity to the tested endpoints - egress appears restricted.' 'SUCCESS'
        }
    }
}

# ============================================================
#  SUMMARY & EXPORT
# ============================================================

Write-Banner 'ASSESSMENT SUMMARY'

$order = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
$counts = @{}
foreach ($s in $order) { $counts[$s] = @($script:Findings | Where-Object { $_.Severity -eq $s }).Count }

foreach ($s in $order) {
    $lvl = switch ($s) { 'CRITICAL' { 'CRITICAL' } 'HIGH' { 'HIGH' } 'MEDIUM' { 'WARNING' } default { 'INFO' } }
    Write-Log ('  {0,-9} : {1}' -f $s, $counts[$s]) $lvl
}
Write-Log ('  {0,-9} : {1}' -f 'TOTAL', $script:Findings.Count)

if ($script:Findings.Count -gt 0) {
    Write-SubBanner 'Findings by Severity'
    foreach ($s in $order) {
        $lvl = switch ($s) { 'CRITICAL' { 'CRITICAL' } 'HIGH' { 'HIGH' } 'MEDIUM' { 'WARNING' } default { 'INFO' } }
        foreach ($f in ($script:Findings | Where-Object { $_.Severity -eq $s })) {
            Write-Log ('  [{0,-8}] (phase {1,2}) {2}' -f $f.Severity, $f.Phase, $f.Title) $lvl
        }
    }
}

# Machine-readable exports for the report pipeline.
try {
    if (Test-Cmd 'ConvertTo-Json') {
        $payload = [pscustomobject]@{
            tool        = "Amr's ATM Automate Script"
            version     = '2.0'
            host        = $env:COMPUTERNAME
            os          = "$((Get-OsInfo).Caption) $((Get-OsInfo).Version)"
            started     = $Timestamp
            redacted    = (-not $NoRedact)
            phasesRun   = $Phases
            counts      = $counts
            findings    = $script:Findings
        }
        $payload | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonFile -Encoding UTF8
        Write-Log "  JSON findings : $JsonFile" 'SUCCESS'
    }
    $script:Findings | Select-Object Severity, Phase, Title, Asset, Detail, Evidence, Impact, Remediation, Ref, Observed |
        Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "  CSV findings  : $CsvFile" 'SUCCESS'
} catch {
    Write-Log "  Export failed: $($_.Exception.Message)" 'ERROR'
}

$summary = @"

  Run directory : $RunDir
  Log           : $LogFile
  Findings      : $($script:Findings.Count)  (critical $($counts['CRITICAL']), high $($counts['HIGH']), medium $($counts['MEDIUM']), low $($counts['LOW']))
  Completed     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

  Reminder: this output directory may contain credential material. Move it to
  encrypted storage and remove it from the terminal before you leave site.
"@
Write-Host $summary -ForegroundColor Green
$script:Writer.WriteLine($summary)

# Exit code encodes the worst severity, so the script is usable from a wrapper.
if ($counts['CRITICAL'] -gt 0)   { $script:ExitCode = 10 }
elseif ($counts['HIGH'] -gt 0)   { $script:ExitCode = 11 }
elseif ($counts['MEDIUM'] -gt 0) { $script:ExitCode = 12 }

$script:Writer.Flush()
$script:Writer.Dispose()
exit $script:ExitCode

