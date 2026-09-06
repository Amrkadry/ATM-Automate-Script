<#
.SYNOPSIS
    Amr's ATM Automate Script
    NCR Personas ATM Penetration Testing Automation

.DESCRIPTION
    Comprehensive PowerShell ATM pentest automation covering:
    - Local admin & user enumeration
    - UAC misconfiguration detection
    - sstauto user group membership check
    - Plaintext credential hunting (registry, files, configs)
    - eJournal & camera backup insecure storage detection
    - Radmin Server hash extraction (HKLM → .reg + parsed output)
    - XFS middleware enumeration via msxfs.dll P/Invoke
    - CDM (Cash Dispenser Module) capability & status queries

.NOTES
    Author  : Amr Kadry
    Project : Amr's ATM Automate Script
    Target  : NCR Personas ATMs (Windows Embedded / IoT)
    Usage   : Run as Local Administrator on the ATM
              .\Amrs-ATM-Automate-Script.ps1

    AUTHORIZED TESTING ONLY - Ensure you have written permission.
#>

#Requires -RunAsAdministrator

# ============================================================
#  CONFIGURATION & OUTPUT SETUP
# ============================================================

$ErrorActionPreference = "Continue"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$OutputDir   = Join-Path $ScriptDir "Amrs Output"
$Timestamp   = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile     = Join-Path $OutputDir "ATM-Pentest-Results_$Timestamp.txt"
$RadminReg   = Join-Path $OutputDir "Radmin-Hashes_$Timestamp.reg"

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ============================================================
#  LOGGING FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line -ForegroundColor $(
        switch ($Level) {
            "CRITICAL" { "Red" }
            "WARNING"  { "Yellow" }
            "SUCCESS"  { "Green" }
            "SECTION"  { "Cyan" }
            "VERBOSE"  { "Gray" }
            default    { "White" }
        }
    )
    Add-Content -Path $LogFile -Value $line
}

function Write-Banner {
    param([string]$Title)
    $sep = "=" * 70
    $banner = @"

$sep
  $Title
$sep
"@
    Write-Host $banner -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $banner
}

function Write-SubBanner {
    param([string]$Title)
    $sep = "-" * 60
    $sub = "`n$sep`n  $Title`n$sep"
    Write-Host $sub -ForegroundColor DarkCyan
    Add-Content -Path $LogFile -Value $sub
}

# ============================================================
#  START
# ============================================================

$header = @"
###############################################################
#                                                             #
#           Amr's ATM Automate Script                         #
#           NCR Personas ATM Penetration Testing              #
#                                                             #
#           Target  : NCR Personas                            #
#           Date    : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
#           Host    : $env:COMPUTERNAME                        #
#           User    : $env:USERNAME                            #
#                                                             #
###############################################################
"@

Write-Host $header -ForegroundColor Green
Set-Content -Path $LogFile -Value $header
Write-Log "Output directory: $OutputDir"
Write-Log "Log file: $LogFile"

# ============================================================
#  PHASE 1 : SYSTEM INFORMATION
# ============================================================

Write-Banner "PHASE 1 : SYSTEM INFORMATION"

Write-Log "Gathering system information..." "VERBOSE"

$sysInfo = @{
    "Hostname"        = $env:COMPUTERNAME
    "OS"              = (Get-CimInstance Win32_OperatingSystem).Caption
    "OS Version"      = (Get-CimInstance Win32_OperatingSystem).Version
    "OS Build"        = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    "Architecture"    = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    "Install Date"    = (Get-CimInstance Win32_OperatingSystem).InstallDate
    "Last Boot"       = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    "Domain"          = (Get-CimInstance Win32_ComputerSystem).Domain
    "Workgroup"       = (Get-CimInstance Win32_ComputerSystem).Workgroup
    "Current User"    = "$env:USERDOMAIN\$env:USERNAME"
    "System Dir"      = $env:SystemRoot
    "Temp Dir"        = $env:TEMP
}

foreach ($k in $sysInfo.Keys | Sort-Object) {
    Write-Log ("  {0,-20} : {1}" -f $k, $sysInfo[$k]) "VERBOSE"
}

# Check if running as SYSTEM or Administrator
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem  = $identity.IsSystem

Write-Log "Running as Administrator : $isAdmin" $(if($isAdmin){"SUCCESS"}else{"WARNING"})
Write-Log "Running as SYSTEM        : $isSystem" $(if($isSystem){"SUCCESS"}else{"INFO"})

# ATM-specific paths check
Write-SubBanner "NCR Software Detection"

$ncrPaths = @(
    "C:\Program Files\NCR",
    "C:\Program Files (x86)\NCR",
    "C:\Program Files\NCR\APTRA",
    "C:\NCR",
    "C:\WOSA\XFS",
    "C:\Program Files\Common Files\XFS"
)

foreach ($p in $ncrPaths) {
    if (Test-Path $p) {
        Write-Log "[FOUND] $p" "SUCCESS"
        $items = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 15
        foreach ($item in $items) {
            Write-Log "    └─ $($item.Name) ($($item.LastWriteTime))" "VERBOSE"
        }
    } else {
        Write-Log "[NOT FOUND] $p" "VERBOSE"
    }
}

# Check installed NCR software from registry
Write-SubBanner "Installed NCR / ATM Software (Registry)"

$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($rp in $regPaths) {
    Get-ItemProperty $rp -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "NCR|APTRA|XFS|Solidcore|McAfee|Radmin|Phoenix|Vista ATM" } |
        ForEach-Object {
            Write-Log "  [INSTALLED] $($_.DisplayName) v$($_.DisplayVersion)" "SUCCESS"
        }
}

# ============================================================
#  PHASE 2 : LOCAL USER & ADMIN ENUMERATION
# ============================================================

Write-Banner "PHASE 2 : LOCAL USER & ADMIN ENUMERATION"

Write-SubBanner "All Local Users"

try {
    $localUsers = Get-LocalUser -ErrorAction Stop
    foreach ($u in $localUsers) {
        $status = if ($u.Enabled) { "ENABLED" } else { "DISABLED" }
        $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        $pwSet     = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        $pwExpires = $u.PasswordExpires
        $pwReq     = $u.PasswordRequired

        Write-Log ("  User: {0,-25} Status: {1,-10} LastLogon: {2}" -f $u.Name, $status, $lastLogon)
        Write-Log ("    Password Set: {0}  Required: {1}  Expires: {2}" -f $pwSet, $pwReq, $pwExpires) "VERBOSE"

        # Flag interesting accounts
        if ($u.Name -match "sstauto|ncr|atm|service|admin" -and $u.Enabled) {
            Write-Log "    ^^^ INTERESTING ACCOUNT - Enabled ATM/Service account" "WARNING"
        }
        if (-not $u.PasswordRequired) {
            Write-Log "    ^^^ NO PASSWORD REQUIRED" "CRITICAL"
        }
    }
} catch {
    # Fallback to net user
    Write-Log "Get-LocalUser unavailable, falling back to net user" "VERBOSE"
    $netUsers = net user 2>&1
    foreach ($line in $netUsers) { Write-Log "  $line" "VERBOSE" }
}

Write-SubBanner "Local Administrators Group"

try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    foreach ($m in $admins) {
        Write-Log "  [ADMIN] $($m.Name)  (Type: $($m.ObjectClass), Source: $($m.PrincipalSource))" "WARNING"
    }
} catch {
    Write-Log "Falling back to net localgroup" "VERBOSE"
    $netAdmins = net localgroup Administrators 2>&1
    foreach ($line in $netAdmins) { Write-Log "  $line" }
}

# ============================================================
#  PHASE 3 : sstauto USER CHECK
# ============================================================

Write-Banner "PHASE 3 : sstauto USER ASSESSMENT"

$sstautoFound = $false

try {
    $sstautoUser = Get-LocalUser -Name "sstauto" -ErrorAction Stop
    $sstautoFound = $true
    Write-Log "[FOUND] sstauto user exists" "WARNING"
    Write-Log "  Enabled         : $($sstautoUser.Enabled)" $(if($sstautoUser.Enabled){"CRITICAL"}else{"INFO"})
    Write-Log "  Password Set    : $($sstautoUser.PasswordLastSet)" "VERBOSE"
    Write-Log "  Password Expires: $($sstautoUser.PasswordExpires)" "VERBOSE"
    Write-Log "  Password Required: $($sstautoUser.PasswordRequired)" $(if(-not $sstautoUser.PasswordRequired){"CRITICAL"}else{"INFO"})
    Write-Log "  Last Logon      : $($sstautoUser.LastLogon)" "VERBOSE"
    Write-Log "  Description     : $($sstautoUser.Description)" "VERBOSE"
    Write-Log "  SID             : $($sstautoUser.SID)" "VERBOSE"
} catch {
    Write-Log "[NOT FOUND] sstauto user does not exist on this system" "INFO"
}

# Check sstauto group memberships
if ($sstautoFound) {
    Write-SubBanner "sstauto Group Memberships"

    try {
        $allGroups = Get-LocalGroup -ErrorAction Stop
        foreach ($grp in $allGroups) {
            try {
                $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction Stop
                $isMember = $members | Where-Object { $_.Name -match "sstauto" }
                if ($isMember) {
                    $severity = if ($grp.Name -eq "Administrators") { "CRITICAL" } else { "WARNING" }
                    Write-Log "  [MEMBER] sstauto is in group: $($grp.Name)" $severity
                    if ($grp.Name -eq "Administrators") {
                        Write-Log "  *** CRITICAL: sstauto has LOCAL ADMIN privileges ***" "CRITICAL"
                    }
                }
            } catch { }
        }
    } catch {
        # Fallback
        $netGroups = net user sstauto 2>&1
        foreach ($line in $netGroups) { Write-Log "  $line" "VERBOSE" }
    }

    # Check sstauto auto-logon
    Write-SubBanner "sstauto Auto-Logon Check"

    $autoLogonKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )

    foreach ($key in $autoLogonKeys) {
        if (Test-Path $key) {
            $autoLogon     = (Get-ItemProperty $key -ErrorAction SilentlyContinue).AutoAdminLogon
            $defaultUser   = (Get-ItemProperty $key -ErrorAction SilentlyContinue).DefaultUserName
            $defaultPass   = (Get-ItemProperty $key -ErrorAction SilentlyContinue).DefaultPassword
            $defaultDomain = (Get-ItemProperty $key -ErrorAction SilentlyContinue).DefaultDomainName

            Write-Log "  AutoAdminLogon : $autoLogon" $(if($autoLogon -eq "1"){"WARNING"}else{"INFO"})
            Write-Log "  DefaultUserName: $defaultUser" $(if($defaultUser -match "sstauto"){"WARNING"}else{"INFO"})
            if ($defaultPass) {
                Write-Log "  DefaultPassword: $defaultPass" "CRITICAL"
                Write-Log "  *** PLAINTEXT AUTO-LOGON PASSWORD FOUND ***" "CRITICAL"
            } else {
                Write-Log "  DefaultPassword: (not set or empty)" "VERBOSE"
            }
            Write-Log "  DefaultDomain  : $defaultDomain" "VERBOSE"
        }
    }
}

# ============================================================
#  PHASE 4 : UAC MISCONFIGURATION CHECK
# ============================================================

Write-Banner "PHASE 4 : UAC MISCONFIGURATION ASSESSMENT"

$uacKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

if (Test-Path $uacKeyPath) {
    $uacProps = Get-ItemProperty $uacKeyPath -ErrorAction SilentlyContinue

    $uacChecks = @(
        @{ Name="EnableLUA";                    Secure=1; Desc="UAC Enabled" },
        @{ Name="ConsentPromptBehaviorAdmin";   Secure=2; Desc="Admin consent prompt behavior (0=no prompt, 1=cred prompt on secure desktop, 2=consent on secure desktop, 5=consent for non-Win binaries)" },
        @{ Name="ConsentPromptBehaviorUser";    Secure=3; Desc="User consent prompt behavior" },
        @{ Name="PromptOnSecureDesktop";        Secure=1; Desc="Prompt on secure desktop" },
        @{ Name="EnableInstallerDetection";     Secure=1; Desc="Installer detection" },
        @{ Name="ValidateAdminCodeSignatures";  Secure=1; Desc="Only elevate signed executables" },
        @{ Name="EnableSecureUIAPaths";         Secure=1; Desc="UIAccess integrity enforcement" },
        @{ Name="EnableVirtualization";         Secure=1; Desc="File/registry virtualization" },
        @{ Name="FilterAdministratorToken";     Secure=1; Desc="Built-in Admin approval mode" }
    )

    foreach ($check in $uacChecks) {
        $val = $uacProps.($check.Name)
        if ($null -eq $val) {
            Write-Log ("  {0,-40} : NOT SET (default applies)" -f $check.Name) "VERBOSE"
        } else {
            $severity = "INFO"
            $finding  = ""

            switch ($check.Name) {
                "EnableLUA" {
                    if ($val -eq 0) { $severity = "CRITICAL"; $finding = " *** UAC IS DISABLED ***" }
                    else { $severity = "SUCCESS" }
                }
                "ConsentPromptBehaviorAdmin" {
                    if ($val -eq 0) { $severity = "CRITICAL"; $finding = " *** ADMIN NEVER PROMPTED - Silent elevation ***" }
                    elseif ($val -eq 1) { $severity = "INFO"; $finding = " (Cred prompt on secure desktop)" }
                    elseif ($val -eq 5) { $severity = "WARNING"; $finding = " (Consent for non-Windows only)" }
                }
                "PromptOnSecureDesktop" {
                    if ($val -eq 0) { $severity = "WARNING"; $finding = " Secure desktop DISABLED - spoofable prompts" }
                }
                "FilterAdministratorToken" {
                    if ($val -eq 0) { $severity = "WARNING"; $finding = " Built-in Admin gets full token without prompt" }
                }
                "ValidateAdminCodeSignatures" {
                    if ($val -eq 0) { $severity = "WARNING"; $finding = " Unsigned executables can elevate" }
                }
            }

            Write-Log ("  {0,-40} : {1}{2}" -f $check.Name, $val, $finding) $severity
        }
    }

    # Additional UAC bypass checks
    Write-SubBanner "UAC Bypass Indicators"

    # Check AlwaysInstallElevated
    $aieUser    = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $aieMachine = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

    if ($aieUser.AlwaysInstallElevated -eq 1 -and $aieMachine.AlwaysInstallElevated -eq 1) {
        Write-Log "  [CRITICAL] AlwaysInstallElevated = 1 on BOTH HKCU and HKLM" "CRITICAL"
        Write-Log "  *** MSI installer UAC bypass is possible ***" "CRITICAL"
    } else {
        Write-Log "  AlwaysInstallElevated: Not exploitable (HKCU=$($aieUser.AlwaysInstallElevated), HKLM=$($aieMachine.AlwaysInstallElevated))" "INFO"
    }

    # Check for auto-elevate binaries in PATH
    Write-Log "`n  Checking for common UAC bypass binaries..." "VERBOSE"
    $bypassBins = @("fodhelper.exe","computerdefaults.exe","sdclt.exe","eventvwr.exe","mmc.exe","cmstp.exe","wsreset.exe")
    foreach ($bin in $bypassBins) {
        $found = Get-Command $bin -ErrorAction SilentlyContinue
        if ($found) {
            Write-Log "  [PRESENT] $bin → $($found.Source)  (potential UAC bypass vector)" "WARNING"
        }
    }

} else {
    Write-Log "UAC registry key not found — unusual configuration" "CRITICAL"
}

# ============================================================
#  PHASE 5 : PLAINTEXT CREDENTIAL HUNTING
# ============================================================

Write-Banner "PHASE 5 : PLAINTEXT CREDENTIAL HUNTING"

Write-SubBanner "Windows Auto-Logon Credentials"

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (Test-Path $winlogonPath) {
    $wlProps = Get-ItemProperty $winlogonPath -ErrorAction SilentlyContinue
    if ($wlProps.DefaultPassword) {
        Write-Log "  [CRITICAL] Auto-logon password found:" "CRITICAL"
        Write-Log "    User: $($wlProps.DefaultDomainName)\$($wlProps.DefaultUserName)" "CRITICAL"
        Write-Log "    Pass: $($wlProps.DefaultPassword)" "CRITICAL"
    }
    if ($wlProps.AutoAdminLogon -eq "1") {
        Write-Log "  [WARNING] AutoAdminLogon is ENABLED" "WARNING"
    }
}

Write-SubBanner "Stored Credentials (cmdkey)"

$cmdkeyOutput = cmdkey /list 2>&1
foreach ($line in $cmdkeyOutput) {
    if ($line -match "Target:|Type:|User:") {
        Write-Log "  $($line.Trim())" "WARNING"
    }
}

Write-SubBanner "Wi-Fi Profiles (plaintext keys)"

try {
    $profiles = netsh wlan show profiles 2>&1
    $profileNames = $profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[-1].Trim()
    }
    foreach ($prof in $profileNames) {
        $detail = netsh wlan show profile name="$prof" key=clear 2>&1
        $keyLine = $detail | Select-String "Key Content"
        if ($keyLine) {
            Write-Log "  [FOUND] Wi-Fi '$prof' Key: $(($keyLine -split ':')[-1].Trim())" "CRITICAL"
        }
    }
} catch {
    Write-Log "  Wi-Fi enumeration not available" "VERBOSE"
}

Write-SubBanner "Registry Credential Search"

$credRegPaths = @(
    "HKLM:\SOFTWARE\RealVNC",
    "HKLM:\SOFTWARE\RealVNC\WinVNC4",
    "HKLM:\SOFTWARE\TightVNC",
    "HKLM:\SOFTWARE\ORL\WinVNC3\Default",
    "HKLM:\SOFTWARE\ORL\WinVNC\Default",
    "HKCU:\SOFTWARE\ORL\WinVNC3\Default",
    "HKLM:\SOFTWARE\WOW6432Node\RealVNC",
    "HKLM:\SOFTWARE\TeamViewer",
    "HKLM:\SOFTWARE\WOW6432Node\TeamViewer",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities",
    "HKLM:\SOFTWARE\NCR\APTRA",
    "HKLM:\SOFTWARE\NCR\Platform",
    "HKLM:\SOFTWARE\WOW6432Node\NCR"
)

foreach ($regPath in $credRegPaths) {
    if (Test-Path $regPath) {
        Write-Log "  [FOUND] Registry key exists: $regPath" "WARNING"
        try {
            $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object {
                $_.Name -match "pass|pwd|secret|key|cred|auth|token" -and
                $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
            } | ForEach-Object {
                Write-Log "    [CREDENTIAL] $($_.Name) = $($_.Value)" "CRITICAL"
            }
        } catch { }
    }
}

Write-SubBanner "Plaintext Files Search (Desktop, Documents, NCR dirs)"

$searchPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "C:\NCR",
    "C:\Program Files\NCR",
    "C:\Program Files (x86)\NCR",
    "C:\WOSA",
    "C:\temp",
    "C:\inetpub"
)

$credFilePatterns = @("*.ini","*.cfg","*.conf","*.config","*.xml","*.txt","*.log","*.bak","*.old","*.properties")

foreach ($sp in $searchPaths) {
    if (Test-Path $sp) {
        foreach ($pattern in $credFilePatterns) {
            Get-ChildItem -Path $sp -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.Length -lt 5MB } |
                ForEach-Object {
                    try {
                        $content = Get-Content $_.FullName -ErrorAction SilentlyContinue -TotalCount 500
                        $hits = $content | Select-String -Pattern "password|passwd|pwd|secret|credential|key\s*=|token|connectionstring|<password|pass=" -AllMatches
                        if ($hits) {
                            Write-Log "  [HIT] $($_.FullName)" "CRITICAL"
                            foreach ($hit in $hits | Select-Object -First 5) {
                                $redacted = $hit.Line.Trim()
                                Write-Log "    Line $($hit.LineNumber): $redacted" "CRITICAL"
                            }
                        }
                    } catch { }
                }
        }
    }
}

Write-SubBanner "Unattended Install Files"

$unattendPaths = @(
    "C:\unattend.xml", "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\Unattend\unattend.xml",
    "C:\Windows\system32\sysprep\unattend.xml",
    "C:\Windows\system32\sysprep\Panther\unattend.xml",
    "C:\sysprep.inf", "C:\sysprep\sysprep.xml"
)

foreach ($upath in $unattendPaths) {
    if (Test-Path $upath) {
        Write-Log "  [FOUND] Unattended file: $upath" "CRITICAL"
        $content = Get-Content $upath -ErrorAction SilentlyContinue | Select-String "Password|AdminPassword|UserAccounts"
        foreach ($c in $content) {
            Write-Log "    $($c.Line.Trim())" "CRITICAL"
        }
    }
}

# ============================================================
#  PHASE 6 : eJOURNAL & CAMERA BACKUP ASSESSMENT
# ============================================================

Write-Banner "PHASE 6 : eJOURNAL & CAMERA BACKUP INSECURE STORAGE"

Write-SubBanner "eJournal File Enumeration"

$ejournalPaths = @(
    "C:\NCR\eJournal",
    "C:\NCR\Journal",
    "C:\Program Files\NCR\eJournal",
    "C:\Program Files (x86)\NCR\eJournal",
    "C:\APTRA\eJournal",
    "C:\NCR\APTRA\eJournal",
    "C:\Users\sstauto\AppData\Local\NCR\eJournal",
    "D:\eJournal",
    "E:\eJournal"
)

# Also search for eJournal via registry
$ejRegPaths = @(
    "HKLM:\SOFTWARE\NCR\eJournal",
    "HKLM:\SOFTWARE\WOW6432Node\NCR\eJournal",
    "HKLM:\SOFTWARE\NCR\APTRA\eJournal"
)

foreach ($ejReg in $ejRegPaths) {
    if (Test-Path $ejReg) {
        Write-Log "  [REGISTRY] eJournal config found: $ejReg" "WARNING"
        $ejProps = Get-ItemProperty $ejReg -ErrorAction SilentlyContinue
        $ejProps.PSObject.Properties | Where-Object {
            $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
        } | ForEach-Object {
            Write-Log "    $($_.Name) = $($_.Value)" "VERBOSE"
            if ($_.Name -match "path|dir|folder|location|archive|backup") {
                $ejournalPaths += $_.Value
            }
        }
    }
}

foreach ($ejPath in ($ejournalPaths | Select-Object -Unique)) {
    if (Test-Path $ejPath) {
        Write-Log "  [FOUND] eJournal directory: $ejPath" "WARNING"

        # Check permissions
        try {
            $acl = Get-Acl $ejPath -ErrorAction Stop
            Write-Log "    Owner: $($acl.Owner)" "VERBOSE"
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users") {
                    Write-Log "    [INSECURE ACL] $($ace.IdentityReference) has $($ace.FileSystemRights)" "CRITICAL"
                }
            }
        } catch {
            Write-Log "    Could not read ACL: $_" "VERBOSE"
        }

        # Count and sample files
        $ejFiles = Get-ChildItem -Path $ejPath -Recurse -ErrorAction SilentlyContinue
        $ejCount = ($ejFiles | Measure-Object).Count
        $ejSize  = ($ejFiles | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        Write-Log "    Files: $ejCount  |  Total Size: $([math]::Round($ejSize/1MB, 2)) MB" "INFO"

        # Check for sensitive data patterns in eJournal files
        $ejSamples = $ejFiles | Where-Object { $_.Extension -match "\.ej$|\.jrn$|\.log$|\.txt$|\.xml$|\.dat$" } | Select-Object -First 10
        foreach ($ej in $ejSamples) {
            try {
                $ejContent = Get-Content $ej.FullName -TotalCount 50 -ErrorAction SilentlyContinue
                $sensitiveHits = $ejContent | Select-String -Pattern "\d{4}[\s\-\*]{0,3}\d{4}[\s\-\*]{0,3}\d{4}[\s\-\*]{0,3}\d{4}|card|account|PAN|track[12]" -AllMatches
                if ($sensitiveHits) {
                    Write-Log "    [SENSITIVE DATA] $($ej.FullName) contains potential card/account data" "CRITICAL"
                    foreach ($sh in $sensitiveHits | Select-Object -First 3) {
                        Write-Log "      $($sh.Line.Trim().Substring(0, [Math]::Min($sh.Line.Trim().Length, 120)))" "CRITICAL"
                    }
                }
            } catch { }
        }

        # Check if eJournal backup location is insecure
        $backupDirs = Get-ChildItem -Path $ejPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "backup|archive|old|bak" }
        foreach ($bd in $backupDirs) {
            Write-Log "    [BACKUP DIR] $($bd.FullName) (Last Modified: $($bd.LastWriteTime))" "WARNING"
        }
    }
}

Write-SubBanner "Camera / Surveillance Backup Enumeration"

$cameraPaths = @(
    "C:\NCR\Camera",
    "C:\NCR\CameraImages",
    "C:\NCR\Surveillance",
    "C:\Program Files\NCR\Camera",
    "C:\APTRA\Camera",
    "C:\NCR\APTRA\ImageArchive",
    "C:\NCR\CameraArchive",
    "D:\Camera",
    "D:\CameraBackup",
    "E:\Camera"
)

# Registry search for camera config
$camRegPaths = @(
    "HKLM:\SOFTWARE\NCR\Camera",
    "HKLM:\SOFTWARE\WOW6432Node\NCR\Camera",
    "HKLM:\SOFTWARE\NCR\APTRA\Camera",
    "HKLM:\SOFTWARE\NCR\ImageArchive"
)

foreach ($camReg in $camRegPaths) {
    if (Test-Path $camReg) {
        Write-Log "  [REGISTRY] Camera config found: $camReg" "WARNING"
        $camProps = Get-ItemProperty $camReg -ErrorAction SilentlyContinue
        $camProps.PSObject.Properties | Where-Object {
            $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
        } | ForEach-Object {
            Write-Log "    $($_.Name) = $($_.Value)" "VERBOSE"
            if ($_.Name -match "path|dir|folder|location|archive|backup|image") {
                $cameraPaths += $_.Value
            }
        }
    }
}

foreach ($camPath in ($cameraPaths | Select-Object -Unique)) {
    if (Test-Path $camPath) {
        Write-Log "  [FOUND] Camera/surveillance directory: $camPath" "WARNING"

        $camFiles = Get-ChildItem -Path $camPath -Recurse -ErrorAction SilentlyContinue
        $camCount = ($camFiles | Measure-Object).Count
        $camSize  = ($camFiles | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        Write-Log "    Files: $camCount  |  Total Size: $([math]::Round($camSize/1MB, 2)) MB" "INFO"

        # Check ACLs
        try {
            $acl = Get-Acl $camPath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users") {
                    Write-Log "    [INSECURE ACL] $($ace.IdentityReference) has $($ace.FileSystemRights)" "CRITICAL"
                }
            }
        } catch { }

        # Check for unencrypted images
        $imgFiles = $camFiles | Where-Object { $_.Extension -match "\.jpg$|\.jpeg$|\.png$|\.bmp$|\.tif$|\.avi$|\.mp4$" }
        $imgCount = ($imgFiles | Measure-Object).Count
        if ($imgCount -gt 0) {
            Write-Log "    [UNENCRYPTED] $imgCount image/video files accessible in plaintext" "CRITICAL"
            $imgFiles | Select-Object -First 5 | ForEach-Object {
                Write-Log "      $($_.FullName) ($([math]::Round($_.Length/1KB)) KB, $($_.LastWriteTime))" "VERBOSE"
            }
        }
    }
}

# Check for network shares exposing eJournal/Camera
Write-SubBanner "Network Shares Exposing Sensitive Data"

$shares = Get-SmbShare -ErrorAction SilentlyContinue
foreach ($share in $shares) {
    if ($share.Path -match "journal|camera|surveillance|image|backup|NCR") {
        Write-Log "  [SHARE] $($share.Name) → $($share.Path) (Description: $($share.Description))" "CRITICAL"
        $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        foreach ($sa in $shareAccess) {
            Write-Log "    $($sa.AccountName) : $($sa.AccessControlType) $($sa.AccessRight)" "WARNING"
        }
    }
}

# ============================================================
#  PHASE 7 : RADMIN HASH EXTRACTION
# ============================================================

Write-Banner "PHASE 7 : RADMIN SERVER HASH EXTRACTION"

Write-SubBanner "Radmin Registry Enumeration"

$radminPaths = @(
    "HKLM:\SOFTWARE\Radmin",
    "HKLM:\SOFTWARE\WOW6432Node\Radmin",
    "HKLM:\SOFTWARE\Radmin\v3.0",
    "HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0",
    "HKLM:\SOFTWARE\Radmin\v3.0\Server",
    "HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0\Server",
    "HKLM:\SOFTWARE\Radmin\v3.0\Server\Parameters",
    "HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters",
    "HKLM:\SOFTWARE\Radmin\v3.0\Server\Parameters\Radmin Security",
    "HKLM:\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security"
)

$radminFound = $false
$radminRootKeys = @()

foreach ($rPath in $radminPaths) {
    if (Test-Path $rPath) {
        $radminFound = $true
        Write-Log "  [FOUND] $rPath" "WARNING"

        # Enumerate all values
        try {
            $props = Get-ItemProperty $rPath -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object {
                $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
            } | ForEach-Object {
                if ($_.Value -is [byte[]]) {
                    Write-Log "    $($_.Name) = [Binary Data, $($_.Value.Length) bytes]" "WARNING"
                    # Hex dump first 64 bytes
                    $hexDump = ($_.Value | Select-Object -First 64 | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                    Write-Log "    Hex: $hexDump" "VERBOSE"
                } else {
                    Write-Log "    $($_.Name) = $($_.Value)" "VERBOSE"
                }
            }
        } catch { }

        # Enumerate sub-keys (user accounts)
        try {
            $subKeys = Get-ChildItem $rPath -ErrorAction SilentlyContinue
            foreach ($sk in $subKeys) {
                Write-Log "  [SUBKEY] $($sk.PSPath)" "WARNING"
                $radminRootKeys += $sk.PSPath
                try {
                    $skProps = Get-ItemProperty $sk.PSPath -ErrorAction SilentlyContinue
                    $skProps.PSObject.Properties | Where-Object {
                        $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
                    } | ForEach-Object {
                        if ($_.Value -is [byte[]]) {
                            Write-Log "    $($_.Name) = [Binary, $($_.Value.Length) bytes]" "WARNING"

                            # Parse TLV structure for Radmin SRP hashes
                            $data = $_.Value
                            Write-Log "    --- TLV Parse Attempt ---" "VERBOSE"
                            $offset = 0
                            while ($offset -lt $data.Length - 4) {
                                try {
                                    $tlvType = [BitConverter]::ToUInt16($data, $offset)
                                    $tlvLen  = [BitConverter]::ToUInt16($data, $offset + 2)
                                    $tlvData = $data[($offset+4)..($offset+3+$tlvLen)]
                                    $tlvHex  = ($tlvData | Select-Object -First 48 | ForEach-Object { "{0:X2}" -f $_ }) -join " "

                                    switch ($tlvType) {
                                        16 {
                                            $username = [System.Text.Encoding]::Unicode.GetString($tlvData) -replace '\x00$',''
                                            Write-Log "    TLV Type 16 (Username) : $username" "CRITICAL"
                                        }
                                        48 {
                                            Write-Log "    TLV Type 48 (Modulus)  : [${tlvLen} bytes] $tlvHex..." "WARNING"
                                        }
                                        64 {
                                            $gen = if ($tlvLen -le 8) { [BitConverter]::ToUInt32($tlvData, 0) } else { "?" }
                                            Write-Log "    TLV Type 64 (Generator): $gen" "WARNING"
                                        }
                                        80 {
                                            Write-Log "    TLV Type 80 (Salt)     : [${tlvLen} bytes] $tlvHex" "CRITICAL"
                                        }
                                        96 {
                                            Write-Log "    TLV Type 96 (Verifier) : [${tlvLen} bytes] $tlvHex..." "CRITICAL"
                                        }
                                        default {
                                            Write-Log "    TLV Type $tlvType       : [${tlvLen} bytes]" "VERBOSE"
                                        }
                                    }

                                    $offset += 4 + $tlvLen
                                } catch {
                                    break
                                }
                            }
                        } else {
                            Write-Log "    $($_.Name) = $($_.Value)" "VERBOSE"
                        }
                    }
                } catch { }
            }
        } catch { }
    }
}

# Export all Radmin registry keys to .reg file
Write-SubBanner "Radmin Registry Export (.reg)"

if ($radminFound) {
    Write-Log "  Exporting Radmin registry hive to: $RadminReg" "INFO"

    $regExportPaths = @(
        "HKLM\SOFTWARE\Radmin",
        "HKLM\SOFTWARE\WOW6432Node\Radmin"
    )

    # Initialize .reg file
    Set-Content -Path $RadminReg -Value "Windows Registry Editor Version 5.00`r`n"
    Add-Content -Path $RadminReg -Value "; Amr's ATM Automate Script - Radmin Hash Export"
    Add-Content -Path $RadminReg -Value "; Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path $RadminReg -Value "; Host: $env:COMPUTERNAME"
    Add-Content -Path $RadminReg -Value ""

    foreach ($exportPath in $regExportPaths) {
        try {
            $tempReg = Join-Path $env:TEMP "radmin_export_$(Get-Random).reg"
            $regExport = & reg export $exportPath $tempReg /y 2>&1

            if (Test-Path $tempReg) {
                $exportContent = Get-Content $tempReg -Raw -ErrorAction SilentlyContinue
                # Strip the header from subsequent exports
                $exportContent = $exportContent -replace "Windows Registry Editor Version 5\.00\r?\n",""
                Add-Content -Path $RadminReg -Value $exportContent
                Remove-Item $tempReg -Force -ErrorAction SilentlyContinue
                Write-Log "  [EXPORTED] $exportPath" "SUCCESS"
            } else {
                Write-Log "  [SKIPPED] $exportPath (not found or access denied)" "VERBOSE"
            }
        } catch {
            Write-Log "  [ERROR] Failed to export $exportPath : $_" "WARNING"
        }
    }

    Write-Log "  Radmin .reg export saved to: $RadminReg" "SUCCESS"
} else {
    Write-Log "  Radmin Server not detected on this system" "INFO"
    Write-Log "  (Checked both HKLM\\SOFTWARE\\Radmin and WOW6432Node)" "VERBOSE"
}

# ============================================================
#  PHASE 8 : XFS MIDDLEWARE ENUMERATION
# ============================================================

Write-Banner "PHASE 8 : XFS MIDDLEWARE ENUMERATION & TESTING"

Write-SubBanner "XFS Installation Detection"

# Check for msxfs.dll
$xfsDllPaths = @(
    "$env:SystemRoot\System32\msxfs.dll",
    "$env:SystemRoot\SysWOW64\msxfs.dll",
    "C:\Program Files\Common Files\XFS\msxfs.dll",
    "C:\WOSA\XFS\msxfs.dll"
)

$xfsDllPath = $null
foreach ($dp in $xfsDllPaths) {
    if (Test-Path $dp) {
        $xfsDllPath = $dp
        $dllInfo = Get-Item $dp
        Write-Log "  [FOUND] msxfs.dll at: $dp" "SUCCESS"
        Write-Log "    Size: $($dllInfo.Length) bytes | Modified: $($dllInfo.LastWriteTime)" "VERBOSE"
        break
    }
}

if (-not $xfsDllPath) {
    Write-Log "  [NOT FOUND] msxfs.dll — XFS middleware may not be installed or uses a custom path" "WARNING"
    Write-Log "  Searching entire system for msxfs.dll..." "VERBOSE"
    $foundDll = Get-ChildItem -Path C:\ -Filter "msxfs.dll" -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 1
    if ($foundDll) {
        $xfsDllPath = $foundDll.FullName
        Write-Log "  [FOUND] msxfs.dll at: $xfsDllPath" "SUCCESS"
    }
}

# XFS Registry enumeration
Write-SubBanner "XFS Registry Configuration"

$xfsRegPaths = @(
    "HKLM:\SOFTWARE\XFS",
    "HKLM:\SOFTWARE\WOW6432Node\XFS"
)

foreach ($xfsReg in $xfsRegPaths) {
    if (Test-Path $xfsReg) {
        Write-Log "  [FOUND] XFS Registry root: $xfsReg" "SUCCESS"

        # Recurse through all XFS registry keys
        function Enumerate-RegKey {
            param([string]$Path, [int]$Depth = 0)
            $indent = "  " + ("  " * $Depth)

            try {
                $props = Get-ItemProperty $Path -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSProvider"
                } | ForEach-Object {
                    $val = if ($_.Value -is [byte[]]) { "[Binary, $($_.Value.Length) bytes]" } else { $_.Value }
                    Write-Log "${indent}$($_.Name) = $val" "VERBOSE"
                }
            } catch { }

            try {
                Get-ChildItem $Path -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Log "${indent}[$($_.PSChildName)]" "INFO"
                    if ($Depth -lt 5) {
                        Enumerate-RegKey -Path $_.PSPath -Depth ($Depth + 1)
                    }
                }
            } catch { }
        }

        Enumerate-RegKey -Path $xfsReg
    }
}

# List XFS Service Providers
Write-SubBanner "XFS Service Providers Enumeration"

$spPaths = @(
    "HKLM:\SOFTWARE\XFS\SERVICE_PROVIDERS",
    "HKLM:\SOFTWARE\WOW6432Node\XFS\SERVICE_PROVIDERS"
)

$serviceProviders = @()

foreach ($spPath in $spPaths) {
    if (Test-Path $spPath) {
        Get-ChildItem $spPath -ErrorAction SilentlyContinue | ForEach-Object {
            $spName = $_.PSChildName
            $spProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $dllPath = $spProps.'(default)' + $spProps.dllname
            $spClass = $spProps.class

            $serviceProviders += @{
                Name    = $spName
                DLL     = $spProps.dllname
                Class   = $spClass
                Path    = $_.PSPath
            }

            Write-Log "  [SP] $spName" "SUCCESS"
            Write-Log "       Class: $spClass | DLL: $($spProps.dllname)" "VERBOSE"
        }
    }
}

# List logical services
Write-SubBanner "XFS Logical Services"

$lsPaths = @(
    "HKLM:\SOFTWARE\XFS\LOGICAL_SERVICES",
    "HKLM:\SOFTWARE\WOW6432Node\XFS\LOGICAL_SERVICES"
)

$logicalServices = @()

foreach ($lsPath in $lsPaths) {
    if (Test-Path $lsPath) {
        Get-ChildItem $lsPath -ErrorAction SilentlyContinue | ForEach-Object {
            $lsName = $_.PSChildName
            $lsProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $provider = $lsProps.provider
            $lsClass  = $lsProps.class

            $logicalServices += @{
                Name     = $lsName
                Provider = $provider
                Class    = $lsClass
            }

            $classLabel = switch ([int]$lsClass) {
                1  { "PTR (Printer)" }
                2  { "IDC (Card Reader)" }
                3  { "CDM (Cash Dispenser)" }
                4  { "PIN (PIN Pad / EPP)" }
                5  { "CHK (Check Reader)" }
                6  { "DEP (Depository)" }
                7  { "TTU (Text Terminal Unit)" }
                8  { "SIU (Sensors & Indicators)" }
                9  { "VDM (Vendor Dependent)" }
                10 { "CAM (Camera)" }
                11 { "ALM (Alarm)" }
                13 { "CIM (Cash-In Module)" }
                14 { "CRD (Card Dispenser)" }
                15 { "BCR (Barcode Reader)" }
                16 { "IPM (Item Processing)" }
                default { "Unknown ($lsClass)" }
            }

            Write-Log "  [LS] $lsName → Provider: $provider → Class: $classLabel" "SUCCESS"

            # Identify CDM services for dispense testing
            if ([int]$lsClass -eq 3) {
                Write-Log "       *** CASH DISPENSER MODULE DETECTED ***" "CRITICAL"
            }
            if ([int]$lsClass -eq 4) {
                Write-Log "       *** PIN PAD / EPP DETECTED ***" "WARNING"
            }
        }
    }
}

# ============================================================
#  PHASE 9 : XFS DIRECT API INTERACTION (P/Invoke)
# ============================================================

Write-Banner "PHASE 9 : XFS API DIRECT INTERACTION"

if ($xfsDllPath) {

    Write-Log "  Attempting XFS API P/Invoke via msxfs.dll..." "INFO"
    Write-Log "  DLL Path: $xfsDllPath" "VERBOSE"

$xfsTypeCode = @"
using System;
using System.Runtime.InteropServices;

public class XfsApi
{
    // --- Constants ---
    public const int WFS_SUCCESS                 = 0;
    public const int WFS_INDEFINITE_WAIT         = 0;
    public const int WFS_SERVICE_CLASS_CDM        = 3;
    public const int CDM_SERVICE_OFFSET           = 300;

    // Info Commands
    public const int WFS_INF_CDM_STATUS           = 301;
    public const int WFS_INF_CDM_CAPABILITIES     = 302;
    public const int WFS_INF_CDM_CASH_UNIT_INFO   = 303;
    public const int WFS_INF_CDM_CURRENCY_EXP     = 306;
    public const int WFS_INF_CDM_MIX_TYPES        = 307;

    // Execute Commands
    public const int WFS_CMD_CDM_DISPENSE         = 302;
    public const int WFS_CMD_CDM_PRESENT          = 303;
    public const int WFS_CMD_CDM_REJECT           = 304;
    public const int WFS_CMD_CDM_RESET            = 321;

    // Device States
    public const int WFS_STAT_DEVONLINE           = 0;
    public const int WFS_STAT_DEVOFFLINE          = 1;
    public const int WFS_STAT_DEVPOWEROFF         = 2;
    public const int WFS_STAT_DEVNODEVICE         = 3;
    public const int WFS_STAT_DEVHWERROR          = 4;
    public const int WFS_STAT_DEVBUSY             = 6;

    // --- Structures ---
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct WFSVERSION
    {
        public ushort wVersion;
        public ushort wLowVersion;
        public ushort wHighVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szSystemStatus;
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
    }

    // --- API Imports ---
    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSStartUp(uint dwVersionsRequired, ref WFSVERSION lpWFSVersion);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSOpen(
        string lpszLogicalName, IntPtr hApp, string lpszAppID,
        uint dwTraceLevel, uint dwTimeOut, uint dwSrvcVersionsRequired,
        ref WFSVERSION lpSrvcVersion, ref WFSVERSION lpSPIVersion,
        ref ushort lphService);

    [DllImport("msxfs.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public static extern int WFSGetInfo(
        ushort hService, uint dwCategory, IntPtr lpQueryDetails,
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

    // --- Helper to decode device state ---
    public static string DeviceStateToString(ushort state)
    {
        switch (state)
        {
            case 0: return "ONLINE";
            case 1: return "OFFLINE";
            case 2: return "POWEROFF";
            case 3: return "NODEVICE";
            case 4: return "HWERROR";
            case 5: return "USERERROR";
            case 6: return "BUSY";
            case 7: return "FRAUDATTEMPT";
            default: return "UNKNOWN(" + state + ")";
        }
    }
}
"@

    try {
        Add-Type -TypeDefinition $xfsTypeCode -ErrorAction Stop
        Write-Log "  [OK] XFS P/Invoke types compiled successfully" "SUCCESS"
    } catch {
        Write-Log "  [ERROR] Failed to compile XFS types: $_" "WARNING"
        Write-Log "  XFS API interaction will be skipped" "WARNING"
    }

    # Attempt XFS Startup
    if ([Type]::GetType("XfsApi")) {

        Write-SubBanner "XFS API Startup"

        $wfsVersion = New-Object XfsApi+WFSVERSION
        $versionRequired = [uint32]0x00000A03  # v3.10

        $hr = [XfsApi]::WFSStartUp($versionRequired, [ref]$wfsVersion)

        if ($hr -eq 0) {
            Write-Log "  [SUCCESS] WFSStartUp returned OK (HRESULT=0)" "SUCCESS"
            Write-Log "    XFS Manager Version : $($wfsVersion.wVersion)" "VERBOSE"
            Write-Log "    Low Version         : $($wfsVersion.wLowVersion)" "VERBOSE"
            Write-Log "    High Version        : $($wfsVersion.wHighVersion)" "VERBOSE"
            Write-Log "    Description         : $($wfsVersion.szDescription)" "VERBOSE"
            Write-Log "    System Status       : $($wfsVersion.szSystemStatus)" "VERBOSE"

            # Iterate through discovered logical services and query each
            Write-SubBanner "XFS Service Provider Queries"

            foreach ($ls in $logicalServices) {
                $lsName = $ls.Name

                Write-Log "`n  --- Querying service: $lsName (Class $($ls.Class)) ---" "INFO"

                $svcVersion = New-Object XfsApi+WFSVERSION
                $spiVersion = New-Object XfsApi+WFSVERSION
                [ushort]$hService = 0

                $hrOpen = [XfsApi]::WFSOpen(
                    $lsName,
                    [IntPtr]::Zero,
                    "AmrATMPentest",
                    0,
                    10000,
                    $versionRequired,
                    [ref]$svcVersion,
                    [ref]$spiVersion,
                    [ref]$hService
                )

                if ($hrOpen -eq 0) {
                    Write-Log "  [OPENED] $lsName → handle $hService" "SUCCESS"
                    Write-Log "    SP Version  : $($svcVersion.wVersion)" "VERBOSE"
                    Write-Log "    SP Desc     : $($svcVersion.szDescription)" "VERBOSE"
                    Write-Log "    SPI Version : $($spiVersion.wVersion)" "VERBOSE"

                    # Query STATUS for all service types
                    $pResult = [IntPtr]::Zero
                    $classOffset = [int]$ls.Class * 100

                    $statusCmd = $classOffset + 1  # STATUS is always offset + 1

                    $hrInfo = [XfsApi]::WFSGetInfo($hService, $statusCmd, [IntPtr]::Zero, 10000, [ref]$pResult)

                    if ($hrInfo -eq 0 -and $pResult -ne [IntPtr]::Zero) {
                        Write-Log "  [STATUS] Query returned OK" "SUCCESS"
                        $result = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pResult, [Type][XfsApi+WFSRESULT])

                        if ($result.lpBuffer -ne [IntPtr]::Zero) {
                            # If CDM (class 3), parse WFSCDMSTATUS
                            if ([int]$ls.Class -eq 3) {
                                try {
                                    $cdmStatus = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                                        $result.lpBuffer, [Type][XfsApi+WFSCDMSTATUS])
                                    Write-Log "    Device State    : $([XfsApi]::DeviceStateToString($cdmStatus.fwDevice))" $(if($cdmStatus.fwDevice -eq 0){"SUCCESS"}else{"WARNING"})
                                    Write-Log "    Safe Door       : $($cdmStatus.fwSafeDoor)" "VERBOSE"
                                    Write-Log "    Dispenser       : $($cdmStatus.fwDispenser)" "VERBOSE"
                                    Write-Log "    Stacker         : $($cdmStatus.fwIntermediateStacker)" "VERBOSE"
                                } catch {
                                    Write-Log "    (Could not parse CDM status struct: $_)" "VERBOSE"
                                }
                            } else {
                                Write-Log "    (Raw buffer available — non-CDM class, generic status retrieved)" "VERBOSE"
                            }
                        }
                        [XfsApi]::WFSFreeResult($pResult) | Out-Null
                    } else {
                        Write-Log "  [STATUS] Query failed or returned null (HRESULT=$hrInfo)" "WARNING"
                    }

                    # Query CAPABILITIES for CDM services
                    if ([int]$ls.Class -eq 3) {
                        $capsCmd = [XfsApi]::WFS_INF_CDM_CAPABILITIES
                        $pResult2 = [IntPtr]::Zero

                        $hrCaps = [XfsApi]::WFSGetInfo($hService, $capsCmd, [IntPtr]::Zero, 10000, [ref]$pResult2)

                        if ($hrCaps -eq 0 -and $pResult2 -ne [IntPtr]::Zero) {
                            Write-Log "  [CAPS] CDM Capabilities query returned OK" "SUCCESS"
                            $capResult = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pResult2, [Type][XfsApi+WFSRESULT])
                            if ($capResult.lpBuffer -ne [IntPtr]::Zero) {
                                try {
                                    $cdmCaps = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                                        $capResult.lpBuffer, [Type][XfsApi+WFSCDMCAPS])
                                    Write-Log "    Device Class       : $($cdmCaps.wClass)" "VERBOSE"
                                    Write-Log "    Type               : $($cdmCaps.fwType)" "VERBOSE"
                                    Write-Log "    Max Dispense Items : $($cdmCaps.wMaxDispenseItems)" "WARNING"
                                    Write-Log "    Compound           : $($cdmCaps.bCompound)" "VERBOSE"
                                    Write-Log "    Shutter            : $($cdmCaps.bShutter)" "VERBOSE"
                                    Write-Log "    Shutter Control    : $($cdmCaps.bShutterControl)" "VERBOSE"
                                    Write-Log "    Safe Door          : $($cdmCaps.bSafeDoor)" "VERBOSE"
                                    Write-Log "    Cash Box           : $($cdmCaps.bCashBox)" "VERBOSE"
                                    Write-Log "    Intermediate Stack : $($cdmCaps.bIntermediateStacker)" "VERBOSE"
                                    Write-Log "    Items Taken Sensor : $($cdmCaps.bItemsTakenSensor)" "VERBOSE"
                                    Write-Log "    Positions          : $($cdmCaps.fwPositions)" "VERBOSE"
                                    Write-Log "    Exchange Type      : $($cdmCaps.fwExchangeType)" "VERBOSE"
                                } catch {
                                    Write-Log "    (Could not parse CDM caps struct: $_)" "VERBOSE"
                                }
                            }
                            [XfsApi]::WFSFreeResult($pResult2) | Out-Null
                        } else {
                            Write-Log "  [CAPS] CDM Capabilities query failed (HRESULT=$hrCaps)" "WARNING"
                        }

                        # Query CASH_UNIT_INFO
                        $cashUnitCmd = [XfsApi]::WFS_INF_CDM_CASH_UNIT_INFO
                        $pResult3 = [IntPtr]::Zero

                        $hrCU = [XfsApi]::WFSGetInfo($hService, $cashUnitCmd, [IntPtr]::Zero, 10000, [ref]$pResult3)
                        if ($hrCU -eq 0) {
                            Write-Log "  [CASH UNITS] Cash unit info query returned OK" "SUCCESS"
                            Write-Log "    (Raw data available — parse WFSCDMCASHUNITINFO for cassette details)" "VERBOSE"
                        } else {
                            Write-Log "  [CASH UNITS] Query failed (HRESULT=$hrCU)" "WARNING"
                        }
                        if ($pResult3 -ne [IntPtr]::Zero) { [XfsApi]::WFSFreeResult($pResult3) | Out-Null }

                        # Query MIX_TYPES
                        $mixCmd = [XfsApi]::WFS_INF_CDM_MIX_TYPES
                        $pResult4 = [IntPtr]::Zero

                        $hrMix = [XfsApi]::WFSGetInfo($hService, $mixCmd, [IntPtr]::Zero, 10000, [ref]$pResult4)
                        if ($hrMix -eq 0) {
                            Write-Log "  [MIX TYPES] Currency mix algorithms query returned OK" "SUCCESS"
                            Write-Log "    (Raw data available — parse WFSCDMMIXTYPE array for mix algorithm names)" "VERBOSE"
                        } else {
                            Write-Log "  [MIX TYPES] Query failed (HRESULT=$hrMix)" "WARNING"
                        }
                        if ($pResult4 -ne [IntPtr]::Zero) { [XfsApi]::WFSFreeResult($pResult4) | Out-Null }

                        # Query CURRENCY_EXP
                        $currCmd = [XfsApi]::WFS_INF_CDM_CURRENCY_EXP
                        $pResult5 = [IntPtr]::Zero

                        $hrCurr = [XfsApi]::WFSGetInfo($hService, $currCmd, [IntPtr]::Zero, 10000, [ref]$pResult5)
                        if ($hrCurr -eq 0) {
                            Write-Log "  [CURRENCY] Currency exponent query returned OK" "SUCCESS"
                        } else {
                            Write-Log "  [CURRENCY] Query failed (HRESULT=$hrCurr)" "WARNING"
                        }
                        if ($pResult5 -ne [IntPtr]::Zero) { [XfsApi]::WFSFreeResult($pResult5) | Out-Null }
                    }

                    # Close the service
                    $hrClose = [XfsApi]::WFSClose($hService)
                    Write-Log "  [CLOSED] $lsName (HRESULT=$hrClose)" "VERBOSE"

                } else {
                    Write-Log "  [FAILED] Could not open $lsName (HRESULT=$hrOpen)" "WARNING"
                    # Decode common errors
                    $errMsg = switch ($hrOpen) {
                        -1  { "INVALID_HSERVICE" }
                        -2  { "ALREADY_STARTED" }
                        -15 { "INTERNAL_ERROR" }
                        -16 { "INVALID_ADDRESS" }
                        -20 { "INVALID_COMMAND" }
                        -26 { "NO_SUCH_DEVICE / DEVICE_NOT_FOUND" }
                        -29 { "OP_IN_PROGRESS" }
                        -37 { "SOFTWARE_ERROR" }
                        -38 { "SP_ERROR" }
                        -48 { "TIMEOUT" }
                        default { "Unknown error code" }
                    }
                    Write-Log "    Error: $errMsg" "VERBOSE"
                }
            }

            # Clean up XFS
            $hrCleanup = [XfsApi]::WFSCleanUp()
            Write-Log "`n  WFSCleanUp returned: $hrCleanup" "VERBOSE"

        } else {
            Write-Log "  [FAILED] WFSStartUp failed (HRESULT=$hr)" "WARNING"
            Write-Log "  The XFS Manager may not be running or is not accessible" "VERBOSE"

            # Check if XFS Manager service is running
            $xfsSvc = Get-Service -Name "XFS*" -ErrorAction SilentlyContinue
            if ($xfsSvc) {
                foreach ($s in $xfsSvc) {
                    Write-Log "  XFS Service: $($s.Name) → Status: $($s.Status)" $(if($s.Status -eq "Running"){"SUCCESS"}else{"WARNING"})
                }
            }
        }
    }
} else {
    Write-Log "  msxfs.dll not found — skipping XFS API interaction" "WARNING"
    Write-Log "  XFS registry enumeration was completed in Phase 8" "INFO"
}

# ============================================================
#  PHASE 10 : ADDITIONAL SECURITY CHECKS
# ============================================================

Write-Banner "PHASE 10 : ADDITIONAL SECURITY CHECKS"

Write-SubBanner "Security Software Status"

$secSoftware = @(
    @{ Name="McAfee Solidcore"; Service="scsrvc" },
    @{ Name="McAfee Agent"; Service="masvc" },
    @{ Name="McAfee VirusScan"; Service="McShield" },
    @{ Name="Windows Defender"; Service="WinDefend" },
    @{ Name="Windows Firewall"; Service="mpssvc" },
    @{ Name="Symantec EP"; Service="SepMasterService" },
    @{ Name="Phoenix Vista ATM"; Service="VistaATM" },
    @{ Name="Radmin Server"; Service="RServer3" },
    @{ Name="RDP TermService"; Service="TermService" },
    @{ Name="VNC Server"; Service="vncserver" }
)

foreach ($sw in $secSoftware) {
    $svc = Get-Service -Name $sw.Service -ErrorAction SilentlyContinue
    if ($svc) {
        $severity = if ($svc.Status -eq "Running") {
            if ($sw.Name -match "Radmin|RDP|VNC") { "WARNING" } else { "SUCCESS" }
        } else { "WARNING" }
        Write-Log ("  {0,-25} : {1} (Start: {2})" -f $sw.Name, $svc.Status, $svc.StartType) $severity
    } else {
        Write-Log ("  {0,-25} : Not Installed" -f $sw.Name) "VERBOSE"
    }
}

Write-SubBanner "McAfee Solidcore (Application Whitelisting) Detail"

$solidcoreCheck = Get-Command "sadmin" -ErrorAction SilentlyContinue
if ($solidcoreCheck) {
    Write-Log "  sadmin found — querying Solidcore status..." "INFO"
    try {
        $sadminStatus = & sadmin status 2>&1
        foreach ($line in $sadminStatus) { Write-Log "    $line" "VERBOSE" }
    } catch {
        Write-Log "  sadmin execution failed: $_" "WARNING"
    }
} else {
    Write-Log "  sadmin not in PATH — Solidcore may not be installed or is in a custom location" "VERBOSE"
}

Write-SubBanner "PowerShell Language Mode"

$langMode = $ExecutionContext.SessionState.LanguageMode
Write-Log "  PowerShell Language Mode: $langMode" $(if($langMode -eq "FullLanguage"){"CRITICAL"}else{"INFO"})
if ($langMode -eq "FullLanguage") {
    Write-Log "  *** FullLanguage mode — reflective DLL loading and Win32 API calls are possible ***" "CRITICAL"
} elseif ($langMode -eq "ConstrainedLanguage") {
    Write-Log "  ConstrainedLanguage mode — blocks Add-Type, [System.Runtime], and Win32 API" "SUCCESS"
}

Write-SubBanner "RDP Configuration"

$rdpReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
if (Test-Path $rdpReg) {
    $rdpDisabled = (Get-ItemProperty $rdpReg -ErrorAction SilentlyContinue).fDenyTSConnections
    Write-Log "  RDP fDenyTSConnections: $rdpDisabled" $(if($rdpDisabled -eq 0){"CRITICAL"}else{"SUCCESS"})
    if ($rdpDisabled -eq 0) {
        Write-Log "  *** RDP IS ENABLED — remote access to ATM is possible ***" "CRITICAL"
    }

    # NLA check
    $nlaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $nlaReg) {
        $nla = (Get-ItemProperty $nlaReg -ErrorAction SilentlyContinue).UserAuthentication
        Write-Log "  NLA (Network Level Auth): $nla" $(if($nla -eq 1){"SUCCESS"}else{"WARNING"})
    }
}

Write-SubBanner "Firewall Status"

try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($fw in $fwProfiles) {
        Write-Log ("  {0,-12} Firewall: Enabled={1}" -f $fw.Name, $fw.Enabled) $(if($fw.Enabled){"SUCCESS"}else{"CRITICAL"})
    }
} catch {
    Write-Log "  Could not query firewall status" "VERBOSE"
}

Write-SubBanner "Listening Ports"

try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess

    foreach ($l in $listeners) {
        $procName = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        Write-Log ("  {0}:{1} → PID {2} ({3})" -f $l.LocalAddress, $l.LocalPort, $l.OwningProcess, $procName) "VERBOSE"
    }
} catch {
    # Fallback
    $netstat = netstat -ano | Select-String "LISTENING"
    foreach ($line in $netstat) { Write-Log "  $($line.Line.Trim())" "VERBOSE" }
}

# ============================================================
#  COMPLETION
# ============================================================

Write-Banner "SCAN COMPLETE"

$summary = @"

  Output Directory  : $OutputDir
  Results Log       : $LogFile
  Radmin .reg Export : $RadminReg
  Scan Completed    : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

  Review the log file for all findings.
  Findings marked [CRITICAL] require immediate attention in your report.

"@

Write-Host $summary -ForegroundColor Green
Add-Content -Path $LogFile -Value $summary

Write-Log "=== Amr's ATM Automate Script completed ===" "SUCCESS"
