#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-shot RDP server setup for a Windows Server (Europe) over Tailscale.

.DESCRIPTION
    - Enables RDP with SecurityLayer=2 (TLS)  -> fixes the classic "RDP refuses TLS" failure
    - Creates an RDP user with a strong password
    - Installs and connects Tailscale
    - Restricts port 3389 to the Tailscale CGNAT range only (100.64.0.0/10)
    - Enables audio services
    - Applies performance tuning
    - Verifies a real TLS handshake before finishing

    Safe by design: the public RDP firewall rules are disabled ONLY after
    Tailscale is confirmed online, so you cannot lock yourself out if the
    Tailscale step fails.

.PARAMETER UserName
    Local account to create/update. Default: RDP

.PARAMETER Password
    Password for the account. If omitted, you are prompted securely.

.PARAMETER TailscaleKey
    Tailscale auth key (tskey-auth-...). If omitted, you are prompted.

.PARAMETER Hostname
    Tailscale machine name. Default: computer name (lowercase).

.PARAMETER EnableNLA
    Require Network Level Authentication (recommended on a public VPS).

.PARAMETER KeepPublicRdpRule
    Keep the default internet-facing RDP firewall rules enabled.

.EXAMPLE
    .\setup-rdp-eu.ps1

.EXAMPLE
    .\setup-rdp-eu.ps1 -UserName RDP -Hostname eu-rdp-01 -EnableNLA
#>
[CmdletBinding()]
param(
    [string]$UserName = 'RDP',
    [string]$Password,
    [string]$TailscaleKey,
    [string]$Hostname,
    [switch]$EnableNLA,
    [switch]$KeepPublicRdpRule
)

$ErrorActionPreference = 'Stop'

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }

# --- 0) admin check ---------------------------------------------------
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}

# --- 1) inputs --------------------------------------------------------
Step 'Inputs'

if (-not $Password) {
    do {
        $s1 = Read-Host -AsSecureString 'New password for the RDP user'
        $s2 = Read-Host -AsSecureString 'Confirm password'
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
        if ($p1 -ne $p2) { Warn 'Passwords do not match.'; $p1 = $null }
    } while (-not $p1)
    $Password = $p1
}

if ($Password -match [regex]::Escape($UserName)) {
    throw "Password contains the username '$UserName' - Windows will reject it. Choose another password."
}
if ($Password.Length -lt 10) {
    throw 'Password is too short - use at least 10 characters.'
}

if (-not $TailscaleKey) {
    $TailscaleKey = Read-Host 'Tailscale auth key (tskey-auth-...)'
}
if ([string]::IsNullOrWhiteSpace($TailscaleKey)) {
    throw 'A Tailscale auth key is required.'
}
if (-not $Hostname) { $Hostname = $env:COMPUTERNAME.ToLower() }

Ok "User=$UserName | Host=$Hostname | NLA=$($EnableNLA.IsPresent)"

# --- 2) RDP settings --------------------------------------------------
Step 'Configuring RDP'
$ts  = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$rdp = "$ts\WinStations\RDP-Tcp"

Set-ItemProperty $ts  -Name 'fDenyTSConnections' -Value 0 -Force
Set-ItemProperty $rdp -Name 'SecurityLayer'      -Value 2 -Force
Set-ItemProperty $rdp -Name 'MinEncryptionLevel' -Value 2 -Force
Set-ItemProperty $rdp -Name 'UserAuthentication' -Value ($(if ($EnableNLA) { 1 } else { 0 })) -Force

Restart-Service TermService -Force
Start-Sleep -Seconds 4

$layer = (Get-ItemProperty $rdp -Name 'SecurityLayer').SecurityLayer
if ($layer -ne 2) { throw "SecurityLayer=$layer (expected 2) - fix failed." }
Ok 'SecurityLayer=2 (TLS) applied'

# --- 3) user ----------------------------------------------------------
Step "Creating user $UserName"
$sec = ConvertTo-SecureString $Password -AsPlainText -Force
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $UserName -Password $sec -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Ok 'User created'
} else {
    Set-LocalUser -Name $UserName -Password $sec
    Ok 'Existing user password updated'
}
Add-LocalGroupMember -Group 'Administrators'       -Member $UserName -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $UserName -ErrorAction SilentlyContinue
Ok 'Added to Administrators and Remote Desktop Users'

# --- 4) firewall: allow from Tailscale range --------------------------
Step 'Firewall (Tailscale range only)'
foreach ($n in 'RDP-Tailscale-TCP','RDP-Tailscale-UDP') {
    Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
New-NetFirewallRule -DisplayName 'RDP-Tailscale-TCP' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 3389 -RemoteAddress '100.64.0.0/10' -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'RDP-Tailscale-UDP' -Direction Inbound -Action Allow `
    -Protocol UDP -LocalPort 3389 -RemoteAddress '100.64.0.0/10' -Profile Any | Out-Null
Ok 'Port 3389 open to Tailscale addresses only'

# --- 5) Tailscale -----------------------------------------------------
Step 'Installing Tailscale'
$tsExe = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
if (-not (Test-Path $tsExe)) {
    $msi = Join-Path $env:TEMP 'tailscale.msi'
    $urls = @(
        'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi',
        'https://pkgs.tailscale.com/stable/tailscale-setup-1.82.0-amd64.msi'
    )
    $downloaded = $false
    foreach ($u in $urls) {
        try {
            Invoke-WebRequest -Uri $u -OutFile $msi -UseBasicParsing -TimeoutSec 120
            $downloaded = $true; break
        } catch { Warn "Download failed: $u" }
    }
    if (-not $downloaded) { throw 'Could not download the Tailscale installer.' }

    Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/quiet', '/norestart' -Wait
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $tsExe)) { throw 'Tailscale installation failed.' }
    Ok 'Installed'
} else { Ok 'Already installed' }

Step 'Connecting Tailscale'
& $tsExe up --authkey=$TailscaleKey --hostname=$Hostname --accept-dns=false
$ip = $null
for ($i = 0; $i -lt 20; $i++) {
    $ip = (& $tsExe ip -4 2>$null)
    if ($ip) { break }
    Start-Sleep -Seconds 3
}
if (-not $ip) { throw 'No Tailscale IP assigned. Check the auth key.' }
Ok "Tailscale IP = $ip"

# --- 6) lock down public RDP only AFTER Tailscale works ---------------
if (-not $KeepPublicRdpRule) {
    Step 'Disabling internet-facing RDP rules'
    Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Ok 'Public RDP rules disabled - reachable via Tailscale only'
}

# --- 7) audio ---------------------------------------------------------
Step 'Enabling audio'
foreach ($s in 'AudioEndpointBuilder','Audiosrv') {
    Set-Service $s -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service $s -ErrorAction SilentlyContinue
}
Ok 'Audio services running'

# --- 8) performance ---------------------------------------------------
Step 'Performance tuning'
powercfg /setactive SCHEME_MIN 2>$null
$hive = 'C:\Users\Default\NTUSER.DAT'
if (Test-Path $hive) {
    reg load 'HKLM\DefUser' $hive | Out-Null
    try {
        reg add 'HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null
        reg add 'HKLM\DefUser\Control Panel\Desktop'               /v MenuShowDelay   /t REG_SZ    /d 0 /f | Out-Null
        reg add 'HKLM\DefUser\Control Panel\Desktop'               /v DragFullWindows /t REG_SZ    /d 0 /f | Out-Null
        reg add 'HKLM\DefUser\Control Panel\Desktop'               /v FontSmoothing   /t REG_SZ    /d 0 /f | Out-Null
        reg add 'HKLM\DefUser\Control Panel\Desktop\WindowMetrics' /v MinAnimate      /t REG_SZ    /d 0 /f | Out-Null
        Ok 'Applied "best performance" to the default profile'
    } finally {
        [gc]::Collect(); Start-Sleep -Seconds 2
        reg unload 'HKLM\DefUser' | Out-Null
    }
}

# --- 9) TLS verification ---------------------------------------------
Step 'Verifying RDP TLS handshake'
try {
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', 3389)
    $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { param($a,$b,$c,$d) $true })
    $ssl.AuthenticateAsClient('localhost')
    Ok "TLS OK: $($ssl.SslProtocol) / $($ssl.CipherAlgorithm)"
    $ssl.Close(); $client.Close()
} catch {
    Warn "TLS test failed: $($_.Exception.Message)"
}

# --- 10) summary ------------------------------------------------------
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  SERVER READY" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Address : $ip"
Write-Host "  User    : $UserName"
Write-Host "  Password: (the one you entered)"
Write-Host "  NLA     : $($EnableNLA.IsPresent)"
Write-Host "  Port    : 3389 (Tailscale only)"
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "`nConnect from your PC:  mstsc /v:$ip" -ForegroundColor Yellow
