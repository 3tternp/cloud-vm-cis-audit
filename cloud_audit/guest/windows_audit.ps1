# READ-ONLY Windows guest audit. Makes no changes to the system.
# Output protocol: one line per check ->  CIS|<id>|<PASS|FAIL|WARN|INFO>|<detail>
$ErrorActionPreference = 'SilentlyContinue'
function Emit($id, $status, $detail) { Write-Output ("CIS|{0}|{1}|{2}" -f $id, $status, $detail) }

# Firewall profiles
$fw = Get-NetFirewallProfile
if ($fw) {
  $off = ($fw | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }) -join ','
  if ($off) { Emit 'WIN-001' 'FAIL' "firewall disabled for: $off" } else { Emit 'WIN-001' 'PASS' 'all firewall profiles enabled' }
} else { Emit 'WIN-001' 'INFO' 'firewall state not readable' }

# SMBv1
$smb = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($null -eq $smb) { Emit 'WIN-002' 'INFO' 'SMB1 state not readable' }
elseif ($smb) { Emit 'WIN-002' 'FAIL' 'SMBv1 server enabled' } else { Emit 'WIN-002' 'PASS' 'SMBv1 server disabled' }

# Defender real-time protection
$mp = Get-MpComputerStatus
if ($mp) { if ($mp.RealTimeProtectionEnabled) { Emit 'WIN-003' 'PASS' 'real-time protection on' } else { Emit 'WIN-003' 'WARN' 'real-time protection off (ok if another EDR is deployed)' } }
else { Emit 'WIN-003' 'INFO' 'Defender status not readable' }

# RDP Network Level Authentication
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
if ($nla -eq 1) { Emit 'WIN-004' 'PASS' 'NLA required for RDP' } elseif ($null -eq $nla) { Emit 'WIN-004' 'INFO' 'NLA not readable' } else { Emit 'WIN-004' 'FAIL' 'NLA not required for RDP' }

# UAC
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
if ($uac -eq 1) { Emit 'WIN-005' 'PASS' 'UAC enabled' } else { Emit 'WIN-005' 'FAIL' "EnableLUA=$uac" }

# Built-in Guest account
$g = Get-LocalUser -Name Guest
if ($g) { if ($g.Enabled) { Emit 'WIN-006' 'FAIL' 'Guest account enabled' } else { Emit 'WIN-006' 'PASS' 'Guest account disabled' } }

# Local password and lockout policy
$na = net accounts 2>$null
$min = ($na | Select-String 'Minimum password length' | ForEach-Object { ($_ -split ':')[1].Trim() })
if ($min -match '^\d+$') { if ([int]$min -ge 14) { Emit 'WIN-007' 'PASS' "min password length $min" } else { Emit 'WIN-007' 'WARN' "min password length $min (<14)" } }
$lock = ($na | Select-String 'Lockout threshold' | ForEach-Object { ($_ -split ':')[1].Trim() })
if ($lock -match '^\d+$') { if ([int]$lock -ge 1 -and [int]$lock -le 5) { Emit 'WIN-008' 'PASS' "lockout threshold $lock" } else { Emit 'WIN-008' 'WARN' "lockout threshold $lock (want 1-5)" } }

# Pending reboot
$pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
if ($pend) { Emit 'WIN-010' 'WARN' 'reboot pending to finish updates' } else { Emit 'WIN-010' 'PASS' 'no pending reboot' }

# Last installed update age (patch hygiene)
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $age = [int]((Get-Date) - $hf.InstalledOn).TotalDays
  if ($age -le 45) { Emit 'WIN-011' 'PASS' "latest hotfix $($hf.HotFixID) installed $age days ago" } else { Emit 'WIN-011' 'WARN' "latest hotfix $($hf.HotFixID) installed $age days ago (>45)" } }
else { Emit 'WIN-011' 'INFO' 'no hotfix history readable' }
