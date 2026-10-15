#Requires -Version 7.2
#Requires -Modules VMware.VimAutomation.Core
<#
.SYNOPSIS
    In-place upgrade of Windows Server 2016 VMs to Windows Server 2025 on vSphere.

.DESCRIPTION
    Per VM, sequentially:
      1. Pre-flight (OS build, edition, free disk, pending reboot, DC role, datastore space)
      2. Snapshot (no memory, no quiesce)
      3. Mount the 2025 ISO from a datastore
      4. Compatibility scan (setup.exe /compat scanonly)
      5. Launch the upgrade as a SYSTEM scheduled task (survives WinRM drop / reboots)
      6. Poll until build >= 26100, or detect rollback / timeout
      7. Unmount ISO, optionally set vSphere guest OS type + upgrade VMware Tools
    The snapshot is NOT removed. Delete it yourself after the soak period.

.EXAMPLE
    $g = Get-Credential CORP\svc_upgrade
    .\Invoke-WS2025Upgrade.ps1 -VCenter vcenter.corp.ivcinc.com -VMName APP01,APP02 `
        -ContentLibraryIso 'WS2025_x64' -GuestCredential $g -ScanOnly
    # or: -IsoPath '[DS-ISO] Windows/WS2025_x64.iso'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VCenter,
    [Parameter(Mandatory)][string[]]$VMName,
    [string]$IsoPath,                                    # "[datastore] folder/file.iso"  -- OR --
    [string]$ContentLibraryIso,                          # content library item name, e.g. "WS2025_x64"
    [string]$ContentLibrary,                             # optional: library name, if the item name isn't unique
    [Parameter(Mandatory)][pscredential]$GuestCredential, # local admin on the guests (WinRM)
    [pscredential]$VCenterCredential,
    [switch]$ScanOnly,                                   # stop after the compat scan
    [switch]$SetGuestOsType,                             # power-cycle VM to set 2025 guest ID
    [switch]$AllowDomainControllers,                     # off by default, see notes
    [int]$MinGuestFreeGB = 40,
    [int]$MinDatastoreFreeGB = 60,                       # snapshot delta grows during upgrade
    [int]$UpgradeTimeoutMinutes = 180,
    [string]$GuestId = 'windows2022srvNext_64Guest',     # "Windows Server 2025" on vSphere 8.0U2+; verify on your build
    # KMS client setup keys (GVLK). Replace with MAK/retail if you don't use KMS.
    [hashtable]$ProductKeys = @{
        ServerStandard   = 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'
        ServerDatacenter = 'D764K-2NDRG-47T6Q-P8T8W-YP6DF'
    },
    [string]$LogRoot = (Join-Path $PSScriptRoot 'upgrade-logs')
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
Start-Transcript -Path (Join-Path $LogRoot "run-$(Get-Date -f yyyyMMdd-HHmmss).log") | Out-Null

function Write-Step($vm, $msg) { Write-Host ("[{0:HH:mm:ss}] {1,-15} {2}" -f (Get-Date), $vm, $msg) }

# setup.exe /compat scanonly result codes
$CompatCodes = @{
    'C1900210' = 'OK - no compatibility issues'
    'C1900208' = 'BLOCKED - incompatible app/driver (see compat XML)'
    'C1900204' = 'BLOCKED - migration choice unavailable (edition/install type mismatch)'
    'C1900200' = 'BLOCKED - system does not meet requirements'
    'C190020E' = 'BLOCKED - insufficient disk space'
}

$conn = if ($VCenterCredential) { Connect-VIServer $VCenter -Credential $VCenterCredential }
        else { Connect-VIServer $VCenter }

if (-not ($IsoPath -xor $ContentLibraryIso)) { throw "Specify exactly one of -IsoPath or -ContentLibraryIso" }
$clItem = $null
if ($ContentLibraryIso) {
    $clArgs = @{ Name = $ContentLibraryIso; ItemType = 'iso' }
    if ($ContentLibrary) { $clArgs.ContentLibrary = Get-ContentLibrary -Name $ContentLibrary }
    $clItem = @(Get-ContentLibraryItem @clArgs)
    if ($clItem.Count -ne 1) { throw "Expected 1 content library ISO named '$ContentLibraryIso', found $($clItem.Count). Use -ContentLibrary to narrow it." }
    $clItem = $clItem[0]
    Write-Host "Using content library ISO: $($clItem.Name) (library: $($clItem.ContentLibrary.Name))"
}

$results = foreach ($name in $VMName) {
    $r = [ordered]@{ VM = $name; Status = 'Started'; Detail = '' }
    try {
        $vm = Get-VM -Name $name
        $guestHost = (Get-VMGuest -VM $vm).HostName
        if (-not $guestHost) { $guestHost = $name }
        $so = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 0

        # ---------- 1. Pre-flight ----------
        Write-Step $name "Pre-flight on $guestHost"
        $pre = Invoke-Command -ComputerName $guestHost -Credential $GuestCredential -SessionOption $so -ScriptBlock {
            $os  = Get-CimInstance Win32_OperatingSystem
            $cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                       (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
                       [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue)
            [pscustomobject]@{
                Build            = [int]$os.BuildNumber
                EditionID        = $cv.EditionID
                InstallationType = $cv.InstallationType          # 'Server' or 'Server Core'
                FreeGB           = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
                PendingReboot    = $pending
                DomainRole       = (Get-CimInstance Win32_ComputerSystem).DomainRole  # 4/5 = DC
            }
        }
        if ($pre.Build -ne 14393)                    { throw "Not Server 2016 (build $($pre.Build))" }
        if (-not $ProductKeys[$pre.EditionID])       { throw "No key/unsupported edition: $($pre.EditionID)" }
        if ($pre.FreeGB -lt $MinGuestFreeGB)          { throw "C: free $($pre.FreeGB) GB < $MinGuestFreeGB GB" }
        if ($pre.PendingReboot)                      { throw "Pending reboot - reboot first" }
        if ($pre.DomainRole -ge 4 -and -not $AllowDomainControllers) { throw "Domain controller - skipped" }
        $dsFree = ($vm | Get-Datastore | Measure-Object FreeSpaceGB -Minimum).Minimum
        if ($dsFree -lt $MinDatastoreFreeGB)         { throw "Datastore free $([int]$dsFree) GB < $MinDatastoreFreeGB GB" }
        Write-Step $name "$($pre.EditionID) / $($pre.InstallationType), C: $($pre.FreeGB) GB free"

        # ---------- 2. Snapshot ----------
        if (-not $ScanOnly) {
            $snapName = "pre-WS2025-$(Get-Date -f yyyyMMdd-HHmm)"
            Write-Step $name "Snapshot '$snapName'"
            New-Snapshot -VM $vm -Name $snapName -Memory:$false -Quiesce:$false -Confirm:$false | Out-Null
        }

        # ---------- 3. Mount ISO ----------
        Write-Step $name "Mounting ISO"
        $cd = Get-CDDrive -VM $vm | Select-Object -First 1
        if (-not $cd) { throw "VM has no CD/DVD drive" }
        if ($clItem) {
            Set-CDDrive -CD $cd -ContentLibraryIso $clItem -StartConnected:$true -Connected:$true -Confirm:$false | Out-Null
        } else {
            Set-CDDrive -CD $cd -IsoPath $IsoPath -StartConnected:$true -Connected:$true -Confirm:$false | Out-Null
        }
        Start-Sleep 10

        # ---------- 4. Compat scan + resolve image index ----------
        Write-Step $name "Compatibility scan (10-30 min)"
        $scan = Invoke-Command -ComputerName $guestHost -Credential $GuestCredential -SessionOption $so -ArgumentList $pre -ScriptBlock {
            param($pre)
            $drive = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and
                       (Test-Path "$($_.DriveLetter):\setup.exe") } | Select-Object -First 1
            if (-not $drive) { throw "ISO not visible in guest" }
            $root  = "$($drive.DriveLetter):"
            $wim   = @("$root\sources\install.wim", "$root\sources\install.esd") | Where-Object { Test-Path $_ } | Select-Object -First 1
            $sku   = if ($pre.EditionID -eq 'ServerDatacenter') { 'Datacenter' } else { 'Standard' }
            $img   = Get-WindowsImage -ImagePath $wim | Where-Object {
                         $_.ImageName -match "\b$sku\b" -and $_.ImageName -notmatch 'Azure' -and
                         (($_.ImageName -match 'Desktop Experience') -eq ($pre.InstallationType -eq 'Server'))
                     } | Select-Object -First 1
            if (-not $img) { throw "No matching image for $sku / $($pre.InstallationType)" }

            New-Item C:\WS2025Upgrade -ItemType Directory -Force | Out-Null
            $p = Start-Process "$root\setup.exe" -Wait -PassThru -ArgumentList @(
                '/auto upgrade', "/imageindex $($img.ImageIndex)", '/compat scanonly',
                '/dynamicupdate disable', '/eula accept', '/quiet', '/copylogs C:\WS2025Upgrade\compat')
            [pscustomobject]@{ Root = $root; ImageIndex = $img.ImageIndex; ImageName = $img.ImageName
                               ExitHex = '{0:X8}' -f $p.ExitCode }
        }
        $verdict = $CompatCodes[$scan.ExitHex]; if (-not $verdict) { $verdict = "Unknown 0x$($scan.ExitHex)" }
        Write-Step $name "Target: $($scan.ImageName) (index $($scan.ImageIndex)) -> $verdict"
        if ($scan.ExitHex -ne 'C1900210') { throw "Compat scan: $verdict" }
        if ($ScanOnly) { $r.Status = 'ScanPassed'; $r.Detail = $scan.ImageName; Set-CDDrive -CD $cd -NoMedia -Confirm:$false | Out-Null; continue }

        # ---------- 5. Launch upgrade as SYSTEM scheduled task ----------
        Write-Step $name "Launching upgrade"
        $startTime = Get-Date
        Invoke-Command -ComputerName $guestHost -Credential $GuestCredential -SessionOption $so `
            -ArgumentList $scan.Root, $scan.ImageIndex, $ProductKeys[$pre.EditionID] -ScriptBlock {
            param($root, $index, $key)
            $args = "/auto upgrade /imageindex $index /pkey $key /eula accept /quiet " +
                    "/dynamicupdate disable /compat ignorewarning /showoobe none /copylogs C:\WS2025Upgrade\upgrade"
            $action    = New-ScheduledTaskAction -Execute "$root\setup.exe" -Argument $args
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6)
            Register-ScheduledTask -TaskName 'WS2025Upgrade' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName 'WS2025Upgrade'
        }

        # ---------- 6. Wait for completion / rollback ----------
        $deadline = $startTime.AddMinutes($UpgradeTimeoutMinutes)
        $done = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep 60
            $state = Invoke-Command -ComputerName $guestHost -Credential $GuestCredential -SessionOption $so -EA SilentlyContinue -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem
                [pscustomobject]@{ Build = [int]$os.BuildNumber; Caption = $os.Caption; Boot = $os.LastBootUpTime }
            }
            if (-not $state) { Write-Step $name "Unreachable (reboot/offline phase)"; continue }
            if ($state.Build -ge 26100) { $done = $true; break }
            if ($state.Boot -gt $startTime) { throw "Rolled back to build $($state.Build). Check C:\`$WINDOWS.~BT\Sources\Rollback and C:\WS2025Upgrade" }
            Write-Step $name "Downlevel phase, still on $($state.Build)"
        }
        if (-not $done) { throw "Timed out after $UpgradeTimeoutMinutes min" }
        Write-Step $name "Upgraded: $($state.Caption) build $($state.Build)"

        # ---------- 7. Cleanup / vSphere housekeeping ----------
        Invoke-Command -ComputerName $guestHost -Credential $GuestCredential -SessionOption $so -ScriptBlock {
            Unregister-ScheduledTask -TaskName 'WS2025Upgrade' -Confirm:$false -EA SilentlyContinue
        }
        Set-CDDrive -CD $cd -NoMedia -Confirm:$false | Out-Null

        if ($SetGuestOsType) {
            Write-Step $name "Setting guest OS type ($GuestId)"
            Stop-VMGuest -VM $vm -Confirm:$false | Out-Null
            while ((Get-VM -Id $vm.Id).PowerState -ne 'PoweredOff') { Start-Sleep 5 }
            Set-VM -VM $vm -GuestId $GuestId -Confirm:$false | Out-Null
            Start-VM -VM $vm | Out-Null
            Wait-Tools -VM $vm -TimeoutSeconds 900 | Out-Null
        }
        Write-Step $name "Updating VMware Tools (no reboot)"
        Update-Tools -VM $vm -NoReboot -EA SilentlyContinue

        $r.Status = 'Upgraded'; $r.Detail = "$($state.Caption) ($($state.Build))"
    }
    catch {
        $r.Status = 'Failed'; $r.Detail = $_.Exception.Message
        Write-Step $name "FAILED: $($_.Exception.Message)"
    }
    [pscustomobject]$r
}

$results | Format-Table -AutoSize
$results | Export-Csv (Join-Path $LogRoot "results-$(Get-Date -f yyyyMMdd-HHmmss).csv") -NoTypeInformation
Disconnect-VIServer $conn -Confirm:$false
Stop-Transcript | Out-Null