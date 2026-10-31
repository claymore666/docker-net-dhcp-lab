# Lab first logon (lab #14), rendered by scripts/build-windows-image.sh and
# run from the seed CD by autounattend.xml. Every step is guarded by a stage
# file, so the run that follows the DHCP role's reboot resumes where it
# stopped. Any failure powers the VM off with no bootstrap-done marker,
# which the build's second boot reports as a refusal.
$ErrorActionPreference = 'Stop'
$lab = 'C:\ProgramData\lab'
New-Item -ItemType Directory -Force -Path $lab | Out-Null
Start-Transcript -Path "$lab\firstlogon.log" -Append | Out-Null

function Test-Stage($name) { Test-Path "$lab\stage-$name" }
function Set-Stage($name) { New-Item -ItemType File -Force -Path "$lab\stage-$name" | Out-Null }

try {
    if ($PSCommandPath -ne "$lab\firstlogon.ps1") {
        Copy-Item -Path $PSCommandPath -Destination "$lab\firstlogon.ps1" -Force
    }

    # Network: both NICs are matched by MAC, never by name (Windows numbers
    # them in a non-deterministic order). The script also runs at every boot,
    # so a run overlay comes up with the segment NIC addressed.
    if (-not (Test-Stage 'net')) {
        $netconfig = @'
$ErrorActionPreference = 'Stop'
$nics = @(
    @{ Mac = '__MGMT_MAC__'; Name = 'mgmt'; Ip = '__MGMT_IP__'; Prefix = __MGMT_PREFIX__; Gw = '__MGMT_GW__' },
    @{ Mac = '__SEG_MAC__'; Name = 'seg'; Ip = '__SEG_IP__'; Prefix = __SEG_PREFIX__; Gw = '' }
)
$changed = $false
foreach ($n in $nics) {
    $a = $null
    for ($i = 0; $i -lt 6 -and -not $a; $i++) {
        $a = Get-NetAdapter | Where-Object { $_.MacAddress -eq $n.Mac }
        if (-not $a) { Start-Sleep -Seconds 5 }
    }
    if (-not $a) { continue }
    if ($a.Name -ne $n.Name) { Rename-NetAdapter -Name $a.Name -NewName $n.Name }
    $have = Get-NetIPAddress -InterfaceAlias $n.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $n.Ip -and $_.PrefixLength -eq $n.Prefix }
    if ($have) { continue }
    Set-NetIPInterface -InterfaceAlias $n.Name -Dhcp Disabled
    Get-NetIPAddress -InterfaceAlias $n.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false
    Remove-NetRoute -InterfaceAlias $n.Name -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
    $p = @{ InterfaceAlias = $n.Name; IPAddress = $n.Ip; PrefixLength = $n.Prefix }
    if ($n.Gw) { $p.DefaultGateway = $n.Gw }
    New-NetIPAddress @p | Out-Null
    Set-DnsClient -InterfaceAlias $n.Name -RegisterThisConnectionsAddress $false
    $changed = $true
}
if ($changed -and (Get-Service -Name DHCPServer -ErrorAction SilentlyContinue)) {
    Restart-Service -Name DHCPServer -Force
}
'@
        Set-Content -Path "$lab\netconfig.ps1" -Value $netconfig -Encoding ascii
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\lab\netconfig.ps1'
        $trg = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName 'LabNet' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        Get-PnpDevice -Class Net, DiskDrive | Format-Table -AutoSize | Out-String | Write-Host
        if (-not (Get-NetAdapter | Where-Object { $_.MacAddress -eq '__MGMT_MAC__' })) {
            throw 'no adapter carries the management MAC: the virtio network driver did not load'
        }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$lab\netconfig.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'netconfig.ps1 failed' }
        Set-Stage 'net'
    }

    # Firewall: explicit rules for every profile, so the "Unidentified
    # network" class of a segment NIC never drops echo, DHCP or ssh.
    if (-not (Test-Stage 'firewall')) {
        New-NetFirewallRule -Name 'lab-icmp-in' -DisplayName 'lab icmp echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null
        New-NetFirewallRule -Name 'lab-dhcp-in' -DisplayName 'lab dhcp server' -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow -Profile Any | Out-Null
        New-NetFirewallRule -Name 'lab-ssh-in' -DisplayName 'lab ssh' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
        Set-Stage 'firewall'
    }

    # The DHCP role. A restart it asks for ends this run; the next logon
    # (RunOnce) starts the script again and skips what is staged.
    if (-not (Test-Stage 'role')) {
        $r = Install-WindowsFeature -Name DHCP -IncludeManagementTools
        if (-not $r.Success) { throw 'the DHCP role did not install' }
        Set-Stage 'role'
        if ("$($r.RestartNeeded)" -ne 'No') {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'LabFirstLogon' `
                -Value 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\lab\firstlogon.ps1'
            Stop-Transcript | Out-Null
            Restart-Computer -Force
            exit 0
        }
    }

    # A standalone server needs no authorisation in a directory; the group
    # and the configuration-state value replace the post-install wizard.
    if (-not (Test-Stage 'dhcp')) {
        Add-DhcpServerSecurityGroup
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name 'ConfigurationState' -Value 2
        Restart-Service -Name DHCPServer -Force
        Add-LocalGroupMember -Group 'DHCP Administrators' -Member 'lab'
        # A policy range must lie inside the scope, so the scope spans the
        # main pool and the B5 class pool with the band between excluded;
        # clients matching no policy are served outside policy ranges (lab #14).
        Add-DhcpServerv4Scope -Name 'lab' -StartRange '__POOL_START__' -EndRange '__CLASS_POOL_END__' `
            -SubnetMask '255.255.255.0' -State Active -LeaseDuration (New-TimeSpan -Hours 12)
        Add-DhcpServerv4ExclusionRange -ScopeId '__SEG_NETWORK__' -StartRange '__GAP_START__' -EndRange '__GAP_END__'
        Add-DhcpServerv4Class -Name 'lab-class-b5' -Type Vendor -Data 'lab-class-b5'
        Add-DhcpServerv4Policy -Name 'b5' -ScopeId '__SEG_NETWORK__' -Condition OR -VendorClass EQ, 'lab-class-b5'
        Add-DhcpServerv4PolicyIPRange -Name 'b5' -ScopeId '__SEG_NETWORK__' -StartRange '__CLASS_POOL_START__' -EndRange '__CLASS_POOL_END__'
        Set-DhcpServerv4OptionValue -ScopeId '__SEG_NETWORK__' -Router '__SEG_GATEWAY__' -DnsServer '__SEG_IP__' -Force
        Set-DhcpServerSetting -ConflictDetectionAttempts 0
        Export-DhcpServer -File "$lab\baseline.xml" -Leases -Force
        Set-Stage 'dhcp'
    }

    # OpenSSH: key only. The key file belongs to the Administrators group
    # and nobody else, as Microsoft's OpenSSH document prescribes.
    if (-not (Test-Stage 'ssh')) {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
        if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        Stop-Service -Name sshd
        $cfg = 'C:\ProgramData\ssh\sshd_config'
        $c = Get-Content -Path $cfg
        $c = $c -replace '^\s*#?\s*PasswordAuthentication\s+.*$', 'PasswordAuthentication no'
        $c = $c -replace '^\s*#?\s*PubkeyAuthentication\s+.*$', 'PubkeyAuthentication yes'
        Set-Content -Path $cfg -Value $c -Encoding ascii
        if (-not (Select-String -Path $cfg -Pattern '^PasswordAuthentication no$' -Quiet)) { throw 'sshd_config still allows passwords' }
        $keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
        Set-Content -Path $keys -Value '__PUBKEY__' -Encoding ascii
        & icacls.exe $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'icacls failed on the authorized keys file' }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -PropertyType String -Force `
            -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | Out-Null
        Start-Service -Name sshd
        Set-Stage 'ssh'
    }

    # No update reboot mid-scenario, a small fixed pagefile (the run overlay
    # grows with it) and the management gateway as the clock.
    if (-not (Test-Stage 'system')) {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 1 -Type DWord
        Stop-Service -Name wuauserv -ErrorAction SilentlyContinue
        Set-Service -Name wuauserv -StartupType Disabled
        Set-CimInstance -InputObject (Get-CimInstance Win32_ComputerSystem) -Property @{ AutomaticManagedPagefile = $false }
        $pf = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($pf) {
            Set-CimInstance -InputObject $pf -Property @{ InitialSize = [uint32]512; MaximumSize = [uint32]512 }
        } else {
            New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name = 'C:\pagefile.sys'; InitialSize = [uint32]512; MaximumSize = [uint32]512 } | Out-Null
        }
        Set-Service -Name w32time -StartupType Automatic
        Start-Service -Name w32time
        & w32tm.exe /config '/manualpeerlist:__MGMT_GW__' /syncfromflags:manual /update | Out-Null
        Set-Stage 'system'
    }

    # Whether an evaluation runs offline is unmeasured: activation is tried
    # while the management network can reach the internet, and the state is
    # logged for the host run to read. A failure here does not fail the build.
    if (-not (Test-Stage 'activation')) {
        try {
            foreach ($o in '/ato', '/xpr', '/dlv') {
                & cscript.exe //nologo "$env:SystemRoot\System32\slmgr.vbs" $o | Out-File -Append -Encoding ascii "$lab\slmgr.log"
            }
        } catch {
            "slmgr: $_" | Out-File -Append -Encoding ascii "$lab\slmgr.log"
        }
        Set-Stage 'activation'
    }

    # Setup may write only \EFI\Microsoft\Boot\bootmgfw.efi; a fresh NVRAM
    # (every lab overlay) boots only through the fallback path (lab #14).
    if (-not (Test-Stage 'efi')) {
        mountvol S: /S
        if (-not (Test-Path 'S:\EFI\Microsoft\Boot\bootmgfw.efi')) { throw 'no bootmgfw.efi on the ESP' }
        New-Item -ItemType Directory -Force -Path 'S:\EFI\BOOT' | Out-Null
        Copy-Item -Path 'S:\EFI\Microsoft\Boot\bootmgfw.efi' -Destination 'S:\EFI\BOOT\bootx64.efi' -Force
        mountvol S: /D
        Set-Stage 'efi'
    }

    # No password survives the install: autologon off, Setup's cached
    # answer files gone.
    $w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -Path $w -Name 'AutoAdminLogon' -Value '0'
    Remove-ItemProperty -Path $w -Name 'DefaultPassword' -ErrorAction SilentlyContinue
    Remove-Item -Path 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml', 'C:\Windows\System32\sysprep\unattend.xml' -Force -ErrorAction SilentlyContinue

    Stop-Transcript | Out-Null
    [IO.File]::WriteAllText("$lab\bootstrap-done", '__BUILD_ID__')
    Stop-Computer -Force
} catch {
    $_ | Out-String | Add-Content -Path "$lab\firstlogon-error.log"
    Stop-Computer -Force
    exit 1
}
