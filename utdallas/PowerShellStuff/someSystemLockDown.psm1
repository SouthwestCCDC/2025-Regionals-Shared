

<#
Make sure to customize firewall rules after this
Also don't run if unsure what need yet
#>
Function FireWallBegin {
    param(
        [bool]$NeedRDP = $true
    )
    Remove-netFireWallRule *
    if($NeedRDP){
        New-NetFirewallRule -DisplayName "Allow TCP-3389-RDP" -Protocol ICMPv4 -Direction Inbound -Action Allow
    }
    New-NetFirewallRule -DisplayName "Allow ICMPv4" -Protocol ICMPv4 -Direction Inbound -Action Allow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
}
Function Remove-EvilProcesses {
    param(
        [String]$EvilUser = "Morgan"
    )
    Get-WmiObject -Class Win32_Process | ForEach-Object {
        try {
            $owner = $_.GetOwner()
            $processName = $_.Name
            $ownerName = $owner.User
            if ($ownerName -eq $EvilUser) { 
                Write-Host "Stopping process: $processName (PID: $($_.ProcessId)) owned by $ownerName"
                Stop-Process -Id $_.ProcessId -Force 
            }
        }
        catch {
            Write-Host "$($_.Name) - Owner not available"
        }
    }
}
Function Disable-SMB { 
    param(
        [bool]$MustSMB = $false
    )
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if($MustSMB){
        Set-SMBServerConfiguration -EnableSMB2Protocol $true
    }
}

Function Set-HardenWithAllScripts {
    param(
        [bool]$NeedRDP = $false,
        [bool]$MustSMB = $false
    )
    Disable-SMB -MustSMB $MustSMB
    FireWallBegin -NeedRDP $NeedRDP

}