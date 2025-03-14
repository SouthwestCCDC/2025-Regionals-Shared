
<# 
.Description  
Enumerates permenant computer detials

.Example  
Get-EnumComp -OutputFile computerDetails.txt

.Notes  
I really hope this works well for us.

#>
Function Get-EnumComp {
    param (
        [string]$OutputFile = ""
    )
    
    
    $Hostname = $env:ComputerName
    $OSVersionInfo = Get-ComputerInfo -Property OsName, OsLanguage, OsArchitecture, OsInstallDate, OsLastBootUpTime, OsUptime | Out-String
    $IPInterfaces = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address
    $CurrentDefualtGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop | Out-String
    $LocalAdmins = Get-LocalGroupMember -Group "Administrators" | Out-String
    $AllUsers = Get-LocalUser | Out-String
    $GetSMBShares = Get-SmbShare | Out-String
    $ScheduledTasks = Get-ScheduledTask | Out-String
    $StartupServices = Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, Status | Out-String
    $CertificatesLocalUser = Get-ChildItem -Path Cert:\LocalMachine\Root | Out-String
    $CertificatesRoot = Get-ChildItem -Path Cert:\LocalMachine\Root | Out-String
    $Content = "-------HostNameAndOSInfo---------", $Hostname, $OSVersionInfo, "-------IPInterfaces--------", $IPInterfaces,
        "Default Gateway = " + $CurrentDefualtGateway, "--------LOCAL ADMINS-----------", $LocalAdmins, "--------ALL USERS------------", $AllUsers,
        "--------ALL SMB Shares--------", $GetSMBShares, "--------Local and Root Certificates---------", $CertificatesLocalUser, $CertificatesRoot, "-----------Scheduled Tasks----------", $ScheduledTasks, "---------Startup Services-------",
        $StartupServices

    if ($OutputFile -ne ""){
        $Content | Out-File -FilePath $OutputFile
    } else {
        Write-Output $Content
    }
}

Function Get-CurrentState{
    param (
        [string]$OutputFile = "",
        [bool]$GetProcessesOwner = $false,
        [bool]$HomeEditionComputer = $true
    )
    if($HomeEditionComputer){
        $CurrentUsers = (Get-WmiObject -Class Win32_LoggedOnUser).__RELPATH | Out-String
    } else {
        $CurrentUsers = quser | Out-String
    }
    $CurrentProcesses = Get-Process | Select-Object Name, Id, CPU, MemoryUsage | Out-String
    if($GetProcessesOwner){
        $GetOwnerOfProcesses = Get-WmiObject -Class Win32_Process | ForEach-Object {
            try {
                $owner = $_.GetOwner()
                $processName = $_.Name
                $ownerName = $owner.User
                "$processName is owned by $ownerName"
            }
            catch {
                "$($_.Name) - Owner not available"
            }
        }
    } else {
        $GetOwnerOfProcesses = ""
    }
    $Services = Get-Service | Out-String

    $Content = "---------Current Users Logged in----------", $CurrentUsers, "---------Current Processes---------", $CurrentProcesses, $GetOwnerOfProcesses,
        "---------------Current Services---------------", $Services
    if ($OutputFile -ne ""){
        $Content | Out-File -FilePath $OutputFile
    } else {
        Write-Output $Content
    }
}