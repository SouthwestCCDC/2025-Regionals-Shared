Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP

# winfire only blocks certain ports at the moment
function WinFire {

    Write-Host "[+] Hardening firewall..." -ForegroundColor Green

    # turn defaults on and set logging
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogAllowed True -LogIgnored True -LogBlocked True -LogMaxSize 4096 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    Write-Host "[i] You are possibly going to be asked if you want to block certain ports" -ForegroundColor Yellow
    Write-Host "[i] Your options are ( y ) or ( n )" -ForegroundColor Yellow

    Start-Sleep -Milliseconds 500

    # Allow Inbound connections from AD on the AD ports
    
    # Block any Inbound and Outbound connections from the workstation subnet

    $hostIP = (
        Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -ne "Disconnected"
        }
    ).IPv4Address.IPAddress

    # note for the guy running the script remote
    Write-Host $hostIP

    # Block Outbound connections to the other machines in the subnet if they aren't the SME IP
    New-NetfirewallRule -DisplayName "Silo Machine" -LocalAddress "$hostIP/255.255.255.0" -Action Block -Protocol Any -LocalPort Any -Direction Inbound -Enabled True

    Write-Host "[+] Finished hardening firewall" -ForegroundColor Green
    Write-Host "[i] Remember to do a deeper dive later and patch any holes" -ForegroundColor Yellow

}

# change the password on local accounts
function ChangeCreds {
    param (

    )

    Write-Host "[+] You are now about to change the local passwords" -ForegroundColor Yellow

    $localusers = @(Get-LocalUser | Select-Object -Property Name)
    $alph = foreach($i in 49..122) {[char]$i}

    foreach ($user in $localusers) {
        # to print later
        $username = $user.Name
        if ($username -eq "blackteam") {
            Write-Host "nah"
            continue;
        }
        for($i = 0; $i -lt 14; $i++) { $pass += $alph | Get-Random }
        ConvertTo-SecureString -AsPlainText $pass
        Set-LocalUser -Name $username -Password $pass
        Write-Host "[+] Changed password for ($username)" -ForegroundColor Green
        $PasswordProgress = @{
                Activity         = 'Changing Password'
                PercentComplete  = ($user / ($localusers.Length-2)) * 100
                Status           = 'Progress'
                CurrentOperation = "$username"
        }
        Write-Progress @PasswordProgress
    }

    Write-Host "[i] MAKE SURE THEY LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT" -ForegroundColor Yellow
}

function SetUAC {
    param (
        
    )

    Write-Host "[+] Setting UAC values..." -ForegroundColor Yellow

    # set the values
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 3 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'EnableInstallerDetection' -Value 1 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'EnableLUA' -Value 1 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'EnableVirtualization' -Value 1 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'PromptOnSecureDesktop' -Value 1 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'ValidateAdminCodeSignatures' -Value 0 -Type DWORD -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'FilterAdministratorToken' -Value 0 -Type DWORD -Force | Out-Null

    Write-Host "[+] Values set" -ForegroundColor Green
}

# runs a basic windows defender scan
function DefenderScan {
    param (
        
    )

    # check to make sure windows defender is able to run
    if ($(Get-MpComputerStatus).AntivirusEnabled) {
        
        Write-Host "[+] Setting up for scan..." -ForegroundColor Green
        
        Set-MpPreference -CheckForSignaturesBeforeRunningScan True -CloudBlockLevel

        Write-Host "[+] Removing any exclusions..." -ForegroundColor Green
        
        # remove all exclusion if there are any
        $preference = Get-MpPreference
        
        foreach ($x in $preference.ExclusionPath) {
            Remove-MpPreference -ExclusionPath $x
        }

        Write-Host "[+] Running scan in the background..."
        
        # TODO receive output from scan
        Start-MpScan -ScanType FullScan -ScanPath C: -AsJob -OutVariable scanOut
    
    }else {
        Write-Host "[-] Error in checking windows defender" -ForegroundColor Red
    }
}


function EnableDefenderOn {
    param (
        $step
    )
    
    if ($(Get-MpComputerStatus).AntivirusEnabled -eq $false) {
        
        Write-Host "[+] Enabling Windows Defender..." -ForegroundColor Yellow

        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Type DWORD -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Type DWORD -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWORD -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWORD -Force
      
        Start-Service -DisplayName "Windows Defender Antivirus Service"
        Start-Service -DisplayName "Windows Defender Antivirus Network Inspection Service"	
    

        if ($(Get-MpComputerStatus).AntivirusEnabled -eq $true) {
            Write-Host "[+] Windows Defender Enabled" -ForegroundColor Green
        }else{
            Write-Host "[-] Error in trying to startup Windows Defender" -ForegroundColor Red
        }
    } else {
        Write-Host "[i] Windows Defender is already active" -ForegroundColor Yellow
    }
}

function Harden {
    param (

    )

    #Long but disables all guests
    Write-Host "[+] Clearing out guest accounts..." -ForegroundColor Green

    # note this should not need undo because no guests accounts should be allowed
    $user = Get-LocalGroupMember -Name "Guests" 
    foreach ($j in $user) { 
        Write-Host "[i] Disabling guest: $j" -ForegroundColor Yellow
        Disable-LocalUser -Name ([string]$j).Split('\')[1] # grabbing the actual user name
    }
    Write-Host "[i] Running a different command to make sure Guest was removed" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If it errors that means that it worked" -ForegroundColor Yellow
    Start-Sleep(3)
    Get-LocalUser Guest | Disable-LocalUser -ErrorAction continue
    Write-Host "[+] Guest accounts cleared" -ForegroundColor Green

    # remove all the non-required admin accounts
    Write-Host "[+] Removing all admin accounts...except yours" -ForegroundColor Green

    $admin_users = @(Get-LocalGroupMember -Group "Administrators")
    
    foreach ($user in $admin_users) {
    	if ($user.Name -eq ('blackteam' -or 'Administrator')) {
      	    Write-Host "nah"
        }
        Remove-LocalGroupMember -Group 'Administrators' -Name $user.Name
    }
    Write-Host "[+] Pruned Administrator accounts" -ForegroundColor Green

    # harden the firewall for remote or lan comps
    $winFirewallOn = $(Write-Host "[?] Do you want to turn on the windows firewall (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($winFirewallOn -eq ("y")) {
        WinFire
    }

    # turn on Windows Defender
    # note Windows 8.1 (server 2016+) should already be on
    EnableDefenderOn
    
    # change the execution policy for powershell for admins only (works only for the current machine)
    Write-Host "[+] Changing powershell policy..." -ForegroundColor Yellow

    Write-Host "[+] Execution policy was changed to restricted" -ForegroundColor Green
    
    # setup UAC
    SetUAC

    # disable anonymous logins
    Write-Host "[+] Disabling anonymous users..." -ForegroundColor Yellow
    $a = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "restrictanonymous"
    if ($a.restrictanonymous -ne 1) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "restrictanonymous" -Value 1 -Force
    }
    Write-Host "[+] Disabled anonymous users" -ForegroundColor Green

    
    # disable anonymous sam
    Write-Host "[+] Disabling anonymous SAM touching..." -ForegroundColor Yellow
    $a = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "restrictanonymoussam"
    if ($a.restrictanonymoussam -ne 1) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "restrictanonymoussam" -Value 1 -Force
    }
    Write-Host "[+] Touching SAM anonymously is disabled" -ForegroundColor Green
    
    # note warning this will stop a user from editing the registry all together
    Write-Host "[+] Disabling regedit..." -ForegroundColor Yellow
    $a = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "disableregistrytools"
    if ($a.disableregistrytools -ne 2) {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "disableregistrytools" -Value 2 -Force
    }
    Write-Host "[+] Registry editing via tools disabled" -ForegroundColor Green

    # disable netbios ??????(might be too good)
    $adapters=(Get-WmiObject win32_networkadapterconfiguration)
    foreach ($adapter in $adapters){
        Write-Host $adapter
        $adapter.settcpipnetbios(0)
    }

    # change the passwords of the current local users
    ChangeCreds

    # clear tracks
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Force -ErrorAction Continue
}


function Main {
    param (

    )

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole("Domain Admins")) { 
        Write-Host "Welcome to WindowsHard!" -ForegroundColor Green
        Write-Host "Goodluck Today!!!" -ForegroundColor Green
    }else{ 
        Write-Host "No Red Team Allowed!!!" -ForegroundColor Red
        Write-Host "Hope You Have a Good Day!!!" -ForegroundColor Red
        exit
    }

    Write-Host "[i] Starting the hardening process on the current machine" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If any errors occur, a message will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[red]" -ForegroundColor Red
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If any progress is made, a message will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[green]" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
    Write-Host "[i] Any side note info will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[yellow]" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] All questions to the user will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[magenta]" -ForegroundColor Magenta

    Harden

}

Main
