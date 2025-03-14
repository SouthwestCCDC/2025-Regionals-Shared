Import-Module ActiveDirectory



Function New-ADSnapshot {
    Param()

    ntdsutil "Activate Instance NTDS" snapshot create quit quit
}



Function Mount-ADDatabase {
    Param (
        [parameter(Mandatory = $true)]
        [ValidateScript({
                # Must specify an LDAP port not in use
                $x = $null
                Try { $x = Get-ADRootDSE -Server localhost:$_ }
                Catch { $null }
                If ($x) { $false } Else { $true }
            })]
        [ValidateRange(1025, 65535)]
        [int]
        $LDAPPort,
        [parameter(Mandatory = $true,
            ParameterSetName = "Filter")]
        [ValidateScript({ $Host.Name -ne 'ServerRemoteHost' })]
        [switch]$Filter,
        [parameter(Mandatory = $true,
            ParameterSetName = "First")]
        [switch]$First,
        [parameter(Mandatory = $true,
            ParameterSetName = "Last")]
        [switch]$Last
    )
    # Parse snapshot list
    $snaps = ntdsutil snapshot "list all" quit quit
    If ($First) {
        # Pick the first snapshot in the list
        # Use @() in case a single row comes back for PSv2
        $ChoiceNumber = (@(($snaps | Select-String -SimpleMatch '/'))[0] -split ':')[0].Trim()
    }
    ElseIf ($Last) {
        # Pick the last snapshot in the list
        # Use @() in case a single row comes back for PSv2
        $ChoiceNumber = (@(($snaps | Select-String -SimpleMatch '/'))[-1] -split ':')[0].Trim()
    }
    Else {
        $Choice = $snaps | Select-String -SimpleMatch '/' |
        Select-Object -ExpandProperty Line |
        Out-GridView -Title 'Select the snapshot to mount' -OutputMode Single
        If ($null -eq $Choice) {
            # What if the user hits the Cancel button in the OGV?
            Exit
        }
        Else {
            $ChoiceNumber = ($Choice -split ':')[0].Trim()
        }
    }

    # Mount Snapshot
    $Mount = ntdsutil snapshot "list all" "mount $ChoiceNumber" quit quit
    # If already mounted, will return "Snapshot {1753bd1a-7905-4e2b-a976-254198a3fe3e} is already mounted."
    $MountPath = (($Mount | Select-String -SimpleMatch 'mounted as') -split 'mounted as')[-1].Trim()
    $DITPath = (Get-Item -Path "HKLM:\SYSTEM\CurrentcontrolSet\Services\NTDS\Parameters").GetValue("DSA Database File").SubString(2)
    $NTDSdit = Join-Path -Path $MountPath -ChildPath $DITPath

    # Mounted snapshots show up in the ExposedName column
    $MountedWMI = Get-WmiObject Win32_ShadowCopy | Select-Object Id, Installdate, OriginatingMachine, ClientAccessible, NoWriters, ExposedName
    $MountedNTDS = ntdsutil snapshot "list mounted" quit quit

    # Mount the database in the snapshot
    # Start in its own process, because it must continue to run in the background.
    Write-Host 'Mounting database: .' -NoNewline
    $DSAMAIN = Start-Process -FilePath dsamain.exe -ArgumentList "-dbpath $NTDSdit -ldapport $LDAPPort" -PassThru

    # Wait for database mount to complete
    # Get-ADRootDSE does not seem to obey the ErrorAction parameter
    $ErrorActionPreference = 'SilentlyContinue'
    $d = $null
    Do {
        $d = Get-ADRootDSE -Server localhost:$LDAPPort
        Start-Sleep -Seconds 1
        Write-Host '.' -NoNewline
    }
    Until ($d)
    Write-Host '.'
    $ErrorActionPreference = 'Continue'

    If ($Verbose) {
        $MountedWMI | Format-Table Id, Installdate, OriginatingMachine, ClientAccessible, NoWriters, ExposedName -AutoSize
        $MountedNTDS
        $DSAMAIN
    }
}



Function Dismount-ADDatabase {
    Param()
    # Dismount the database
    Get-Process dsamain -ErrorAction SilentlyContinue | Stop-Process

    # Unmount snapshot
    # $ChoiceNumber no longer cooresponds here, because the list is different
    ntdsutil snapshot "list mounted" "unmount *" quit quit

}



Function Show-ADSnapshot {
    Param (
        [switch]$WMI
    )
    If ($WMI) {
        Get-WmiObject Win32_ShadowCopy | Select-Object Id, @{name = 'Install_Date'; expression = { $_.ConvertToDateTime($_.InstallDate) } }, OriginatingMachine, ClientAccessible, NoWriters, ExposedName | Sort-Object Install_Date
    }
    Else {
        ntdsutil snapshot "list all" quit quit
    }
}



Function Remove-ADSnapshot {
    Param(
        [parameter(Mandatory = $true,
            ParameterSetName = "All")]
        [switch]$All,
        [parameter(Mandatory = $true,
            ParameterSetName = "First")]
        [parameter(Mandatory = $true,
            ParameterSetName = "Last")]
        [int]$Keep,
        [parameter(Mandatory = $true,
            ParameterSetName = "First")]
        [switch]$First,
        [parameter(Mandatory = $true,
            ParameterSetName = "Last")]
        [switch]$Last
    )

    If ($All) {
        ntdsutil snapshot "list all" "delete *" quit quit
    }
    Else {
        # Decide which array index to delete, first or last.
        # If keeping first x, then trim last.
        # If keeping last x,  then trim first.
        $snaps = ntdsutil snapshot "list all" quit quit
        $snapsArray = @(($snaps | Select-String -SimpleMatch '/'))
        If ($snapsArray.Count -gt $Keep) {
            If ($First) { $DeleteMe = -1 } Else { $DeleteMe = 0 }
            While ($snapsArray.count -gt $Keep) {
                $ChoiceNumber = ($snapsArray[$DeleteMe] -split ':')[0].Trim()
                ntdsutil snapshot "list all" "delete $ChoiceNumber" quit quit
                $snaps = ntdsutil snapshot "list all" quit quit
                $snapsArray = @(($snaps | Select-String -SimpleMatch '/'))
            }
        }
        Else {
            "No snapshots to delete in that range."
        }
    }

}

Function New-RandomPassword {
    Param(
        [parameter(Mandatory = $true)]
        [int]$Length
    )
    $Password = "a"
    while (-not ($Password -match '[a-z]' -and $Password -match '[A-Z]' -and $Password -match '[0-9]' -and $Password -match '[-_.?!+=:^()]')) {
        $AllowedCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.?!+=:^()'
        $Password = -Join ($AllowedCharacters.ToCharArray() | Get-Random -Count $Length | ForEach-Object { [char]$_ })
    }
    Return $Password
}   

Function Repair-ADUsers {
    Param(
        [parameter(Mandatory = $true)]
        [ValidateScript({
                # Must specify an LDAP snapshot port in use
                $x = $null
                Try { $x = Get-ADRootDSE -Server localhost:$_ }
                Catch { $null }
                If ($x) { $true } Else { $false }
            })]
        [ValidateRange(1025, 65535)]
        [int]
        $LDAPPort,
        [switch]$Modify
    )

    $SnapshotUsers = Get-ADUser -Filter * -Server "localhost:$LDAPPort" -Properties *
    $PasswordList = @{}
    foreach ($user in $SnapshotUsers) {
        # Check if account exists in current AD
        $CurrentAccount = Get-ADUserSafe -Username $user.Name
        if ($CurrentAccount) {
            if ($Modify) {
                # Account exists, compare attributes
                $Properties = @("Name", "GivenName", "Surname", "EmailAddress", "Enabled")
                foreach ($property in $Properties) {
                    if ($user.$property -ne $CurrentAccount.$property) {
                        # Repair attribute
                        Set-ADUser -Identity $CurrentAccount.Name -Server localhost -Replace @{ $property = $user.$property }
                    }
                }
                Write-Host "Modified user $($user.Name)"
            }
        }
        else {
            # Account does not exist, create it
            $RandomPassword = New-RandomPassword -Length 12
            $PasswordList[$user.Name] = $RandomPassword
            $splat = @{
                Name            = $user.Name
                GivenName       = $user.GivenName
                Surname         = $user.Surname
                EmailAddress    = $user.EmailAddress
                AccountPassword = (ConvertTo-SecureString $RandomPassword -AsPlainText -Force)
                Enabled         = $user.Enabled
            }
            New-ADUser @splat
            Write-Host "Created user $($user.Name)"
        }
    }
    $RandomPassword = $null
    Return $PasswordList
}

Function Update-ADUserPasswords {
    Param(
        [parameter(Mandatory = $true)]
        [String[]]$Blacklist
    )
    
    $AllUsers = Get-ADUser -Filter *
    $PasswordList = @{}
    foreach ($user in $AllUsers) {
        if ($Blacklist -notcontains $user.Name) {
            $RandomPassword = New-RandomPassword -Length 12
            $PasswordList[$user.Name] = $RandomPassword
        }
    }
    $ChosenUsers = ($PasswordList.Keys | Sort-Object)
    # Ask user to confirm if we should change the chosen users' passwords
    $ChosenUsers | ForEach-Object {
        Write-Host "$_"
    }
    $Confirm = Read-Host "Do you want to change the passwords for these users? (y/n)"
    if ($Confirm -eq 'y') {
        Set-ADPasswords -PasswordList $PasswordList
    } else {
        Write-Host "Passwords not changed."
    }
    Return $PasswordList
}

Function Set-ADPasswords {
    Param(
        [parameter(Mandatory = $true)]
        [hashtable]$PasswordList
    )

    foreach ($user in $PasswordList.Keys) {
        Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString $PasswordList[$user] -AsPlainText -Force)
        Write-Host "Updated password for $user"
    }

}

Function Export-PasswordList {
    Param(
        [parameter(Mandatory = $true)]
        [hashtable]$PasswordList,
        [parameter(Mandatory = $true)]
        [string]$Path
    )
    $PasswordList.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Name     = $_.Key
            Password = $_.Value
        }
    } | Export-Csv -Path $Path -NoTypeInformation
    ((Get-Content $Path | Select-Object -Skip 1) -replace '"','') | Set-Content $Path
}

Function Get-ADUserSafe {
    Param(
        [parameter(Mandatory = $true)]
        [string]$Username
    )
    try {
        $user = Get-ADUser -Identity $Username -Properties *
        Return $user
    }
    catch {
        Return $null
    }
}

Function Repair-ADGroups {
    Param(
        [parameter(Mandatory = $true)]
        [ValidateScript({
                # Must specify an LDAP snapshot port in use
                $x = $null
                Try { $x = Get-ADRootDSE -Server localhost:$_ }
                Catch { $null }
                If ($x) { $true } Else { $false }
            })]
        [ValidateRange(1025, 65535)]
        [int]$LDAPPort
    )

    $SnapshotGroups = Get-ADGroup -Filter * -Server "localhost:$LDAPPort" -Properties *
    foreach($Group in $SnapshotGroups) {
        $CurrentGroup = Get-ADGroup -Identity $Group.Name
        if ($CurrentGroup) {
            # Group exists, compare attributes
            $Properties = @("Name", "Description", "GroupCategory", "GroupScope", "IsCriticalSystemObject", "ManagedBy", "Members", "MemberOf", "SamAccountName")
            foreach ($property in $Properties) {
                if ($Group.$property -ne $CurrentGroup.$property) {
                    # Repair attribute
                    Set-ADGroup -Identity $CurrentGroup.Name -Server localhost -Replace @{ $property = $Group.$property }
                }
            }
            Write-Host "Modified group $($Group.Name)"
        }
        else {
            # Group does not exist, create it
            $splat = @{
                Name            = $Group.Name
                Description     = $Group.Description
                GroupCategory   = $Group.GroupCategory
                GroupScope      = $Group.GroupScope
                IsCriticalSystemObject = $Group.IsCriticalSystemObject
                ManagedBy       = $Group.ManagedBy
                Members         = $Group.Members
                MemberOf        = $Group.MemberOf
                SamAccountName  = $Group.SamAccountName
            }
            New-ADGroup @splat
            Write-Host "Created group $($Group.Name)"
        }
    }
}

Function Export-ADData {
    Param(
        [parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    $addir = New-Item -ItemType Directory -Path $BackupPath -Name "AD"

    Write-Host "Exporting users..."
    $users = Get-ADUser -Filter * -Properties *
    $users | Out-File "$($addir.FullName)\users.txt"

    Write-Host "Exporting groups..."
    $groups = Get-ADGroup -Filter * -Properties *
    $groups | Out-File "$($addir.FullName)\groups.txt"

    Write-Host "Exporting computers..."
    $computers = Get-ADComputer -Filter * -Properties *
    $computers | Out-File "$($addir.FullName)\computers.txt"

    Write-Host "Exporting GPOs..."
    $gpodir = New-Item -ItemType Directory -Path "$($addir.FullName)\GPOs"
    $null = Backup-GPO -All -Path $gpodir.FullName
}

# Dismount-ADDatabase
# Mount-ADDatabase -LDAPPort 50300 -Last
# $PasswordList = Repair-ADUsers -LDAPPort 50300
# Export-PasswordList -PasswordList $PasswordList -Path .\passwords.csv
# Dismount-ADDatabase

# $Blacklist = @('admin', 'administrator', 'krbtgt', 'guest', 'blackteam')
# $PasswordList = Update-ADUserPasswords -Blacklist $Blacklist
# Export-PasswordList -PasswordList $PasswordList -Path .\passwords.txt
