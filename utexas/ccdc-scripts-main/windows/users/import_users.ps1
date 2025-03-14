Import-Module ActiveDirectory

Function Import-ADUsers {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $users = Import-Csv $Path

    foreach ($user in $users) {
        $acc = @{
            Name            = (($user.GivenName).ToLower() + "." + ($user.Surname).ToLower())
            GivenName       = $user.GivenName
            Surname         = $user.Surname
            EmailAddress    = $user.EmailAddress
            AccountPassword = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
            Enabled         = $true
        }
        try {
            $null = Get-ADUser -Identity $acc.Name
            Remove-ADUser -Identity $acc.Name -Confirm:$false
        }
        catch {
            # New-ADUser @acc
            # Write-Host "Created user $($acc.Name)"
        }
    }
}

Import-ADUsers -Path .\fakeusers.csv