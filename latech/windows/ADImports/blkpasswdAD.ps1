Import-Module ActiveDirectory

function BlkPasswd { 
    
    Write-Host "[+] Changing all of the passwords and writing them to a csv..." -ForegroundColor Green

    $alph = foreach($i in 65..90) {[char]$i}
    $alph += foreach($i in 97..122) {[char]$i}
    $safe = @('sys32admin', 'blackteam')
    Get-ADUser -Filter * | % { 
        if ($_.SamAccountName -notin $safe) {
            $pass = [string]$null
            for($i = 0; $i -lt 21; $i++) { $char = $alph | Get-Random; $pass += $char }
            $secpass = ConvertTo-SecureString -AsPlainText $pass -force
            Set-ADAccountPassword -Identity $_.SamAccountName -Reset -NewPassword $secpass
            write-output "$($_.SamAccountName),$pass" >> "$env:USERPROFILE\export.csv"
        }
    }

    Write-Host "[+] Bulk password change is complete and csv file is located on your desktop" -ForegroundColor Green
}
