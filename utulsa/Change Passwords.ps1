#gets the OU path of every OU in AD, find the one with all the users and use that for the next cmdlet
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName

$users = Get-ADUser -filter "cn -ne '<ACC NAME>'" -SearchBase "<OU PATH>" -SearchScope OneLevel

foreach ($name in $users.samAccountName) {
#Generate a 15-character random password
$Password = -join ((33..126) | Get-Random -Count 15 | ForEach-Object { [char]$_ })

#Convert the password to secure string
$Pass = ConvertTo-SecureString $Password -AsPlainText -Force

#Reset the account password
Set-ADAccountPassword $name -NewPassword $Pass -Reset

#Display userid and password values
Write-Output $name, $Password 

# For txt file:
Write-Output $name, $Password | Out-file "user.txt" -Append

# For CSV file:
[pscustomobject]@{
	User = $name
	Password = $Password
} | export-csv "user.csv" -NoTypeInformation -Append

}
