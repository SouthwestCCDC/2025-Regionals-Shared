Function Get-BackupPath {
    Add-Type -Assembly System.Windows.Forms
    $browser = New-Object System.Windows.Forms.FolderBrowserDialog
    $res = $browser.ShowDialog()
    if ($res -ne "OK") {
        return $null
    }
    $filepath = $browser.SelectedPath
    return $filepath
}


$BackupPath = Get-BackupPath
if ($null -eq $BackupPath) {
    Write-Host "No backup path selected"
    return
}

# $BackupPath = "C:\Users\ameya\Documents\School\HASH\windows\baseline\Backups"


# check if IIS installed
Write-Host "Checking for IIS..."
try {
    $null = Get-Service -Name W3SVC -ErrorAction Stop
    Write-Host "IIS installed"
    Write-Host "Backing up IIS data..."
    . .\iis.ps1
    Backup-IISData -BackupPath $BackupPath
}
catch {
    Write-Host "IIS not installed"
}

Write-Host "`n------------------------------------`n"

# check if AD installed
Write-Host "Checking for AD..."
try {
    $null = Get-Service -Name ADWS -ErrorAction Stop
    Write-Host "AD installed"
    Write-Host "Creating AD snapshot..."
    . .\ad.ps1
    New-ADSnapshot
    Write-Host "Exporting AD data..."
    Export-ADData -BackupPath $BackupPath
}
catch {
    Write-Host "AD not installed"
}

Write-Host "`n------------------------------------`n"

Write-Host "Exporting generic baseline data..."
. .\generic.ps1
Export-GenericBaseline -BackupPath $BackupPath