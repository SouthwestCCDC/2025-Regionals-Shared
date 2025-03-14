function Backup-IISData {
    param (
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    $datestr = Get-Date -Format dd-HH-mm
    $null = Backup-WebConfiguration -Name "IIS $datestr"
    $iisdir = New-Item -ItemType Directory -Path $BackupPath -Name "IIS $datestr"
    $sites = Get-IISSite
    ForEach ($site in $sites) {
        $webpath = "IIS:\Sites\$($site.Name)"
        $datapath = Get-WebFilePath -PSPath $webpath
        $destpath = "$($iisdir.FullName)\$($site.Name)"
        Compress-Archive -Path $datapath -DestinationPath $destpath -Compression Fastest
    }
}

function Restore-IISData {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Date,
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    Restore-WebConfiguration -Name "IIS $Date"
    $iisdir = Get-Item -Path "$BackupPath\IIS $Date"
    $sites = Get-IISSite
    ForEach ($site in $sites) {
        $webpath = "IIS:\Sites\$($site.Name)"
        $datapath = Convert-Path -Path (Get-ItemPropertyValue $webpath -Name PhysicalPath) | Split-Path -Parent
        $destpath = "$($iisdir.FullName)\$($site.Name)"
        Expand-Archive -Path $destpath -DestinationPath $datapath -Force
    }
}

function Convert-Path {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $regex = '%([^%]+)%'
    $rmatches = [regex]::Matches($Path, $regex)

    foreach ($match in $rmatches) {
        $envVar = $match.Groups[1].Value
        $envValue = (Get-Item -Path "Env:\$envVar").Value
        $Path = $Path.Replace($match.Value, $envValue)
    }

    return $Path
}