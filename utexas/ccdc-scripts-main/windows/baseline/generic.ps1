Function Get-ProcessTree() {

    Function Get-ProcessAndChildProcesses($Level, $Process) {
        "{0}[{1,-5}] [{2}] [{3}]" -f ("  " * $Level), $Process.ProcessId, $Process.Name, $Process.CreationDate
        $Children = $AllProcesses | where-object { $_.ParentProcessId -eq $Process.ProcessId -and $_.CreationDate -ge $Process.CreationDate }
        if ($null -ne $Children) {
            foreach ($Child in $Children) {
                Get-ProcessAndChildProcesses ($Level + 1) $Child
            }
        }
    }

    $AllProcesses = Get-CimInstance -ClassName "win32_process"
    $RootProcesses = @()
    # Process "System Idle Process" is processed differently, as ProcessId and ParentProcessId are 0
    # $AllProcesses is sliced from index 1 to the end of the array
    foreach ($Process in $AllProcesses[1..($AllProcesses.length - 1)]) {
        $Parent = $AllProcesses | where-object { $_.ProcessId -eq $Process.ParentProcessId -and $_.CreationDate -lt $Process.CreationDate }
        if ($null -eq $Parent) {
            $RootProcesses += $Process
        }
    }
    # Process the "System Idle process" separately
    "[{0,-5}] [{1}] [{2}]" -f $AllProcesses[0].ProcessId, $AllProcesses[0].Name, $AllProcesses[0].CreationDate
    foreach ($Process in $RootProcesses) {
        Get-ProcessAndChildProcesses 0 $Process
    }
}

Function Export-GenericBaseline {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $datapath = New-Item -ItemType Directory -Path $BackupPath -Name "Generic"
    $netstat = netstat -abno
    $netstat | Out-File "$($datapath.FullName)\netstat.txt"
    $psout = Get-Process -IncludeUserName
    $psout | Out-File "$($datapath.FullName)\processes.txt"
    $processtree = Get-ProcessTree
    $processtree | Out-File "$($datapath.FullName)\processtree.txt"
    $threadfolder = New-Item -ItemType Directory -Path $datapath.FullName -Name "Threads"
    foreach ($pdata in $psout) {
        $pname = $pdata.Name
        $tdata = ($pdata | Select-Object -ExpandProperty Threads)
        $tdata | Out-File ("{0}\{1}-{2:D5}.txt" -f $threadfolder.FullName, $pname, $pdata.Id)
    }
    Export-ProcessToCsv -Path $datapath.FullName
}

Function Export-ProcessToCsv {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$ExportAll
    )
    $plist = Get-Process -IncludeUserName
    $filtered = $plist | ForEach-Object {
        $_.Refresh()
        [PSCustomObject]@{
            Name         = $_.Name
            Id           = ($_ | Select-Object Id).Id -as [int]
            HandleCount  = ($_ | Select-Object HandleCount).HandleCount -as [int]
            WorkingSet64 = ($_ | Select-Object WorkingSet64).WorkingSet64
            FileVersion  = ($_ | Select-Object FileVersion).FileVersion
            Path         = ($_ | Select-Object Path).Path
            Threads      = (($_ | Select-Object Threads).Threads | ForEach-Object { $_.Id } | Sort-Object) -join ';'
            UserName     = $_.UserName
            StartTime    = ($_ | Select-Object StartTime).StartTime
        }
    } | Sort-Object -Property Name, Id
    $filtered | Export-Csv -Path "$Path\processes.csv"
    if ($ExportAll) {
        $plist | Export-Csv -Path "$Path\full_processes.csv"
    }
}

Function ConvertTo-ProcessMap {
    Param(
        [Parameter(Mandatory = $true)]
        [Object[]]$List
    )
    $pmap = @{}
    foreach ($process in $List) {
        if (!$pmap.ContainsKey($process.Name)) {
            $pmap[$process.Name] = @{}
        }
        $pmap[$process.Name][$process.Id] = $process
    }
    return $pmap
}

Function Compare-ProcessData {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$OldFile,
        [Parameter(Mandatory = $true)]
        [string]$NewFile,
        [switch]$CheckThreads
    )

    $olist = Import-Csv -Path $OldFile
    $nlist = Import-Csv -Path $NewFile
    $omap = ConvertTo-ProcessMap -List $olist
    $nmap = ConvertTo-ProcessMap -List $nlist
    $pnames = ($omap.Keys + $nmap.Keys) | Sort-Object | Get-Unique
    $newprocesses = @()
    $terminated = @()
    foreach ($name in $pnames) {
        if (!$omap.ContainsKey($name)) {
            $newprocesses += $name
            continue
        }
        if (!$nmap.ContainsKey($name)) {
            $terminated += $name
            continue
        }

        $output = $false
        
        $OldList = $omap[$name]
        $NewList = $nmap[$name]
        if ($OldList.count -ne $NewList.count) {
            Write-Host "$($name): # of processes $($OldList.count) -> $($NewList.count)"
            $output = $true
        }

        $ids = ($OldList.Keys + $NewList.Keys) | Sort-Object | Get-Unique
        foreach ($id in $ids) {
            if (!$NewList.ContainsKey($id)) {
                Write-Host "$name [$id] terminated"
                $output = $true
                continue
            }
            if (!$OldList.ContainsKey($id)) {
                Write-Host "$name [$id] new process"
                continue
            }
            $oproc = $OldList[$id]
            $nproc = $NewList[$id]
            if ($oproc.Path -ne $nproc.Path) {
                Write-Host "$name [$id]: path $($oproc.Path) -> $($nproc.Path)"
                $output = $true
            }
            if ($oproc.FileVersion -ne $nproc.FileVersion) {
                Write-Host "$name [$id]: version $($oproc.FileVersion) -> $($nproc.FileVersion)"
                $output = $true
            }
            if ($CheckThreads -and ($oproc.Threads -ne $nproc.Threads)) {
                $num1 = (Select-String ";" -InputObject $oproc.Threads -AllMatches).Matches.Count + 1
                $num2 = (Select-String ";" -InputObject $nproc.Threads -AllMatches).Matches.Count + 1
                Write-Host "$name [$id]: threads $num1 -> $num2"
                $output = $true
            }
            if ($oproc.UserName -ne $nproc.UserName) {
                Write-Host "$name [$id]: username $($oproc.UserName) -> $($nproc.UserName)"
                $output = $true
            }
            if ($oproc.StartTime -ne $nproc.StartTime) {
                Write-Host "$name [$id]: start time $($oproc.StartTime) -> $($nproc.StartTime)"
                $output = $true
            }
        }

        if ($output) {
            Write-Host "`n-----------------------------------------`n"
        }
    }
    $newprocesses | ForEach-Object {
        Write-Host "New Process: $($_)"
    }
    if ($newprocesses.length -eq 0) {
        Write-Host "No new processes"
    }
    $terminated | ForEach-Object {
        Write-Host "Terminated Process: $($_)"
    }
    if ($terminated.length -eq 0) {
        Write-Host "No terminated processes"
    }
}

Export-ProcessToCsv -Path .
# Compare-ProcessData -OldFile oprocesses.csv -NewFile processes.csv