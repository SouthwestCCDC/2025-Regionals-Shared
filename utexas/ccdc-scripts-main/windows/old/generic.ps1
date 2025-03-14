Function Get-ProcessTree() {

    Function Get-ProcessAndChildProcesses($Level, $Process) {
        "{0}[{1,-5}] [{2}] [{3}]" -f ("  " * $Level), $Process.ProcessId, $Process.Name, $Process.CreationDate
        $Children = $AllProcesses | where-object {$_.ParentProcessId -eq $Process.ProcessId -and $_.CreationDate -ge $Process.CreationDate}
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
    foreach ($Process in $AllProcesses[1..($AllProcesses.length-1)]) {
        $Parent = $AllProcesses | where-object {$_.ProcessId -eq $Process.ParentProcessId -and $_.CreationDate -lt $Process.CreationDate}
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

    $datestr = Get-Date -Format dd-HH-mm
    $datapath = New-Item -ItemType Directory -Path $BackupPath -Name "Generic $datestr"
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
}