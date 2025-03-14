# https://nmap.org/dist/nmap-7.94-setup.exe
# https://npcap.com/dist/npcap-1.79.exe


$cidrs = ,"10.10.0.2/31"
$output_file = "Output.csv"


### Calculating IPs
Write-Host $cidrs
$output = nmap $cidrs -sL -n -oX - --noninteractive --no-stylesheet
$xml = [XML]$output
$total = $xml.nmaprun.host.count
Write-Host "Checking $total IPs..."
Write-Host ""

### Find Targets
Write-Host "Finding Targets"
$output = nmap $cidrs -sn -n -T5 -oX - --noninteractive --no-stylesheet --privileged
$xml = [XML]$output
$targets = $xml.nmaprun.host

### Enumerate Targets and Populate Results
$results = $targets | ForEach-Object -Parallel {
  $result = New-Object PSObject

  $address = $_.address.addr
  Add-Member -InputObject $result NoteProperty "Address" $address

  Write-Host "Beginning Scan of $address"

  $output = nmap $address -Pn -R --system-dns -sV --version-light -O --osscan-limit -T5 -oX - --open --noninteractive --no-stylesheet --privileged
  $xml = [XML]$output

  $target = $xml.nmaprun.host
  Add-Member -InputObject $result NoteProperty "Hostnames" ($target.hostnames.hostname.name -join ';')
  Add-Member -InputObject $result NoteProperty "OS" $target.os.osmatch.name[0]
  Add-Member -InputObject $result NoteProperty "Ports" ($target.ports.port.portid -join ';')

  Write-Host "Completed Scan of $address"

  $result
}

### Save Results to CSV
Remove-Item $output_file
foreach ($result in $results) {
  Export-Csv -InputObject $result $output_file -Append
}
notepad.exe $output_file
