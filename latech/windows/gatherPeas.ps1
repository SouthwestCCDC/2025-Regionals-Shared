Import-Module ActiveDirectory

. "$env:USERPROFILE\tools\peasParsers\peas2json.ps1"
. "$env:USERPROFILE\tools\peasParsers\json2html.ps1"

$Windows_Comps = Get-ADComputer -Filter "OperatingSystem -like 'Windows*'"

$username = "sys32admin"
$Password = Read-Host -AsSecureString "password guy: "

$cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $Username, $Password

mkdir "$env:USERPROFILE\tools\peasOutputs"

# for ease of development do this sequentially
# in the future do the in parallel per computer basis
foreach ($Computer in $Windows_Comps) {

    $name = $Computer.Name

    $peas = Invoke-Command -ComputerName $name -Credential $cred -Authentication Kerberos -ScriptBlock {

                # Get latest release
                $url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"

                # One liner to download and execute winPEASany from memory in a PS shell
                $wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); 
                [winPEAS.Program]::Main("domain -lolbas")

            }
    $peas | Out-File -FilePath "$env:USERPROFILE\tools\peasOutputs\$($(Computer).Name).txt"
    #peas2json("$name.txt", "$env:USERPROFILE\tools\peasOutputs\$name.json")
    #json2html("$env:USERPROFILE\peasOutputs\$name.json", "$env:USERPROFILE\tools\peasOutputs\$name.html")
}
