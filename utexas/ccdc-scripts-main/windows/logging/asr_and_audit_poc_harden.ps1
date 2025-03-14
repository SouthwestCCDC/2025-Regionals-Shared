# PLEASE REVIEW I HAVE NO EXPERIENCE WITH WINDOWS POWERSHELL SCRIPT
# UNTESTED


#  Start Defender Service
sc start WinDefend
# Enable Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
#  Update signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
#  Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
#  Enable Defender periodic scanning
# reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f


#  Enable early launch antimalware driver for scan of boot-start drivers
#  3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
# reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f

# 
#  Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
#  Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
#  Note these only work when Defender is your primary AV
# 
#  Block Office Child Process Creation 
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
#  Block Process Injection
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
#  Block Win32 API calls in macros
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
#  Block Office from creating executables
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
#  Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
#  Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
#  Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
#  Block lsass cred theft
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
#  Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
#  Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
#  Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
#  Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled

#  ADDING NEW STUFF
#  Block abuse of exploited vulnerable signed drivers	
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
#  Block executable files from running unless they meet a prevalence, age, or trusted list criterion	NOT ADDED: NOT sure if needed
# powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
#  Block Office communication application from creating child processes	
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
#  Block rebooting machine in Safe Mode (preview)	 NOT ADDED: NOT sure if needed
# powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled
# Block use of copied or impersonated system tools (preview)	
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions Enabled
# Block Webshell creation for Servers	
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions Enabled
# Use advanced protection against ransomware	
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled


#Enable Windows Event Detailed Logging
# This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
# For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable


# AUDIT POLICIES BEING SET BASED ON WINDOWS BEST-PRACTICES
# System
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:disable > $null
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable > $null
auditpol /set /subcategory:"IPsec Driver" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable > $null

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Logoff" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable > $null
auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable > $null
auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable > $null
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:disable > $null
auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:disable > $null
auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable > $null

# Object Access
auditpol /set /subcategory:"File System" /success:disable /failure:enable > $null
auditpol /set /subcategory:"Registry" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable > $null
auditpol /set /subcategory:"SAM" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Application Generated" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable > $null
auditpol /set /subcategory:"File Share" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable > $null
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Detailed File Share" /success:disable /failure:enable > $null
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable > $null
auditpol /set /subcategory:"Central Policy Staging" /success:disable /failure:disable > $null

