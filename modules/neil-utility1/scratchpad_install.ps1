# %%

#!powershell

# install this package (in a possibly hacky way -- more research is needed to optimize the installation process)

$PSHOME
$env:PSModulePath -split ";" | select-object -First 1

ls ~/Documents


"$(Resolve-Path ~)"
$env:userprofile



pwsh -c '[String]$($psversiontable.PSVersion)'
powershell -c '[String]$($psversiontable.PSVersion)'

# %%
$probe = ([String] @'
write-host "version: $([String]$($psversiontable.PSVersion))"
write-host "PSHOME: $PSHOME"
write-host "env:psModulePath: $($env:PSModulePath)" 
# write-host "psModulePath: $($PSModulePath)"
# write-host "PROFILE: "; $PROFILE | Get-Member -Type NoteProperty
'@
)


pwsh -c $probe 
powershell -c $probe



# %%

enable-ipv6
Get-Module ipv6-control
Get-Module pwsh_utility

get-module -ListAvailable

Import-Module ipv6-control

# %%
# importing non-core modules into pwsh - possible?
Get-Module (Get-Command Get-NetAdapter).Source | fl
Get-Module (Get-Command enable-ipv6).Source | fl
(Get-Command enable-ipv6).Source | fl
Get-Module -ListAvailable neil-utility1 | fl
Get-Command -Module neil-utility1
Import-Module neil-utility1
$env:psModulePath
$env:psModulePath = "c:\windows\system32\windowspowershell\v1.0\Modules;$($env:psModulePath)"
exit
powershell
pwsh
Get-Netadapter

Import-Module "C:\work\pwsh_utility\modules\neil-utility1\neil-utility1.psm1" -verbose
Import-Module "C:\work\pwsh_utility\modules\neil-utility1\neil-utility1.psd1" -verbose
Import-Module (Get-Module -ListAvailable neil-utility1 ).Path -verbose
Get-Command enable-ipv6 | get-member
(Get-Command enable-ipv6).Source
(Get-Command enable-ipv6).ScriptBlock | get-member
(Get-Command enable-ipv6).ScriptBlock.File
New-ModuleManifest 

. & "C:\work\pwsh_utility\modules\neil-utility1\neil-utility1.psm1"

(Test-ModuleManifest "C:\work\pwsh_utility\modules\neil-utility1\neil-utility1.psd1").ExportedCommands | fl

Resolve-Path "." | get-member

disable-ipv6
enable-ipv6

pwsh -c "disable-ipv6"
pwsh -c "enable-ipv6"

powershell -c "disable-ipv6"
powershell -c "enable-ipv6"

(Get-Module 'ExchangeOnlineManagement').Path 
Import-Module 'ExchangeOnlineManagement' 
$env:psModulePath -split ";"

(Get-InstalledModule 'ExchangeOnlineManagement').InstalledLocation
(Get-InstalledModule 'AzureADPreview').InstalledLocation
(Get-InstalledModule 'AzureADPreview') | fl
#>>> C:\Program Files\WindowsPowerShell\Modules\ExchangeOnlineManagement\3.0.0


[Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') -split [IO.Path]::PathSeparator
[Environment]::GetEnvironmentVariable('PSModulePath', 'User') -split [IO.Path]::PathSeparator

(join-path $env:ProgramFiles "WindowsPowerShell/Modules")
powershell Install-Module -Name Microsoft.Graph 

import-module ./utility.psm1
addEntryToPSModulePathPersistently "C:\work\pwsh_utility\modules"