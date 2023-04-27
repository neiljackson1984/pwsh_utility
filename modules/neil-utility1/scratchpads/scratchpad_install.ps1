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


# 2023-04-27-1317
#%%
Get-InstalledModule | Sort Name
Get-Help Install-Module -Online
Get-Help Get-InstalledModule -Online
Update-Help

Get-PSRepository | fl
Get-PSRepository | get-member
@(Get-PSRepository)[0].PackageManagementProvider | fl
@(Get-PSRepository)[0].PackageManagementProvider.GetType().FullName

Get-PackageProvider | fl
@(Get-PackageProvider)[0].GetType().FullName

Find-PackageProvider

#see [https://learn.microsoft.com/en-us/powershell/gallery/how-to/working-with-local-psrepositories?view=powershellget-2.x]
#%%
$pathOfLocalRepository = "c:\work\neil-powershell-repository1"
$nameOfLocalRepository = (split-path $pathOfLocalRepository -Leaf)
New-Item  $pathOfLocalRepository -ItemType 'Directory' -ErrorAction SilentlyContinue
Unregister-PSRepository -Name $nameOfLocalRepository
@{
    Name                    = $nameOfLocalRepository
    SourceLocation          = $pathOfLocalRepository
    # ScriptSourceLocation    = $pathOfLocalRepository
    InstallationPolicy      = 'Trusted'
} | % {Register-PSRepository @_}
#%%
# Unregister-PSRepository -Name "neil-ps-repository1"
# 
#%%
Get-Help -Online Register-PSRepository
Get-Help -Online UnRegister-PSRepository
Get-Help -Online Publish-Module
Get-Help -Online Test-ModuleManifest
Get-Help  Publish-Module

#%%
# @{
#     Name = 'ConnectWiseControlAPI'
#     Repository = 'PSGallery'
#     AcceptLicense = $True
#     Path = $pathOfLocalRepository
# } | % { Save-Module @_ }
#%%
@{
    Name = 'ConnectWiseControlAPI'
    # Source = 'PSGallery'
    Source = (Get-PackageSource PSGallery).Location

    # AcceptLicense = $True
    Path = $pathOfLocalRepository
} | % { Save-Package @_ }
#%%
Get-PackageSource PSGallery | fl

Get-Package 'ConnectWiseControlAPI'
Find-Package 'ConnectWiseControlAPI' | fl
$pathOfModuleManifestFile = "C:\work\pwsh_utility\modules\neil-utility1\neil-utility1.psd1"
$pathOfModule = (split-path $pathOfModuleManifestFile -Parent)
@{
    Path = $pathOfModule
    Repository = $nameOfLocalRepository
} | % {Publish-Module @_}

#>>>  Publish-PSArtifactUtility: PowerShellGet cannot resolve the module dependency
#>>>  'ConnectWiseControlAPI' of the module 'neil-utility1' on the repository
#>>>  'neil-powershell-repository1'. Verify that the dependent module
#>>>  'ConnectWiseControlAPI' is available in the repository
#>>>  'neil-powershell-repository1'. If this dependent module
#>>>  'ConnectWiseControlAPI' is managed externally, add it to the
#>>>  ExternalModuleDependencies entry in the PSData section of the module manifest.

# After I added said ExternalModuleDependencies entry, the above command than
# ran succesfully. I happened to have the ConnectWiseControlAPI module installed
# when I ran the above command -- I am not sure how, if at all, the fact of a
# dependency being installed affects the operation of the above command -- I
# would expect it to have no effect.
#
# The result of running the above commnad is that a single file, named
# "neil-utility1.0.0.1.nupkg" appeared in the directory $pathOfLocalRepository .
# The nupkg file seemed to contain absolutely every file from the directory
# $pathOfModule, along with several newly-created files containing metadata.
#%%



Test-ModuleManifest $pathOfModuleManifestFile
explorer.exe "/root,$($pathOfLocalRepository)"
Install-Module -confirm:$false -force 'ConnectWiseControlAPI'
Get-InstalledModule 'ConnectWiseControlAPI' | fl
Get-Module 'ConnectWiseControlAPI' | fl
Import-Module 'ConnectWiseControlAPI' 

Get-InstalledModule 'ConnectWiseControlAPI'
Get-InstalledModule 'neil-utility1'

UnInstall-Module 'ConnectWiseControlAPI'
UnInstall-Module -Force 'ConnectWiseControlAPI'
Uninstall-Module -Force  'neil-utility1'

##>>>   PS U:\scripting_journal> UnInstall-Module 'ConnectWiseControlAPI'
##>>>   Uninstall-Package: The module 'ConnectWiseControlAPI' of version '0.3.5.0' in module base folder 'C:\Users\Admin\Documents\PowerShell\Modules\ConnectWiseControlAPI\0.3.5.0' cannot be uninstalled, because one or more other modules 'neil-utility1' are dependent on this module. Uninstall the modules
##>>>   that depend on this module before uninstalling module 'ConnectWiseControlAPI'.
##>>>   PS U:\scripting_journal> Uninstall-Module 'neil-utility1'
##>>>   Uninstall-Package: No match was found for the specified search criteria and module names 'neil-utility1'.
##>>>   PS U:\scripting_journal> 

UnInstall-Module 'ConnectWiseControlAPI' -Force
UnInstall-Module 'neil-utility1' -Force
UnInstall-Package 'neil-utility1' -Force

#%%
Install-Module -Name "neil-utility1"  -Repository "neil-powershell-repository1"
Install-Module -Name "ConnectWiseControlAPI"  -Repository "neil-powershell-repository1"
#%%
Import-Module neil-utility1
Import-Module -Force neil-utility1
Get-Module neil-utility1 | fl
Get-InstalledModule neil-utility1 | fl

Find-Module neil-utility1

Get-Package 'ConnectWiseControlAPI' | fl
Find-Package 'ConnectWiseControlAPI' | fl

Install-Package 'ConnectWiseControlAPI'
Get-InstalledModule 'ConnectWiseControlAPI' | fl
(Get-InstalledModule 'ConnectWiseControlAPI').Metadata
(Find-Package 'ConnectWiseControlAPI').Metadata.GetType().FullName
(Find-Package 'ConnectWiseControlAPI').Metadata | get-member
(Find-Package 'ConnectWiseControlAPI') | fl
(Find-Package 'ConnectWiseControlAPI').Metadata['PackageManagementProvider']

Find-Package '*7zip*'
Get-PackageSource
winget --help

winget source list

get-packageprovider
find-module xjea

update-module PowershellGet
Get-Module PowershellGet
Install-Module PowerShellGet
Get-InstalledModule PowerShellGet 

Find-Module PowershellGet | fl
Start-Process "$((Find-Module PowershellGet ).ProjectUri)"

Get-Module PowershellGet | fl