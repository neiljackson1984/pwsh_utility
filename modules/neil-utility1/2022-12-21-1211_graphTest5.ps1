#!pwsh
# [System.Reflection.Assembly]::Load("System.IdentityModel.Tokens.Jwt")
# [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
# [System.Reflection.Assembly]::LoadFrom("C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\System.IdentityModel.Tokens.Jwt.dll")
# [System.Reflection.Assembly]::LoadFrom("C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\System.IdentityModel.Tokens.Jwt.dll")
Remove-Module neil-utility1 -ErrorAction SilentlyContinue
Import-Module neil-utility1
# Disconnect-MgGraph 2> $null
# connectToOffice365 -bitwardenItemIdOfTheConfiguration "autoscaninc.com powershell management of office365"
# connectToOffice365 -primaryDomainName "autoscaninc.com"

# doUglyHackToFixDependencyHellFor_System_IdentityModel_Tokens_Jwt
# Import-Module ExchangeOnlineManagement
# Disconnect-ExchangeOnline -confirm:0 
# forceExchangeModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt

$primaryDomainName = "autoscaninc.com"

$doInitialSetup = $true

if($doInitialSetup){
    # for the initial setup, microsoft.grpah version 1.19 cannot succesfully use
    # version 6.21.0.0 of the System.IdentityModel.Tokens.Jwt assembly that
    # ExchangeOnlineMAnagementModule uses. so, for initial setup, we have to
    # ensure that Microsfot.Graph's preferred version of this assembly is
    # loaded. But then, for normal operation, we need to have
    # ExchangeOnlineManagement's version of the assemlby loaded, because
    # ExchangeOnlineManagement module will not work with Graph's preferred
    # version of the assembly.  They don't call it dll hell for nothing.

    bw sync
    bw delete item (getBitwardenItem "$($primaryDomainName.Trim().ToLower()) companyParameters" )['id']
    bw delete item (getBitwardenItem "$($primaryDomainName.Trim().ToLower()) powershell management of office36" )['id']
    connectToOffice365 -tenantIdHint $primaryDomainName -makeNewConfiguration
} else {
    forceExchangeModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt
    connectToOffice365 -primaryDomainName $primaryDomainName
}


Write-Host "ready"

return
