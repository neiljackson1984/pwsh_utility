
<#  Ugly hack to try to work around dll hell between Exchange Online module and
    MGGraph module:

    ```
    [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
    [System.Reflection.Assembly]::LoadFrom("C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\System.IdentityModel.Tokens.Jwt.dll") 
    ```

#>

function forceExchangeModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt(){
    # [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
    # 
    # I am well aware that this is extremely heavy-handed, and actually wrong if we happen to be in windows powershell rather than powershell core.

    # It seems that the Microsoft.Graph module is actually perfectly content,
    # and fully functional, if all of the assemblies included with the Exchange
    # module (including System.IdentityModel.Tokens.Jwt version 6.21.0.0) happen
    # to already be loaded.  I think I was noticing problems (the
    # Microsoft.Identity logging error) when I ran Microsoft.Graph after only
    # having explicitly loaded System.IdentityModel.Tokens.Jwt version 6.21.0.0,
    # and not the Exhange Module's other assemblies.
    # System.IdentityModel.Tokens.Jwt version 6.21.0.0 was loaded, but the graph
    # module was then trying to load the older versions of some other assemblies
    # (like the one responsilbe for Microsoft.Identity logging) that probably
    # themselves expected to work with the older version of the
    # System.IdentityModel.Tokens.Jwt assembly.

    $pathOfRootFolderOfExchangeModule = (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation 

    # $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file = (join-path $pathOfRootFolderOfExchangeModule "netCore/System.IdentityModel.Tokens.Jwt.dll")
    $pathsOfRootAssembliesToForce = @(
        (join-path $pathOfRootFolderOfExchangeModule "netCore/System.IdentityModel.Tokens.Jwt.dll")
        (join-path $pathOfRootFolderOfExchangeModule "netCore/Microsoft.Identity.Client.dll")
        (join-path $pathOfRootFolderOfExchangeModule "netCore/Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll")
    )


    foreach ($pathOfRootAssemblyToForce in $pathsOfRootAssembliesToForce){
        $assembliesToLoad = @(
                @{
                    rootAssembly = (
                        [System.Reflection.Assembly]::LoadFile(
                            $pathOfRootAssemblyToForce
                        )
                    )

                    filter = { Test-SubPath -ChildPath $_.Location -ParentPath  $pathOfRootFolderOfExchangeModule}

                    pathHints = @(
                        Split-Path $pathOfRootAssemblyToForce -Parent
                    )

                } |% {getReferencedAssembliesRecursivelyForReflection @_ }
            )

        $pathsOfDllFilesToLoad = @(
            # (join-path $pathOfRootFolderOfExchangeModule "netCore/System.IdentityModel.Tokens.Jwt.dll")
        
            # (Get-ChildItem `
            #     -Path (join-path $pathOfRootFolderOfExchangeModule "netCore") `
            #     -Recurse `
            #     -Include "*.dll" 
            # ) | foreach-object {$_.FullName}

            $assembliesToLoad | foreach-object {$_.Location}
        )

        Write-Debug "We will now attempt to load the following $($pathsOfDllFilesToLoad.Length) dll files: "
        $pathsOfDllFilesToLoad | Write-Debug

        foreach(
            $pathOfDllFile in $pathsOfDllFilesToLoad
        ){
            try { 
                $private:ErrorActionPreference = "Stop"
                [System.Reflection.Assembly]::LoadFrom($pathOfDllFile) 1> $null
            } catch {
                Write-Debug "Catching an error: $_"
            }
        }
    }

    
    # Import-Module ExchangeOnlineManagement
    # Disconnect-ExchangeOnline -confirm:$false
    
    $(
        [System.AppDomain]::CurrentDomain.GetAssemblies() | 
            Where-Object Location | 
            Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
            Sort-Object -Property FullName | 
            Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted  
    ) | Write-Debug
}

function forceGraphModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt(){
    # [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll"))
    
    # Import-Module ExchangeOnlineManagement
    # Disconnect-ExchangeOnline -confirm:$false
    
    foreach(
        $pathOfDllFile in 
        @(
            (join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll")
        )
    ){
        try { 
            $private:ErrorActionPreference = "Stop"
            [System.Reflection.Assembly]::LoadFrom($pathOfDllFile)
        } catch {
            Write-Debug "Catching an error: $_"
        }
    }


    [System.AppDomain]::CurrentDomain.GetAssemblies() | 
        Where-Object Location | 
        Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
        Sort-Object -Property FullName | 
        Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted |
        fl
}

function forceLoadConflictingAssemblies(){
    <#

        2023-12-20-1653 : Loads several assemblies from the
        Microsoft.Graph.Authentication module and ExchangeOnlineManagement that
        must be loaded in a particular order in order not to cause a dll
        hell/diamond problem.

        2023-12-20-1653: There was some change to the order that was needed
        after updating the Microsoft.Graph and ExchangeOnlineManagement modules
        today to the latest version.


    #>
    [CmdletBinding()]
    Param()

    $rootAssembliesToForceSpecs = @(
        <#  Coming up with a working list of specs here is purely trial and error
            guided (sort of) by the error messages. 
        #>
        @{
            nameOfModule                      = "Microsoft.Graph.Authentication"
            relativePathOfRootAssemblyToForce = "Dependencies/Core/Microsoft.Identity.Client.dll"
        }
        @{
            nameOfModule                      = "Microsoft.Graph.Authentication"
            relativePathOfRootAssemblyToForce = "Dependencies/Core/Microsoft.Graph.Core.dll"
        }
        @{
            nameOfModule                      = "Microsoft.Graph.Authentication"
            relativePathOfRootAssemblyToForce = "Dependencies/Core/Azure.Core.dll"
        }
        @{
            nameOfModule                      = "Microsoft.Graph.Authentication"
            relativePathOfRootAssemblyToForce = "Dependencies/Microsoft.Kiota.Authentication.Azure.dll"
        }
        @{
            nameOfModule                      = "ExchangeOnlineManagement"
            relativePathOfRootAssemblyToForce = "netCore/System.IdentityModel.Tokens.Jwt.dll"
        }
        ## @{
        ##     nameOfModule                      = "ExchangeOnlineManagement"
        ##     relativePathOfRootAssemblyToForce = "netCore/Microsoft.Identity.Client.dll"
        ## }
        ## @{
        ##     nameOfModule                      = "ExchangeOnlineManagement"
        ##     relativePathOfRootAssemblyToForce = "netCore/Azure.Core.dll"
        ## }
        @{
            nameOfModule                      = "ExchangeOnlineManagement"
            relativePathOfRootAssemblyToForce = "netCore/Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll"
        }
    )

    foreach ($spec in $rootAssembliesToForceSpecs){
        $pathOfRootFolderOfModule  = (Get-InstalledModule $spec.nameOfModule).InstalledLocation
        $pathOfRootAssemblyToForce = join-path $pathOfRootFolderOfModule $spec.relativePathOfRootAssemblyToForce
        
        $assembliesToLoad = @(
            @{
                rootAssembly = [System.Reflection.Assembly]::LoadFile( $pathOfRootAssemblyToForce )
                # filter = { Test-SubPath -ChildPath $_.Location -ParentPath $pathOfRootFolderOfModule }
                filter = [ScriptBlock]::Create("Test-SubPath -ChildPath `$_.Location -ParentPath '$pathOfRootFolderOfModule' ")
                pathHints = @(
                    Split-Path $pathOfRootAssemblyToForce -Parent
                )

            } | % { getReferencedAssembliesRecursivelyForReflection @_ }
        )

        $pathsOfDllFilesToLoad = @(
            $assembliesToLoad |
            % {$_.Location}
        )

        Write-Debug "We will now attempt to load the following $($pathsOfDllFilesToLoad.Length) dll files: "
        $pathsOfDllFilesToLoad | Write-Debug

        foreach(
            $pathOfDllFile in $pathsOfDllFilesToLoad
        ){
            try { 
                $private:ErrorActionPreference = "Stop"
                [System.Reflection.Assembly]::LoadFrom($pathOfDllFile) 1> $null
            } catch {
                Write-Debug "Catching an error: $_"
            }
        }
    }
}

function doUglyHackToFixDependencyHellFor_System_IdentityModel_Tokens_Jwt(){
    # see https://stackoverflow.com/questions/72490964/powershell-core-resolving-assembly-conflicts
    # see https://stackoverflow.com/questions/68972925/powershell-why-am-i-able-to-load-multiple-versions-of-the-same-net-assembly-in

    
    #%%
    # look at the versions of the assemblies in the dlls used by Exchange and
    # Graph.  OVerwrite the higher-versioned asesmbly to the path o fthe
    # lower-versioned assembly.

    $dllPathsSortedByVersion =@(
        @(
            #pathOfDllUSedByExchange:
            (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")

            #pathOfDllUsedByGraph:
            (join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll")

        ) | Sort-Object -Property {[System.Reflection.Assembly]::LoadFile($_).GetName().Version}
    )

    $dllPathsSortedByVersion | foreach-object {"$([System.Reflection.Assembly]::LoadFile($_).GetName().Version)    $($_)"}
    $versions = $dllPathsSortedByVersion | foreach-object {[System.Reflection.Assembly]::LoadFile($_).GetName().Version}
    if ($versions[0] -eq $versions[1]){
        Write-Host "both versions are the same, namely version $($versions[0])"
    } else {
        Write-Host "moving newer-versioned file ($($dllPathsSortedByVersion[1]), version $($versions[1])) to path of older-versioned file ($($dllPathsSortedByVersion[0]), version $($versions[0]))."
        Move-Item -Force -Confirm:$false $dllPathsSortedByVersion[0] "$($dllPathsSortedByVersion[0]).setaside"
        Copy-Item $dllPathsSortedByVersion[1] $dllPathsSortedByVersion[0] 
    }
    #%%

    # check to see which version of the problematic assembly is loaded:
    [System.AppDomain]::CurrentDomain.GetAssemblies() | 
        Where-Object Location | 
        Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
        Sort-Object -Property FullName | 
        Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted |
        fl

    #%%
}

<#  2022-12-21-1142. I was not able to make the "2.0.0-preview1" or
    "2.0.0-preview2" versions of the Microsoft.Graph module work correctly.
    Specifically, when attempting to set the Application KeyCredentials I would
    get an error complaining that "the literal ... cannot be converted to
    edm.binary" (or something to that effect) the error message makes me think
    that the preview versions are not correctly encoding the byte array into a
    url-safe base64 string.  My only recourse is to revert to the non-preview
    version of Microsoft.Graph, which is problematic because of the dll  hell
    issue.  (The preview versions also hjad a dll hell conflict with
    ExchangeOnlineManagement module, but at least the preview versions used a
    version of the conflicting assembly that was closer to the one Exchange was
    using (both 6.something) that (I think) the two modules worked corectly with
    either version of the assembly.  The non-preview verison of the
    Microsoft.Graph module uses a 5.something version of the conflicting
    assembly, which I suspect makes my workaround less likely to work. 
#>


Import-Module (join-path $psScriptRoot "utility.psm1")

<#  2022-12-18 todo: store the certificate (and private key) in bitwarden rahter
    than what we are curently doing (which is storing the certificate and
    private key on the local machine's  certificate store and storing the
    certificate's thumbprint (i.e. hash) in the configuration that we store in
    bitwarden. 
#>

<#  2022-12-18 todo: allow us to specify the tenant somehow (perhaps by one of
    the domain names -- those are fairly unique within azure active directory, I
    think) when we are creating a fresh configuration and creating a new
    bitwarden entry. this would be useful for initial setup in a declarative,
    understandable, unambiguous way. 
#>

<#  todo: handle nonexisting or more-than-one-existing bitwarden item (because
    we can use the name as item id if its unique, but of course the name might
    not be unique (what happens if an item has a name that is the itemId of
    another item -- what happens when you do a get for that itemId?) ) cases
    more intelligently. 
#>

# private
function Script:getCanonicalNameOfBitwardenItemBasedOnPrimaryDomainName {
    [OutputType([String])] # really I mean a nullable string
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True
        )]
        [String] $primaryDomainName
    )
    
    if($primaryDomainName.Trim().ToLower()){
        "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement"
    } else {
        $null
    }
}

function Install-MicrosoftGraphDependencies {
    [CmdletBinding()]
    [OutputType([Void])]
    param ()
    <#  This whole function is a bit of a hack; I'm sure this is not the
        preferred cleanest way to install depencies, but it is marginally better
        then putting these commands in comments somewhere, which is how I've
        been doing it until now. 
    #>
    process {
        
        @(
            "Microsoft.Graph"
            "Microsoft.Graph.Beta"
            "ExchangeOnlineManagement"
            "PnP.PowerShell"
        ) | % { 
            <#  During testing, before running this function, I go manually delete any
                graph, Exchange, and pnp -related folders from within the following folders:
                  * %programfiles%\WindowsPowerShell\Modules 
                  * %userprofile%\Documents\PowerShell\Modules
                  * %userprofile%\Documents\WindowsPowerShell\Modules (this folder does not exist as of 2023-02-26-1411 (I deleted it)) 
            #>

            Write-Host "now installing $($_) in Windows Powershell."
            powershell -c "Install-Module -Confirm:0 -Force -AllowPrerelease -Name $($_)"
            <#  I don't think I am using windows powershell at all anymore, so
                installing the modules in windows in windows powershell is
                probably completely unnecessary and serves no purpose. 
            #>

            Write-Host "now installing $($_) in Powershell core."
            pwsh -c "Install-Module -Confirm:0 -Force -AllowPrerelease -Name $($_)"

        }
    }

    <#  As of 2023-02-26-1616, in order to avoid the Edm.Binary error when
        creating a new configuration we must have something prior to the 2.0
        version of mggraph installed. Could the edm.binary error be related to
        newtonsoft json dll hell? 
    #>
    
    ## pwsh -c "Install-Module -Confirm:0 -Force -Name Microsoft.Graph -MaximumVersion 1.22"  
    ## pwsh -c "Install-Module -Confirm:0 -Force -AllowPrerelease -Name Microsoft.Graph"   
    ## pwsh -c "Install-Module -Confirm:0 -Force -AllowPrerelease -Name PnP.PowerShell"   

}

function getBitwardenItemContainingMicrosoftGraphManagementConfiguration {
    <#  2022-12-20 at the moment, this function is only used in the setup of new
        configurations.  It is not used by the conectToOffice365 function in the
        normnal course of established operations. However, I have half a mind to
        give the ability of connectToOffice365 the ability to accept,as an
        alternative to the bitwarden item id of a configuration, a primary
        domain name of the tenant.  In that case, I will have
        connectToOffice365() use this function to (attempt to) get the
        configuration. 
    #>
    [OutputType([HashTable])] # really I mean a nullable hasthable.
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True
        )]
        [String] $primaryDomainName,

        [Parameter(
        )]
        [Switch] $createIfNotAlreadyExists
    )
    Write-Host "now working on $($primaryDomainName.ToLower())"
    $nameOfBitwardenItem = getCanonicalNameOfBitwardenItemBasedOnPrimaryDomainName $primaryDomainName
    <#   We are relying on this function agreeing with connectToOffice365()
        about the name format. this is a little bit inelegant. 
    #>
    $bitwardenItem = getBitwardenItem $nameOfBitwardenItem
    if($bitwardenItem){
        Write-Host "Found a suitable existing bitwarden item, whose id is $($bitwardenItem['id'])."
    } else {
        if($createIfNotAlreadyExists){
            Write-Host ""
            Write-Host "======================="
            Write-Host "We will now construct Microsoft Graph management credentials for $($primaryDomainName.ToLower()).  Please respond to the authorization prompt(s) accordingly."
            Write-Host "$($primaryDomainName.ToLower())"
            Write-Host "======================="
            Write-Host ""
            connectToOffice365 -makeNewConfiguration:$true -tenantIdHint:$($primaryDomainName.ToLower()) | Write-Host

            $bitwardenItem = getBitwardenItem $nameOfBitwardenItem
            if($bitwardenItem){
                Write-Host "After constructing a fresh configuration, we have now found a suitable bitwarden item, whose id is $($bitwardenItem['id'])."
            } else {
                Write-Host "After constructing a fresh configuration, we are still unable to find a suitable bitwarden item."    
            }
        }
    }
    return $bitwardenItem
}

Function getRoleSpecificationsExpression(){
    <#  This function is for debugging and verification: it can be used to
        generate an expression for $roleSpecifications that can be pasted above
        (starting with an app that has been manually configured in the desired
        way. 
    #>
    
    param(
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal]  $servicePrincipalForApp
    )
    
    <#  how to construct $roleSpecifications programmatically, if needed:

        we can look up the proper/allowed $roleSpecifications by doing the
        following in a tenant that is already properly set up. this assumes
        that $azureAdServicePrincipal is the service principal for the app
        that we have created. 
    #>


    
    $roleSpecifications = @(
        foreach( $idOfTargetServicePrincipal in @(
                Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalForApp.Id |
                    foreach-object {$_.ResourceId} | 
                    select -Unique
            )  
        ){
            $appRoleIds = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalForApp.Id |
                Where-Object {$_.ResourceId -eq $idOfTargetServicePrincipal} |
                ForEach-Object {$_.AppRoleId}
            @{
                nameOfTargetServicePrincipal = (Get-MgServicePrincipal -ServicePrincipalId $idOfTargetServicePrincipal).DisplayName;
                namesOfRequiredAppRoles = @(
                    (Get-MgServicePrincipal -ServicePrincipalId $idOfTargetServicePrincipal).AppRoles |
                    Where-Object {$_.Id -in $appRoleIds} |
                    foreach-object {$_.Value}
                )
            }
        }
    )
    
    

    $roleSpecificationsExpression = `
        "`$roleSpecifications = @(`n" `
        + (
            (
                &{
                    foreach ($roleSpecification in $roleSpecifications){      
                        "`t"*1 + "@{`n" `
                        + "`t"*2 +   "nameOfTargetServicePrincipal" + " = " + "'" + $roleSpecification.nameOfTargetServicePrincipal + "'" + ";" + "`n" `
                        + "`t"*2 +   "namesOfRequiredAppRoles" + " = " + "@(" + "`n" `
                        + (($roleSpecification.namesOfRequiredAppRoles | foreach-object {"`t"*3 + "'" + $_ + "'"}) -Join ",`n") + "`n" `
                        + "`t"*2 +   ")" + "`n" `
                        + "`t"*1 + "}"
                    } 
                }
            ) -Join ",`n"
        )  `
        + "`n" + ")`n"

    $roleSpecificationsExpression
    
    
    #=== LEFTOVERS: 
    # $targetServicePrincipal = Get-AzureADServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"
    # $namesOfAllAvailableAppPermissions = $targetServicePrincipal.AppRoles | foreach-object {$_.Value}

    # #or, while working in some other tenant that is set up properly, by doing
    # $namesOfAppPermissionsThatWeWant = `
        # Get-AzureADServiceAppRoleAssignment -ObjectId $azureAdServicePrincipal.ObjectId |
        # where {$_.ResourceId -eq $targetServicePrincipal.ObjectId} -PipelineVariable roleAssignment |
        # foreach-object { ($targetServicePrincipal.AppRoles | where {$_.Id -eq $roleAssignment.Id}).Value }
    
    # $namesOfTargetServicePrincipals =  `
        # Get-AzureADServiceAppRoleAssignment -ObjectId $azureAdServicePrincipal.ObjectId | 
        # select -Unique ResourceId |
        # foreach-object { (Get-AzureADObjectByObjectId -ObjectIds @($_.ResourceId  )).DisplayName}

}

function getNamesOfAllAppRolesSupportedByServicePrincipal{
    [CmdletBinding()]
    [OutputType([string])]
    
    Param(
        [string] $idOfServicePrincipal,
        [switch] $excludeRedundantReadRoles = $False
    )

    ## $targetServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $targetServicePrincipal.Id -Property AppRoles,Oauth2PermissionScopes,ResourceSpecificApplicationPermission
    $targetServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $idOfServicePrincipal -Property *

    $namesOfAppRoles = @(
        (Get-MgServicePrincipal -ServicePrincipalId $targetServicePrincipal.Id -Property AppRoles).AppRoles | select -expand Value
        (Get-MgServicePrincipal -ServicePrincipalId $targetServicePrincipal.Id -Property Oauth2PermissionScopes).Oauth2PermissionScopes | select -expand Value
        (Get-MgServicePrincipal -ServicePrincipalId $targetServicePrincipal.Id -Property ResourceSpecificApplicationPermissions).ResourceSpecificApplicationPermissions | select -expand Value
    ) | select -unique

    if($excludeRedundantReadRoles){
        $namesOfAppRolesWithoutRedundantReadRoles = excludeRedundantReadRoleNamesFromASetOfAppRoleNames $namesOfAppRoles
        return $namesOfAppRolesWithoutRedundantReadRoles
    } else {
        return $namesOfAppRoles
    }
    


    <#
        I do not fully understand the relationship between a servcie principal's
        AppRoles, Oauth2PermissionScopes, ResourceSpecificApplicationPermissions
        .

        I suspect that both Oauth2PermissionScope and
        ResourceSpecificApplicationPermission are, in some sense (but not in the
        powershell graph model in the strict sense), subclasses of AppRole.

        I am trying to return all possible supported app role names, and am
        willing to incorrectly return a few names that might not be app role
        names.
    #>

}

function excludeRedundantReadRoleNamesFromASetOfAppRoleNames([string[]] $namesOfAppRoles){
    @(
        @(
            foreach($candidate in $namesOfAppRoles){
                $partsOfCandidate = @($candidate -split "\.")
                if(
                    ## $partsOfCandidate[1] -eq "Read"
                    $partsOfCandidate[1] -in "Read","Write"
                ){
                    # only allow this candidate through if there is not a matching
                    # "ReadWrite" AppRole in the list
                    $correspondingReadWriteAppRole = $(
                        $namesOfAppRoles |
                        ? {
                            $innerCandidate = $_
                            $partsOfInnerCandidate = @($innerCandidate -split "\.")
                            (
                                ($partsOfInnerCandidate -eq "ReadWrite") -and
                                ($partsOfInnerCandidate[0] -eq $partsOfCandidate[0]) -and
                                ($partsOfInnerCandidate[2] -eq $partsOfCandidate[2]) 
                            )
                        } |
                        select -first 1
                    )
                    
                    if($correspondingReadWriteAppRole){
                        ## don't return anything here.
                    } else {
                        $candidate
                    }

                }  else {
                    $candidate
                }
            }
        ) |
        select -unique
    )
}

function connectToOffice365 {
    <#  To get pre-requisites:

        ```
        Install-Module -Confirm:$false -Force -Name 'AzureAD', 'ExchangeOnlineManagement', 'PnP.PowerShell'
        Install-Module -Confirm:$false -Force -Name 'AzureADPreview', 'ExchangeOnlineManagement', 'PnP.PowerShell'
        UnInstall-Module -Confirm:$false -Force -Name 'AzureAD'
        UnInstall-Module -Confirm:$false -Force -Name 'AzureADPreview'
        ```

        To make this work with Powershell Core (which, as of 2021-10-26, does
        not work out of the box with the AzureAD module), install the following
        special version of the AzureAD module as follows: (thanks to
        https://endjin.com/blog/2019/05/how-to-use-the-azuread-module-in-powershell-core)

        ```
           # Check if test gallery is registered
           $packageSource = Get-PackageSource -Name 'Posh Test Gallery'
           if (!$packageSource)
           {
            $packageSource = Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'Posh Test Gallery' -Location 'https://www.poshtestgallery.com/api/v2/'
           }

           # Check if module is installed
           $module = Get-Module 'AzureAD.Standard.Preview' -ListAvailable -ErrorAction SilentlyContinue

           if (!$module) 
           {
             Write-Host "Installing module AzureAD.Standard.Preview ..."
             $module = Install-Module -Name 'AzureAD.Standard.Preview' -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber 
             Write-Host "Module installed"
           }
        ```




        update 2022-09-16:

        to get prerequisistes:

        AzureADPreview (and AzureAD) STILL does not work completely correctly
        under powershell core. The -UseWindowsPowerShell  option of powershell
        core's Import-Module function seemed promising as a way to use the
        windowsPowershell module from within powershell core, but the
        serializing of the command output is a dealbreaker.  Therefore, we are
        STILL constrained to use windowsPowershell and not powershell core.

        ```
        powershell -c "Install-Module -Confirm:0 -Force -Name AzureADPreview"
        powershell -c "Install-Module -Confirm:0 -Force -Name ExchangeOnlineManagement -AllowPrerelease"
        powershell -c "Install-Module -Confirm:0 -Force -Name PnP.PowerShell"

        powershell -c "Install-Module -Confirm:0 -Force -Name Microsoft.Graph" 
        pwsh -c "Install-Module -Confirm:0 -Force -Name Microsoft.Graph"

        powershell -c (@(
            "Install-Module -Confirm:0 -Force -Name Microsoft.Graph -AllowPrerelease; Install-Module -Confirm:0 -Force -Name ExchangeOnlineManagement -AllowPrerelease"
            "Install-Module -Confirm:0 -Force -Name PnP.PowerShell"
        ) -join "; ") 
        
        
        pwsh -c "Install-Module -Confirm:0 -Force -Name Microsoft.Graph.Beta -AllowPrerelease"
        pwsh -c "Install-Module -Confirm:0 -Force -Name PnP.PowerShell -AllowPrerelease"
        ```

    #>
    <#  When I attempt connect-azuread in powershell core (even when I am using
        the version of connect-azuread from the AzureAD.Standard.Preview
        module), I encounter the error "Certificate based authentication is not
        supported in netcore version." I take that as the nail in the coffin of
        the hope of using this script from within powershell core (for now).
        Install-Module -Confirm:$false -Force -Name 'AzureAD',
        'ExchangeOnlineManagement', 'PnP.PowerShell' TODO (potentially): check
        the version of powershell that we are running under and throw some kind
        of error or warning if we notice that we are running under powershell
        core, because the AzureAD module does not quite work correctly under
        powershell core, it seems. 
    #>
    <#  The AzureADPreview module is being deprecated, and replaced with
        "Microsoft Graph Powershell".
          * see
            (https://learn.microsoft.com/en-us/powershell/azure/active-directory/migration-faq?view=azureadps-2.0)
          * see
            (https://learn.microsoft.com/en-us/powershell/microsoftgraph/azuread-msoline-cmdlet-map?view=graph-powershell-1.0)
          * see
            (https://practical365.com/connect-microsoft-graph-powershell-sdk/)
          * see (https://learn.microsoft.com/en-us/graph/api/overview)

        As part of the migration process, the commands Find-MgGraphCommand and
        Find-MgGraphPermission are useful to figure out what MgGraph command to
        use in place of a given AzureAD command, and what permissions (i.e.
        scopes, I think) we need in order to be able to run a given mggraph
        command (oops -- that is not exactly what those commands do (or not the
        only thing that they do). To translate from powershell command to api
        endpoint, use Find-MgGraphCommand with the -Command option. 
    #>


    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage= {@(
                "This is just a shortcut for specifying the "
                "bitwarden item id in the canonical way.  "
                "This parameter is completely ignored if "
                "bitwardenItemIdOfTheConfiguration is truthy."
            ) -join ""},
            Position=0
        )]
        [String] $primaryDomainName = "",
        
    
    
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item containing the configuration data.  passing a falsey bitwardenItemIdOfTheConfiguration along with a truthy makeNewConfiguration will cause us to create a new configuration and create a new bitwarden item to store it in. ")]
        [String] $bitwardenItemIdOfTheConfiguration = "",
        [Switch] $makeNewConfiguration = $False,

        [Parameter(HelpMessage=  "This argument is only relevant when makeNewConfiguration is true.  This string will, if truthy, be passed to the Connect-MgGraph command to try to force a connection to the specified tenant -- to prevent mistakenly logging in to the wrong tenant. ")]
        [String] $tenantIdHint = ""


    )
    

    ## forceLoadConflictingAssemblies
    <#  2024-06-29-1212: we are no longer relying on forcing a custom load order
        of dlls to work around dll hell.  Rather, we are now loading the
        ExchangeOnlineManagement commands in a separate Powershell Session and
        importing the commands from that separate session by means of implicit
        remoting.  Thus, the ExchangeOnlineManagement module is free to have its
        own, preferred versions of assemblies (I rather suspect that Newtonsoft
        Json is at the heart of the problem), without bolloxing the
        PnP.PowerShell, Microsoft.Graph, and Az modules, which all seem to play
        nicely with one another out of the box. 
    #>

    <#  todo: think through and simplify all the possibilities of parameters.
        We have three parameters (namely: bitwardenItemIdOfTheConfiguration,
        tenantIdHint, primaryDomainName)  that, at first glance, appear to be
        doing almost the same thing: namely, identifying the tenant to which we
        want to connect (in a more-or-less direct way).  The overlap between
        these three parameters is way too confusing for production (but I had my
        reasons for using them.) 
    #>

    if(-not $bitwardenItemIdOfTheConfiguration -and -not $primaryDomainName -and -not $makeNewConfiguration){
        Write-Host "you must specify at least one of bitwardenItemIdOfTheConfiguration, primaryDomainName, makeNewConfiguration.  doing nothing."
        return $null
    }

    if((-not $bitwardenItemIdOfTheConfiguration) -and ($primaryDomainName)){            
        $bitwardenItemIdOfTheConfiguration = getCanonicalNameOfBitwardenItemBasedOnPrimaryDomainName $primaryDomainName
    }


    ## Import-Module -Name 'ExchangeOnlineManagement'


    <#  2024-06-28-1715: now using implicit psremoting to avoid the dll hell
        problem.  All the ExchangeOnlineManagement commands live in a separate
        powershell session.

    #>
    $psSessionForExchangeOnlineManagementModule = (New-PsSession -Name "psSessionForExchangeOnlineManagementModule" -ConfigurationName "Powershell.7")
    invoke-command -Session $psSessionForExchangeOnlineManagementModule { import-module ExchangeOnlineManagement -DisableNameChecking:$true}
    Import-Module -Scope Global -Name 'ExchangeOnlineManagement' -PSSession $psSessionForExchangeOnlineManagementModule -DisableNameChecking:$true
    
    ## Get-command connect-exchangeonline | select *
    ## Get-command connect-exchangeonline |  select -expand module | get-member
    ## Get-command connect-exchangeonline |  select -expand module | select  -ExcludeProperty Definition,OnRemove | select *
    ## Import-Module -Name 'PnP.PowerShell'

    ## Import-Module -Name 'Microsoft.Graph' 
    <#  Strangely, explicitly importing the Microsoft.Graph module takes a long
        time (several minutes). Fortunately, we do not incur the same wait if we
        simply call commands without first importing (which relies on the
        automatic-module-importing mechanism of powershell.) 
    #>

    <#  We run into an error when we run Connect-ExchangeOnline if we have
        previously invoked Connect-MgGraph. The error message is
        "OperationStopped: Could not load file or assembly
        'System.IdentityModel.Tokens.Jwt, Version=6.22.1.0, Culture=neutral,
        PublicKeyToken=31bf3856ad364e35'. Could not find or load a specific
        file. (0x80131621)".  I suspect that the MgGraph module and the
        ExchangeOnlineManagement are each trying to load a different version of
        the System.IdentityModel.Tokens.Jwt assembly. For Whatever reason, we
        can avoid this error by letting the ExchangeOnlineManagement do its
        assembly-loading before we let the MgGraph module do its assembly
        loading. It seems that MgGraph can tolerate the version of the
        System.IdentityModel.Tokens.Jwt assembly that ExchangeOnlineManagement
        loads, but not vice versa. I am noticing that MgGraph tends to load
        version 5.6.0.0 of the assembly, and ExchangeOnlineManagement wants to
        load version 6.22.1.0 .

        Curiously, this error happens only in powershell core, not Windows
        Powershell. 

         After carefully letting Exchange Online do its assembly loading, and
         then letting Microsoft.Graph do its assembly loading, we have the
         following results:

        In Windows Powershell:
        ```
            [System.AppDomain]::CurrentDomain.GetAssemblies() | 
                Where-Object Location | 
                Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
                Sort-Object -Property FullName | 
                Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted |
                fl 
        ```
        ``` RESULT:
            FullName            : System.IdentityModel.Tokens.Jwt, Version=5.6.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
            Location            : C:\Program Files\WindowsPowerShell\Modules\Microsoft.Graph.Authentication\1.18.0\Dependencies\System.Ident
                                    ityModel.Tokens.Jwt.dll
            GlobalAssemblyCache : False
            IsFullyTrusted      : True

            FullName            : System.IdentityModel.Tokens.Jwt, Version=6.21.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
            Location            : C:\Program Files\WindowsPowerShell\Modules\ExchangeOnlineManagement\3.0.0\netFramework\System.IdentityMode
                                    l.Tokens.Jwt.dll
            GlobalAssemblyCache : False
            IsFullyTrusted      : True
        ```

         In Powershell Core:
         ```
               [System.AppDomain]::CurrentDomain.GetAssemblies() | 
                   Where-Object Location | 
                   Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
                   Sort-Object -Property FullName | 
                   Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted |
                   fl 
        ```
        ``` RESULT:
            FullName            : System.IdentityModel.Tokens.Jwt, Version=6.22.1.0, Culture=neutral, 
                                PublicKeyToken=31bf3856ad364e35
            Location            : C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\Sys 
                                tem.IdentityModel.Tokens.Jwt.dll
            GlobalAssemblyCache : False
            IsFullyTrusted      : True
        ```
         Notice that, uniquley, in Windows Powershell, both versions of the
         assembly are simultaneously loaded.

        I am seeing which version of the assembly is loaded by using the
        following command (thanks to
        https://www.koskila.net/how-to-list-all-of-the-assemblies-loaded-in-a-powershell-session/):
        ```
            [System.AppDomain]::CurrentDomain.GetAssemblies() | 
                Where-Object Location | 
                Sort-Object -Property FullName | 
                Select-Object -Property FullName, Location, GlobalAssemblyCache, IsFullyTrusted | 
                Out-GridView
        ```

        We do the below call to Connect-ExchangeOnline, which we know will fail,
        and which we want to fail, for the express purpose of ensuring (unless
        we are dot-sourced into an existing session that already has the
        System.IdentityModel.Tokens.Jwt loaded, of course), that the
        ExchangeOnlineManagement gets the first crack at loading that assembly.

        this strategy does not work. to facilitate a partial-workaround, I will
        save the initialDomainName in the configuration file so that we can, in
        the normal course of operation, call the Connect-ExchangeOnline cmdlet
        before we call Connect-MgGraph.
        ```
        try{
            @{
                AppID                   = "234523452345"
                CertificateThumbprint   = "asdfgasdfasdfasdfasdf"
                ## Organization            = $initialDomainName 
                Organization            = "whateverc1a6dee0ed884239baaec483d6b31550.onmicrosoft.com"
                ShowBanner              = $false
            } |% {Connect-ExchangeOnline @_}
        } catch {

        } 
        ```
    #>

    if($makeNewConfiguration){
        Write-Host "Constructing fresh configuration."
           

        .{Function GrantAllThePermissionsWeWant() {
            # thanks to https://stackoverflow.com/questions/61457429/how-to-add-api-permissions-to-an-azure-app-registration-using-powershell
                param(
                    [String]                                                            $nameOfTargetServicePrincipal,
                    [String[]]                                                          $namesOfRequiredAppRoles,
                    <#[Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication1]#>  $childApp,
                    [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal]  $servicePrincipalForApp

                )

                <#  Given the name (DisplayName) of the target service principal
                    and a list of strings namesOfRequiredAppRoles, we need to
                    retrieve a list of corresponding members of the
                    targetServicePrincipal's AppRoles collection (the
                    "requiredAppRoles"). What I am calling the
                    nameOfRequiredAppRole is acutually stored in a propertry of
                    AppRole named "value". 
                #>


                
                # $targetServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$($nameOfTargetServicePrincipal)'"
                $targetServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$($nameOfTargetServicePrincipal)'" -Property *

                # Iterate Permissions array
                Write-Host 'Retrieve app roles'

                [Microsoft.Graph.PowerShell.Models.MicrosoftGraphAppRole[] ] $requiredAppRoles = @()

                Foreach ($nameOfRequiredAppRole in $namesOfRequiredAppRoles) {
                    # $appRole = $targetServicePrincipal.AppRoles | Where-Object { $_.Value -eq $nameOfRequiredAppRole}
                    $requiredAppRoles += ($targetServicePrincipal.AppRoles | Where-Object { $_.Value -eq $nameOfRequiredAppRole})
                }


                .{ 
                    @{
                        ApplicationId = $childApp.Id
                        RequiredResourceAccess = (
                            (
                                @(
                                    (Get-MgApplication -ApplicationId $mgApplication.Id ).RequiredResourceAccess
                                ) +
                                @(
                                    @{
                                        ResourceAppId = $targetServicePrincipal.AppId
                                        # Microsoft really ought to have made this name plural: "ResourceAccesses"
                                        # because its type is Microsoft.Graph.PowerShell.Models.IMicrosoftGraphResourceAccess[]
                                        ResourceAccess = @(
                                            foreach ($appRole in $requiredAppRoles) {
                                                @{
                                                    Type="Role"
                                                    Id=$appRole.Id
                                                }
                                            }
                                        )
                                    }
                                )
                            ) | Select-Object -Unique
                        )
                    } | % { Update-MgApplication @_ }
                }
                Start-Sleep -s 1

                # grant the required resource access
                foreach ($appRole in $requiredAppRoles) {
                    Write-Host ('Granting admin consent for App Role: {0}' -f $($appRole.Value))

                    # check whether this assigment already exists
                    $mgServicePrincipalAppRoleAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalForApp.Id |
                        Where-Object {
                            ( 
                                $_.AppRoleId -eq $appRole.Id
                            ) -and (
                                $_.ResourceId -eq $targetServicePrincipal.Id 
                            ) -and (
                                $_.PrincipalId -eq $servicePrincipalForApp.Id
                            )
                        }
                    
                    if($mgServicePrincipalAppRoleAssignment){
                        Write-Host 'the mgServicePrincipalAppRoleAssignment already exists, so we will not bother to re-create it.'
                    } else {
                        @{
                            ServicePrincipalId  = $servicePrincipalForApp.Id 
                            AppRoleId           = $appRole.Id 
                            PrincipalId     = $servicePrincipalForApp.Id
                            <#  I do not understand why there is both a
                                "PrincipalId" and a "ServicePrincipalId"
                                parameter.  Are these the same thing? 
                            #>
                            ResourceId      = $targetServicePrincipal.Id 
                        } |% { New-MgServicePrincipalAppRoleAssignment @_}
                    }
                    ## Start-Sleep -s 1
                }
                
                #TO-do: see if we can get rid of, or at least reduce, the above sleeps.
            }
        }

        Write-Host "disconnecting from any existing graph session."
        Disconnect-MgGraph  -ErrorAction SilentlyContinue 1>$null
        <# the disconnect command will clear out any cached identity/crednetials that the Graph powershell module might have cached. #>
    
        Write-Host "attempting to connect to MGGraph"
        try{ 
            (
                $(
                    if($tenantIdHint){
                        @{TenantId = $tenantIdHint}
                    } else {
                        @{}
                    }
                ) +
                @{
                    ContextScope = "Process"
                    Scopes = @(
                        "Application.Read.All"
                        "Application.ReadWrite.All" 
                        "Directory.ReadWrite.All"
                        "RoleManagement.ReadWrite.Directory"
                        "Directory.Read.All"
                        "AppRoleAssignment.ReadWrite.All"
                    )
                }
             ) |%{Connect-MgGraph @_ -ErrorAction "Stop" }
        } catch {
            Throw "failed to connect to MGGraph, therefore we will return.  The error is: $_"
        }


        

        $roleSpecifications = @(
            @{ nameOfTargetServicePrincipal = 'Windows Azure Active Directory';
                namesOfRequiredAppRoles = @(
                    'Application.ReadWrite.All'
                    'Application.ReadWrite.OwnedBy'
                    'Device.ReadWrite.All'
                    # 'Directory.Read.All'
                    'Directory.ReadWrite.All'
                    'Domain.ReadWrite.All'
                    'Member.Read.Hidden'
                    'Policy.Read.All'
                )
            }

            @{ nameOfTargetServicePrincipal = 'Office 365 Exchange Online';
                namesOfRequiredAppRoles = @(
                    'Exchange.ManageAsApp'
                )
            }

            @{ nameOfTargetServicePrincipal = 'Office 365 Management APIs';
                namesOfRequiredAppRoles = @(
                    'ServiceHealth.Read'
                    'ActivityFeed.Read'
                    'ActivityFeed.ReadDlp'
                )
            }

            @{ nameOfTargetServicePrincipal = 'Office 365 SharePoint Online';
                namesOfRequiredAppRoles = @(
                    'Sites.FullControl.All'
                    'TermStore.ReadWrite.All'
                    'User.ReadWrite.All'
                )
            }

            if($false){ # as of 2024-04-28, we are dynamically discovering all supported app roles for Microsoft Graph rather than hardcoding them.
                @{ nameOfTargetServicePrincipal = 'Microsoft Graph';
                    namesOfRequiredAppRoles = @(
                        # 'Sites.Selected'
                        # 'ChatMember.ReadWrite.All'
                        # 'DataLossPreventionPolicy.Evaluate'
                        # 'SensitivityLabel.Evaluate'
                        # 'APIConnectors.ReadWrite.All'
                        # 'TeamsTab.ReadWriteForUser.All'
                        # 'TeamsTab.ReadWriteForChat.All'
                        # 'Policy.Read.ConditionalAccess'
                        # 'ShortNotes.ReadWrite.All'
                        # 'ServiceMessage.Read.All'
                        # 'TeamMember.ReadWriteNonOwnerRole.All'
                        # 'TeamsAppInstallation.ReadWriteSelfForUser.All'
                        # 'TeamsAppInstallation.ReadWriteSelfForTeam.All'
                        # 'TeamsAppInstallation.ReadWriteSelfForChat.All'
                        # 'TeamsAppInstallation.ReadForUser.All'
                        # 'TeamsAppInstallation.ReadForChat.All'
                        # 'Teamwork.Migrate.All'
                        # 'PrintJob.ReadWriteBasic.All'
                        # 'PrintJob.Read.All'
                        # 'PrintJob.Manage.All'
                        # 'Printer.ReadWrite.All'
                        # 'Printer.Read.All'
                        # 'Policy.ReadWrite.PermissionGrant'
                        # 'Policy.Read.PermissionGrant'
                        # 'Policy.ReadWrite.AuthenticationMethod'
                        # 'Policy.ReadWrite.AuthenticationFlows'
                        # 'TeamMember.Read.All'
                        # 'TeamSettings.ReadWrite.All'
                        # 'Channel.ReadBasic.All'
                        # 'ChannelSettings.Read.All'
                        # 'UserShiftPreferences.Read.All'
                        # 'Device.Read.All'
                        # 'Policy.ReadWrite.ApplicationConfiguration'
                        # 'TeamsTab.ReadWrite.All'
                        # 'TeamsTab.Read.All'
                        # 'TeamsTab.Create'
                        # 'UserAuthenticationMethod.Read.All'
                        # 'UserAuthenticationMethod.ReadWrite.All'
                        # 'Policy.ReadWrite.ConditionalAccess'
                        # 'Schedule.ReadWrite.All'
                        # 'BitlockerKey.ReadBasic.All'
                        # 'BitlockerKey.Read.All'
                        # 'TeamsApp.Read.All'
                        # 'ApprovalRequest.ReadWrite.CustomerLockbox'
                        # 'PrivilegedAccess.Read.AzureAD'
                        # 'TeamsActivity.Send'
                        # 'TeamsActivity.Read.All'
                        # 'DelegatedPermissionGrant.ReadWrite.All'
                        # 'OrgContact.Read.All'
                        # 'Calls.InitiateGroupCall.All'
                        # 'Calls.JoinGroupCall.All'
                        # 'Calls.JoinGroupCallAsGuest.All'
                        # 'OnlineMeetings.Read.All'
                        # 'OnlineMeetings.ReadWrite.All'
                        # 'IdentityUserFlow.ReadWrite.All'
                        # 'Calendars.Read'
                        # 'Device.ReadWrite.All'
                        # 'Directory.ReadWrite.All'
                        # 'Group.Read.All'
                        # 'Mail.ReadWrite'
                        # 'MailboxSettings.Read'
                        # 'Domain.ReadWrite.All'
                        # 'Application.ReadWrite.All'
                        # 'Chat.UpdatePolicyViolation.All'
                        # 'People.Read.All'
                        # 'AccessReview.ReadWrite.All'
                        # 'Application.ReadWrite.OwnedBy'
                        # 'User.ReadWrite.All'
                        # 'EduAdministration.Read.All'
                        # 'EduAssignments.ReadWrite.All'
                        # 'EduAssignments.ReadWriteBasic.All'
                        # 'EduRoster.Read.All'
                        # 'IdentityRiskyUser.ReadWrite.All'
                        # 'IdentityRiskEvent.ReadWrite.All'
                        # 'SecurityEvents.Read.All'
                        # 'Sites.Read.All'
                        # 'SecurityActions.ReadWrite.All'
                        # 'ThreatIndicators.ReadWrite.OwnedBy'
                        # 'AdministrativeUnit.Read.All'
                        # 'OnPremisesPublishingProfiles.ReadWrite.All'
                        # 'DeviceManagementServiceConfig.Read.All'
                        # 'DeviceManagementManagedDevices.Read.All'
                        # 'AccessReview.ReadWrite.Membership'
                        # 'Place.Read.All'
                        # 'RoleManagement.Read.Directory'
                        # 'Sites.ReadWrite.All'
                        # 'Mail.ReadBasic.All'



                        # 2022-12-31: I generated the below list by evaluating: 
                        # $(@(@(@((Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'").AppRoles) |% {$_.Value}) |% {"'$($_)'"}) -join ",`n")
                        # this should give every AppRole that the Microsoft Graph API supports.
                        
                        # I then sorted alphabetically and used the following regex to comment out redundant "Read" lines, where a corresponindg ReadWrite line already existed:
                        # ('([^.']+\.)Read((\.[^']+)?)'\s*)(\n\s*'\2ReadWrite\3')
                        # ==>
                        # $1$5

                        # 'AccessReview.Read.All'
                        'AccessReview.ReadWrite.All'
                        'AccessReview.ReadWrite.Membership'
                        'Acronym.Read.All'
                        # 'AdministrativeUnit.Read.All'
                        'AdministrativeUnit.ReadWrite.All'
                        # 'Agreement.Read.All'
                        'Agreement.ReadWrite.All'
                        'AgreementAcceptance.Read.All'
                        # 'APIConnectors.Read.All'
                        'APIConnectors.ReadWrite.All'
                        # 'AppCatalog.Read.All'
                        'AppCatalog.ReadWrite.All'
                        # 'Application.Read.All'
                        'Application.ReadWrite.All'
                        'Application.ReadWrite.OwnedBy'
                        'AppRoleAssignment.ReadWrite.All'
                        'AttackSimulation.Read.All'
                        'AuditLog.Read.All'
                        # 'AuthenticationContext.Read.All'
                        'AuthenticationContext.ReadWrite.All'
                        'BillingConfiguration.ReadWrite.All'
                        'Bookings.Read.All'
                        'BookingsAppointment.ReadWrite.All'
                        'Bookmark.Read.All'
                        # 'BrowserSiteLists.Read.All'
                        'BrowserSiteLists.ReadWrite.All'
                        # 'BusinessScenarioConfig.Read.OwnedBy'
                        'BusinessScenarioConfig.ReadWrite.OwnedBy'
                        # 'BusinessScenarioData.Read.OwnedBy'
                        'BusinessScenarioData.ReadWrite.OwnedBy'
                        'Calendars.Read'
                        'Calendars.ReadBasic.All'
                        'Calendars.ReadWrite'
                        'CallRecord-PstnCalls.Read.All'
                        'CallRecords.Read.All'
                        'Calls.AccessMedia.All'
                        'Calls.Initiate.All'
                        'Calls.InitiateGroupCall.All'
                        'Calls.JoinGroupCall.All'
                        'Calls.JoinGroupCallAsGuest.All'
                        'Channel.Create'
                        'Channel.Delete.All'
                        'Channel.ReadBasic.All'
                        # 'ChannelMember.Read.All'
                        'ChannelMember.ReadWrite.All'
                        'ChannelMessage.Read.All'
                        'ChannelMessage.UpdatePolicyViolation.All'
                        # 'ChannelSettings.Read.All'
                        'ChannelSettings.ReadWrite.All'
                        'Chat.Create'
                        'Chat.Read.All'
                        'Chat.Read.WhereInstalled'
                        'Chat.ReadBasic.All'
                        'Chat.ReadBasic.WhereInstalled'
                        'Chat.ReadWrite.All'
                        'Chat.ReadWrite.WhereInstalled'
                        'Chat.UpdatePolicyViolation.All'
                        'ChatMember.Read.All'
                        'ChatMember.Read.WhereInstalled'
                        'ChatMember.ReadWrite.All'
                        'ChatMember.ReadWrite.WhereInstalled'
                        'ChatMessage.Read.All'
                        # 'CloudPC.Read.All'
                        'CloudPC.ReadWrite.All'
                        # 'ConsentRequest.Read.All'
                        'ConsentRequest.ReadWrite.All'
                        # 'Contacts.Read'
                        'Contacts.ReadWrite'
                        'CrossTenantInformation.ReadBasic.All'
                        # 'CrossTenantUserProfileSharing.Read.All'
                        'CrossTenantUserProfileSharing.ReadWrite.All'
                        # 'CustomAuthenticationExtension.Read.All'
                        'CustomAuthenticationExtension.ReadWrite.All'
                        'CustomAuthenticationExtension.Receive.Payload'
                        # 'CustomSecAttributeAssignment.Read.All'
                        'CustomSecAttributeAssignment.ReadWrite.All'
                        # 'CustomSecAttributeDefinition.Read.All'
                        'CustomSecAttributeDefinition.ReadWrite.All'
                        # 'DelegatedAdminRelationship.Read.All'
                        'DelegatedAdminRelationship.ReadWrite.All'
                        'DelegatedPermissionGrant.ReadWrite.All'
                        # 'Device.Read.All'
                        'Device.ReadWrite.All'
                        'DeviceLocalCredential.Read.All'
                        'DeviceLocalCredential.ReadBasic.All'
                        # 'DeviceManagementApps.Read.All'
                        'DeviceManagementApps.ReadWrite.All'
                        # 'DeviceManagementConfiguration.Read.All'
                        'DeviceManagementConfiguration.ReadWrite.All'
                        'DeviceManagementManagedDevices.PrivilegedOperations.All'
                        # 'DeviceManagementManagedDevices.Read.All'
                        'DeviceManagementManagedDevices.ReadWrite.All'
                        # 'DeviceManagementRBAC.Read.All'
                        'DeviceManagementRBAC.ReadWrite.All'
                        # 'DeviceManagementServiceConfig.Read.All'
                        'DeviceManagementServiceConfig.ReadWrite.All'
                        # 'Directory.Read.All'
                        'Directory.ReadWrite.All'
                        'Directory.Write.Restricted'
                        # 'DirectoryRecommendations.Read.All'
                        'DirectoryRecommendations.ReadWrite.All'
                        # 'Domain.Read.All'
                        'Domain.ReadWrite.All'
                        # 'eDiscovery.Read.All'
                        'eDiscovery.ReadWrite.All'
                        # 'EduAdministration.Read.All'
                        'EduAdministration.ReadWrite.All'
                        'EduAssignments.Read.All'
                        'EduAssignments.ReadBasic.All'
                        'EduAssignments.ReadWrite.All'
                        'EduAssignments.ReadWriteBasic.All'
                        'EduRoster.Read.All'
                        'EduRoster.ReadBasic.All'
                        'EduRoster.ReadWrite.All'
                        # 'EntitlementManagement.Read.All'
                        'EntitlementManagement.ReadWrite.All'
                        # 'EventListener.Read.All'
                        'EventListener.ReadWrite.All'
                        # 'ExternalConnection.Read.All'
                        'ExternalConnection.ReadWrite.All'
                        'ExternalConnection.ReadWrite.OwnedBy'
                        # 'ExternalItem.Read.All'
                        'ExternalItem.ReadWrite.All'
                        'ExternalItem.ReadWrite.OwnedBy'
                        # 'Files.Read.All'
                        'Files.ReadWrite.All'
                        'Group.Create'
                        # 'Group.Read.All'
                        'Group.ReadWrite.All'
                        # 'GroupMember.Read.All'
                        'GroupMember.ReadWrite.All'
                        # 'IdentityProvider.Read.All'
                        'IdentityProvider.ReadWrite.All'
                        # 'IdentityRiskEvent.Read.All'
                        'IdentityRiskEvent.ReadWrite.All'
                        # 'IdentityRiskyServicePrincipal.Read.All'
                        'IdentityRiskyServicePrincipal.ReadWrite.All'
                        # 'IdentityRiskyUser.Read.All'
                        'IdentityRiskyUser.ReadWrite.All'
                        # 'IdentityUserFlow.Read.All'
                        'IdentityUserFlow.ReadWrite.All'
                        # 'IndustryData-DataConnector.Read.All'
                        'IndustryData-DataConnector.ReadWrite.All'
                        'IndustryData-DataConnector.Upload'
                        # 'IndustryData-InboundFlow.Read.All'
                        'IndustryData-InboundFlow.ReadWrite.All'
                        'IndustryData-ReferenceDefinition.Read.All'
                        'IndustryData-Run.Read.All'
                        # 'IndustryData-SourceSystem.Read.All'
                        'IndustryData-SourceSystem.ReadWrite.All'
                        # 'IndustryData-TimePeriod.Read.All'
                        'IndustryData-TimePeriod.ReadWrite.All'
                        'IndustryData.ReadBasic.All'
                        'InformationProtectionContent.Sign.All'
                        'InformationProtectionContent.Write.All'
                        'InformationProtectionPolicy.Read.All'
                        # 'LearningContent.Read.All'
                        'LearningContent.ReadWrite.All'
                        'LicenseAssignment.ReadWrite.All'
                        # 'LifecycleWorkflows.Read.All'
                        'LifecycleWorkflows.ReadWrite.All'
                        'Mail.Read'
                        'Mail.ReadBasic.All'
                        'Mail.ReadBasic'
                        'Mail.ReadWrite'
                        'Mail.Send'
                        # 'MailboxSettings.Read'
                        'MailboxSettings.ReadWrite'
                        'Member.Read.Hidden'
                        # 'NetworkAccessBranch.Read.All'
                        'NetworkAccessBranch.ReadWrite.All'
                        # 'NetworkAccessPolicy.Read.All'
                        'NetworkAccessPolicy.ReadWrite.All'
                        # 'Notes.Read.All'
                        'Notes.ReadWrite.All'
                        'OnlineMeetingArtifact.Read.All'
                        'OnlineMeetingRecording.Read.All'
                        # 'OnlineMeetings.Read.All'
                        'OnlineMeetings.ReadWrite.All'
                        'OnlineMeetingTranscript.Read.All'
                        'OnPremisesPublishingProfiles.ReadWrite.All'
                        # 'Organization.Read.All'
                        'Organization.ReadWrite.All'
                        'OrgContact.Read.All'
                        'People.Read.All'
                        'Place.Read.All'
                        'Policy.Read.All'
                        'Policy.Read.ConditionalAccess'
                        'Policy.Read.PermissionGrant'
                        'Policy.ReadWrite.AccessReview'
                        'Policy.ReadWrite.ApplicationConfiguration'
                        'Policy.ReadWrite.AuthenticationFlows'
                        'Policy.ReadWrite.AuthenticationMethod'
                        'Policy.ReadWrite.Authorization'
                        'Policy.ReadWrite.ConditionalAccess'
                        'Policy.ReadWrite.ConsentRequest'
                        'Policy.ReadWrite.CrossTenantAccess'
                        'Policy.ReadWrite.ExternalIdentities'
                        'Policy.ReadWrite.FeatureRollout'
                        'Policy.ReadWrite.PermissionGrant'
                        'Policy.ReadWrite.SecurityDefaults'
                        'Policy.ReadWrite.TrustFramework'
                        'Presence.ReadWrite.All'
                        # 'Printer.Read.All'
                        'Printer.ReadWrite.All'
                        'PrintJob.Manage.All'
                        'PrintJob.Read.All'
                        'PrintJob.ReadBasic.All'
                        'PrintJob.ReadWrite.All'
                        'PrintJob.ReadWriteBasic.All'
                        'PrintSettings.Read.All'
                        'PrintTaskDefinition.ReadWrite.All'
                        'PrivilegedAccess.Read.AzureAD'
                        'PrivilegedAccess.Read.AzureADGroup'
                        'PrivilegedAccess.Read.AzureResources'
                        'PrivilegedAccess.ReadWrite.AzureAD'
                        'PrivilegedAccess.ReadWrite.AzureADGroup'
                        'PrivilegedAccess.ReadWrite.AzureResources'
                        # 'ProgramControl.Read.All'
                        'ProgramControl.ReadWrite.All'
                        'QnA.Read.All'
                        # 'RecordsManagement.Read.All'
                        'RecordsManagement.ReadWrite.All'
                        'Reports.Read.All'
                        # 'ReportSettings.Read.All'
                        'ReportSettings.ReadWrite.All'
                        'RoleManagement.Read.All'
                        'RoleManagement.Read.CloudPC'
                        'RoleManagement.Read.Directory'
                        'RoleManagement.ReadWrite.CloudPC'
                        'RoleManagement.ReadWrite.Directory'
                        # 'Schedule.Read.All'
                        'Schedule.ReadWrite.All'
                        # 'SearchConfiguration.Read.All'
                        'SearchConfiguration.ReadWrite.All'
                        # 'SecurityActions.Read.All'
                        'SecurityActions.ReadWrite.All'
                        # 'SecurityAlert.Read.All'
                        'SecurityAlert.ReadWrite.All'
                        # 'SecurityEvents.Read.All'
                        'SecurityEvents.ReadWrite.All'
                        # 'SecurityIncident.Read.All'
                        'SecurityIncident.ReadWrite.All'
                        'ServiceHealth.Read.All'
                        'ServiceMessage.Read.All'
                        # 'ServicePrincipalEndpoint.Read.All'
                        'ServicePrincipalEndpoint.ReadWrite.All'
                        # 'SharePointTenantSettings.Read.All'
                        'SharePointTenantSettings.ReadWrite.All'
                        # 'ShortNotes.Read.All'
                        'ShortNotes.ReadWrite.All'
                        'Sites.FullControl.All'
                        'Sites.Manage.All'
                        # 'Sites.Read.All'
                        'Sites.ReadWrite.All'
                        'Sites.Selected'
                        # 'SubjectRightsRequest.Read.All'
                        'SubjectRightsRequest.ReadWrite.All'
                        # 'Synchronization.Read.All'
                        'Synchronization.ReadWrite.All'
                        # 'Tasks.Read.All'
                        'Tasks.ReadWrite.All'
                        'Team.Create'
                        'Team.ReadBasic.All'
                        # 'TeamMember.Read.All'
                        'TeamMember.ReadWrite.All'
                        'TeamMember.ReadWriteNonOwnerRole.All'
                        'TeamsActivity.Read.All'
                        'TeamsActivity.Send'
                        'TeamsAppInstallation.ReadForChat.All'
                        'TeamsAppInstallation.ReadForTeam.All'
                        'TeamsAppInstallation.ReadForUser.All'
                        'TeamsAppInstallation.ReadWriteAndConsentForChat.All'
                        'TeamsAppInstallation.ReadWriteAndConsentForTeam.All'
                        'TeamsAppInstallation.ReadWriteAndConsentSelfForChat.All'
                        'TeamsAppInstallation.ReadWriteAndConsentSelfForTeam.All'
                        'TeamsAppInstallation.ReadWriteForChat.All'
                        'TeamsAppInstallation.ReadWriteForTeam.All'
                        'TeamsAppInstallation.ReadWriteForUser.All'
                        'TeamsAppInstallation.ReadWriteSelfForChat.All'
                        'TeamsAppInstallation.ReadWriteSelfForTeam.All'
                        'TeamsAppInstallation.ReadWriteSelfForUser.All'
                        # 'TeamSettings.Read.All'
                        'TeamSettings.ReadWrite.All'
                        'TeamsTab.Create'
                        # 'TeamsTab.Read.All'
                        'TeamsTab.ReadWrite.All'
                        'TeamsTab.ReadWriteForChat.All'
                        'TeamsTab.ReadWriteForTeam.All'
                        'TeamsTab.ReadWriteForUser.All'
                        'TeamsTab.ReadWriteSelfForChat.All'
                        'TeamsTab.ReadWriteSelfForTeam.All'
                        'TeamsTab.ReadWriteSelfForUser.All'
                        'TeamTemplates.Read.All'
                        'Teamwork.Migrate.All'
                        # 'TeamworkAppSettings.Read.All'
                        'TeamworkAppSettings.ReadWrite.All'
                        # 'TeamworkDevice.Read.All'
                        'TeamworkDevice.ReadWrite.All'
                        # 'TeamworkTag.Read.All'
                        'TeamworkTag.ReadWrite.All'
                        # 'TermStore.Read.All'
                        'TermStore.ReadWrite.All'
                        'ThreatAssessment.Read.All'
                        'ThreatHunting.Read.All'
                        'ThreatIndicators.Read.All'
                        'ThreatIndicators.ReadWrite.OwnedBy'
                        # 'ThreatSubmission.Read.All'
                        'ThreatSubmission.ReadWrite.All'
                        'ThreatSubmissionPolicy.ReadWrite.All'
                        # 'TrustFrameworkKeySet.Read.All'
                        'TrustFrameworkKeySet.ReadWrite.All'
                        # 'User-LifeCycleInfo.Read.All'
                        'User-LifeCycleInfo.ReadWrite.All'
                        'User.Export.All'
                        'User.Invite.All'
                        'User.ManageIdentities.All'
                        'User.Read.All'
                        'User.ReadBasic.All'
                        'User.ReadWrite.All'
                        # 'UserAuthenticationMethod.Read.All'
                        'UserAuthenticationMethod.ReadWrite.All'
                        'UserNotification.ReadWrite.CreatedByApp'
                        # 'UserShiftPreferences.Read.All'
                        'UserShiftPreferences.ReadWrite.All'
                        # 'VirtualAppointment.Read.All'
                        'VirtualAppointment.ReadWrite.All'
                        'WindowsUpdates.ReadWrite.All'
                        'WorkforceIntegration.ReadWrite.All'
                    )
                }
            }

            $namesOfTargetServicePrincipalsForWhichToDynamicallyDiscoverAppRoles = @(
                'Microsoft Graph'
            )

            foreach($nameOfTargetServicePrincipal in $namesOfTargetServicePrincipalsForWhichToDynamicallyDiscoverAppRoles){                
                @{
                    nameOfTargetServicePrincipal = $nameOfTargetServicePrincipal
                    namesOfRequiredAppRoles = @(
                        @{
                            excludeRedundantReadRoles = $True 
                            idOfServicePrincipal = (Get-MgServicePrincipal -Filter "DisplayName eq '$($nameOfTargetServicePrincipal)'" ).Id
                        }|%{getNamesOfAllAppRolesSupportedByServicePrincipal @_} |
                        ? {
                            <#  exclude certain hardcoded values in certain cases: 
                            
                            #>
                            -not (
                                ($nameOfTargetServicePrincipal -eq 'Microsoft Graph') -and
                                ($_ -eq "Directory.Write.Restricted")
                            )
                        }
                    )
                }
            }


        )
        



        #following along with instructions at: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps

        # Create the self signed cert
        

        # $pathOfPfxFile = (Join-Path $PSScriptRoot "certificate.pfx")
        # $passwordOfthePfxFile = ""
        
        # if($pathOfPfxFile){
        #     $securePassword =  $( 
        #         if( $passwordOfthePfxFile ) {
        #             ConvertTo-SecureString -String $passwordOfthePfxFile -AsPlainText -Force
        #         } else {
        #             New-Object System.Security.SecureString
        #         }  
        #     )
        #     try {
        #         $certificate = Import-PfxCertificate `
        #             -FilePath $pathOfPfxFile `
        #             -Password $securePassword `
        #             -CertStoreLocation $certificateStorageLocation
        #     } catch {
        #         Write-Output "Failed to import the certificate from the certificate file"
        #         # Remove-Variable certificate -ErrorAction SilentlyContinue
        #         $certificate = $null
        #     }
        # }
        

        Write-Host "constructing fresh certificate"
        $currentDate = Get-Date
        $endDate = $currentDate.AddYears(10)
        $notAfter = $endDate.AddYears(10)
        # $certificateStorageLocation = "Cert:\CurrentUser\My"
        $certificate = @{
            # CertStoreLocation = $certificateStorageLocation 
            DnsName = "com.foo.bar"
            KeyExportPolicy = "Exportable" 
            Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider" 
            NotAfter = $notAfter
        } | %{New-SelfSignedCertificate @_}
        $pfxPassword = @(1..25 | foreach-object {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" -split "" | Get-Random}) -join ""
        $base64EncodedPfx = x509Certificate2ToBase64EncodedPfx -certificate $certificate -password $pfxPassword
        Remove-Item -Force -Path $certificate.PSPath

        $certificate = base64EncodedPfxToX509Certificate2 $base64EncodedPfx -password $pfxPassword
        
        $initialDomainName = ((Get-MgOrganization).VerifiedDomains | where-object {$_.IsInitial -eq $true}).Name
        $displayNameOfApplication = (Get-MgContext).Account.ToString() + "_powershell_management"
        
        # Get the Azure Active Directory Application, creating it if it does not already exist.
        $mgApplication = $(Get-MgApplication -ConsistencyLevel eventual -Search "DisplayName:$displayNameOfApplication")
        if (! $mgApplication) {
            $mgApplication = $(
                @{
                    DisplayName                 = $displayNameOfApplication 
                    IdentifierUris              = ('https://{0}/{1}' -f $initialDomainName , $displayNameOfApplication) 
                    Web = @{
                        HomePageUrl = "https://localhost"
                        LogoutUrl = "https://localhost"
                        # RedirectUriSettings = @(
                        #     @{
                        #         Index = 0
                        #         Uri = @("https://localhost") 
                        #     }
                        # )
                        RedirectUris = @("https://localhost") 
                        # ImplicitGrantSettings = @{
                        #     EnableAccessTokenIssuance = $True
                        #     EnableIdTokenIssuance = $True
                        # }
                        # I do not know how much of this stuff is strictly necessary
                    }
                    # KeyCredentials = ([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphKeyCredential[]]      @(
                    #     ([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphKeyCredential]   @{
                    #         Type = "AsymmetricX509Cert"
                    #         Usage = "Verify"
                    #         Key = $certificate.GetRawCertData()
                    #     }))
                    # )
                } |%  {New-MgApplication @_}
            )
        } else {
            # Write-Host  ('App Registration {0} already exists' -f $displayNameOfApplication)
            Write-Host "mgApplication $($mgApplication.DisplayName) (id = $($mgApplication.Id))"
        }

        if(-not $mgApplication){
            write-error "application does not exist.  We cannot proceed."
            return
        } else {
            write-host "mgApplication exists:"
            $mgApplication | select * | out-string | write-host
        }
        
        # Get the service principal associated with $mgApplication, creating it if it does not already exist.
        $mgServicePrincipal = Get-MgServicePrincipal -Filter ("appId eq '" + $mgApplication.AppId + "'")
        if(! $mgServicePrincipal){
            
            $mgServicePrincipal = New-MgServicePrincipal -AppId $mgApplication.AppId
        }  else {
            Write-Host "Service Principal $($mgServicePrincipal.DisplayName) (id = $($mgServicePrincipal.Id)) already exists."
        }
        
        #ensure that the service principal has global admin permissions to the current tenant
        $globalAdminMgDirectoryRole =  Get-MgDirectoryRole | where {$_.DisplayName -eq "Global Administrator"}
        # todo: do this search on the server side, rather than here on the client side, by using a -filter (or maybe -search ?) argument.

        if(!$globalAdminMgDirectoryRole){
            # $globalAdminAzureAdDirectoryRole =  Get-AzureADDirectoryRole | where {$_.DisplayName -eq "Company Administrator"}
            $globalAdminMgDirectoryRole =  Get-MgDirectoryRole  | where {$_.DisplayName -eq "Company Administrator"}
            # for reasons unknown, in some tenants, the displayname of the global admin role is "Company Administrator"
        }

        ##  $mgDirectoryRoleMember = Get-MgDirectoryRoleMember -ConsistencyLevel eventual -DirectoryRoleId $globalAdminMgDirectoryRole.Id | where {$_.Id -eq $mgServicePrincipal.Id}
        #
        # you might think that adding "-ConsistencyLevel eventual" would be enough,
        # but it's not; you also have to add the -Count argument, even if you pass
        # $null as Count. I do not understand why the Count argument is required in
        # order to get the correct behavior.  Maybe it has something to do with
        # paging of the results, but it strikes me as pretty kludgy to require the
        # Count argument.

        $mgDirectoryRoleMember = Get-MgDirectoryRoleMember -ConsistencyLevel eventual -Count $null -DirectoryRoleId $globalAdminMgDirectoryRole.Id | where {$_.Id -eq $mgServicePrincipal.Id}
        

        # iff. $azureAdServicePrincipal has the global admin permission, then $azureADDirectoryRoleMember will be $azureAdServicePrincipal, otherwise will be null
        if(! $mgDirectoryRoleMember ){
            New-MgDirectoryRoleMemberByRef -DirectoryRoleId  $globalAdminMgDirectoryRole.Id  -oDataId "https://graph.microsoft.com/v1.0/directoryObjects/$($mgServicePrincipal.Id)"
            # I have no idea how I would come up with the above value in the oDataId
            # argument (except by blindly copying the example from
            # https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/new-mgdirectoryrolememberbyref?view=graph-powershell-1.0,
            # which is what I did
            # ) 
            #
            # possibly, I ought to be using New-MgRoleManagementDirectoryRoleAssignment
            # instead.  see
            # https://stackoverflow.com/questions/73088374/how-do-i-use-the-command-new-mgrolemanagementdirectoryroleassignment
            # . 
        } else {
            Write-Host 'the service principal already has global admin permissions.'
        }
        # we could have probably gotten away simply wrapping Add-AzureADDirectoryRoleMember in a try/catch statement.
        
        #ensure that our public key is installed in our application


        $keyCredential = $mgApplication.KeyCredentials | where { 
                [System.Convert]::ToBase64String($_.CustomKeyIdentifier) -eq 
                [System.Convert]::ToBase64String([System.Convert]::FromBase64String($certificate.Thumbprint))
            }

        if($keyCredential){
            Write-Host "The desired keyCredential already exists among the app's keyCredentials, so we will not bother to add it: $keyCredential"
        } else {
            Write-Host "The desired keyCredential does not already exist, so we will attempt to add it."
            @{
                ApplicationId = ($mgApplication.Id)
                KeyCredentials = @(
                    @{
                        Type = "AsymmetricX509Cert"
                        Usage = "Verify"
                        Key = $certificate.GetRawCertData()
                        # Key = [System.Convert]::ToBase64String($certificate.GetRawCertData())
                    }
                )
                # PassThru = $True 
                #
                # setting PassThru=$True causes Update-MgApplication to return
                # $null or $True according to the failure or success of the
                # operation. otherwise, Update-MgApplication always returns
                # $null regardless.
                # 2023-02-26-1532: the PassThru parameter seems to no longer be accepted.
            } | % { Update-MgApplication  @_ -ErrorAction Stop}
            #%%
        }

        #grant all the required approles (as defined by $roleSpecifications) to our app's service principal
        foreach ( $roleSpecification in $roleSpecifications){
            @{
                childApp                     = $mgApplication
                servicePrincipalForApp       = $mgServicePrincipal
                nameOfTargetServicePrincipal = $roleSpecification.nameOfTargetServicePrincipal
                namesOfRequiredAppRoles      = $roleSpecification.namesOfRequiredAppRoles
            } |% {GrantAllThePermissionsWeWant @_}
        }

        $configuration = @{
 
            
            tenantId = (Get-MgOrganization).Id 
            #
            # we seem to be able to use initialDomainName in all places
            # where the value of (Get-MgOrganization).Id (which is a guid
            # string) could be used. Moreover, there is at least one place
            # (namely, the Connect-ExchangeOnline command) where the guid does
            # not work and initialDomainName is required. Therefore,
            # let's not bother looking up or storing the guid string retuirned
            # by (Get-MgOrganization).Id. and instead we will only store
            # initialDomainName

            primaryDomainName = (((Get-MgOrganization).VerifiedDomains | where-object {$_.IsDefault -eq $true}).Name)

            # initialDomainNameOfTenant  = $initialDomainName 
            initialDomainName  = $initialDomainName 
            # we are only storing initialDomainName in the configuration file
            # to aid in the work-around of the dll hell caused by the
            # ExchangeOnlineManagementModule and the MgGraph module wanting to use
            # different versions of the System.IdentityModel.Tokens.Jwt assembly.

            # I really should only need one of tenantId, primaryDomainName,
            # initialDomainName However, to aid in debugging (and
            # avoiding the laborious process of recreating the configurations if
            # and when I decide to change which of these three properties I
            # standardize on), I will record all three properties. Todo: figure
            # out how to standadize on just one of these three properties. I
            # suspect that initialDomainName or tenantId are the most
            # stable (because I know that a tenant can change its
            # primaryDomainName at will, and possibly multiple tenants can have
            # the same primarydomainName. Therefore, initialDomainName
            # or tenantId would be the best candidates for the single standard
            # way to specify tenant identity.

            appId = $mgApplication.AppId

            # certificateThumbprint = $certificate.Thumbprint
            base64EncodedPfx = $base64EncodedPfx

            pfxPassword = $pfxPassword
            # it's slightly ridiculous to password-encrypt the private key when
            # we're already working within bitwarden, but I am choosing to do
            # this because I am having to rely on pfx conversion routines that
            # write the pfx data to a temporary file. The pfx password (which
            # lives in memory only) protects the pfx data when it is written to
            # the filesystem in a temporary file. One alternative would be to
            # use a serialization format other than pfx, but most such
            # reasonable choices for serialization formats other than pfx would
            # require storing the certificate and the private key as two
            # separate blobs.  So, one way or another, it seems like I am being
            # forced to have to keep track of two blobs.
        } 
        
        # $configuration | ConvertTo-JSON | Out-File $pathOfTheConfigurationFile

        if(-not $bitwardenItemIdOfTheConfiguration){            
            $bitwardenItemIdOfTheConfiguration = (
                makeNewBitwardenItem -name (
                    getCanonicalNameOfBitwardenItemBasedOnPrimaryDomainName (((Get-MgOrganization).VerifiedDomains | where-object {$_.IsDefault -eq $true}).Name)
                )
            )['id']
            Write-Host "created a new bitwarden item (id='$bitwardenItemIdOfTheConfiguration').'"
        }

        putFieldMapToBitwardenItem `
            -fieldMap $configuration `
            -bitwardenItemId $bitwardenItemIdOfTheConfiguration
        Write-Host "modified a bitwarden item (id='$bitwardenItemIdOfTheConfiguration').'"
        

        Disconnect-MgGraph
        
        # $configuration = Get-Content -Raw $pathOfTheConfigurationFile | ConvertFrom-JSON
    }



    try {
        $configuration = (getFieldMapFromBitwardenItem -bitwardenItemId $bitwardenItemIdOfTheConfiguration 2> $null)
    } catch {
        Write-Host "Failed to get configuration from bitwarden, with error: $($_)"
        Remove-Variable configuration -ErrorAction SilentlyContinue
    }

    if(! $configuration){
        Write-Host "We have failed to obtain a valid configuration from bitwarden and therefore must return."
        return
    }


    <#  At this point, we expect to have a valid $configuration and can proceed
        with making the connection: 
    #>

    $certificate = base64EncodedPfxToX509Certificate2 $configuration['base64EncodedPfx'] -password $configuration['pfxPassword']

    $pathOfTemporaryCertificateFile = New-TemporaryFile
    Set-Content  -AsByteStream -Value ([System.Convert]::FromBase64String($configuration['base64EncodedPfx'] )) -LiteralPath $pathOfTemporaryCertificateFile | out-null
    
    .{ #functions for MgGraph
        function getWeAreConnectedToMgGraph {
            [OutputType([Boolean])]
            param ()
            <#  Unlike with the old AzureAD powershell, with Graph, it might be
                problematic to use a succesfull invoking of Get-MgOrganization to infer
                that an existing connection exists.  Because the Graph powershell module
                caches crednetials across sessions, its possible that Get-MgOrganization
                will return a result without complaint from an old closed session that I
                am long done with and have forgotten about.  
                Is there any way (perhaps an argument we can pass to connect-mggraph) to
                force the Graph module not to cache crednetials after the end of the
                session? Answer: I think  "-ContextScope Process" (and maybe also
                "-ForceRefresh") are the arguments that will have the desired effect.
            #>
            

            <#  This  might be another way to test for connectivity:
                ```
                $null -ne [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance
                ```
            #>

            return (
                [Boolean] $(
                    &{
                        Get-MgOrganization | 
                        ? { 
                            $($_.VerifiedDomains | ? {$_.IsInitial -eq $true})?.Name.Trim().ToLower() -eq
                            $configuration['initialDomainName'].Trim().ToLower()
                        }
                    } -erroraction silentlycontinue 2>$null
                )
            )

        }

        function connectToMgGraph {
            [OutputType([Void])]
            param ()
            Write-Debug "about to do Connect-MgGraph"
            # Select-MgProfile -Name Beta
            Disconnect-MgGraph -ErrorAction SilentlyContinue 1>$null 2>$null
            @{
                ClientId                = $configuration['appId']
                # CertificateThumbprint   = $configuration['certificateThumbprint'] 
                Certificate             = $certificate

                # TenantId                = $configuration['initialDomainName']
                # at least as of version 1.19 of the Microsoft.Graph module,
                # passing initialDomainName as the tenantId (in some cases, at least)
                # causes the error: "Connect-MgGraph: You specified a different tenant - once in WithAuthority() and once using WithTenant()."
                # pass the guid version of the tenant id seems to avoid this problem.
                TenantId                = $configuration['tenantId']
                ContextScope            = "Process"
            } |%{Connect-MgGraph @_ } | out-null
            Write-Debug "Finished doing Connect-MgGraph"
        }

        function tryToEnsureThatWeAreConnectedToMgGraph {
            [OutputType([Void])]
            param ()
            try{ 
                if( getWeAreConnectedToMgGraph ){
                    Write-Host ("It seems that a connection to Microsoft Graph already " +
                        "exists, so we will not bother attempting to reconnect.")
                } else {
                    connectToMgGraph 
                } 
            } 
            catch {
                Write-Host ("encountered error when attempting to ensure that we are " +
                    "connected to Microsoft Graph: $($_)")
            }
        }
    }

    .{  # functions for SharepointOnline
        function getWeAreConnectedToSharepointOnline {
            [OutputType([Boolean])]
            param ()
            return (
                [Boolean] $(
                    &{
                        $(
                            try{
                                Get-PnpConnection -erroraction silentlycontinue 2>$null 
                            } catch {
                                $null
                            }
                        ) | 
                        ? {$_} |
                        ? { 
                            $_.Tenant.Trim().ToLower() -eq
                            $configuration['initialDomainName'].Trim().ToLower() 
                        }
                    } -erroraction silentlycontinue 2>$null
                )
            )
        }

        function connectToSharepointOnline {
            # [OutputType([Void])]
            param ()
            Write-Debug "about to do Connect-PnPOnline (which I call 'SharepointOnline')"    
            
            # $temporaryFile = New-TemporaryFile
            # Set-Content  -AsByteStream -Value ([System.Convert]::FromBase64String($configuration['base64EncodedPfx'])) -LiteralPath $temporaryFile.FullName 1> $null
            
            # $certStoreLocation = "Cert:\CurrentUser\My"
            # Remove-Item -Force -Path (join-path $certStoreLocation $certificate.Thumbprint)
            # $s = @{
            #     CertStoreLocation =  $certStoreLocation
            #     Password = (stringToSecureString "") 
            #     FilePath = $temporaryFile.FullName
            #     Exportable = $True
            # }; $x = Import-PfxCertificate @s 
            # # $y = [System.Convert]::ToBase64String($x.RawData)
            # # this doesn't work, of course, because $y does not contain the private key.

            # # $y = [System.Convert]::ToBase64String($x.PrivateKey.ExportRSAPrivateKey())
            # # $y = $x.PrivateKey.ExportRSAPrivateKeyPem()


            # Write-Debug "`$certificate.PSPath: $($certificate.PSPath)"
            # Remove-Item -Force -Path $temporaryFile.FullName
            

            # note: to understand the relationship between X509Certificate2::RawData
            # and X509Certificate2::ExportCertificatePem(), observe that, for any
            # valid X509Certificate2 object $x:
            ## (
            ##      (@(($x.ExportCertificatePem() -split "\n") | Select-Object -Skip 1 | Select-Object -SkipLast 1) -join "") -eq 
            ##      [System.Convert]::ToBase64String($x.RawData)
            ## )
            ##>>>   True
            #
            # The first and last lines of the string returned by
            # $x.ExportCertificatePem() are "-----BEGIN CERTIFICATE-----" and
            # "-----END CERTIFICATE-----"

            $env:PNPPOWERSHELL_UPDATECHECK = "Off"
            # this environemnt variable suppresses the annoying "a new version
            # is available" message that almost always occurs (a new version, in
            # the sense that the checking mechanism cares about, is released at
            # least once per day, most of the time, it seems.).
            if( 
                $(
                    $(
                        try{
                            Get-PnpConnection -erroraction silentlycontinue 2>$null 
                        } catch {
                            $null
                        }
                    ) 
                )
            ){
                Disconnect-PnPOnline -ErrorAction SilentlyContinue 2>$null
            }


            
            @{
                Url = ( "https://" +  ($configuration['initialDomainName'] -Split '\.')[0] + ".sharepoint.com") 
                ClientId = $configuration['appId'] 
                Tenant = $configuration['initialDomainName'] 
                # Thumbprint = $configuration['certificateThumbprint']
                CertificateBase64Encoded = $configuration['base64EncodedPfx']
                CertificatePassword = (stringToSecureString $configuration['pfxPassword'])
                
                <#  The official documentation for the connect-pnponline command
                    (https://pnp.github.io/powershell/cmdlets/Connect-PnPOnline.html)
                    does not completely describe what the command is expecting
                    to receive for the -CertificateBase64Encoded argument.
                    After much thrashing, I figured out that it is expecting the
                    base64-encoded bytes of a pfx file (which, conveniently, is
                    exactly what I am storing in bitwarden.).  
                    It is conceivable, I think, that the connect-pnponline
                    command could use, instead of the bytes of a pfx file, the
                    bytes of a pkcs#1-encoded RSA private key.  I have not
                    ascertained whether the connect-pnponline command actually
                    works that way.   
                #>

            } |%  { Connect-PnPOnline @_} | out-null

            # see
            # (https://pnp.github.io/powershell/cmdlets/Connect-PnPOnline.html)
            #
            # see
            # (https://learn.microsoft.com/en-us/sharepoint/dev/solution-guidance/security-apponly-azuread)
            
            Write-Debug "Finished doing Connect-PnPOnline (I use the word 'SharepointOnline' in the names of my functions.)"   
            
        }

        function tryToEnsureThatWeAreConnectedToSharepointOnline {
            [OutputType([Void])]
            param ()
            
            try{ 
                if( getWeAreConnectedToSharepointOnline ){
                    Write-Debug ("It seems that a connection to Sharepoint Online already " +
                        "exists, so we will not bother attempting to reconnect.")
                } else {
                    connectToSharepointOnline 
                } 
            } 
            catch {
                Write-Host ("encountered error when attempting to ensure that we are " +
                    "connected to Sharepoint Online: $($_) $($_.Exception)")
            }
        }
    }

    .{ # functions for ExchangeOnline
        function getWeAreConnectedToExchangeOnline {
            [OutputType([Boolean])]
            param ()
            return (
                [Boolean] $(
                    Get-ConnectionInformation | ?{$_.Name.StartsWith("ExchangeOnline_")} |
                    ? { 
                        $_.Organization.Trim().ToLower() -eq
                        $configuration['initialDomainName'].Trim().ToLower() 
                    }
                )
            )
        }

        function connectToExchangeOnline {
            [OutputType([Void])]
            param ()
            Write-Debug "about to do Connect-ExchangeOnline"
            
            Get-ConnectionInformation | ? {$_.Name.StartsWith("ExchangeOnline_")} |
            %{ Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId }


            $result = @{
                AppID                   = $configuration['appId'] 
                
                ##  Certificate             = $certificate
                CertificateFilePath = $pathOfTemporaryCertificateFile
                CertificatePassword  = ConvertTo-SecureString -AsPlainText $configuration['pfxPassword']

                Organization            = $configuration['initialDomainName']

                ## UseRPSSession = $false
                # the above "UseRPSSession  = $false" is unnecessary and redundant.

                ShowBanner=$false
            } |% {Connect-ExchangeOnline @_}


            @{
                Scope     = "Global"
                PSSession = $psSessionForExchangeOnlineManagementModule

                ## Name      = (invoke-command -Session $psSessionForExchangeOnlineManagementModule {(Get-Command get-mailbox).Module.Name})
                ## ModuleInfo      = (invoke-command -Session $psSessionForExchangeOnlineManagementModule {(Get-Command get-mailbox).Module})
                ## FullyQualifiedName      = (invoke-command -Session $psSessionForExchangeOnlineManagementModule {(Get-Command get-mailbox).Module})
                FullyQualifiedName      = (invoke-command -Session $psSessionForExchangeOnlineManagementModule {(Get-Command get-mailbox).Module.Path})
                ## NoClobber = $True
                ## Verbose = $true

                DisableNameChecking=$true
            } |% {Import-Module @_}

            <#  2024-06-29-1207: I wonder if, once prepared, the temporary
                module file created by the Connect-ExchangeOnline command (and
                Connect-IPPSSession command) could be imported into the current
                session without causing any dll hell; maybe the dll hell is
                related only to the authentication and connection activities,
                not the use of the commands after connected.
            #>

            ## Write-Debug "Finished doing Connect-ExchangeOnline, and the result is $($result).  First mailbox is $(@(get-mailbox)[0])"
            ## Write-Host "Finished doing Connect-ExchangeOnline, and the result is $($result).  First mailbox is $(@(get-mailbox)[0])"
        }

        function tryToEnsureThatWeAreConnectedToExchangeOnline {
            [OutputType([Void])]
            param ()
            try{  
                if( getWeAreConnectedToExchangeOnline ){
                    Write-Debug ("It seems that a connection to Exchange Online already " +
                        "exists, so we will not bother attempting to reconnect.")
                } else {
                    connectToExchangeOnline | out-null
                }
            } 
            catch {
                Write-Host ("encountered error when attempting to ensure that we are " +
                    "connected to ExchangeOnline: $($_)")
            }
            
            
            
            

        }
    }

    .{ # functions for IPPSSession
        <#  IPS session is not entirely an independent thiung from Exchange session
            (e.g. calling Disconnect-ExchangeOnline will also disconnect any active
            IPS session).  It is not quite correct to treat IPS session as another
            top-=level item, we ought to make it a substituent of the Exchange
            connection somehow, but oh well.  
        #>
        function getWeAreConnectedToIPPSSession {
            [OutputType([Boolean])]
            param ()
            return (
                [Boolean] $(
                    Get-ConnectionInformation | ? {$_.Name.StartsWith("ExchangeOnlineProtection_")} |
                    ? { 
                        $_.Organization.Trim().ToLower() -eq
                        $configuration['initialDomainName'].Trim().ToLower() 
                    }
                )
            )
        }

        function connectToIPPSSession {
            # [OutputType([Void])]
            param ()
                

            # # connect to "Security & Compliance PowerShell in a Microsoft 365 organization."
            # # Write-Debug "about to do Connect-IPPSSession "
            # # $s = @{
            # #     AppID                   = $configuration['appId']  
            # #     CertificateThumbprint   = $configuration['certificateThumbprint'] 
            # #     Organization            = $initialDomainName
            # # }
            # # Write-Debug "arguments are $($s | out-string)"
            # # Connect-IPPSSession @s
            # # Write-Debug "done"

            # # Connect-IPPSSession does not seem to be working properly with 
            # # unattended app-based authentication.  Connect-IPPSSession tends to 
            # # launch a username and apssword prompt (and then fails when the oauth redirect url doesn't match).
            # # It appears that connect-ipppssession is a wrapper around connect-exchangeonline.  
            # # connect-ippssession calls connect-exchangeonline with 
            # # a couple of parameters specified:
            # # -UseRPSSession:$true
            # # -ShowBanner:$false
            # # -ConnectionUri 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId' 
            # # -AzureADAuthorizationEndpointUri 'https://login.microsoftonline.com/organizations'


            # Write-Debug "about to do our own equivalent of 'Connect-IPPSSession' "
            # $s = @{
            #     AppID                               = $configuration['appId']
            #     # CertificateThumbprint               = $configuration['certificateThumbprint']
            #     Certificate                         = $certificate
            #     Organization                        = $configuration['initialDomainName']
            #     UseRPSSession                       = $true
            #     ShowBanner                          = $false
            #     ConnectionUri                       = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId' 
            #     AzureADAuthorizationEndpointUri     = 'https://login.microsoftonline.com/organizations'
            # }
            # Write-Debug "arguments are $($s | out-string)"
            # $result = Connect-ExchangeOnline @s
            # Write-Debug "Finished doing our own equivalent of 'Connect-IPPSSession"

            Write-Debug "about to do Connect-IPPSSession"
            
            Get-ConnectionInformation | ? {$_.Name.StartsWith("ExchangeOnlineProtection_")} |
            %{ Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId }
            
            $result = @{
                AppID           = $configuration['appId']
                
                ##  Certificate     = $certificate
                CertificateFilePath = $pathOfTemporaryCertificateFile
                CertificatePassword  = ConvertTo-SecureString -AsPlainText $configuration['pfxPassword']
                
                Organization    = $configuration['initialDomainName']
                ## PSSessionOption = $(
                ##     @{
                ##         OpenTimeout = 15000
                ##         IdleTimeout = (4*60000)
                ##     } |% {New-PSSessionOption @_}
                ## )
                <#  2024-06-29-1223: I do not remember why I ever thought to
                    pass the PSSessionOption argument.  As of 2024-06-29-1224,
                    it is not needed, and I worry that it might cause us to
                    connect using the now-deprecated "remote powershell"
                    connection system rather than the currently-preferred, REST
                    http-based system.

                    Even after commenting out the PSSessionOption parameter (and
                    certainly before commenting it out), I am still seeing the
                    welcome-banner/warning message saying "We have made updates
                    to move the SCC admin experience to REST-based APIs. In
                    doing so, we will be deprecating the legacy Remote
                    PowerShell (RPS) protocol starting July 15, 2023."

                    This warning banner only shows up when I do
                    Connect-IPPSSession, not when doing Connect-ExchangeOnline.
                    This makes me think that my ionvocation of
                    Connect-IPPSSession is doing a Remote-Powershell-based
                    connection rather than a REST http connection.

                    Upon further investigation, it seems that the warning banner
                    showing up was purely a function of whether I passed the
                    ShowBanner=$false parameter to the Connect-IPPsSession (or
                    connect-ExchangeOnline ) commands.  Both commands show the
                    same RPS warning banner if I don't pass ShowBanner=$false.  

                    I suspect that the presence of that warning message in the
                    banner does not mean that we are connecting with RPS.
                #>

                ## UseRPSSession = $false
                # the above "UseRPSSession  = $false" is unnecessary and redundant.

                ShowBanner=$false

            }  |% {Connect-IPPSSession @_}
            Write-Debug "Finished doing  'Connect-IPPSSession', with result: $($result)"


            @{
                Scope     = "Global"
                PSSession = $psSessionForExchangeOnlineManagementModule
                FullyQualifiedName      = (invoke-command -Session $psSessionForExchangeOnlineManagementModule {(Get-Command Get-RetentionCompliancePolicy).Module.Path})
                ## NoClobber = $True
                ## Verbose = $true
                DisableNameChecking=$true

            } |% {Import-Module @_}

        }

        function tryToEnsureThatWeAreConnectedToIPPSSession {
            [OutputType([Void])]
            param ()
            try{
                if( getWeAreConnectedToIPPSSession ){
                    Write-Host ("It seems that a connection to IPPSSession already " +
                        "exists, so we will not bother attempting to reconnect.")
                } else {
                    connectToIPPSSession 
                }
            }    
            catch {
                Write-Host ("encountered error when attempting to ensure that we are " +
                    "connected to IPPSSession: $($_)")
            }
        }
    }


    tryToEnsureThatWeAreConnectedToMgGraph
    tryToEnsureThatWeAreConnectedToSharepointOnline
    tryToEnsureThatWeAreConnectedToIPPSSession
    tryToEnsureThatWeAreConnectedToExchangeOnline

    <#  I am intentionally doing Connect-ExchangeOnline after
        Connect-IPPSSession, in the hopes that, wherever there is overlap in
        command names between the two modules, we will end up with the commands
        created by Connect-ExchangeOnline instead of those created by
        Connect-IPPSSession
    #>

    if(getWeAreConnectedToMgGraph){
        Write-Host (-join @(
            "You are connected to Microsoft Graph for the organization "
            "'$((Get-MgOrganization -Property "displayName").displayName)'"
        ))
    } else {
        Write-warning (-join @(
            "You are not connected to microsoft graph."
        ))
    }

    if(getWeAreConnectedToSharepointOnline){
        Write-Host (-join @(
            "You are connected to SharepointOnline for the following Tenant(s): "
            
            @(
                Get-PnpConnection |
                select -expand Tenant
            ) -join ", "

        )) 
    } else {
        Write-warning "You are not connected to SharepointOnline."
    }

    if(getWeAreConnectedToExchangeOnline){
        Write-Host (-join @(
            "You are connected to ExchangeOnline for the following organization(s): "
            
            @(
                Get-ConnectionInformation | ? {$_.Name.StartsWith("ExchangeOnline_")} |
                select -expand Organization
            ) -join ", "

        ))
    } else {
        Write-warning "You are not connected to ExchangeOnline."
    }

    if(getWeAreConnectedToIPPSSession){
        Write-Host (-join @(
            "You are connected to IPPSSession for the following organization(s): "
            
            @(
                Get-ConnectionInformation | ? {$_.Name.StartsWith("ExchangeOnlineProtection_")} |
                select -expand Organization
            ) -join ", "

        ))
    } else {
        Write-warning "You are not connected to IPPSSession."
    }

    <#  It is important that the Exchange Online stuff occurs before the MgGraph
        stuff because Graph loads an older version of the
        System.IdentityModel.Tokens.Jwt assembly than does Exchange Online.  IF
        we try to do the graph stuff first, we get an error when trying to do
        then do the Exchange online stuff. 
    #>



}
