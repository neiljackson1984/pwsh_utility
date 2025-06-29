<#
    Trying to standardize and encapsulate the process of setting up a (set of)
    remote sessions for an IT consulting session. 

    I am not at all fond of having the hardcoded list of function names
    $namesOfFunctionsToImport because we really should be doing something with
    modules instead, but at least with this module, the ever-growing list of
    useful functions can reside in one central place (here in this module),
    rather than being copied and pasted in a million variations all over the
    place.
#>

Import-Module (join-path $psScriptRoot "utility.psm1")
Import-Module (join-path $psScriptRoot "connect_to_office_365.psm1")
Import-Module (join-path $psScriptRoot "softethervpn.psm1")
Import-Module (join-path $psScriptRoot "openvpn.psm1")

class Computer {
    [string] $hostname
    [string[]] $handles

    <# optionally overrides the credential that would otherwise be used #>
    [PSCredential] $credential

    Computer(){}

    Computer([string] $hostname){$this.hostname = $hostname}
}

function Initialize-RemoteSessions {
    <# 
        $computers and $mainComputers will be merged together to construct
        $invokersByHostname and $screenconnectInvokersByHostname.

        The rmain and rsmain functions will be defined for mainComputers. These
        are the computers that we are actively configuring, whereas the non-main
        computers are sessions we might need for reference or central control.

    #>
    
    <# 
        It might be better to create and return a dynamically-created module
        containing the newly-created objects (which the caller can import at his
        discretion) rather than defining the newly created objects in the global
        scope. Principle of least surprise.
    #>
    [cmdletbinding()]
    param(
        [Computer[]] $computers = @(),
        [Computer[]] $mainComputers = @(),
        [string] $bitwardenItemIdOfWindowsCredentialOnTheHypervisor =  "",
        [string] $bitwardenItemIdOfCompanyParameters,
        [string[]] $namesOfVariablesToImport = @(),
        [string[]] $namesOfFunctionsToImport = @(),

        [alias("bitwardenItemIdOfScreenconnectCredentials")]
        [string] $bitwardenItemIdOfScreenconnectCredential,

        [string] $ConfigurationName
    )

    <# 2025-01-09-1014: old to new name convention
    
        ```
        hostamesOfWorkstations                      --> ??
        workstationScreenconnectInvokersByHostname  --> screenconnectInvokersByHostname
        workstationInvokersByHostname               --> invokersByHostname

        hostnamesOfWorkstationsToBeConfigured       --> hostnamesOfComputersToBeConfigured 
        (this is used externally)
        ```
    #>

    $companyParameters = $(getFieldMapFromBitwardenItem $bitwardenItemIdOfCompanyParameters)

    $nameOfScreenconnectGroup = $companyParameters.nameOfScreenconnectGroup ?? 'All Machines'
    $activeDirectoryDomainName = ($companyParameters.domainController -split "\.") | select -skip 1 | join-string -Separator "."

    $namesOfVariablesToImport = @( $namesOfVariablesToImport )
    $namesOfFunctionsToImport = @( $namesOfFunctionsToImport )
    $computers = [Computer[]]  @($computers)
    $mainComputers = [Computer[]]  @($mainComputers)

    $computers = [Computer[]]  @(
        $computers
        $mainComputers
        @{hostname=$companyParameters.domainController; handles=@("dc")}
    )


    $namesOfFunctionsToImport += @(
        "addEntryToSystemPathPersistently"
        "blipnetworkadapter"
        "Convert-FromBase64EncodedCliXml"
        "Convert-ToBase64EncodedCliXml"
        "Convert-XmlDocumentToFormattedXml"
        "cslmgr"
        "Disable-IPv4"
        "Disable-IPv6"
        "Disable-UserAccountControl"
        "Dismount-AllMountedIsoImages"
        "downloadAndExpandArchiveFile"
        "downloadFileAndReturnPath"
        "downloadFileFromSpecialPublicSharepointFolder"
        "Enable-IPv4"
        "Enable-IPv6"
        "Enable-RemoteDesktop"
        "Enable-UserAccountControl"
        "expandArchiveFile"
        "findFileInProgramFiles"
        "format-sortedlist"
        "Get-EncodedPowershellCommand"
        "Get-LastLoggedOnUserName"
        "Get-LastLoggedOnUserProfile"
        "Get-LastLoggedOnUserSID"
        "Get-LocalAccountTokenFilterPolicy"
        "Get-NeilWindowsUpdateLog"
        "Get-ShortPath"
        "getCwcPwshWrappedCommand"
        "getInstalledAppsFromRegistry"
        "getPathOfPossiblyNestedFileMatchingPattern"
        "getStronglyNamedPath"
        "grantEveryoneFullAccessToFile"
        "Install-Winget"
        "installGoodies"
        "Invoke-Periodically"
        "Invoke-WUJob2"
        "Merge-Hashtables"
        "New-TemporaryDirectory"
        "Remove-OrphanedSids"
        "reportDrives"
        "runElevatedInActiveSession"
        "runInActiveSession"
        "Select-Enumerated"
        "select-single"
        "select-singleordefault"
        "sendKeystrokesToVm"
        "Set-LocalAccountTokenFilterPolicy"
        "Set-ScreenSaveTimeOut"
        "uploadFileToSpecialPublicSharepointFolder"
    )

    $namesOfFunctionsToImport  = @($namesOfFunctionsToImport | select -unique)
    $commonArgumentsForNewInvoker = @(
        @{
            VariablesAndFunctionsToImport = @(
                Get-Item -Path @(
                    $namesOfFunctionsToImport |% {"function:$($_)"}
                    $namesOfVariablesToImport |% {"variable:$($_)"}
                )
            )

            StartupScript = {
                ## $InformationPreference='Continue'
                <#  see
                    (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_windows_powershell_compatibility?view=powershell-7.4)

                    see
                    (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_config?view=powershell-7.4)

                    see
                    (https://github.com/PowerShell/PowerShell-RFC/blob/master/Final/RFC0050-Importing-Windows-PowerShell-modules-in-PowerShell-Core.md)

                    Ideally,  I would like to manipulate the curently-active
                    settings corresponding to the compatiility-related settings
                    that can be controlled in a Powershell session configuration
                    file (namely, the "DisableImplicitWinCompat",
                    "WindowsPowerShellCompatibilityModuleDenyList", and
                    "WindowsPowerShellCompatibilityNoClobberModuleList"
                    settings). However, I can not seem to find any way to modify
                    (or even reliably read) these settings for the
                    currently-active session.  therefore, I will have to resort to a clunkier method for selectively disabling the WinPsCompat mechanism.

                    I would expect these settings to be exposed somewhere among the automatic variables or preference variables.  see perhaps:
                        * (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-7.4)
                        * (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.4)
                #>
                &{# explicitly import some modules with judicious of the Windows Powershell compatibility mechanism
                    
                    <#  Explicitly import some modules with judicious of the
                        Windows Powershell compatibility mechanism, in order to
                        work around some bugs in the mechanism that is supposed
                        to automatically correctly decide whether to use the
                        powershell compatibility mechanism.  (there are some
                        modules which powershell core wil, by default, load
                        using the compatibility mechanism but which we would
                        like to load (or try to load) without the compatibility
                        mechanism.  Also, more rearely, there are some modules
                        (e.g. the 'Appx' module) that Powershell core loads by
                        default not using the compatibility mechanism (and it
                        loads successfully), but then the module doesn't work,
                        therefore we need to load it with the compatibility
                        mechanism.)

                    #>


                    ## $initialGlobalErrorActionPreference =  $global:errorActionPreference
                    ## $global:errorActionPreference = "stop"
                    ##if($env:computername -in @("cot15")){return}
                    
                    try{
                        foreach($spec in @(
                                @{nameOfModule = "ActiveDirectory"              ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "ADCSAdministration"           ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "AppX"                         ; weWantToLoadTheModuleByMeansOfWincompat = $False <# $True  #>  }
                                @{nameOfModule = "DhcpServer"                   ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "DnsServer"                    ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "GroupPolicy"                  ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "hyper-v"                      ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "ServerManager"                ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "smbshare"                     ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                @{nameOfModule = "StorageMigrationService"      ; weWantToLoadTheModuleByMeansOfWincompat = $False  }
                                <#  see
                                    (https://github.com/PowerShell/PowerShell/issues/13138#issuecomment-1820195503).
                                #>
                            )
                        ){
                            $module = $(get-module -SkipEditionCheck -listavailable -Name $spec.nameOfModule )
                            
                            
                            if($module){
                                ## $moduleSpecification  = @{
                                ##     ModuleName      = $module.Name
                                ##     GUID            = $module.Guid
                                ##     RequiredVersion = $module.Version
                                ## }

                                $powershellWantsToLoadTheModuleByMeansOfWincompat =  [bool] -not $(
                                    ## get-module -listavailable -FullyQualifiedName $moduleSpecification 
                                    get-module -listavailable -FullyQualifiedName $module.Path
                                )

                                if($powershellWantsToLoadTheModuleByMeansOfWincompat -ne $spec.weWantToLoadTheModuleByMeansOfWincompat){
                                    <# In this case, powershell disagrees with
                                        us about whether the module should be
                                        loaded by means of wincompt.  Therefore,
                                        we will explicitly load the module here
                                        the way we want, in order to prevent
                                        powershell from loading the module the
                                        way we don't want later.
                                    #>

                                    write-information (-join @(
                                        "Trying to import the module "
                                        "'$($module.Name)' version $($module.Version) (guid: $($module.Guid)) "
                                        "explicitly "
                                        if($spec.weWantToLoadTheModuleByMeansOfWincompat){
                                            "by means of the Windows Powershell compatibility mechanism"
                                        } else {
                                            "without resorting to the Windows Powershell compatibility mechanism"
                                        }
                                        "." 
                                    ))

                                    try{
                                        $(
                                            if($spec.weWantToLoadTheModuleByMeansOfWincompat){
                                                @{
                                                    FullyQualifiedName = $module.Path
                                                    UseWindowsPowershell = $true
                                                }
                                            } else {
                                                @{
                                                    ModuleInfo       = $module
                                                    SkipEditionCheck = $True
                                                }
                                            }
                                        )|% { import-module @_  *>&1} | write-information

                                        <#  clever automatic way to specify what
                                            we want to do without having to
                                            explicitly load  the module:

                                            ```
                                            $PSDefaultParameterValues['Import-Module:UseWindowsPowerShell'] = { 
                                                if ((Get-PSCallStack)[1].Position.Text -match '\bAppX') { $true } 
                                            } 
                                            ```

                                            see
                                            (https://github.com/PowerShell/PowerShell/issues/13138#issuecomment-1820195503).

                                            I am not using this technique for
                                            fear that it might be too clever and
                                            too fragile.

                                        #>


                                    }  catch {
                                        write-information (-join @(
                                            "Blithely ignoring an exception that occured "
                                            "while trying to import the module "
                                            "'$($module.Name)' version $($module.Version) (guid: $($module.Guid)) "
                                            if($spec.weWantToLoadTheModuleByMeansOfWincompat){
                                                "by means of the Windows Powershell compatibility mechanism"
                                            } else {
                                                "without resorting to the Windows Powershell compatibility mechanism"
                                            }
                                            ": "
                                            $_
                                        ))
                                    }
                                }
                            }
                        }
                    } finally {
                        ## $global:errorActionPreference = $initialGlobalErrorActionPreference 
                    }
                }
            }

            bitwardenItemIdOfCompanyParameters = $bitwardenItemIdOfCompanyParameters
            ConfigurationName = "powershell.7" 
            ## ConfigurationName = "microsoft.powershell" 
        }
        if($ConfigurationName){@{ConfigurationName = $ConfigurationName}}
    ) | Merge-HashTables

    $cwcArgs = @{ 
        bitwardenItemIdOfScreenconnectCredentials = $bitwardenItemIdOfScreenconnectCredential
        nameOfGroup                               = $nameOfScreenconnectGroup
        pwsh                                      = $False
        preambleCommand                           = @(
            {$InformationPreference='Continue'}    

            $namesOfFunctionsToImport | 
            % {(get-command $_).ScriptBlock.Ast}
        )
    }
    



    $invokersByHostname = (
        @(
            foreach($hostname in @($computers |% {$_.hostname}  | select -unique)){
                $credential  = $($computers |? {$_.hostname -eq $hostname} |% credential  |? {$_}  | select  -first 1)

                @{
                    $hostname = (
                        @(
                            $commonArgumentsForNewInvoker
                            if($credential){@{Credential = $credential}  }
                            @{ComputerName = $hostname}
                        ) | 
                        Merge-HashTables |
                        % {New-Invoker @_ } 
                    )
                }
            } 
        ) | Merge-Hashtables
    )
    
    $hostnameOfHypervisor = $(if($bitwardenItemIdOfWindowsCredentialOnTheHypervisor) {Get-HostnameFromBitwardenItem $bitwardenItemIdOfWindowsCredentialOnTheHypervisor})
    if($hostnameOfHypervisor ){
        $computers = [Computer[]]  @($computers; @{hostname=$hostnameOfHypervisor; handles=@("h")})
    }

    

    if($hostnameOfHypervisor -and $bitwardenItemIdOfWindowsCredentialOnTheHypervisor){
        $invokersByHostname[$hostnameOfHypervisor] =  $(
            @(
                $commonArgumentsForNewInvoker    
                @{ComputerName = $hostnameOfHypervisor}
                @{Credential = Get-CredentialFromBitwardenItem $bitwardenItemIdOfWindowsCredentialOnTheHypervisor}
            ) | 
            Merge-HashTables |
            % {New-Invoker @_ } 
        )  
    }

    $screenconnectInvokersByHostname = (
        @(
            foreach($hostname in @($computers |% {$_.hostname}  | select -unique)){
                @{
                    $hostname = New-ScreenconnectInvoker (Merge-HashTables $cwcArgs @{nameOfSession  = @($hostname -split "\.")[0]})
                }
            } 
        ) | Merge-Hashtables
    )

    foreach($computer in $computers ){
        ## if($computer.handle){
        ##     write-information "defining short-named functions (r$($computer.handle) and rs$($computer.handle)) for handle '$($computer.handle)' and hostname '$($computer.hostname)'. "
        ##     Set-Item -LiteralPath "function:global:r$($computer.handle)" -Value $invokersByHostname[$computer.hostname]
        ##     Set-Item -LiteralPath "function:global:rs$($computer.handle)" -Value $screenconnectInvokersByHostname[$computer.hostname]
        ## }
        
        foreach($handle in $computer.handles){
            write-information "defining short-named functions (r$($handle) and rs$($handle)) for handle '$($handle)' and hostname '$($computer.hostname)'. "
            Set-Item -LiteralPath "function:global:r$($handle)" -Value $invokersByHostname[$computer.hostname]
            Set-Item -LiteralPath "function:global:rs$($handle)" -Value $screenconnectInvokersByHostname[$computer.hostname]
        }
    }

    $hostnamesOfMainComputers = @($mainComputers |% {$_.hostname}  | select -unique)
    $function:rmain = {

        <# hack: I copied and pasted the parameter block from ($invokersByHostname.Values | select -first  1)  

            #TODO: do this kind of currying automatically.
        #>
        [CmdletBinding()]
        Param(
            [parameter()]
            [ScriptBlock] $ScriptBlock,

            [parameter()]
            [Object[]] $ArgumentList
        )

        foreach($hostname in $hostnamesOfMainComputers) {
            write-information "$(get-date): now working on $($hostname)"
            & $invokersByHostname[$hostname] @PSBoundParameters
        }
    }.GetNewClosure()

    $function:rsmain = {
        <# hack: I copied and pasted the parameter block from ($screenconnectInvokersByHostname.Values | select -first  1)  

            #TODO: do this kind of currying automatically.
        #>

        [CmdletBinding(PositionalBinding=$False)]
        Param(
            [Parameter(Mandatory=$False)] 
            [System.TimeSpan] $timeout,
    
            [Parameter(Mandatory=$False)] 
            [int] $timeoutMilliseconds,

            [Parameter(Mandatory=$False)]
            [boolean] $pwsh,

            [Parameter(
                Position=1,
                Mandatory=$False
            )]
            [string[]] $command,

            [Parameter(Mandatory=$False)]
            [switch]$NoWait = $false

        )

        foreach($hostname in $hostnamesOfMainComputers) {
            write-information "$(get-date): now working, via screenconnect, on $($hostname)"
            & $screenconnectInvokersByHostname[$hostname] @PSBoundParameters
        }
    }.GetNewClosure()
    
    <# export some useful global variables: #>
    ${global:hostnamesOfMainComputers}        = $hostnamesOfMainComputers
    ${global:invokersByHostname}              = $invokersByHostname
    ${global:screenconnectInvokersByHostname} = $screenconnectInvokersByHostname
    ${function:global:rmain}                  = $function:rmain
    ${function:global:rsmain}                 = $function:rsmain
    ${global:companyParameters}               = $companyParameters
    ${global:nameOfScreenconnectGroup}        = $nameOfScreenconnectGroup
    ${global:activeDirectoryDomainName}       = $activeDirectoryDomainName



}


## Export-ModuleMember -Function * -Alias *

