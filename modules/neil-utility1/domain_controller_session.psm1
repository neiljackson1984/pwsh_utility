
Import-Module (join-path $psScriptRoot "utility.psm1")

function New-DomainControllerPSSession {
    <#
        .DESCRIPTION
        Establishes and returns a PSSession to the domain controller specified 
        by primaryDomainName (looking up the corresponding "companyParameters" entrry in bitwarden.

        This is basically a wrapper around New-PSSession, which pulls in canned configuration data from bitwarden.
    #>

    # This is basically a wrapper around New-PSSession, which pulls in canned configuration data from bitwarden.

    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])] #really, nullable PSSession
    Param(
        [Parameter(
            HelpMessage= {@(
                "This is just a shortcut for specifying the "
                "bitwarden item id in the canonical way.  "
                "This parameter is completely ignored if "
                "bitwardenItemIdOfTheCompanyParameters is truthy."
            ) -join ""},
            Position=0
        )]
        [String] $primaryDomainName = "",

        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item containing the companyParameters.")]
        [String] $bitwardenItemIdOfTheCompanyParameters = ""
    )

    if(-not ($primaryDomainName -or $bitwardenItemIdOfTheCompanyParameters)){
        Write-Host "you must specify at least one of bitwardenItemIdOfTheCompanyParameters or primaryDomainName.  doing nothing."
        return $null
    }

    if((-not $bitwardenItemIdOfTheCompanyParameters) -and ($primaryDomainName)){            
        $bitwardenItemIdOfTheCompanyParameters = "$($primaryDomainName) companyParameters"
    }

    $companyParameters = getFieldMapFromBitwardenItem $bitwardenItemIdOfTheCompanyParameters
    $bitwardenItemContainingActiveDirectoryCredentials = Get-BitwardenItem $companyParameters['idOfBitwardenItemContainingActiveDirectoryCredentials']
    $username = (
        @(
            $bitwardenItemContainingActiveDirectoryCredentials.fields | Where-Object {$_.name -eq 'active_directory_domain_name'} | 
                Foreach-object {$_.value}
        )[0] +
        "\" + 
        ($bitwardenItemContainingActiveDirectoryCredentials.login.username -split "@")[0]
    )
    $password = $bitwardenItemContainingActiveDirectoryCredentials.login.password
    if ($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController']){
        Write-Host "connecting to vpn connection $($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'])"
        vpncmd /client localhost /cmd AccountConnect $companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'] | Out-Null
    }
    
    # Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value $companyParameters['domainController']
    Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value $(
        @( 
            ((Get-Item WSMan:\localhost\Client\TrustedHosts).Value) -split "," | Where-Object {$_}
            $companyParameters['domainController']
        ) -join "," 
    )

    $ss = @{
        ComputerName = $companyParameters['domainController'];
        
        Credential=(New-Object `
            System.Management.Automation.PSCredential `
            $username, (ConvertTo-SecureString $password -AsPlainText -Force)
        )
        
        # ConfigurationName="Powershell.7.1.5";
        ConfigurationName="microsoft.powershell";
        # run Get-PSSessionConfiguration  to see a complete list of available configurations
        
        SessionOption=@{
            # OutputBufferingMode=;
        };
    
        # Authentication='Digest';
        # UseSSL=$True;
    }
    
    $psSession = New-PSSession @ss

    if($psSession){
        Write-Host "$(Invoke-Command -Session $psSession { return "hello from $($env:computername).  ((Get-ADDomain).DistinguishedName): $((Get-ADDomain).DistinguishedName)" })"
    }

    return $psSession
}