
Import-Module (join-path $psScriptRoot "utility.psm1")
Import-Module (join-path $psScriptRoot "connect_to_office_365.psm1")
Import-Module (join-path $psScriptRoot "softethervpn.psm1")
Import-Module (join-path $psScriptRoot "openvpn.psm1")

function initializeUser {
    [CmdletBinding()]
    Param(
            [HashTable] $userSpec,
            [Switch] $sendToDebuggingAddressInsteadOfTrueAddresses = $false,
            [Switch] $doSendWelcomeMessage = $false,
            [String] $emailAccountForSendingAdvisoryMessages = $null
    )
    $companyParameters = getFieldMapFromBitwardenItem $userSpec['bitwardenItemIdOfCompanyParameters']
    connectToOffice365 -bitwardenItemIdOfTheConfiguration $companyParameters['idOfBitwardenItemContainingMicrosoftGraphManagementConfiguration']
    $publicDomainName = ((Get-MgOrganization).VerifiedDomains | where-object {$_.IsDefault -eq $true}).Name
        

    $defaultUsername        = ($userSpec['firstName'][0] + $userSpec['lastName']).toLower()
    $defaultEmailAddress    = "$defaultUsername@$publicDomainName"
    $username               = if($userSpec.preferredEmailAlias){$userSpec.preferredEmailAlias} else {$defaultUsername}
    $primaryEmailAddress    = "$username@$publicDomainName"
    $userPrincipalName      = $primaryEmailAddress
    $password               = $userSpec['password']
    $displayName            = "$($userSpec['firstName']) $($userSpec['lastName'])"
    
    if ($companyParameters['emailDomainName'] -eq 'nakanoassociates.com'){
        Write-Host "this is a Nakano job"
        
        $idOfBitwardenItemContainingSoftetherVpnServerCredentials='5d918212-baf7-44d7-bf18-acf701364944'
        $bitwardenItemContainingSoftetherVpnServerCredentials = Get-BitwardenItem $idOfBitwardenItemContainingSoftetherVpnServerCredentials
        $vpnServerPassword=$bitwardenItemContainingSoftetherVpnServerCredentials.login.password
        $softetherVpnServerHostname = ( $bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[0]
        $softetherVpnServerPortnumber = ( $bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[1]
        $softetherVpnServerNameOfHub = (@($bitwardenItemContainingSoftetherVpnServerCredentials.fields | Where-Object {$_.name -eq 'name of HUB'} | Foreach-object {$_.value})[0])

    


        vpncmd ($softetherVpnServerHostname + ":" + $softetherVpnServerPortnumber) /SERVER /PASSWORD:"$vpnServerPassword" /ADMINHUB:"$softetherVpnServerNameOfHub"  /CMD UserCreate $username /GROUP:none /REALNAME:none /NOTE:none 
        vpncmd ($softetherVpnServerHostname + ":" + $softetherVpnServerPortnumber) /SERVER /PASSWORD:"$vpnServerPassword" /ADMINHUB:"$softetherVpnServerNameOfHub"  /CMD UserPasswordSet $username /PASSWORD:"$password"


        $scriptToBeRunOnNaserver1 = @(
            # "username=`"$username`"" 
            # "password=`"$($password)`"" 
            "# create a linux account for the new user" 
            "useradd -m '$username'" 
            "" 
            "# set the password of the linux user:" 
            "echo '$password' | passwd --stdin '$username'" 
            "" 
            "# add new user to the samba users database:" 
            "echo -e '$password\n$password' | smbpasswd -a '$username'" 
            "echo -e '$password\n$password' | smbpasswd -s '$username'" 
            "" 
            "# add the new user to the samba_users group:" 
            "gpasswd --add '$username' samba_users" 
            "" 
            "# (optional) restart the smb server:" 
            "service smb restart" 
        ) -join "`n"

        # this is a bit of hack: we simply copy a command to the clipboard that is suitable for pasting into the screenconnect command interface.
        # perhaps eventually, we would ssh the command directly to naserver1.
        Set-Clipboard -Value ("#!sh`n#timeout=90000`n#maxlength=99999`n$scriptToBeRunOnNaserver1");


        $mgUser = (Get-MgUser -UserId  $userPrincipalName -ErrorAction SilentlyContinue)
        
        if( $mgUser ){
            Write-Host "An MgUser having id '$userPrincipalName' already exists, so we will not create a new user." 
        } else {
            Write-Host "No MgUser having id '$userPrincipalName' exists, so we will create one." 
            $s = @{
                AccountEnabled    = $True
                # DisplayName       = "to_be updated_later"
                PasswordProfile  = @{
                    ForceChangePasswordNextSignIn           = $False
                    ForceChangePasswordNextSignInWithMfa    = $False
                    Password                                = $password
                }
                MailNickname      = $username
                UserPrincipalName = $userPrincipalName
                Surname           = $userSpec['lastName'] 
                GivenName         = $userSpec['firstName'] 
                DisplayName       = $displayName
            }; New-MgUser @s 1> $null;
        }


        $mgUser = Get-MgUser -UserId  $userPrincipalName 
        
        @{
            userId               = $mgUser.Id
            skuPartNumbers       = $userSpec.licenses
            namesOfDisabledPlans = $userSpec.namesOfDisabledPlans
        } | % { setLicensesAssignedToMgUser @_ }
        
   
        $mgUser = Get-MgUser -UserId  $mgUser.Id  
        
        
        $desiredEmailAddresses = @()
        $desiredEmailAddresses += "$primaryEmailAddress"
        if(! ($primaryEmailAddress -eq $defaultEmailAddress)){
            # make sure that the $default email address, as a non-primary smtp address, exists in the ProxyAddresses array
            $desiredEmailAddresses += "$defaultEmailAddress"
        }
        foreach($desiredAdditionalEmailAddress in $userSpec['desiredAdditionalEmailAddresses']){
            $desiredEmailAddresses += "$desiredAdditionalEmailAddress"
        }


        $mailbox = Get-Mailbox $mgUser.Id -ErrorAction SilentlyContinue
        if (! $mailbox ){
            Write-Host "The user $userPrincipalName does not appear to have a mailbox, so we will not attempt to adjust email addresses."
        } else {
            
            
            # Write-Host "initially, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
            
            # $emailAddressesToRemove = $mailbox.EmailAddresses | where-object {
            #     ($_ -match '(?-i)^SMTP:.+$') -and (-not ($_ -in $desiredEmailAddresses)) # it is an smtp address of some sort and it is not in the desiredEmailAddresses List
            # }
            # $emailAddressesToAdd = $desiredEmailAddresses | where-object {
            #     -not ($_ -in $mailbox.EmailAddresses) # it is not already in the mailbox's Email Addresses
            # }

            # if( ([Boolean] $emailAddressesToRemove) -or ([Boolean] $emailAddressesToAdd) ){
            #     Write-Host "emailAddressesToRemove ($($emailAddressesToRemove.Length)): ", $emailAddressesToRemove
            #     Write-Host "emailAddressesToAdd ($($emailAddressesToAdd.Length)): ", $emailAddressesToAdd
                

            #     $s = @{
            #         EmailAddresses = @{
            #             Add=@($emailAddressesToAdd); 
            #             Remove=@($emailAddressesToRemove)
            #         }; 
            #     }; $mailbox | Set-Mailbox @s ; 
            #     $mailbox =  Get-Mailbox $mgUser.Id
            #     Write-Host "finally, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
            # } else {
            #     Write-Host "email addresses for $userPrincipalName are as desired, so we will not bother to add or remove any."
            # }
            
            @{
                mailboxId = $mailbox.Guid 
                desiredSmtpAddresses = $desiredEmailAddresses
                desiredPrimarySmtpAddress = $primaryEmailAddress
            } | % { setSmtpAddressesOfMailbox  @_ }


        }
        # return;
    } else {


        $scriptBlockToBeRunOnDomainController = {
            $userSpec               = $using:userSpec
            
            
            # $defaultUsername        = ($userSpec['firstName'][0] + $userSpec['lastName']).toLower()
            # $defaultEmailAddress    = "$defaultUsername@$publicDomainName"
            # $username               = if($userSpec.preferredEmailAlias){$userSpec.preferredEmailAlias} else {$defaultUsername}
            # $primaryEmailAddress    = "$username@$publicDomainName"
            # $userPrincipalName      = $primaryEmailAddress
            # $password               = $userSpec['password']


            $defaultUsername        = $using:defaultUsername       
            $defaultEmailAddress    = $using:defaultEmailAddress   
            $username               = $using:username              
            $primaryEmailAddress    = $using:primaryEmailAddress   
            $userPrincipalName      = $using:userPrincipalName     
            $password               = $using:password              
            $publicDomainName       = $using:publicDomainName              
            $displayName            = $using:displayName              


            Write-Host "$env:computername is working on $($userSpec['firstName'][0] + $userSpec['lastName'])"
            # assert $publicDomainName -eq (get-adforest).UPNSuffixes[0]
            $adUser = Get-ADUser $username
            if($adUser){
                Write-Host "The adUser `"$($username)`" already exists, so we will not bother to create."
            } else {
                Write-Host "creating adUser `"$($username)`"."
                
                New-ADUser `
                    -ErrorAction SilentlyContinue `
                    -Path ( "OU=humans" + "," + "OU=users" + "," + "OU=company" + "," + (Get-ADDomain).DistinguishedName  ) `
                    -Name $username `
                    -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force  ) `
                    -Enabled $True `
                    -PassThru 
                
                $adUser = Get-ADUser $username
            }
                
            $adUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force  ) 
            
            @{
                UserPrincipalName   =  $userPrincipalName 
                EmailAddress        =  $userPrincipalName 
                Surname             =  $userSpec['lastName'] 
                GivenName           =  $userSpec['firstName'] 
                DisplayName         =  $displayName
                # Name                =  $displayName
            } | % { $adUser | Set-ADUser @_ }
            
            # $adUser = $adUser | Get-ADUser ; $adUser.Name = $adUser.DisplayName; Set-ADUser -Instance $adUser;
            #doesn't work

            # $adUser | Get-ADObject | Rename-ADObject -NewName $adUser.DisplayName
            #works, but decided not to do.

            if($userSpec['encodedDesiredMSDsConsistencyGuid']){
                @{
                    Path   = "AD:\$($adUser.distinguishedName)" 
                    Name   = "mS-DS-ConsistencyGuid" 
                    Value  = ([Convert]::FromBase64String($userSpec['encodedDesiredMSDsConsistencyGuid']))
                } | % { Set-ItemProperty  @_ }
            }

            $adUser = $adUser | Get-ADUser -Properties ProxyAddresses
            $initialProxyAddresses = @($adUser.ProxyAddresses)
            
            #remove all (probably one) primary email addresses (i.e. elements of proxyAddresses starting with "SMTP:"
            $entriesToRemoveFromProxyAddresses = $adUser.ProxyAddresses | where-object {$_.StartsWith("SMTP:")}
            foreach($entryToRemoveFromProxyAddresses in $entriesToRemoveFromProxyAddresses){
                $adUser.ProxyAddresses.remove($entryToRemoveFromProxyAddresses)
            }         
            
            $adUser.ProxyAddresses.add("SMTP:$primaryEmailAddress")
            
            $desiredProxyAddressesEntry="SMTP:$primaryEmailAddress"
            if( ! ( $adUser.ProxyAddresses.contains($desiredProxyAddressesEntry) ) ){
                $adUser.ProxyAddresses.add($desiredProxyAddressesEntry)
            }
            
            if(! ($primaryEmailAddress -eq $defaultEmailAddress)){
                #make sure that the $default email address, as a non-primary smtp address, exists in the ProxyAddresses array
                $desiredProxyAddressesEntry="smtp:$defaultEmailAddress"
                if( ! ( $adUser.ProxyAddresses.contains($desiredProxyAddressesEntry) ) ){
                    $adUser.ProxyAddresses.add($desiredProxyAddressesEntry)
                }
            }
            
            foreach($desiredAdditionalEmailAddress in $userSpec['desiredAdditionalEmailAddresses']){
                if( ! ( ($adUser.ProxyAddresses.contains("smtp:$desiredAdditionalEmailAddress")) -or ($adUser.ProxyAddresses.contains("SMTP:$desiredAdditionalEmailAddress"))) ){
                    $adUser.ProxyAddresses.add("smtp:$desiredAdditionalEmailAddress")
                }
            }
            
            $desiredFinalProxyAddresses = $adUser.ProxyAddresses
            
            Write-Host "initialProxyAddresses: ", $initialProxyAddresses
            Write-Host "desiredFinalProxyAddresses: ", $desiredFinalProxyAddresses
            
            
            Set-ADUser -Instance $adUser 1> $null

            # add the user to the various wse groups.
            foreach($nameOfGroup in @(
                "WseAllowAddInAccess"
                "WseAllowComputerAccess"
                "WseAllowHomePageLinks"
                "WseAllowShareAccess"
                "WseRemoteAccessUsers"
                "WseRemoteWebAccessUsers"
            )){
                Add-ADGroupMember -Identity $nameOfGroup -Members $adUser.objectGUID 
            }


            Import-Module ADSync
            Start-ADSyncSyncCycle  -PolicyType Delta  
            Write-Host "adUser: $($adUser | Out-String)"

            return $adUser
        }

        $VerbosePreference = 'Continue'
        $adUser = (
            @{
                Session = (getDcSession -bitwardenItemIdOfCompanyParameters $userSpec['bitwardenItemIdOfCompanyParameters'])
                ScriptBlock = $scriptBlockToBeRunOnDomainController
            } | 
            % {Invoke-Command @_} |
            Select-Object -Last 1
        )
        Write-Host "adUser: $($adUser | Out-String)"

        if(-not $adUser){
            Write-Host "we have failed to retrieve the adUser, and so will return now."
            return
        }

        $mgUser = Get-MgUser -UserId $adUser.UserPrincipalName -ErrorAction SilentlyContinue

        if (! $mgUser ){
            Write-Host "No MgUser having id $($adUser.UserPrincipalName) exists.  Probably need to wait a few minutes for adsync to push changes to the cloud."
        } else {
            # assign licenses:
            @{
                userId               = $mgUser.Id
                skuPartNumbers       = $userSpec.licenses
                namesOfDisabledPlans = $userSpec.namesOfDisabledPlans
            } | % { setLicensesAssignedToMgUser @_ }

        }

    }


    if($doSendWelcomeMessage){
        $recipientAddress = ($displayName + "<" + $userPrincipalName + ">")

            
        @{
            emailAccount = $emailAccountForSendingAdvisoryMessages

            from = $emailAccountForSendingAdvisoryMessages

            to = $(
                if($sendToDebuggingAddressInsteadOfTrueAddresses){
                    $companyParameters['debuggingAddress']
                } else {
                    $recipientAddress
                }
            )

            cc = @( 
                
                $companyParameters['managerName'] + 
                "<" + 
                $(
                    if($sendToDebuggingAddressInsteadOfTrueAddresses){
                        $companyParameters['debuggingAddress']
                    } else {
                        $companyParameters['managerEmailAddress']
                    }
                ) + 
                ">" 

                if(-not $sendToDebuggingAddressInsteadOfTrueAddresses){
                    $userSpec.personalEmailAddresses
                }
            )

            subject = (
                $(
                    if($sendToDebuggingAddressInsteadOfTrueAddresses){
                        "(TO: $recipientAddress) " 
                    } else {
                        ""
                    } 
                ) + 
                "$($companyParameters['companyName']) Active Directory account for $($userSpec['firstName']) $($userSpec['lastName'])"
            )

            body  = @( 
                "Dear $($userSpec.firstName) $($userSpec.lastName), "

                ""

                "Welcome to $($companyParameters['companyName']).  " +
                "Here are your $($companyParameters['companyName']) Active Directory credentials:"

                "    username (and email address): $($userPrincipalName)"

                "    password: $($password)"

                ""

                if($companyParameters['passwordChangeUrl']){
                    "To change your " +
                    "password, go to  $($companyParameters['passwordChangeUrl'])."

                    ""
                } else {
                    "To change your " +
                    "password, log in to your computer, press  Ctrl-Alt-Delete, then click `"Change a password`"."

                    ""
                }

                ##  "Use the above username and password to log into " +
                ##  "your computer at the $($companyParameters['companyName']) office and " +
                ##  "to access $($companyParameters['companyName']) email.  "


                "Use the above username and password to log into " +
                "your $($companyParameters['companyName']) computer and " +
                "to access $($companyParameters['companyName']) email.  "

                ""
                
                if ($companyParameters['emailDomainName'] -eq 'lucasinterior.com'){

                    "Your $($companyParameters['companyName']) email account is provided " +
                    "by Gmail.  To access $($companyParameters['companyName']) email, use the web interface at " +
                    "https://gmail.com or use your email client of choice.  "

                } else {

                    ##  "There is a webmail interface at https://outlook.office.com, which allows " +                                   
                    ##  "you to access your $($companyParameters['companyName']) email from a web " +                                   
                    ##  " browser.  You can also access email in Outlook on your $($companyParameters['companyName']) computer."        
                    ##                                                                                                                  
                    ##  ""                                                                                                              
                    ##                                                                                                                  
                    ##  "Here are all the details that you might need to " +                                                            
                    ##  "set up email on your smart phone, if you are so inclined:"                                                     
                    ##                                                                                                                  
                    ##  "    Account type: Exchange (some phones call this `"Corporate`")"                                              
                    ##                                                                                                                  
                    ##  "    Email address: $($userPrincipalName)"                                                                      
                    ##                                                                                                                  
                    ##  "    Username: $($userPrincipalName)"                                                                           
                    ##                                                                                                                  
                    ##  "    Password: $($password)"                                                                                    
                    ##                                                                                                                  
                    ##  "    Domain: $($companyParameters['emailDomainName'])"                                                          
                    ##                                                                                                                  
                    ##  "    Exchange Server address: outlook.office365.com"                                                            
                    ##                                                                                                                  
                    ##  "    TLS (this is usually a checkbox): yes (checked)"                                                           

                    "Your $($companyParameters['companyName']) mailbox is hosted on " +
                    "Microsoft Exchange Online.  To access $($companyParameters['companyName']) email, use the web interface at " +
                    "https://outlook.office.com or use your email client of choice.  "

                }

                if ($userSpec.phoneExtensionNumber -and $userSpec.directDialPhoneNumber){

                    ""

                    "Your $($companyParameters['companyName']) phone extension number " + 
                    "is $($userSpec.phoneExtensionNumber).  "

                    ""

                    "Your $($companyParameters['companyName']) phone direct-dial " +
                    "number is $($userSpec.directDialPhoneNumber)."

                }


                if ($userSpec.phoneMacAddress){

                    ""

                    "Your desk phone's MAC address is " + 
                    "$($userSpec.phoneMacAddress).  "

                }


                ""
                ""
                "Sincerely,"
                "Neil Jackson"
                "neil@autoscaninc.com"
                "425-218-6726 (cell)"
                "206-282-1616 ext. 102 (office)"
                ""
                "Autoscan, Inc."
                "4040 23RD AVE W"
                "SEATTLE WA 98199-1209"
                "206-282-1616"
            ) -Join "`n"

        } | % { sendMail @_ }
    }

}

function getDcSession {
    <#
    .SYNOPSIS
    This is basically a wrapper around New-PsSession that takes an additional
    argument: bitwardenItemIdOfCompanyParameters. This is used to look up a
    bitwarden item to set the default hostname to connect to and to control
    whether we attempt to connect to some vpn connection.

    TODO (perhaps): somcehow automatically disconnect from the VPN at an
    appropriate time, rather than leaving the VPN connection connected
    indefintely in our wake.  This might be acheived by handling the kill
    signal, or, perhaps more exotically, with a scheduled task or keepalive
    mechanism, or maybe something built into softether vpn client?
    #>
    
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    Param(
        [Parameter(
            Mandatory=$True
            
        )]
        [String] 
        $bitwardenItemIdOfCompanyParameters,



        ## the only New-PSSession arguments that we need to specify here are the ones for which we want to construct a "default" value.
        ## any NewPSSession argument that we don't care about constructing a "default" value for will be handled by $remainingArguments below.
        ## having to specify these here is in some sense a result of there not being a convenient way to reverse-splat an argument list into a hash table. 
        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default ComputerName argument"            
        )]
        [String] 
        # New-PSSession's ComputerName argument has type String[] , in which case it will return more than one pssession's.  
        # This confuses me because I do not know how to declare the OutputType to indicate that a function might return multiple objects,
        # so I am going to specify my ComputerName argument as having type String.  Probably not ideal, but good enough for my application.
        $ComputerName,
        
        [Parameter(
            Mandatory=$False,
            HelpMessage="disable the automatic vpn connection behavior"            
        )]
        [Switch] 
        $DisableAutomaticVpnConnection = $False,

        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default ConfigurationName argument"            
        )]
        [String] 
        $ConfigurationName,

        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default Credential argument"            
        )]
        [System.Management.Automation.PSCredential] 
        $Credential,

        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default SessionOption argument"            
        )]
        [Object] 
        $SessionOption,

        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default Name argument"            
        )]
        [string] 
        $Name,

        [Parameter(
            ValueFromRemainingArguments = $True,
            # HelpMessage = "remaining arguments will be passed to New-PsSession",
            Mandatory = $False
        )]
        [Object[]] 
        $remainingArguments = @()

        <#  My idea with "remainingArguments" is not working as I had expected
            because Powershell does not treat the parameter names within a
            function invokation (i.e. strings starting with a dash) as strings
            but they are really high-level name tokens.  If you try to include
            "-blarg" in the argument list of a function call to a function that
            does not have an explicitly-decalred parameter named "blarg",
            powershell throws an error.

            the "remainingArguments" mechanism would work for positional
            parameters.



            * see
              [https://stackoverflow.com/questions/27764394/get-valuefromremainingarguments-as-an-hashtable]
            * see
              [https://stackoverflow.com/questions/27463602/nested-parameters-for-powershell-cmdlet]
            * see
              [https://www.powershellgallery.com/packages/MSAL.PS/4.7.1.2/Content/Select-PsBoundParameters.ps1] 
        #>
    )

    $companyParameters = getFieldMapFromBitwardenItem $bitwardenItemIdOfCompanyParameters
    $bitwardenItemContainingActiveDirectoryCredentials = Get-BitwardenItem $companyParameters['idOfBitwardenItemContainingActiveDirectoryCredentials']

    $username = (
        @(
            $bitwardenItemContainingActiveDirectoryCredentials.fields | 
                ? {$_.name -eq 'active_directory_domain_name'} | 
                % {$_.value}
        )[0] +
        "\" + 
        @($bitwardenItemContainingActiveDirectoryCredentials.login.username -split "@")[0]
    )
    $password=$bitwardenItemContainingActiveDirectoryCredentials.login.password

    if (-not $DisableAutomaticVpnConnection){
        if($($companyParameters['vpn'])){
            write-host "attempting to connect to vpn specified by '$($companyParameters['vpn'])'. "
            Connect-OpenVpn -bitwardenItemId $($companyParameters['vpn'])
        } elseif ($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController']){
            write-host "ensuring connection to vpn '$($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'])'. "
            Connect-SoftEtherVpn $companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'] | out-null
        } 
    }

    $argumentsForNewPsSession = (

        # my constructed "defaults":
        @{
            ComputerName = $(if($ComputerName){$ComputerName} else {$companyParameters['domainController']     })

            Credential = $(if($Credential){$Credential} else { (
                @{
                    TypeName = "System.Management.Automation.PSCredential"
                    ArgumentList =  @(
                        $username
                        (ConvertTo-SecureString $password -AsPlainText -Force)
                    )
                } | % { New-Object @_ }
            ) })
            
            # ConfigurationName="Powershell.7.1.5";
            ConfigurationName = $(if($ConfigurationName){$ConfigurationName} else  {"microsoft.powershell"})
            # run Get-PSSessionConfiguration  to see a complete list of available configurations
            
            # SessionOption=@{
            #     # OutputBufferingMode=;
            # }
    
            # Authentication='Digest';
            # UseSSL=$True;

        } + $(
            if($SessionOption){@{SessionOption=$SessionOption}}
            else {@{}}
        ) + $(
            if($Name){@{Name=$Name}}
            else {@{}}
        )
    )



    # #overrides:
    # @{
    #     # somehow massage $remainingArguments into the form of a hash table
    # }.GetEnumerator().ForEach( {$argumentsForNewPsSession[$_.key] = $_.value} )


    # $HostName = $HostName ? $HostName : $companyParameters['domainController']
    
    
    Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Concatenate -Value $argumentsForNewPsSession['ComputerName'] | Out-Null
    # The -concatenate switch ensures that we do not clobber the existing list.
    # probably ought to also check whether $HostName is already in the list (it
    # looks like the set-item -Concatenate mechanism is already preventing
    # duplicates automatically, so we won't bother).

    # return ( New-PSSession @argumentsForNewPsSession @remainingArguments )
    # return ( New-PSSession @argumentsForNewPsSession )

    $psSession = $( New-PSSession @argumentsForNewPsSession )

    if($psSession) {
        Invoke-Command $psSession {  
            write-host (
                @(
                    "hello from $($env:computername).  Running powershell $($psVersionTable.PSEdition) $($psVersionTable.PSVersion)."
                ) -join "`n"
            )
        } | write-host
    } 

    return $psSession
}


function getArgumentsForGetDcSessionForNonDomainSession  {
    
    <#  This function is a bit of a hack.  What we really want is a robust way
        to encode, in a bitwarden item (and ideally we wuld not be strictly
        dependent on bitwarden but could work with any arbitrary secrets
        database) all the information (including secrets) necessary to establish
        a a psremoting session.  At the moment, the mechanism that we have to do
        this is geared toward pulling a domain administrator credential from a
        "companyParameters" bitwarden item.  This function here exists to allow
        us to use local credentials instead.

        in general, we need to rethink how we do bitwarden-assisted
        authentication into psremoting sessions (we ought to prefer public key
        cryptography).

        This whole thing is a bit messy.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    Param(
        [string] $bitwardenItemIdOfWindowsCredentialsOnTargetComputer,
        [string] $bitwardenItemIdOfCompanyParameters,
        [parameter(mandatory=$false)][string] $ConfigurationName
    )

    $bitwardenItem = Get-BitwardenItem $bitwardenItemIdOfWindowsCredentialsOnTargetComputer
    $hostname = (
        (getFieldMapFromBitwardenItem $bitwardenItem.id)['hostname'] ?? 
        ([System.Uri] @($bitwardenItem.login.uris)[0].uri).Host ??
        @($bitwardenItem.login.uris)[0].uri
    )
    ## write-host "hostname: $hostname"
    @{
        bitwardenItemIdOfCompanyParameters = $bitwardenItemIdOfCompanyParameters
        ComputerName = $hostname
        Credential = (
            @{
                TypeName = "System.Management.Automation.PSCredential"
                ArgumentList = @(
                    # "$($hostname)\$($bitwardenItem.login.username)"
                    "$($bitwardenItem.login.username)"
                    (ConvertTo-SecureString $bitwardenItem.login.password -AsPlainText -Force)  
                )
            } | % { New-Object @_ } 
        )
    } + (
        $ConfigurationName ?
        @{ ConfigurationName = $ConfigurationName } :
        @{}
    ) 
}


function New-Invoker {
    <#
    .SYNOPSIS
    Returns a function (a script block) that accepts a ScriptBlock and
    ArgumentList, much like Invoke-Command does, but with canned connection
    details with authentication based on Bitwarden, the ability to accept a
    bitwarden item id as a reference to credentials (via ArgumentsForDcSession),
    and the ability to make a set of variables and functions from the local
    session available in the global scope of the remote session (via
    serialization).  The returned function attempts to re-use the same session
    from a previous calls, but checks to ensure that the session is open and
    available and, if not, automatically attempts to create a new session and
    reconnect.

    .DESCRIPTION
    Before I wrote New-Invoker, I was in the habit of creating, and connecting
    to, all the various PsSession's that I needed at once at the beginning of a
    session.  This process was slow (due in part to very slow bitwarden
    lookups), and if even one of the PsSessions became invalid or disconnected
    (due for example to restarting the remote computer), the most convenient way
    to create a new valid session to replace the failed session was to re-run
    the entire sequence to recreate and reconnect to all sessions.  This was
    slow.  Often, I wouldn't immediately need some of the PsSessions -- I just
    wanted to re-establish one failed session to run the next command that I
    wanted to run.  New-Invoker (or, more accurately, the functions that
    New-Invoker returns, imprvoe the situation).

    TODO: consider the consequences of re-using the same remote session for
    multiple calls to the function returned by New-Invoker.  Sometimes,
    particulary while debugging, it is useful to have the session preserveds so
    that we can inspect variables and run large sequences of commands
    incrementally and in some sense interactively.  Re-using an already-used
    session might avoid the overhead of creating a new session on every call.
    However, eliminating the saved state of a re-used session could potentially
    improve predictability, stability, and security.  Our current strategy, of
    silently (except for a few Write-Host messages) recreating the session if it
    has become disconnected or ceased to exist, could confuse the user, who
    might be expecting the session state to be as he left it.  I can almost
    imagine having a Switch argument (to the function returned by New-Invoker)
    called -NeedPreviousState, that would cause the function to throw an error
    (and not attempt to run the passed command) if the session had to be
    recreated.  Maybe we also need a switch called "NeedFreshState" that would
    force a new session to be created.  Such switch arguments are obviously ugly
    and seem impractical at the moment, but we should try to be sensitive
    (somehow) to the user's expectation about whether he is running one more
    command in an existing session (with state leftover from previous commands)
    or, alternatively, whether he is running the command in a virgin session
    ("virgin" except, perhaps, for the imported VariablesAndFunctionsToImport).

    TODO: clean up the authentication system.  I do not like relying on
    getDcSession, which itself is a bit of a hack.  I would also prefer to use
    asymmetric keys for authentication rather than usernames and passwords.

    TODO:  think about the best way to share variables and functions with the
    remote session.  It would be good to try to take advantage of Powershell's
    "module" concept, and share an entire module.

    TODO perhaps: if a session is merely disconnected, but still exists on the
    remote computer, attempt to reconnect to the existing session on the remote
    computer rather than creating an entirely new session.

    TODO perhaps: provide a way to create multiple simultaneous sessions on a
    remote computer, all with the same local session.  On the other hand, maybe
    this is best handled within the one "master" remote session.  what I have in
    mind is the case where I want to create a "long-running" session on the
    remote computer that will persist and continue running and exising and
    working even if I disconnect for a long time.  

    .PARAMETER ArgumentsForGetDcSession
    These arguments will be applied to a set of default arguments defined in
    this function, and then splatted into getDcSession, which we use internally
    to get the ps remoting session.  Relying on getDcSession, and the whole
    getDcSession mechanism is all a bit of a hack to automate the use of
    Bitwarden to store credentials for psremoting.  The whole thing needs to be
    refactored, and ideally made to use public key infrastructure rather than
    the current system of usernames and passwords.


    .PARAMETER ComputerName
    If present, this parameter overrides any ComputerName parameter that might
    be in ArgumentsForGetDcSession.  The ComputerName, which is read from the
    ComputerName parameter (if present) or from the ComputerName value in
    ArgumentsForGetDcSession is used to form a name for the session that is
    intended to be unique for each combination of local session and remote
    computer.


    .PARAMETER VariablesAndFunctionsToImport
    Generate this parameter by doing something like:
    ```
    @(
        Get-Item @(
            "function:foo"
            "function:bar"
            "variable:x"
            "variable:y"
        )
    )
    ```

    I am not sure this is the most elegant way to share variables and functions
    with a remote session, but it is better than nothing.  One problem with this
    function sharing mechanism is that there is no automatic check or guarantee
    that an imported function will have the functions that it calls or the
    module variables that it references available in the remote session.

    .EXAMPLE
    ```
        $namesOfFunctionsToImport = @( "addEntryToSystemPathPersistently"
            "Disable-UserAccountControl" "Enable-UserAccountControl"
            "downloadAndExpandArchiveFile" "downloadFileAndReturnPath"
            "Enable-UserAccountControl" "expandArchiveFile" "findFileInProgramFiles"
        )

        $namesOfVariablesToImport = @( "urlOfEnscapeInstallerFile"
            "enscapeLicenseKey" "urlsOfOdisInstallerPackageFiles"
        )

        $commonNewInvokerArguments = @{ VariablesAndFunctionsToImport = @( Get-Item
            -Path @( $namesOfFunctionsToImport |% {"function:$($_)"}
            $namesOfVariablesToImport |% {"variable:$($_)"}
                )
            )

            ArgumentsForGetDcSession   = @{
                bitwardenItemIdOfCompanyParameters = $bitwardenItemIdOfCompanyParameters
                ConfigurationName                  = "PowerShell.7"
            }
        }

        ${function:rss} = New-Invoker @commonNewInvokerArguments -ComputerName "host1.contoso.com" 
        ${function:rsd} = New-Invoker @commonNewInvokerArguments -ComputerName "host2.contoso.com"

    ```
    Now, you can invoke a command on host1.contoso.com and host2.contoso.com,
    respectively, by doing:

    ```
        rss { Write-Host "hello from $($env:computername)" } 
        rsd { Write-Host "hello from $($env:computername)" }
    ```

    .NOTES
    It would be nice to integrate Screenconnect's remote command facility more
    tightly into the PSRemoting paradigm.  I can imagine having Screenconnect be
    just one more transport protocol ("transport protocol" is probably not the
    official word for it, but you know what I mean) for Powershell remoting,
    akin to WSMan and SSH and VMBus.  I wonder if anyone (other than Microsoft)
    has implemented any third-party PSRemoting transport protocol What
    Screenconnect provides natively (one string submitted, maybe one string
    received as output) comes close to (and perhaps could serve as a basis for
    an implementation of) the PSRemoting protocol.  the main thing that's
    missing is the serialization and deserialization to and from the remote
    session.  I imagine that many of the other Remote Machine Management (RMM)
    systems (besides Screenconnect) probably have a remote command running
    facility similar to Screenconnect's.

    #>
    
    [CmdletBinding()]
    [OutputType([ScriptBlock])]
    Param(
        [parameter()]
        [HashTable] $ArgumentsForGetDcSession ,

        [parameter()]
        [string] $ComputerName ,
        
        <#  really this is expected to be an array in which each member is
            either a System.Management.Automation.PSVariable or a
            System.Management.Automation.FunctionInfo 
        #>
        [parameter()]
        [Object[]] $VariablesAndFunctionsToImport,

        [parameter(Mandatory=$false)]
        [ScriptBlock] $StartupScript =  {}


    )

    # $uniqueMagicStringForThisFunction = "517f7e13f0c84e1d96b729651fe06b48"

    $uniqueMagicStringForThisFunction = "$(new-guid)"
    <#  we actually do not want to hardcode a magic string here.  Rather, we
        want each call to New-Invoker to return a function (really a closure)
        that contains a unique session name within it.  We also don't need to
        include the computer name in the unique session name.
    #>

    $ComputerName = $(if($ComputerName){$ComputerName}else{$argumentsForGetDcSession['ComputerName']})
    if(-not $ComputerName){
        Write-Error "could not resolve ComputerName"
        return 
    }

    $argumentListForInitializer = @(
        @{
            ## functionsToImport = (
            ##     $namesOfFunctionsToImport |% {@{$_ = (get-command $_).ScriptBlock}} | Merge-HashTables
            ## )
            ## variablesToImport = (
            ##     $namesOfVariablesToImport |% {@{$_ = (get-Variable $_).Value}} | Merge-HashTables
            ## )
            ####    itemsToImport = @(
            ####        Get-Item -Path @(
            ####            $namesOfFunctionsToImport |% {"function:$($_)"}
            ####            $namesOfVariablesToImport |% {"variable:$($_)"}
            ####        )
            ####    )
            itemsToImport = $VariablesAndFunctionsToImport
            startupScript = $StartupScript
        }
    )
    $initializer = {
        #### $args[0].variablesToImport.GetEnumerator() |% { Set-Variable -Name $_.Name -Value $_.Value  }
        ## $args[0].variablesToImport.GetEnumerator() |% { Set-Item -Path "variable:$($_.Name)"  -Value $_.Value  }
        ## $args[0].functionsToImport.GetEnumerator() |% { Set-Item -Path "function:$($_.Name)"  -Value $_.Value  }
        Write-Host "initializer is running"
        foreach($item in $args[0].itemsToImport) { 
            ## Write-Host "now processing $($item.PSPath )"
            
            # Set-Item -LiteralPath $item.PSPath  -Value $(switch($item.PSDrive){"Variable" {$item.Value}; "Function" {$item.ScriptBlock}}) 

            switch($item.PSDrive){
                "Variable" {
                    Set-Variable -Scope "Global" -Name $item.Name -Value $item.Value
                }
                
                "Function" {
                    ## Set-Item -LiteralPath $item.PSPath  -Value $item.ScriptBlock
                }
            }
        }

        New-Module -ArgumentList @(@{itemsToImport = $args[0].itemsToImport}) -ScriptBlock {
            foreach($item in $args[0].itemsToImport) { 
                ## Write-Host "now processing $($item.PSPath )"
                
                # Set-Item -LiteralPath $item.PSPath  -Value $(switch($item.PSDrive){"Variable" {$item.Value}; "Function" {$item.ScriptBlock}}) 
    
                switch($item.PSDrive){
                    "Variable" {
                        ## Set-Variable -Scope "Global" -Name $item.Name -Value $item.Value
                    }
                    
                    "Function" {
                        Set-Item -LiteralPath $item.PSPath  -Value $item.ScriptBlock
                    }
                }
            }
        } | out-null

        if([bool] ([string] $args[0].startupScript)){
            write-host "running StartupScript"
            invoke-expression $args[0].startupScript
        }
        Write-Host "initializer is finished"


    }



    return {
        [CmdletBinding()]
        Param(
            [parameter()]
            [ScriptBlock] $ScriptBlock,

            [parameter()]
            [Object[]] $ArgumentList 
        )

        $uniqueNameOfSession = "$($uniqueMagicStringForThisFunction)--$([Runspace]::DefaultRunspace.InstanceId)--$($ComputerName)"
        $session = $(Get-PSSession -Name $uniqueNameOfSession -ErrorAction SilentlyContinue)
        
        ## get-member -inputobject (Get-Runspace | select -first 1 )
        ## Get-Runspace | select -first 1 | select *
        ## Get-Runspace | select InstanceId, Id, RunspaceIsRemote, RunspaceStateInfo, RunspaceAvailability, {$_.ConnectionInfo.ComputerName}| ft -auto
        ## [Runspace]::DefaultRunspace | select -expand InstanceID
        ## code  --goto (getcommandpath getdcsession)

        if(
            $session -and
            ($session.State -eq  "Opened") -and 
            ($session.Availability -eq "Available")
        ){
            # do nothing, $session is already as desired
            ## write-host "session is already as desired"
        } else {
            if($session){
                write-host (-join @(
                    "session exists, but is not both Open and Available "
                    "(State is $($session.State), Availability is $($session.Availability)), "
                    "so we will remove and recreate the session."
                ))
                Remove-PSSession -Session $session | out-null
                ## TODO: attempt to reconnect before resorting to removal.
            } else {
                write-host "session does not exist"
            }
            $session = $(
                Merge-Hashtables @( 
                    $argumentsForGetDcSession 
                    @{ ComputerName = $ComputerName }
                    @{ Name = $uniqueNameOfSession  }
                ) | % {getDCSession @_ }
            )
            Connect-PSSession $session | out-null
            if(
                $session -and
                ($session.State -eq  "Opened") -and 
                ($session.Availability -eq "Available")
            ){
                icm -Session (Connect-PSSession $session) -ScriptBlock $initializer -ArgumentList $argumentListForInitializer
            } else {
                Write-Error "failed to obtain an open and available session"
                $session = $null
            }
        }

        if($session){
            icm -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
    }.GetNewClosure()
}


function New-ScreenconnectInvoker {
    [CmdletBinding()]
    [OutputType([ScriptBlock])]
    Param(
        [parameter()]
        [HashTable] $argumentsForRunInCwcSession
    )

    return {
        # see perhaps
        # [https://stackoverflow.com/questions/62291492/powershell-create-dynamic-param-from-ast-of-another-script-block
        [CmdletBinding(PositionalBinding=$False)]
        Param(
            [Parameter(Mandatory=$False)] 
            [int] $timeout,

            [Parameter(Mandatory=$False)] 
            [boolean] $pwsh,

            [Parameter(
                Position=1,
                Mandatory=$False
            )] 
            [string[]] $command
        )
        ## DynamicParam {}
        ## code --goto (getcommandPath runInCwcSession)

        # "PSBoundParameters: "
        # $PSBoundParameters.GetTYpe().FullName
        # $PSBoundParameters

        Merge-Hashtables $argumentsForRunInCwcSession $PSBoundParameters |% {runInCwcSession @_}
    }.GetNewClosure()
}
