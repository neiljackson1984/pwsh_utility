
Import-Module (join-path $psScriptRoot "utility.psm1")
Import-Module (join-path $psScriptRoot "connect_to_office_365.psm1")

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
        
        setLicensesAssignedToMgUser -userId $mgUser.Id -skuPartNumbers $userSpec.licenses
        
   
        $mgUser = Get-MgUser -UserId  $mgUser.Id  
        
        
        $desiredEmailAddresses = @()
        $desiredEmailAddresses += "$primaryEmailAddress"
        if(! ($primaryEmailAddress -eq $defaultEmailAddress)){
            #make sure that the $default email address, as a non-primary smtp address, exists in the ProxyAddresses array
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
            setLicensesAssignedToMgUser -userId $mgUser.Id -skuPartNumbers $userSpec.licenses
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
        $Credential
        ,
        [Parameter(
            Mandatory=$False,
            HelpMessage="Optionally, override the default SessionOption argument"            
        )]
        [Object] 
        $SessionOption
        ,


        [Parameter(
            ValueFromRemainingArguments = $True,
            # HelpMessage = "remaining arguments will be passed to New-PsSession",
            Mandatory = $False
        )]
        [Object[]] 
        $remainingArguments = @()

        # My idea with "remainingArguments" is not working as I had expected
        # because Powershell does not treat the parameter names within a
        # function invokation (i.e. strings starting with a dash) as strings but
        # they are really high-level name tokens.  If you try to include
        # "-blarg" in the argument list of a function call to a function that
        # does not have an explicitly-decalred parameter named "blarg",
        # powershell throws an error.
        #
        # the "remainingArguments" mechanism would work for positional parameters.
        #
        # 

        # see [https://stackoverflow.com/questions/27764394/get-valuefromremainingarguments-as-an-hashtable]
        # see [https://stackoverflow.com/questions/27463602/nested-parameters-for-powershell-cmdlet]
        # see [https://www.powershellgallery.com/packages/MSAL.PS/4.7.1.2/Content/Select-PsBoundParameters.ps1]
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
        if ($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController']){
            connectVpn $companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'] | out-null
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

function connectVpn {
    <#
    .SYNOPSIS
    Ensures that we are connected to the specified softether vpn connection.
    Currently, we are specifying the softether vpn connection only by name, and
    relying on an entry of that name existing and being correctly configured.

    # .DESCRIPTION
    # Long description

    # .PARAMETER bitwardenItemIdOfCompanyParameters
    # Parameter description

    # .PARAMETER HostName
    # Parameter description

    # .EXAMPLE
    # An example

    # .NOTES
    # General notes
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(
            Mandatory=$True
            
        )]
        [String] 
        $nameOfSoftetherVpnConnection
    )

        
    $trialDuration = New-Timespan -Seconds 15
    $giveUpTime = (Get-Date) + $trialDuration
    $attemptsCount = 0
    while(
        (
            (
                Get-Date
            ) -le $giveUpTime
        ) -and
        (
            $(
                vpncmd @(
                    "localhost"
                    "/client"
                    "/cmd", "AccountStatusGet"
                    $nameOfSoftetherVpnConnection
                ) | 
                Out-Null;
                $LASTEXITCODE 
            ) -ne 0
        )
    ) {
        $result = $(
            vpncmd localhost /client  /cmd AccountConnect $nameOfSoftetherVpnConnection | 
                Out-Null

            $LASTEXITCODE 
        )
        $attemptsCount++
        # write-host "result was $($result)."

        if($result -eq 43){
            # error 43 is described thus:
            #
            # Error occurred. (Error code: 43) The Virtual Network Adapter
            # used by the specified VPN Connection Setting is already being
            # used by another VPN Connection Setting. If there is another
            # VPN Connection Setting that is using the same Virtual Network
            # Adapter, disconnect that VPN Connection Setting.

            # Write-Host "disconnecting from all existing softether vpn connections"
            disconnectAllVpnConnections

            # we might, alternatively, consider creating a new softether virtual
            # nic and setting the connection to use that nic.
        }

        Start-Sleep 5
    }
    # write-host "attemptsCount: $($attemptsCount)"

}


function disconnectAllVpnConnections {
    <#
    .SYNOPSIS
    Disconnects all existing Softether VPN connections
    #>
    
    [CmdletBinding()]
    [OutputType([void])]
    Param(
    )

    


    ## vpncmd localhost /client  /cmd AccountList |
    ## % { 
    ##     if($_ -match '^\s*VPN Connection Setting Name\s*\|(.*)$'){
    ##         $Matches[1].Trim()
    ##     }
    ## } |
    ## % { 
    ##     Write-Host "disconnecting from `"$($_)`""
    ##     vpncmd localhost /client  /cmd AccountDisconnect "$($_)" | Out-Null
    ## }


    @( 
        Get-SoftEtherConnectionNames | 
        % {"AccountDisconnect `"$($_)`""}
    ) | vpncmd localhost /client  2>$null | out-null

}

function Get-SoftEtherNicNames {
    <#
    .SYNOPSIS
    gets the names of all existing SoftEther virtual nics.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    vpncmd localhost /client /cmd  NicList | 
    out-string -stream | 
    select-string '(?<=^\s*Virtual Network Adapter Name\s*\|\s*)\b.*\b(?=\s*$)' | 
    % {$_.Matches[0].ToString()}
}

function Get-SoftEtherNextAvailableNicName {
    <#
    .SYNOPSIS
    Gets the next valid softether nic name that is not already assigned to an existing softether nic.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    $allowedNicNames = @(""; 2..127) |% {"VPN$($_)"} 
    $existingNicNames = @(Get-SoftEtherNicNames)
    $nextAvailableNicName = ($allowedNicNames |? {-not ($existingNicNames -contains $_)} | select -first 1)
    return $nextAvailableNicName
}

function Get-SoftEtherNetAdapterFromSoftEtherNicName {
    <#
    .SYNOPSIS
    returns the
    Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter
    object corresponding to the given softetherNicName, or nothing if no such object exists.
    exists.
    #>
    
    [CmdletBinding()]
    # [OutputType([Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter])]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    Param(
        [Parameter(
            Mandatory=$True    
        )]
        [String] 
        $softetherNicName
    )

    $nicGuid = (vpncmd localhost /client /cmd NicGetSetting $softetherNicName | out-string -stream | select-string '(?<=^\s*GUID\s*\|\s*).*(?=\s*$)' | % {$_.Matches[0].ToString()})
    Get-NetAdapter -IncludeHidden |? {$_.InterfaceGuid -eq $nicGuid}
}

function Get-SoftEtherConnectionNames {
    <#
    .SYNOPSIS
    gets the names of all existing SoftEther connections.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    vpncmd localhost /client /cmd  AccountList | 
    out-string -stream | 
    select-string '(?<=^\s*VPN Connection Setting Name\s*\|\s*)\b.*\b(?=\s*$)' | 
    % {$_.Matches[0].ToString()}
}