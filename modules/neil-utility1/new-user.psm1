
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
    if ($companyParameters['emailDomainName'] -eq 'nakanoassociates.com'){
        Write-Host "this is a Nakano job"
        
        $idOfBitwardenItemContainingSoftetherVpnServerCredentials='5d918212-baf7-44d7-bf18-acf701364944'
        $bitwardenItemContainingSoftetherVpnServerCredentials = getBitwardenItem $idOfBitwardenItemContainingSoftetherVpnServerCredentials
        $vpnServerPassword=$bitwardenItemContainingSoftetherVpnServerCredentials.login.password
        $softetherVpnServerHostname = ( $bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[0]
        $softetherVpnServerPortnumber = ( $bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[1]
        $softetherVpnServerNameOfHub = (@($bitwardenItemContainingSoftetherVpnServerCredentials.fields | Where-Object {$_.name -eq 'name of HUB'} | Foreach-object {$_.value})[0])


        # . $companyParameters['scriptBlockToConnectToCloud']
        connectToOffice365 `
            -bitwardenItemIdOfTheConfiguration $companyParameters['idOfBitwardenItemContainingMicrosoftGraphManagementConfiguration']

        #$publicDomainName = @(Get-AzureAdDomain | where-object {$_.IsDefault})[0].Name
        $publicDomainName = ((Get-MgOrganization).VerifiedDomains | where-object {$_.IsDefault -eq $true}).Name

        $defaultUsername        =($userSpec['firstName'][0] + $userSpec['lastName']).toLower()
        $defaultEmailAddress    ="$defaultUsername@$publicDomainName"
        $username               = if($userSpec.preferredEmailAlias){$userSpec.preferredEmailAlias} else {$defaultUsername}
        $primaryEmailAddress    = "$username@$publicDomainName"
        $userPrincipalName      = $primaryEmailAddress
        $password = $userSpec['password']

        vpncmd ($softetherVpnServerHostname + ":" + $softetherVpnServerPortnumber) /SERVER /PASSWORD:"$vpnServerPassword" /ADMINHUB:"$softetherVpnServerNameOfHub"  /CMD UserCreate $username /GROUP:none /REALNAME:none /NOTE:none 
        vpncmd ($softetherVpnServerHostname + ":" + $softetherVpnServerPortnumber) /SERVER /PASSWORD:"$vpnServerPassword" /ADMINHUB:"$softetherVpnServerNameOfHub"  /CMD UserPasswordSet $username /PASSWORD:"$password"


        $scriptToBeRunOnNaserver1 = @(
            # "username=`"$username`"" 
            # "password=`"$($userSpec['password'])`"" 
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

        

        
        
        # $azureAdUser = (Get-AzureADUser -ObjectId  $userPrincipalName -ErrorAction SilentlyContinue)
        $mgUser = (Get-MgUser -UserId  $userPrincipalName -ErrorAction SilentlyContinue)
        
        if( $mgUser ){
            Write-Host "An MgUser having id '$userPrincipalName' already exists, so we will not create a new user." 
        } else {
            Write-Host "No MgUser having id '$userPrincipalName' exists, so we will create one." 
            $s = @{
                AccountEnabled    = $True
                # DisplayName       = "to_be updated_later"
                # PasswordProfile   = $(
                #     $passwordProfile = (New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile)
                #     $passwordProfile.ForceChangePasswordNextLogin = $false
                #     $passwordProfile.Password = $password
                #     $passwordProfile
                # )
                PasswordProfile  = @{
                    ForceChangePasswordNextSignIn           = $False
                    ForceChangePasswordNextSignInWithMfa    = $False
                    Password                                = $password
                }
                MailNickname      = $username
                UserPrincipalName = $userPrincipalName
                Surname           = $userSpec['lastName'] 
                GivenName         = $userSpec['firstName'] 
                DisplayName       = "$($userSpec['firstName']) $($userSpec['lastName'])"
            # }; New-AzureADUser @s;
            }; New-MgUser @s 1> $null;
        }

        # $azureAdUser = (Get-AzureADUser -ObjectId  $primaryEmailAddress)
        $mgUser = Get-MgUser -UserId  $userPrincipalName 
        
        # $s = @{
        #     ObjectID            = $azureAdUser.ObjectID
        #     AccountEnabled      = $True
        #     PasswordProfile     = $passwordProfile
        #     MailNickname        = $username
        #     UserPrincipalName   = $userPrincipalName
        #     Surname             = $userSpec['lastName'] 
        #     GivenName           = $userSpec['firstName'] 
        #     DisplayName         = "$($userSpec['firstName']) $($userSpec['lastName'])"
        # }; Set-AzureADUser @s;

        # setLicensesAssignedToAzureAdUser -objectIdOfAzureAdUser $azureAdUser.ObjectID -skuPartNumbers $userSpec.licenses
        setLicensesAssignedToMgUser -userId $mgUser.Id -skuPartNumbers $userSpec.licenses
        
        
        # $azureAdUser = (Get-AzureADUser -ObjectId  $primaryEmailAddress)    
        $mgUser = Get-MgUser -UserId  $mgUser.Id  
        
        
        $desiredEmailAddresses = @()
        $desiredEmailAddresses += "SMTP:$primaryEmailAddress"
        if(! ($primaryEmailAddress -eq $defaultEmailAddress)){
            #make sure that the $default email address, as a non-primary smtp address, exists in the ProxyAddresses array
            $desiredEmailAddresses += "smtp:$defaultEmailAddress"
        }
        foreach($desiredAdditionalEmailAddress in $userSpec['desiredAdditionalEmailAddresses']){
            $desiredEmailAddresses += "smtp:$desiredAdditionalEmailAddress"
        }


        # $mailbox = Get-Mailbox $azureAdUser.ObjectID -ErrorAction SilentlyContinue
        $mailbox = Get-Mailbox $mgUser.Id -ErrorAction SilentlyContinue
        if (! $mailbox ){
            Write-Host "The user $userPrincipalName does not appear to have a mailbox, so we will not attempt to adjust email addresses."
        } else {
            Write-Host "initially, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
            
            $emailAddressesToRemove = $mailbox.EmailAddresses | where-object {
                ($_ -match '(?-i)^SMTP:.+$') -and (-not ($_ -in $desiredEmailAddresses)) # it is an smtp address of some sort and it is not in the desiredEmailAddresses List
            }
            $emailAddressesToAdd = $desiredEmailAddresses | where-object {
                -not ($_ -in $mailbox.EmailAddresses) # it is not already in the mailbox's Email Addresses
            }

            if( ([Boolean] $emailAddressesToRemove) -or ([Boolean] $emailAddressesToAdd) ){
                Write-Host "emailAddressesToRemove ($($emailAddressesToRemove.Length)): ", $emailAddressesToRemove
                Write-Host "emailAddressesToAdd ($($emailAddressesToAdd.Length)): ", $emailAddressesToAdd
                

                $s = @{
                    EmailAddresses = @{
                        Add=@($emailAddressesToAdd); 
                        Remove=@($emailAddressesToRemove)
                    }; 
                }; $mailbox | Set-Mailbox @s ; 
                # $mailbox = Get-Mailbox $azureAdUser.ObjectID
                $mailbox =  Get-Mailbox $mgUser.Id
                Write-Host "finally, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
            } else {
                Write-Host "email addresses for $userPrincipalName are as desired, so we will not bother to add or remove any."
            }
        }
        return;
    }


    $scriptBlockToBeRunOnDomainController = {
        $userSpec               = $using:userSpec
        # $userPrincipalName      = $using:userPrincipalName
        # $primaryEmailAddress    = $using:primaryEmailAddress
        # $userPrincipalName      = $using:userPrincipalName

        Write-Host "$env:computername is working on $($userSpec['firstName'][0] + $userSpec['lastName'])"

        $publicDomainName = (get-adforest).UPNSuffixes[0]

        $defaultUsername        =($userSpec['firstName'][0] + $userSpec['lastName']).toLower()
        $defaultEmailAddress    ="$defaultUsername@$publicDomainName"
        $username               = if($userSpec.preferredEmailAlias){$userSpec.preferredEmailAlias} else {$defaultUsername}
        $primaryEmailAddress    = "$username@$publicDomainName"
        $userPrincipalName      = $primaryEmailAddress

        $adUser = Get-ADUser $username
        if($adUser){
            Write-Host "The adUser `"$($username)`" already exists, so we will not bother to create."
        } else {
            Write-Host "creating adUser `"$($username)`"."
            
            New-ADUser `
                -ErrorAction SilentlyContinue `
                -Path ( "OU=humans" + "," + "OU=users" + "," + "OU=company" + "," + (Get-ADDomain).DistinguishedName  ) `
                -Name $username `
                -AccountPassword (ConvertTo-SecureString $userSpec['password'] -AsPlainText -Force  ) `
                -Enabled $True `
                -PassThru 
            
            $adUser = Get-ADUser $username
        }
            
        $adUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $userSpec['password'] -AsPlainText -Force  ) 
        
        $s = @{
            UserPrincipalName   =  $userPrincipalName 
            EmailAddress        =  $userPrincipalName 
            Surname             =  $userSpec['lastName'] 
            GivenName           =  $userSpec['firstName'] 
            DisplayName         =  ($userSpec['firstName'] + " " + $userSpec['lastName'])
            # Name                =  ($userSpec['firstName'] + " " + $userSpec['lastName'])
        }; $adUser | Set-ADUser @s 
        
        
        # $adUser = $adUser | Get-ADUser ; $adUser.Name = $adUser.DisplayName; Set-ADUser -Instance $adUser;
        #doesn't work

        # $adUser | Get-ADObject | Rename-ADObject -NewName $adUser.DisplayName
        #works, but decided not to do.

        if($userSpec['encodedDesiredMSDsConsistencyGuid']){
            $s = @{
                Path   = "AD:\$($adUser.distinguishedName)" 
                Name   = "mS-DS-ConsistencyGuid" 
                Value  = ([Convert]::FromBase64String($userSpec['encodedDesiredMSDsConsistencyGuid']))
            }; Set-ItemProperty 
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

    $bitwardenItemContainingActiveDirectoryCredentials = getBitwardenItem $companyParameters['idOfBitwardenItemContainingActiveDirectoryCredentials']
    $username = (
        @(
            $bitwardenItemContainingActiveDirectoryCredentials.fields | Where-Object {$_.name -eq 'active_directory_domain_name'} | 
                Foreach-object {$_.value}
        )[0] +
        "\" + 
        ($bitwardenItemContainingActiveDirectoryCredentials.login.username -split "@")[0]
    )
    $password=$bitwardenItemContainingActiveDirectoryCredentials.login.password

    if ($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController']){
        Write-Host "connecting to vpn connection $($companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController'])"
        vpncmd /client localhost /cmd AccountConnect $companyParameters['nameOfSoftetherVpnConnectionNeededToTalkToDomainController']
    }

    Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value $companyParameters['domainController']
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

    $VerbosePreference = 'Continue'
    $adUser = Invoke-Command @ss -ScriptBlock $scriptBlockToBeRunOnDomainController | Select-Object -Last 1
    Write-Host "adUser: $($adUser | Out-String)"

    if(-not $adUser){
        Write-Host "we have failed to retrieve the adUser, and so will return now."
        return
    }

    # . $companyParameters['scriptBlockToConnectToCloud']
    connectToOffice365 -bitwardenItemIdOfTheConfiguration $companyParameters['idOfBitwardenItemContainingMicrosoftGraphManagementConfiguration']

    # $azureAdUser = Get-AzureADUser -ObjectId $adUser.UserPrincipalName
    $mgUser = Get-MgUser -UserId $adUser.UserPrincipalName -ErrorAction SilentlyContinue

    # if (! $azureAdUser ){
    if (! $mgUser ){
        Write-Host "No MgUser having id $($adUser.UserPrincipalName) exists.  Probably need to wait a few minutes for adsync to push changes to the cloud."
    } else {
        # assign licenses:
        # setLicensesAssignedToAzureAdUser -objectIdOfAzureAdUser $azureAdUser.ObjectID -skuPartNumbers $userSpec.licenses
        setLicensesAssignedToMgUser -userId $mgUser.Id -skuPartNumbers $userSpec.licenses
    }


    if($doSendWelcomeMessage){
        # $adUser = Get-ADUser $username
        $recipientAddress = ($adUser.DisplayName + "<" + $adUser.UserPrincipalName + ">")

            
        $xx = @{
            emailAccount = $emailAccountForSendingAdvisoryMessages
            from         = $emailAccountForSendingAdvisoryMessages
            to           = $(if($sendToDebuggingAddressInsteadOfTrueAddresses){$companyParameters['debuggingAddress']} else {$recipientAddress})
            cc           = ( $companyParameters['managerName'] + "<" + $(if($sendToDebuggingAddressInsteadOfTrueAddresses){$companyParameters['debuggingAddress']} else {$companyParameters['managerEmailAddress']}) + ">" )
            subject      = $(if($sendToDebuggingAddressInsteadOfTrueAddresses){"(TO: $recipientAddress) " } else {""} ) + "$($companyParameters['companyName']) Active Directory account for $($userSpec['firstName']) $($userSpec['lastName'])"
            body         = @( 
                "Dear $($userSpec.firstName) $($userSpec.lastName), "
                ""
                "Welcome to $($companyParameters['companyName']).  " `
                + "Here are your $($companyParameters['companyName']) Active Directory credentials:"
                "    username (and email address): $($adUser.UserPrincipalName)"
                "    password: $($userSpec['password'])"
                ""
                "Use the above username and password to log into " `
                + "your computer at the $($companyParameters['companyName']) office and " `
                + "to access $($companyParameters['companyName']) email.  To change your " `
                + "password, go to  $($companyParameters['passwordChangeUrl'])."
                ""
                "There is a webmail interface at https://outlook.office.com, which allows " `
                + "you to access your $($companyParameters['companyName']) email from a web " `
                + " browser.  You can also access email in Outlook on your $($companyParameters['companyName']) computer."
                ""
                "Here are all the details that you might need to "`
                + "set up email on your smart phone, if you are so inclined:"
                "    Account type: Exchange (some phones call this `"Corporate`")"
                "    Email address: $($adUser.UserPrincipalName)"
                "    Username: $($adUser.UserPrincipalName)"
                "    Password: $($userSpec['password'])"
                "    Domain: $($companyParameters['emailDomainName'])"
                "    Exchange Server address: outlook.office365.com"
                "    TLS (this is usually a checkbox): yes (checked)"
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
        };     sendMail @xx
    }




}

