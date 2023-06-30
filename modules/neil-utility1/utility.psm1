function unlockTheBitwardenVault(){
    #temporary hack to speed things up:
    Write-Debug "blindly assuming that bitwarden vault is unlocked..."; return
    
    Write-Host "Attempting to unlock the bitwarden vault..."
    if ($(bw unlock --check)) {
        Write-Host "The bitwarden vault is already unlocked."
    }
    else { 
        $env:BW_SESSION =  $(pwsh -Command "bw unlock --raw || bw login --raw") 
    }
}

# function getBitwardenItem {
function Get-BitwardenItem {
    [OutputType([HashTable])] # I really want an Optional[HashTable] -- I will return null in case of failure.
    
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item to get")]
        [String]$bitwardenItemId
    )
    
    unlockTheBitwardenVault
    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get item $bitwardenItemId  | ConvertFrom-Json -AsHashtable)
    #todo: error handling

    ## 2023-05-15-1101: 
    #  the type of $bitwardenItem (and the type of any nested objects) at this
    #  point happens to be System.Management.Automation.OrderedHashtable.  If we
    #  were to omit the "-AsHashTable" switch, above, the type of $bitwarenItem
    #  (and the type of any nested objects) would be
    #  System.Management.Automation.PSCustomObject.  These types behave very
    #  similarly, but the hash table has the advantage that all of the original
    #  json properties are represented as keys in the hash table, whereas with
    #  the pscustomobject, I have the sense that there would be some property
    #  names that could appear in the original json but would not be accessible
    #  in the PScustomObject because they would be shadowed by PsCustomObject's
    #  own properties.  In other words, with the hash table, uniquely, we can
    #  always resort to square-bracket member access operator if we need to.


    #todo: a bit of a hack to work around the overhead in calling the bw
    # executable might be to store a private cache of the vault here (or memoize
    # one result at a time).  Not great for security or concurrency, but it
    # might help bring the delay into a tolerable range.  Along the same lines,
    # we might explore the "rbw" client, which is an unofficial bitwardin
    # command-line client written in Rust that purports to be much faster than
    # the official, node.js-based, bitwarden client.
    return $bitwardenItem
}

function Set-BitwardenItem {
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item")]
        [HashTable] $bitwardenItem
    )
    #todo 2023-05-15-1146: accept pipeline input.  think about what the return type should be.
    unlockTheBitwardenVault
    $bitwardenItem | ConvertTo-Json -Depth 99 | bw --nointeraction --raw  encode | bw --nointeraction --raw edit item $bitwardenItem.id

}

function makeNewBitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The name of the bitwarden item")]
        [String] $name = ""
    )

    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get template item | ConvertFrom-Json -AsHashtable)
    $bitwardenItem['name'] = $name
    $bitwardenItem['notes'] = "created programmatically $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss")`nfoo_ef7ba3fce1bc482c8fb5304da2e2a89e" 
    # this magic string is mainly for testing, just to help me find and delete all the new bitwarden items that I created during testing .

    $bitwardenItem['login'] = ( bw --nointeraction --raw get template item.login | ConvertFrom-Json -AsHashtable)
    $bitwardenItem['login']['username'] = ""
    $bitwardenItem['login']['password'] = ""
    $bitwardenItem['login']['totp'] = ""

    unlockTheBitwardenVault
    $result = [System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json -Depth 50)) )  | bw --nointeraction --raw create item 
    $newlyCreatedBitwardenItem = ( $result | ConvertFrom-Json -AsHashtable)
    Write-Host "created new bitwarden item having id $($newlyCreatedBitwardenItem['id'])."
    return (Get-BitwardenItem -bitwardenItemId $newlyCreatedBitwardenItem['id'] )
}



function getFieldMapFromBitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item containing the configuration data.")]
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [String]$bitwardenItemId 
    )

    [HashTable] $bitwardenItem = Get-BitwardenItem -bitwardenItemId $bitwardenItemId

    $fieldMap = @{}
    
    foreach($field in @($bitwardenItem['fields'])){
        $fieldMap[$field['name']] = $field['value']
    }

    return $fieldMap
}

function putFieldMapToBitwardenItem {
    [OutputType([Void])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The field map.")]
        [HashTable] $fieldMap,

        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item into which we will inject the configuration data.")]
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [String]$bitwardenItemId=""

        # [Boolean]$doMakeNewBitwardenItem=$False,

        # [String]$nameForNewBitwardenItem=""
    )
    
    # [System.Management.Automation.OrderedHashtable] $bitwardenItem = ( bw --nointeraction --raw get item $bitwardenItemId  | ConvertFrom-Json )
    # $bitwardenItemId = "12d90ae7-d294-4a3e-b100-af70002c83e6"

    [HashTable] $bitwardenItem = (
        # if($doMakeNewBitwardenItem){ 
        #     makeNewBitwardenItem -name $nameForNewBitwardenItem
        # } else { 
        #     Get-BitwardenItem -bitwardenItemId $bitwardenItemId 
        # }
        Get-BitwardenItem -bitwardenItemId $bitwardenItemId 
    )
    foreach($key in $fieldMap.keys){
        if(-not $bitwardenItem['fields']){$bitwardenItem['fields'] = @()}
        
        $newFields = @()
        $ourField = $null
        for($i=0; $i -lt $bitwardenItem['fields'].Length; $i++){
            if( $bitwardenItem['fields'][$i]['name'] -eq $key ){
                if($ourField){
                    #don't do anything, which will effectively omit this field from the newFields list.
                } else {
                    $ourField = $bitwardenItem['fields'][$i]
                    $newFields += $ourField
                }
            } else {
                $newFields += $bitwardenItem['fields'][$i]
            }
        }
        if(-not $ourField){
            $ourField = ( bw --nointeraction --raw get template item.field | ConvertFrom-Json -AsHashtable)
            $ourField['name'] = $key
            $newFields += $ourField
        }
        $bitwardenItem['fields'] = $newFields

        # all of the above brain damage is to preserve the existing order of the
        # fields as much as possible, AND ensure that there is only a single
        # field having the name $key.
        
        $ourField['value']=$fieldMap[$key]

    }
    unlockTheBitwardenVault 1> $null
    ([System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json -Depth 50)) ) | bw --nointeraction --raw edit item $bitwardenItem['id'] ) 1> $null
}

function x509Certificate2ToBase64EncodedPfx {
    [OutputType([String])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $certificate,

        [Parameter()]
        [String] $password=""
    )
    $temporaryFile = New-TemporaryFile

    Export-PfxCertificate -Password (stringToSecureString $password) -Cert $certificate -FilePath $temporaryFile.FullName 1> $null
    $pfxBytes = Get-Content -AsByteStream -ReadCount 0 -LiteralPath $temporaryFile.FullName
    Remove-Item -Force -Path $temporaryFile.FullName  1> $null
    return [System.Convert]::ToBase64String( $pfxBytes )
}

function base64EncodedPfxToX509Certificate2 {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $base64EncodedPfx,

        
        [Parameter()]
        [String] $password=""
    )

    $temporaryFile = New-TemporaryFile
    $pfxBytes = [System.Convert]::FromBase64String($base64EncodedPfx)
    Set-Content  -AsByteStream -Value $pfxBytes -LiteralPath $temporaryFile.FullName 1> $null
    $certificate = Get-PfxCertificate -Password (stringToSecureString $password) -FilePath $temporaryFile.FullName
    # it seems that Get-PfxCertificate returns a certificate that has a non-exportable private key.
    Remove-Item -Force -Path $temporaryFile.FullName  1> $null


    return $certificate
}


function stringToSecureString {
    [OutputType([System.Security.SecureString])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $in
    )
    return (
        [System.Security.SecureString] $(
            if($in -eq ""){
                (new-object System.Security.SecureString)
            } else {
                ConvertTo-SecureString -String $in -AsPlainText -Force 
            }
        )
    )
}


function sendMail($emailAccount, $from, $to = @(), $cc = @(), $bcc = @(), $subject, $body){
    # unlock the bitwarden vault:
    # unlockTheBitwardenVault

    $bitwardenQueryString = "$emailAccount"
    $rawBitwardenItems = bw --nointeraction --raw list items --search "$bitwardenQueryString"
    #unfortunately, the bitwarden command-line tool's search function does not seem to search in notes or in custom fields.
    $exitCodeOfBitwardenCommand = $LastExitCode
    if ($exitCodeOfBitwardenCommand -ne 0){
        unlockTheBitwardenVault
        $rawBitwardenItems = bw --nointeraction --raw list items --search "$bitwardenQueryString"
    }

    # $bitwardenItems = $rawBitwardenItems | ConvertFrom-Json | Where-Object {$_.name -eq 'AzureAD app password' -and $_.login.username -eq $emailAccount}
    $bitwardenItems = $rawBitwardenItems | ConvertFrom-Json 
    $matchingBitwardenItems = $bitwardenItems | 
        where-object { 
            $_.fields | 
                where-object { 
                    $_.name -eq 'record_type' -and 
                    $_.value -eq 'smtp_mail_sending' 
                } 
        }

    $bitwardenItemContainingEmailCredentials = $matchingBitwardenItems[0]
    if (! $bitwardenItemContainingEmailCredentials ){
        Write-Error "unable to find a Bitwarden item corresponding to the email account $emailAccount"
        return
    }
    
    $explicitAppPassword=@($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'app_password'} | Foreach-object {$_.value})[0]
    $password="$(if($explicitAppPassword){$explicitAppPassword} else {$bitwardenItemContainingEmailCredentials.login.password})"


    $SMTPClient = New-Object Net.Mail.SmtpClient(  
        @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_host'} | Foreach-object {$_.value})[0], 
        @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_port'} | Foreach-object {$_.value})[0] 
    )   
    $SMTPClient.EnableSsl = ([bool] ([int] @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_enable_ssl'} | Foreach-object {$_.value})[0]))    
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($bitwardenItemContainingEmailCredentials.login.username, $password) 
    
    if(-not $from){
        $from=$bitwardenItemContainingEmailCredentials.login.username
    }

    $mailMessage = New-Object Net.Mail.MailMessage
    $mailMessage.From = New-Object System.Net.Mail.MailAddress($from)
    foreach ($address in @($to)){ $mailMessage.To.Add($address) }
    foreach ($address in @($cc)){ $mailMessage.CC.Add($address) }
    foreach ($address in @($bcc)){ $mailMessage.Bcc.Add($address) }
    $mailMessage.Subject = $subject
    $mailMessage.Body = $body
    $result = $SMTPClient.Send($mailMessage)
    Write-Host "result of sending the message: $result"

}

function Send-TestMessage(){
    [CmdletBinding()]
    [OutputType([Void])]
    param (   
        [
            Parameter(
                Mandatory = $True
            )
        ]
        [String] 
        $recipientEmailAddress,

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $emailAccount = "neil@autoscaninc.com",

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $senderEmailAddress = "neil@autoscaninc.com"
    )
    process {
        @{
            emailAccount = $emailAccount
            from         = $senderEmailAddress
            to           =  "$recipientEmailAddress"
            subject      = "test message from $($senderEmailAddress) to $($recipientEmailAddress) $('{0:yyyy/MM/dd HH:mm:ss K}' -f [timezone]::CurrentTimeZone.ToLocalTime((Get-Date)))"
            body         = @( 
                "This is a test message sent from $($senderEmailAddress) to $($recipientEmailAddress).  Please disregard."

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

function setLicensesAssignedToMgUser($userId, $skuPartNumbers){
    # $azureAdUser = Get-AzureADUser -ObjectId $objectIdOfAzureAdUser
    # $mgUser = Get-MgUser -UserId  $userId
    
    # $propertyNames = @(get-mguser -UserId $userId  | get-member -MemberType Property | foreach-object {$_.Name}) 
    # $mgUser = get-mguser -UserId $userId -Property $propertyNames
    
    # $mgUser = get-mguser -UserId $userId -Property @("UsageLocation", "AssignedLicenses") 
    $mgUser = get-mguser -UserId $userId 
    if (! $mgUser ){
        Write-Host "No mgUser having id $userId exists."
        return
    } 

    # to view the available sku part numbers, run the following command:
    # # (Get-AzureADSubscribedSku).SkuPartNumber
    # (Get-MgSubscribedSku).SkuPartNumber

    $mgSubscribedSku = Get-MgSubscribedSku

    # assign licenses:
    # annoyingly, there does not seem to be a good way to buy licenses programmatically 
    $desiredSkuIds = @(
        $mgSubscribedSku | 
            where-object { $_.SkuPartNumber -in @($skuPartNumbers) } |
            foreach-object { $_.SkuId }
    )
    $initialExistingSkuIds = @(
        # Get-MgUserLicenseDetail -UserId $mgUser.Id | 
        # $mgUser.AssignedLicenses | 
        (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
            where-object { $_ } | 
            foreach-object {$_.SkuId}
    )
    Write-Host (
        @(
            "Initially, $($mgUser.UserPrincipalName) has the "
            "following $($initialExistingSkuIds.Length) skuPartNumbers: " 
            ( 
                @( 
                    # $mgSubscribedSku |
                    # where-object { $_.SkuId -in $initialExistingSkuIds } |
                    # foreach-object {$_.SkuPartNumber}

                    $initialExistingSkuIds | % {skuIdToSkuPartNumber $_}


                ) -Join ", "
            )
        ) -join ""
    )
    
    #ensure that licenses are assigned:
    $skuIdsToRemoveFromUser = @($initialExistingSkuIds | where-object {-not ($_ -in $desiredSkuIds)});
    $skuIdsToGiveToUser = @($desiredSkuIds | where-object {-not ($_ -in $initialExistingSkuIds)});
    
    Write-Host ("skuIdsToRemoveFromUser ($($skuIdsToRemoveFromUser.Length)): ", $skuIdsToRemoveFromUser)
    Write-Host ("skuIdsToGiveToUser ($($skuIdsToGiveToUser.Length)):", $skuIdsToGiveToUser)
    
    if($skuIdsToRemoveFromUser -or $skuIdsToGiveToUser){
        Write-Host "changing the user's license assignment to match the desired configuration"
        
        # make sure that the user has a UsageLocationn defined

        $intialUsageLocation = (get-mguser -UserId $mgUser.Id -Property @("UsageLocation")).UsageLocation
        if($intialUsageLocation){
            Write-Host (@(
                "$($mgUser.UserPrincipalName) already seems to have a UsageLocation "
                "assigned (namely, `"$($intialUsageLocation)`"), so we will not "
                "bother to set UsageLocation."
            ) -join "")
        } else {
            $newUsageLocation = (Get-MgOrganization).CountryLetterCode
            Write-Host (@(
                "$($mgUser.UserPrincipalName) seems to have "
                "no UsageLocation, so we will set UsageLocation "
                "to `"$($newUsageLocation)`"."
            ) -join "")

            Update-MgUser -UserId $mgUser.Id -UsageLocation $newUsageLocation 1> $null
            # $mgUser = get-mguser -UserId $userId -Property @("UsageLocation", "AssignedLicenses") 
        }

        # if($skuIdsToRemoveFromUser){
        #     # # $assignedLicenses.RemoveLicenses = @($skuIdsToRemoveFromUser | foreach-object {$x = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense; $x.SkuId = $_; $x })
        #     $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
        #     $assignedLicenses.RemoveLicenses = $skuIdsToRemoveFromUser
        #     Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses


        # }
        
        # foreach($skuIdToGiveToUser in $skuIdsToGiveToUser){
        #     $assignedLicense = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense;
        #     $assignedLicense.SkuId = $skuIdToGiveToUser;
        #     $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses;
        #     $assignedLicenses.AddLicenses = $assignedLicense;
        #     $azureAdUser | Set-AzureADUser -UsageLocation "US"
        #     Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        # }

        # if($skuIdsToGiveToUser){
            # $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            # $assignedLicenses.AddLicenses = $skuIdsToGiveToUser
            # Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        # }



        $s = @{
            UserId = $mgUser.Id
            RemoveLicenses = $skuIdsToRemoveFromUser
            AddLicenses = (
                # [IMicrosoftGraphAssignedLicense[]]
                @(
                    $skuIdsToGiveToUser | 
                        foreach-object {
                            (
                                # [IMicrosoftGraphAssignedLicense] 
                                @{
                                    DisabledPlans = @()
                                    SkuId = $_
                                }
                            )
                        }
                )
            )
        }; Set-MgUserLicense @s 1> $null

        $finalExistingSkuIds = @(
            # Get-MgUserLicenseDetail -UserId $mgUser.Id |
            # $mgUser.AssignedLicenses | 
            (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses |
                where-object { $_ } | 
                foreach-object {$_.SkuId}
        )
        Write-Host (
            @(
                "After making changes, $($mgUser.UserPrincipalName) "
                "has these $($finalExistingSkuIds.Length) skuPartNumbers: " 
                ( 
                    @(
                        # $mgSubscribedSku | 
                        #     where-object { $_.SkuId -in $finalExistingSkuIds } | 
                        #     foreach-object {$_.SkuPartNumber}

                        $finalExistingSkuIds | % {skuIdToSkuPartNumber $_}

                    ) -Join ", "
                )
            ) -join ""
        )
    } else {
        Write-Host "no changes need to be made to the user's licenses."
    }

}

function setSmtpAddressesOfMailbox
{

    <#
	.SYNOPSIS
	effectively deletes and replaces all smtp addresses in the EmailAddresses property of a mailbox.

	.DESCRIPTION

	.EXAMPLE
	setSmtpAddressesOfMailbox `
        -mailboxId "f4476753-3c37-4f09-9d62-64955041c411" `
        -desiredSmtpAddresses @(
            # primary address:
            "john@apples.com",

            #secondary addresses:
            "johnny@apples.com",
            "jdog@apples.com"
        )


	#>

	[CmdletBinding()]

    [OutputType([Void])]

    param (   
        [
            Parameter(
                Mandatory = $True
            )
        ]
        [String] 
        $mailboxId,

        [
            Parameter(
                Mandatory = $False,
                HelpMessage = (
                    "The first element will be taken to be the " + 
                    "desired primary smtp address, unless the "  +
                    " desiredPrimarySmtpAddress argument is "    +
                    "present."
                )
            )
        ]
        [String[]] $desiredSmtpAddresses = @(),

        [
            Parameter(
                Mandatory = $False,
                HelpMessage = (
                    "This argument, if present, will be used to " +
                    "forcefully specify which address shall be "  +
                    "primary, rather than implicitly using the "  +
                    "first element of the desiredSmtpAddresses "  +
                    "array."
                )
            )
        ]
        [String] $desiredPrimarySmtpAddress = $null
    )

    process
    {
        $candidateMailboxes = @(Get-Mailbox -Identity $mailboxId -ErrorAction SilentlyContinue)
        if($candidateMailboxes.Count -ne 1){
            Write-Host (
                "we could not find a single mailbox having " +
                "Identity `"$($mailboxId)`".  Therefore, " + 
                "we will stop here."
            )
            return
        } 
        $mailbox = $candidateMailboxes[0]

        Write-Host "setting the email addresses for the mailbox $($mailbox.Identity)."

        # from the arguments, extract one $primarySmtpAddress
        # and an array of $secondarySmtpAddresses, not containing the $primarySmtpAddress .
        [String] $primarySmtpAddress = $(
            if($desiredPrimarySmtpAddress){
                $desiredPrimarySmtpAddress
            } else {
                $desiredSmtpAddresses[0]
            }
        )

        $desiredEmailAddresses = @(
            "SMTP:$($primarySmtpAddress)"

            $desiredSmtpAddresses |
                ? { 
                    $_ -ne  $primarySmtpAddress 
                    # this is not quite right, because we should be doing
                    # case-insensitive comparison.
                } |
                % {"smtp:$($_)"}
        )

        Write-Host "initially, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        
        $emailAddressesToRemove = @($mailbox.EmailAddresses | where-object {
            ($_ -match '(?i)^SMTP:.+$') -and (-not ($_ -in $desiredEmailAddresses)) 
            # it is an smtp address of some sort and it is not in the desiredEmailAddresses List
        })
        $emailAddressesToAdd = @($desiredEmailAddresses | where-object {
            -not ($_ -in $mailbox.EmailAddresses)
            # it is not already in the mailbox's Email Addresses
        })

        if( ([Boolean] $emailAddressesToRemove) -or ([Boolean] $emailAddressesToAdd) ){
            Write-Host "emailAddressesToRemove ($($emailAddressesToRemove.Count)): ", $emailAddressesToRemove
            Write-Host "emailAddressesToAdd ($($emailAddressesToAdd.Count)): ", $emailAddressesToAdd
            $emailAddressesArg = (
                $(
                    if($emailAddressesToRemove.Count -gt 0){
                        @{ Remove=@($emailAddressesToRemove) }
                    } else {
                        @{}
                    }
                ) + 
                $(
                    if($emailAddressesToAdd.Count -gt 0){
                        @{ Add=@($emailAddressesToAdd) }
                    } else {
                        @{}
                    }
                )
            )

            Write-Host "`$emailAddressesArg: $($emailAddressesArg | format-list | Out-String)"
            
            # in the case where $emailAddressesToAdd is empty or
            # $emailAddressesToRemove is empty (or mayube they both have to be
            # empty?), the Set-Mailbox command throws the following  error.
            # Therefore, we have to take pains to avoid passing an empty list.
            #
            # Set-Mailbox: Cannot process argument transformation on parameter
            # 'EmailAddresses'. Cannot convert value
            # "System.Collections.Generic.Dictionary`2[System.String,System.Object]"
            # to type "Microsoft.Exchange.Data.ProxyAddressCollection". Error:
            # "MultiValuedProperty collections cannot contain null values.
            
            @{
                Identity = $mailbox.Guid
                EmailAddresses = $emailAddressesArg
            } | % {Set-Mailbox @_} 

            $mailbox =  Get-Mailbox -Identity $mailbox.Guid
            Write-Host "finally, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        } else {
            Write-Host "email addresses for $($mailbox.Identity) are as desired, so we will not bother to add or remove any."
        }  
    }
}



function grantUserAccessToMailbox(
    $idOfUserToBeGrantedAccess, 
    $idOfMailbox, 
    $sendInstructionalMessageToUsersThatHaveBeenGrantedAccess=$False, 
    $emailAccountForSendingAdvisoryMessages="neil@autoscaninc.com", 
    $dummyAddressForAdvisoryMessages="administrator@autoscaninc.com",
    $sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress=$False,
    $createInboxRuleToRedirect=$False
){


    $mgUserToBeGrantedAccess = Get-MgUser -UserId $idOfUserToBeGrantedAccess
    $mailbox = Get-Mailbox -ID $idOfMailbox

    Write-Host "now giving the user $($mgUserToBeGrantedAccess.UserPrincipalName) full access to the mailbox $($mailbox.PrimarySmtpAddress)."

    Remove-MailboxPermission -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue
    # we first remove any existing permission, as a way (apparently, this is the only way) to be sure that Automapping is turned off
    Add-MailboxPermission    -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Automapping:$false 
    Add-RecipientPermission  -Identity $mailbox.Id   -Trustee $mgUserToBeGrantedAccess.Id -AccessRights SendAs  -confirm:$false

    if($createInboxRuleToRedirect){
        $nameOfInboxRule = "redirect to $($mgUserToBeGrantedAccess.Mail) 5146a9a247d64ef9ba6dcfd1057e00e3"
        Remove-InboxRule -confirm:$false -Mailbox $mailbox.Id -Identity $nameOfInboxRule -ErrorAction SilentlyContinue
        $s = @{
            Mailbox                    = $mailbox.Id 
            Name                       = $nameOfInboxRule      
            RedirectTo                 = $mgUserToBeGrantedAccess.Mail
            StopProcessingRules        = $False
        }; New-InboxRule @s
    }


    # send an email to the user informing them that they now have full access to the mailbox and how to access it.
    $mgUserToBeAdvised = $mgUserToBeGrantedAccess
    $recipientAddress = ($mgUserToBeAdvised.DisplayName + "<" + $mgUserToBeAdvised.Mail + ">")
    if($sendInstructionalMessageToUsersThatHaveBeenGrantedAccess){
        $messageBodyLines = @()
        $messageBodyLines += 
            @( 
                "Dear $($mgUserToBeAdvised.DisplayName), " 

                ""

                "You now have full access to the $($mailbox.PrimarySmtpAddress) mailbox."

                ""

                "You can access this mailbox's webmail interface at https://outlook.office.com/mail/$($mailbox.PrimarySmtpAddress) ."

                ""

                "If so desired, you can add this mailbox to the left sidebar of "    + `
                "Outlook on your computer by doing the following: Within Outlook, "  + `
                "go to File -> Account Settings -> Account Settings -> Change -> "   + `
                " More Settings -> Advanced -> Add .  Then, type " + `
                "'$($mailbox.PrimarySmtpAddress)' as the address of the mailbox that you want to add."

                ""
            )

        if($createInboxRuleToRedirect){
            $messageBodyLines += 
                @( 

                    "In addition to you having full access to the $($mailbox.PrimarySmtpAddress) mailbox, " +
                    "there is an Inbox Rule within the $($mailbox.PrimarySmtpAddress) mailbox " +
                    "that is causing a copy of any message sent to that mailbox to be deposited in your inbox.  " +
                    "If so desired, you can delete the Inbox Rule in the web interface at " + 
                    "https://outlook.office.com/mail/$($mailbox.PrimarySmtpAddress)/options/mail/rules .  " +
                    "The name of the Inbox Rule is `"$($nameOfInboxRule)`".  " +
                    "Deleting the Inbox Rule will cause the automatic forwarding of messages to stop, but will " + 
                    "have no effect on your ability to access the mailbox."

                    ""
                )
        }

        $messageBodyLines += 
            @( 
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
            )
        $messageBody = $messageBodyLines -Join "`n"
        $xx = @{
            emailAccount = $emailAccountForSendingAdvisoryMessages
            from         = $emailAccountForSendingAdvisoryMessages
            to           = $(if($sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress){$dummyAddressForAdvisoryMessages} else {$recipientAddress})
            subject      = $(if($sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress){"(TO: $recipientAddress) " } else {""} ) + "$($mgUserToBeAdvised.DisplayName) now has full access to the $($mailbox.PrimarySmtpAddress) mailbox"
            body         = $messageBody
        } ; sendMail @xx
    }


}



## thanks to https://stackoverflow.com/questions/3281999/format-list-sort-properties-by-name
function Format-SortedList
{
    [OutputType([String[]])]
    

    #Todo: deal properly with multiple pipeline inputs.
    # allow user to pass arguments in to the underlying calls to format-list and sort-object.

    param (
        [Parameter(ValueFromPipeline = $true)]
        [Object]$InputObject

        # [Parameter(Mandatory = $false)]
        # [Switch]$Descending
    )

    process
    {
        # $properties = $InputObject | Get-Member -MemberType Properties

        # if ($Descending) {
        #     $properties = $properties | Sort-Object -Property Name -Descending
        # }

        # $longestName = 0
        # $longestValue = 0

        # $properties | ForEach-Object {
        #     if ($_.Name.Length -gt $longestName) {
        #         $longestName = $_.Name.Length
        #     }

        #     if ($InputObject."$($_.Name)".ToString().Length -gt $longestValue) {
        #         $longestValue = $InputObject."$($_.Name)".ToString().Length * -1
        #     }
        # }

        # Write-Host ([Environment]::NewLine)

        # $properties | ForEach-Object { 
        #     Write-Host ("{0,$longestName} : {1,$longestValue}" -f $_.Name, $InputObject."$($_.Name)".ToString())
        # }


        $initialOutputRendering = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::Ansi
        # $x = ($InputObject | fl | Out-String -Width 999999) -split "`n" | Sort-Object
        $x = @(($InputObject | fl | Out-String) -split "`n" | Sort-Object)
        $PSStyle.OutputRendering = $PSStyle.OutputRendering
        $x
    }
}



#see https://docs.microsoft.com/en-us/answers/questions/3572/change-aad-joined-windows-10-device-ownership-with.html
function setAzureAdDeviceOwner ( $nameOfDevice, $nameOfUser ){
    
    $azureAdDevice=@(Get-AzureADDevice -All 1 | where-object {
            $_.DisplayName -eq $nameOfDevice  # -and $_.DeviceTrustType -eq "AzureAd" 
    })[0]

    $azureAdUser = Get-AzureADUser -ObjectID $nameOfUser

    $existingOwner = Get-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId

    Write-Output "initially, registered owner of $($azureAdDevice.DisplayName): $($existingOwner.UserPrincipalName)"

    if( $existingOwner -and ($existingOwner.Length -eq 1 ) -and ($existingOwner.ObjectID -eq $azureAdUser.ObjectID) ){
        Write-Output "owner is already as desired.  $($existingOwner.UserPrincipalName) owns $($azureAdDevice.DisplayName)"
    } else {
        Write-Output "owner is not as desired, so we will change"

        if ($existingOwner){
            Write-Output "removing the exsting owner(s)"
            foreach ($x in $existingOwner){
                Write-Output "removing the exsting owner $($x.UserPrincipalName)"
                Remove-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId -OwnerId $x.ObjectId
            }
        }

        $s = @{
            ObjectId=$azureAdDevice.ObjectId
            RefObjectId=$azureAdUser.ObjectId
        }; Add-AzureADDeviceRegisteredOwner @s 
    }



    Write-Output (
        "Finally, registered owner of $($azureAdDevice.DisplayName): " +
        (
            Get-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId
        ).UserPrincipalName
    )



}


function blipNetworkAdapter(){
    # blips any currently-enabled and connected network adapters

    foreach (
        $netAdapter in 
        (
            Get-NetAdapter 
        )
    ){
        Write-Host "now processing netadpater: $($netAdapter.Name)"

        if ( ($netAdapter.AdminStatus -eq "Up") -and ($netAdapter.ifOperStatus -eq "Up") ){
            Write-Host "netadapter $($netAdapter.Name) is enabled and connected, so we will poke at it."

            $netConnectionProfile = $null
            $netConnectionProfile = Get-NetConnectionProfile -InterfaceAlias $netAdapter.Name -ErrorAction SilentlyContinue
            if($netConnectionProfile ){
                Write-Host( "netConnectionProfile: $($netConnectionProfile | Out-String )")
            }

            Disable-NetAdapter -Confirm:0 -InputObject $netAdapter 
            Start-Sleep 1
            Enable-NetAdapter -Confirm:0 -InputObject $netAdapter

        } else {
            Write-Host "netadapter $($netAdapter.Name) is not both enabled and connected, so we will not touch it."
        }



    }
}


function convertRedirectEntryToEmailAddress($redirectEntry){
    # redirectEntry is expected to be a string like the members
    # of an InboxRule's RedirectTo property.

    # we expect redirectEntry to resemble one of the following examples:
    #   example 1: $redirectEntry == '"John Doe" [SMTP:jdoe@acme.com]'
    #   example 2: $redirectEntry == '"John Doe" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe]'
    #   example 3: $redirectEntry == '/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe'
    #   example 4: $redirectEntry == 'jdoe@acme.com'


    $pattern='^(?:"(?<displayName>[^"]*)"\s*\[(?<protocol>[^:]*):(?<address>.*)\]|(?<address>.*))$'
    #when we apply $pattern to redirectEntry, the matching groups will pull out
    # the part between quotes (i.e. the Display name), the protocol name, and
    # the address, respectively. we want to extract, from redirectEntry, three
    # strings: displayName, protocol, and address . We actually don't care about
    # displayName or protocol. Then, we operate on the address with
    # {(Get-Recipient -Identity $args[0]).PrimarySmtpAddress} If this gives a result,
    # we return it.  Else (i.e. in case of Exception or null result), we return
    # address.
    
    # in the case of example 1, the matching groups will be:
    #   - $1: John Doe
    #   - $2: SMTP
    #   - $3: jdoe@acme.com    
    
    # in the case of example 2, the matching groups will be:
    #   - $1: John Doe
    #   - $2: EX
    #   - $3: /o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe  
    
    # in case of example 3 or 4, the match will fail, so we take address to be the entire $redirectEntry
    
    #in either case, we can attempt to "convert the address to SMTP by attempting to do (Get-Recipient $3).primarySMTPAddress
    # if this throws a "couldn't find" error, then we return $3 as is.
    $matches = $null
    $result = $redirectEntry -match $pattern
    # we have designed our pattern so that it will match any string.


    $resolvedRecipientSMTPAddress = (Get-Recipient -Identity $matches['address']).PrimarySmtpAddress  2>$null
    $resolvedMailboxSMTPAddress = (Get-Mailbox -Identity $matches['address']).PrimarySmtpAddress  2>$null
    if($resolvedRecipientSMTPAddress){
        $resolvedRecipientSMTPAddress
    } elseif( $resolvedMailboxSMTPAddress) {
        $resolvedMailboxSMTPAddress
    } elseif($matches['address']) {
        $matches['address']
    } else {
        $redirectEntry
    }

    $returnValue
}

function skuIdToSkuPartNumber($skuId){
    # ( Get-AzureADSubscribedSku | where-object { $_.SkuId -eq $skuId }).SkuPartNumber
    ( Get-MgSubscribedSku | where-object { $_.SkuId -eq $skuId }).SkuPartNumber
}
 

function deduplicate($list){
    # returns a new list that is a copy of the input list, but with only the
    # first occurence of each member retained.
    
    $returnValue = @()

    foreach ($item in $list){
        if(-not ($returnValue -contains $item)){
            $returnValue += $item
        }
    }

    $returnValue
}

function addEntryToPSModulePathPersistently($pathEntry){
    $existingPathEntries = @(([Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')) -Split ([IO.Path]::PathSeparator) | Where-Object {$_})
    $desiredPathEntries = deduplicate($existingPathEntries + $pathEntry)


    [Environment]::SetEnvironmentVariable(
        'PSModulePath', 
        ([String]::Join([IO.Path]::PathSeparator, $desiredPathEntries)),
        'Machine'
    )

}


# I grabbed this function from a google search.  Todo: inspect it, clean it, delete it if possible.
function Test-SubPath
{
	<#
	.SYNOPSIS
	Tests whether one path is a subpath of another.

	.DESCRIPTION
	Tests whether one path is a subpath of another.
	The values passed in are compared as file path strings.
	An optional switch allows for checking of the physical existence of the paths.

	.PARAMETER ChildPath
	The path of the child item.

	.PARAMETER ParentPath
	The path of the parent item.

	.PARAMETER Physical
	When the Physical switch is used, the output will be true only if the child item (and therefore also the parent item) actually exists.

	.EXAMPLE
	## Test paths as strings ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistentFolder'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath
	True

	# Returns True because the parent path is a subpath of the child path.

	.EXAMPLE
	## Test paths as strings ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistent'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath
	False

	# Returns False because, although the parent path is a substring of the child path, it is not a subpath.

	.EXAMPLE
	## Test paths as strings and check existence ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistentFolder'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath -Physical
	False

	# Returns False because, although the parent path is a subpath of the child path, the child item does not exist.

	.EXAMPLE
	## Test paths as strings and check existence ##

	PS C:\> $childPath  = $Env:HOME
	PS C:\> $parentPath = "$Env:HOMEDRIVE\"
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath -Physical
	True

	# Returns True because the parent path is a subpath of the child path and the child item (and therefore the parent item) exists.

	.INPUTS
	[System.String]
	Accepts string objects via the ChildPath parameter. The output of Get-ChildItem can be piped into Test-SubPath.

	.OUTPUTS
	[System.Boolean]
	Returns a boolean (true/false) object.

	.NOTES
	Author : nmbell

	.LINK
	Test-PowdrgitPath
	.LINK
	about_powdrgit
	.LINK
	https://github.com/nmbell/powdrgit/blob/main/help/about_powdrgit.md
	#>

	# Use cmdlet binding
	[CmdletBinding()]

	# Declare output type
	[OutputType([System.Boolean])]

	# Declare parameters
	Param
	(


		[Parameter(
	  	  Mandatory                       = $false
	  	, Position                        = 0
	  	, ValueFromPipeline               = $true
	  	, ValueFromPipelineByPropertyName = $true
	  	)]
		[Alias('FullName','Path')]
		[String]
		$ChildPath

	,	[Parameter(
	  	  Mandatory                       = $false
	  	, Position                        = 1
	  	, ValueFromPipeline               = $false
	  	, ValueFromPipelineByPropertyName = $true
	  	)]
		[String]
		$ParentPath

	,	[Switch]
		$Physical
	)

	BEGIN
	{
		# $bk = 'B'

		# Common BEGIN:
		Set-StrictMode -Version 3.0
		# $thisFunctionName = $MyInvocation.MyCommand
		# $start            = Get-Date
		# $indent           = ($Powdrgit.DebugIndentChar[0]+'   ')*($PowdrgitCallDepth++)
		$PSDefaultParameterValues += @{ '*:Verbose' = $(If ($DebugPreference -notin 'Ignore','SilentlyContinue') { $DebugPreference } Else { $VerbosePreference }) } # turn on Verbose with Debug
		# Write-Debug "  $(ts)$indent[$thisFunctionName][$bk]Start: $($start.ToString('yyyy-MM-dd HH:mm:ss.fff'))"

		# Function BEGIN:
	}

	PROCESS
	{
		# $bk = 'P'

		$result = $false

		If ($ChildPath.Trim() -and $ParentPath.Trim())
		{
			# Test by the string values of the paths
			$testPath = $ChildPath
			Do {
				If ($testPath -eq $ParentPath)
				{
					$result = $true
					Break
				}
				$testPath = Split-Path -Path $testPath -Parent
			} While ($testPath)

			# Test for physical existence
			If ($result -and $Physical)
			{
				$result = Test-Path -Path $ChildPath
			}
		}

		Write-Output $result
	}

	END
	{
		# $bk = 'E'

		# Function END:

		# Common END:
		# $end      = Get-Date
		# $duration = New-TimeSpan -Start $start -End $end
		# Write-Debug "  $(ts)$indent[$thisFunctionName][$bk]Finish: $($end.ToString('yyyy-MM-dd HH:mm:ss.fff')) ($($duration.ToString('d\d\ hh\:mm\:ss\.fff')))"
		# $PowdrgitCallDepth--
	}
}


function getReferencedAssembliesRecursivelyForReflection([System.Reflection.Assembly] $rootAssembly, $filter={$true}, [String[]] $pathHints = @(), $accumulatedNames = ([System.Collections.ArrayList] @())){
    # write-host "now processing $($rootAssembly.FullName)"
    # the passed assembly is assumed to be in its own "private": load context that we are free to pollute.
    # therefore, when calling this function, you shjould load the rooitAssembly especially in a temporary load context just to be polluted by this function.
    $referencedAssemblyNames = $rootAssembly.GetReferencedAssemblies() 
    

    
    
    foreach(
        $assembly in $(
            @(
                $rootAssembly

                $rootAssembly.GetReferencedAssemblies() | 
                    % {
                        [System.Reflection.AssemblyName] $assemblyName = $_

                        
                        # (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyName($_)
                        try {
                            & {
                                $private:ErrorActionPreference = "Stop"
                                # [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($rootAssembly).LoadFromAssemblyName($assemblyName)
                                (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyName($assemblyName) 2> $null
                            }
                        } catch {
                            # in this case, the runtime has been unable to load
                            # the assembly based on its AssemblyName alone, so
                            # we will look in the pathHints (should we be doing
                            # pathHints first?)
                            $pathsOfMatchingCandidateDllFiles = @(
                                $pathHints |
                                    foreach-object {
                                        (Get-ChildItem `
                                            -Path $_ `
                                            -Recurse `
                                            -File `
                                            -Include "*.dll" 
                                        ) | foreach-object {$_.FullName}
                                    } | 
                                    where-object {
                                        try{
                                            & {
                                                $private:ErrorActionPreference = "Stop"
                                                ([System.Reflection.Assembly]::LoadFile($_)).FullName -eq $assemblyName.FullName 2> $null
                                            }
                                        } catch {
                                            $False
                                        }
                                    }
                            )

                            # (Get-ChildItem `
                            #     -Path (join-path $pathOfRootFolderOfExchangeModule "netCore") `
                            #     -Recurse `
                            #     -Include "*.dll" 
                            # ) | foreach-object {$_.FullName}

                            if($pathsOfMatchingCandidateDllFiles ){
                                (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyPath($pathsOfMatchingCandidateDllFiles[0])
                            }

                        }
                    } 
            ) | where-object $filter 
        )
    ){
        if( -not ($assembly.FullName -in $accumulatedNames ) ){
            # Write-Host "emitting: $($assembly.FullName)"
            $assembly
            $accumulatedNames.Add($assembly.FullName) 1> $null
            # write-host "`$accumulatedNames.Count:  $($accumulatedNames.Count)"
            getReferencedAssembliesRecursivelyForReflection -rootAssembly $assembly -filter $filter -accumulatedNames $accumulatedNames
        }
    }
    
    # $referencedAssemblies | where-object $filter 
}


function getAmazonAddToCartUrl {
    [OutputType([String])]
    
    #example:
    # getAmazonAddToCartUrl @(
    #   ,@("B09S9VWQK1", 1) # NVIDIA RTX A4500 video card ($1145)
    #   ,@("B0BHJF2VRN", 1) # Samsung 990 PRO 1TB PCIe NVMe  SSD M.2
    # )

    param (
        [Parameter()]
        [Object[][]] $asinQuantityPairs

        # [Parameter(Mandatory = $false)]
        # [Switch]$Descending
    )

    # Amazon add-to-cart URL syntax:
    # (see https://webservices.amazon.com/paapi5/documentation/add-to-cart-form.html)
    $url = "https://www.amazon.com/gp/aws/cart/add.html?" + (
            @(
                for ($i=0; $i -lt $asinQuantityPairs.count; $i++ ){
                    if($asinQuantityPairs[$i][1]){
                        "ASIN.$($i+1)=$($asinQuantityPairs[$i][0])"
                        "Quantity.$($i+1)=$($asinQuantityPairs[$i][1])"
                    }
                }
            ) -join "&"
        )

    # Set-Clipboard -Value $url
    $url
}


function sendTestMessage([String] $recipient){
    @{
        emailAccount = "neil@autoscaninc.com"
        from         = "neil@autoscaninc.com"
        to           =  "$recipient"
        subject      = "test message sent to $($recipient) $('{0:yyyy/MM/dd HH:mm:ss K}' -f [timezone]::CurrentTimeZone.ToLocalTime((Get-Date)))"
        body         = @( 
            "This is a test message sent to $($recipient).  Please disregard."

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


function downloadAndExpandArchiveFile([String] $url, [String] $pathOfDirectoryInWhichToExpand){
    $localPathOfArchiveFile = (join-path $env:temp (New-Guid).Guid)
    # Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile

    # #hack to avoid redownloading:
    # $localPathOfArchiveFile = (join-path (join-path $env:temp "549b0588649a4cb19217ed6fe46c97e4") (split-path $url -leaf))
    # New-Item -ItemType "directory" -Path (Split-Path $localPathOfArchiveFile -Parent) -ErrorAction SilentlyContinue 
    # if(-not (Test-Path -Path $localPathOfArchiveFile -PathType leaf) ){
    #     Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile
    # }

    New-Item -ItemType "directory" -Path (Split-Path $localPathOfArchiveFile -Parent) -ErrorAction SilentlyContinue 
    Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile
    
    New-Item -ItemType "directory" -Path $pathOfDirectoryInWhichToExpand -ErrorAction SilentlyContinue
    7z @(
        # eXtract files with full paths    
        "x"

        #Recurse subdirectories for name search
        "-r"

        #-y : assume Yes on all queries
        "-y" 
        
        # -o{Directory} : set Output directory
        "-o$($pathOfDirectoryInWhichToExpand)" 
        
        # <archive_name>
        "$localPathOfArchiveFile" 
        
        # <file_names>...
        "*"
    )

}

function installGoodies([System.Management.Automation.Runspaces.PSSession] $session){
    Invoke-Command $session {  #ensure that chocoloatey is installed, and install other goodies
        & { #ensure that chocoloatey is installed
            
            #!ps
            #timeout=1800000
            #maxlength=9000000

            Set-ExecutionPolicy Bypass -Scope Process -Force  
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))  
            choco upgrade --acceptlicense --confirm chocolatey  
    
            #ensure that 7zip is installed
            choco install --acceptlicense -y 7zip  
            choco upgrade --acceptlicense -y 7zip 
    
            #ensure that pwsh is installed
            choco install --acceptlicense -y pwsh  
            choco upgrade --acceptlicense -y pwsh  
    
            choco install --acceptlicense -y --force "winmerge"
            choco install --acceptlicense -y --force "spacesniffer"
            choco install --acceptlicense -y --force "notepadplusplus"
            choco install --acceptlicense -y --force "sysinternals"
            # choco install --acceptlicense -y --force "cygwin"
            
            choco install --acceptlicense -y --force "hdtune"
        }
    
    
    }
}


function installGoodies2(){
    <#
    .SYNOPSIS
    To run this in a remote session $s, do 
    icm $s -ScriptBlock ${function:installGoodies2} 
    #>

    & { #ensure that chocolatey is installed, and install other goodies
        
        #!ps
        #timeout=1800000
        #maxlength=9000000

        Set-ExecutionPolicy Bypass -Scope Process -Force  
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))  
        choco upgrade --acceptlicense --confirm chocolatey  

        #ensure that 7zip is installed
        choco install --acceptlicense -y 7zip  
        choco upgrade --acceptlicense -y 7zip 

        #ensure that pwsh is installed
        choco install --acceptlicense -y pwsh  
        choco upgrade --acceptlicense -y pwsh  

        choco install --acceptlicense -y --force "winmerge"
        choco install --acceptlicense -y --force "spacesniffer"
        choco install --acceptlicense -y --force "notepadplusplus"
        choco install --acceptlicense -y --force "sysinternals"
        # choco install --acceptlicense -y --force "cygwin"
        
        choco install --acceptlicense -y --force "hdtune"
    }
}


function runElevatedInActiveSession(){
    <#
        .SYNOPSIS
        This is a hack on several levels that gets the job done.  Given a powershell session (typically a remote session),
        this command runs psexec on the remote computer with the arguments passed to this function.
    #>
    
    Param(
        [System.Management.Automation.Runspaces.PSSession] $session,
        [parameter(ValueFromRemainingArguments = $true)]
        [String[]] $remainingArguments
    )
    Invoke-Command $session {             
        & PsExec @(
            # -accepteula This flag suppresses the display of the license dialog.
            "-accepteula"

            # -nobanner   Do not display the startup banner and copyright message.
            "-nobanner"
            
            # -d         Don't wait for process to terminate (non-interactive).
            "-d"

            # -h         If the target system is Vista or higher, has the
            # process run with the account's elevated token, if available.
            "-h"

            # -i         Run the program so that it interacts with the desktop
            # of the specified session on the remote system. If no session is
            # specified the process runs in the console session.
            "-i",((query session | select-string '(?i)^.*\s+(\d+)\s+active(\s|$)').Matches[0].Groups[1].Value)
            
            # -s         Run the remote process in the System account.
            "-s"

            #command and arguments: 
            $using:remainingArguments
        )
    }
}

function addEntryToSystemPathPersistently($pathEntry){
    $existingPathEntries = @(([System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)) -Split ([IO.Path]::PathSeparator) | Where-Object {$_})
    # $desiredPathEntries = deduplicate($existingPathEntries + $pathEntry)
    $desiredPathEntries = @(
        @( 
            @($existingPathEntries)
            $pathEntry
        ) | select-object -unique 
    )


    [System.Environment]::SetEnvironmentVariable(
        'PATH', 
        ([String]::Join([IO.Path]::PathSeparator, $desiredPathEntries)),
        [System.EnvironmentVariableTarget]::Machine
    )
}

function reportDrives(){

    Get-Disk | 
        sort Number |
        select @(
            "Number"
            "IsOffline"
            "OfflineReason"
            @{
                name="Size"
                expression = {"{0:N} gigabytes" -f ($_.Size/[math]::pow(10,9))}
            }
        ) |
        Format-Table


    # Get-WmiObject -Class Win32_LogicalDisk |
    Get-CimInstance -Class Win32_LogicalDisk |
        ? {$_.DriveType -ne 5} |
        Sort-Object Name | 
        Select-Object @(
            "Name"
            "VolumeName"
            "VolumeSerialNumber"
            "SerialNumber"
            "FileSystem"
            "Description"
            "VolumeDirty"
            @{"Label"="total space`n(gigabytes)";"Expression"={"{0:N}" -f ($_.Size/[math]::pow(10,9)) -as [float]}}
            @{"Label"="used space`n(gigabytes)";"Expression"={"{0:N}" -f ( ( $_.Size - $_.FreeSpace)/[math]::pow(10,9)) -as [float]}}
            @{"Label"="free space`n(gigabytes)";"Expression"={"{0:N}" -f ($_.FreeSpace/[math]::pow(10,9)) -as [float]}}
            @{"Label"="fraction free";"Expression"={"{0:N}" -f ($_.FreeSpace/$_.Size) -as [float]}}
        ) |
        Format-Table -AutoSize
    

    Get-Partition  | 
        Sort DiskNumber,PartitionNumber |
        select @(
            "DiskNumber"
            "PartitionNumber"
            "Type"
            # "DriveLetter"
            @{
                name="Drive Letter"
                expression={
                    # if($_.DriveLetter){$_.DriveLetter}
                    # $_.DriveLetter.ToString()
                    # "$($_.DriveLetter)"
                    # $_.DriveLetter -as [String]
                    if($_.DriveLetter){$_.DriveLetter}
                }
                # driveletter is a char, and is a null char to indicate no assigned drive letter.
                # a null char screws up the alignment in the terminal.
            }
            @{
                name="size"
                expression={"{0,9:f1} gigabytes" -f (($_.Size/[math]::pow(10,9) ) -as [float])}
            } 
            @{
                name="offset"
                expression={"{0,9:f1} gigabytes" -f (($_.Offset/[math]::pow(10,9) ) -as [float])}
            } 
            "Guid"
        ) | 
        format-table -autosize | 
        # out-string |
        write-output

}