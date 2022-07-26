function unlockTheBitwardenVault(){
    Write-Host "Attempting to unlock the bitwarden vault..."
    if ($(bw unlock --check)) {
        Write-Host "The bitwarden vault is already unlocked."
    }
    else { 
        $env:BW_SESSION =  $(pwsh -Command "bw unlock --raw || bw login --raw") 
    }
}

function getBitwardenItem {
    [OutputType([HashTable])] # I really want an Optional[HashTable] -- I will return null in case of failure.
    
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item to get")]
        [String]$bitwardenItemId
    )
    
    unlockTheBitwardenVault
    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get item $bitwardenItemId  | ConvertFrom-Json -AsHashtable)
    #todo: error handling
    return $bitwardenItem
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
    $result = [System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json)) )  | bw --nointeraction --raw create item 
    $newlyCreatedBitwardenItem = ( $result | ConvertFrom-Json -AsHashtable)
    Write-Host "created new bitwarden item having id $($newlyCreatedBitwardenItem['id'])."
    return (getBitwardenItem -bitwardenItemId $newlyCreatedBitwardenItem['id'] )
}



function getFieldMapFromBitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item containing the configuration data.")]
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [String]$bitwardenItemId 
    )

    [HashTable] $bitwardenItem = getBitwardenItem -bitwardenItemId $bitwardenItemId

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
        #     getBitwardenItem -bitwardenItemId $bitwardenItemId 
        # }
        getBitwardenItem -bitwardenItemId $bitwardenItemId 
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
    ([System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json)) ) | bw --nointeraction --raw edit item $bitwardenItem['id'] ) 1> $null
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
    $matchingBitwardenItems = $bitwardenItems | where-object { $_.fields | where-object { $_.name -eq 'record_type' -and $_.value -eq 'smtp_mail_sending' } }

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

function setLicensesAssignedToAzureAdUser($objectIdOfAzureAdUser, $skuPartNumbers){
    $azureAdUser = Get-AzureADUser -ObjectId $objectIdOfAzureAdUser
    if (! $azureAdUser ){
        Write-Host "No Azure AD user having id $objectIdOfAzureAdUser exists."
        return
    } 

    # to view the available sku part numbers, run the following command:
    # (Get-AzureADSubscribedSku).SkuPartNumber

    # assign licenses:
    # annoyingly, there does not seem to be a good way to buy licenses programmatically 
    $desiredSkuIds = @(( Get-AzureADSubscribedSku | where-object { $_.SkuPartNumber -in @($skuPartNumbers) }).SkuId)
    $existingSkuIds = @($azureAdUser.AssignedLicenses | foreach-object {$_.SkuId})
    Write-Host (
        "Initially, $($azureAdUser.UserPrincipalName) has these skuPartNumbers: " + ( 
            @(
                ( Get-AzureADSubscribedSku | where-object { $_.SkuId -in $existingSkuIds }).SkuPartNumber
            ) -Join ", "
        )
    )
    
    #ensure that licenses are assigned:
    $skuIdsToRemoveFromUser = $existingSkuIds | where-object {-not ($_ -in $desiredSkuIds)};
    $skuIdsToGiveToUser = $desiredSkuIds | where-object {-not ($_ -in $existingSkuIds)};
    
    Write-Host ("skuIdsToRemoveFromUser: ", $skuIdsToRemoveFromUser)
    Write-Host ("skuIdsToGiveToUser: ", $skuIdsToGiveToUser)
    
    if($skuIdsToRemoveFromUser -or $skuIdsToGiveToUser){
        Write-Host "changing the user's license assignment to match the desired configuration"
        
        if($skuIdsToRemoveFromUser){
            # $assignedLicenses.RemoveLicenses = @($skuIdsToRemoveFromUser | foreach-object {$x = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense; $x.SkuId = $_; $x })
            $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            $assignedLicenses.RemoveLicenses = $skuIdsToRemoveFromUser
            Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        }
        
        foreach($skuIdToGiveToUser in $skuIdsToGiveToUser){
            $assignedLicense = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense;
            $assignedLicense.SkuId = $skuIdToGiveToUser;
            $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses;
            $assignedLicenses.AddLicenses = $assignedLicense;
            $azureAdUser | Set-AzureADUser -UsageLocation "US"
            Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        }
        
        # if($skuIdsToGiveToUser){
            # $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            # $assignedLicenses.AddLicenses = $skuIdsToGiveToUser
            # Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        # }

        $existingSkuIds = @((Get-AzureAdUser -ObjectId $azureAdUser.ObjectId).AssignedLicenses | foreach-object {$_.SkuId})
        Write-Host (
            "After making changes, $($azureAdUser.UserPrincipalName) has these skuPartNumbers: " + ( 
                @(
                    ( Get-AzureADSubscribedSku | where-object { $_.SkuId -in $existingSkuIds }).SkuPartNumber
                ) -Join ", "
            )
        )

    } else {
        Write-Host "no changes need to be made to the user's licenses."
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

    $azureAdUserToBeGrantedAccess = Get-AzureADUser -ObjectID $idOfUserToBeGrantedAccess
    $mailbox = Get-Mailbox -ID $idOfMailbox

    Write-Host "now giving the user $($azureAdUserToBeGrantedAccess.UserPrincipalName) full access to the mailbox $($mailbox.PrimarySmtpAddress)."

    Remove-MailboxPermission -Identity $mailbox.Id   -User    $azureAdUserToBeGrantedAccess.ObjectID -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue
    # we first remove any existing permission, as a way (apparently, this is the only way) to be sure that Automapping is turned off
    Add-MailboxPermission    -Identity $mailbox.Id   -User    $azureAdUserToBeGrantedAccess.ObjectID -AccessRights FullAccess -Automapping:$false 
    Add-RecipientPermission  -Identity $mailbox.Id   -Trustee $azureAdUserToBeGrantedAccess.ObjectID -AccessRights SendAs  -confirm:$false

    if($createInboxRuleToRedirect){
        $nameOfInboxRule = "redirect to $($azureAdUserToBeGrantedAccess.Mail) 5146a9a247d64ef9ba6dcfd1057e00e3"
        Remove-InboxRule -confirm:$false -Mailbox $mailbox.Id -Identity $nameOfInboxRule -ErrorAction SilentlyContinue
        $s = @{
            Mailbox                    = $mailbox.Id 
            Name                       = $nameOfInboxRule      
            RedirectTo                 = $azureAdUserToBeGrantedAccess.Mail
            StopProcessingRules        = $False
        }; New-InboxRule @s
    }


    # send an email to the user informing them that they now have full access to the mailbox and how to access it.
    $azureAdUserToBeAdvised = $azureAdUserToBeGrantedAccess
    $recipientAddress = ($azureAdUserToBeAdvised.DisplayName + "<" + $azureAdUserToBeAdvised.Mail + ">")
    if($sendInstructionalMessageToUsersThatHaveBeenGrantedAccess){
        $messageBodyLines = @()
        $messageBodyLines += 
            @( 
                "Dear $($azureAdUserToBeAdvised.DisplayName), " 

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
            subject      = $(if($sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress){"(TO: $recipientAddress) " } else {""} ) + "$($azureAdUserToBeAdvised.DisplayName) now has full access to the $($mailbox.PrimarySmtpAddress) mailbox"
            body         = $messageBody
        } ; sendMail @xx
    }


}



## thanks to https://stackoverflow.com/questions/3281999/format-list-sort-properties-by-name
function Format-SortedList
{
    param (
        [Parameter(ValueFromPipeline = $true)]
        [Object]$InputObject,
        [Parameter(Mandatory = $false)]
        [Switch]$Descending
    )

    process
    {
        $properties = $InputObject | Get-Member -MemberType Properties

        if ($Descending) {
            $properties = $properties | Sort-Object -Property Name -Descending
        }

        $longestName = 0
        $longestValue = 0

        $properties | ForEach-Object {
            if ($_.Name.Length -gt $longestName) {
                $longestName = $_.Name.Length
            }

            if ($InputObject."$($_.Name)".ToString().Length -gt $longestValue) {
                $longestValue = $InputObject."$($_.Name)".ToString().Length * -1
            }
        }

        Write-Host ([Environment]::NewLine)

        $properties | ForEach-Object { 
            Write-Host ("{0,$longestName} : {1,$longestValue}" -f $_.Name, $InputObject."$($_.Name)".ToString())
        }
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
    ( Get-AzureADSubscribedSku | where-object { $_.SkuId -eq $skuId }).SkuPartNumber
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

