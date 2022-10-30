function unlockTheBitwardenVault(){
    Write-Host "Attempting to unlock the bitwarden vault..."
    if ($(bw unlock --check)) {
        Write-Host "The bitwarden vault is already unlocked."
    }
    else { 
        $env:BW_SESSION =  $(pwsh -Command "bw unlock --raw || bw login --raw") 
    }
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
