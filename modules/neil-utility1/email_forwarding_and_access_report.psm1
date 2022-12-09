
import-module (join-path $psScriptRoot "utility.psm1")
function make_email_forwarding_and_access_report(){

    $reportTime = (Get-Date )
    $defaultDomainName = (Get-AzureAdDomain | where-object {$_.IsDefault}).Name

    $pathOfOutputReportFile = "email_forwarding_and_access_report_$defaultDomainName_$('{0:yyyy-MM-dd_HH-mm}' -f $reportTime).txt"

    $allMailboxPermissions = get-mailbox | get-mailboxpermission 
    $allRecipientPermissions = get-mailbox | get-RecipientPermission 
    $allAzureAdUsers = Get-AzureADUser
    $licensedAzureAdUsers = $allAzureAdUsers | where {$_.AssignedLicenses.Length -gt 0}


    "" | Out-File -FilePath $pathOfOutputReportFile
    $reportTime = (Get-Date )


    @(
        "EMAIL FORWARDING AND ACCESS REPORT"
        "$defaultDomainName"
        "Prepared $('{0:yyyy/MM/dd HH:mm}' -f $reportTime)"
    ) | Out-File  -Width 99999 -Append -FilePath $pathOfOutputReportFile



    foreach($mailbox in (get-mailbox | Sort-Object -Property PrimarySmtpAddress)){
    # foreach($mailbox in (get-mailbox | Sort-Object -Property PrimarySmtpAddress | Where-Object { -not $_.Identity.Contains("-snapshot20210502")  })){
        $azureAdUserWhoOwnsThisMailbox = $allAzureAdUsers | where {$_.UserPrincipalName -eq $mailbox.PrimarySmtpAddress}
        
        $fullAccessPermissionsToThisMailbox = (
            $allMailboxPermissions | where {
                ($_.Identity -eq $mailbox.Identity) -and 
                ($_.AccessRights.contains( "FullAccess" )) -and
                (! $_.Deny) -and
                # (($allAzureAdUsers.UserPrincipalName).contains($_.User))
                (($licensedAzureAdUsers.UserPrincipalName).contains($_.User))
            }
        )
        
        $recipientPermissionsToThisMailbox = (
            $allRecipientPermissions | where {
                ($_.Identity -eq $mailbox.Identity) -and 
                ($_.AccessRights.contains( "SendAs" )) -and
                ($_.AccessControlType -eq "Allow") -and 
                (($licensedAzureAdUsers.UserPrincipalName).contains($_.Trustee))
            }
        )
        
        
        $azureAdUsersThatHaveFullAccessToThisMailbox = (
            ([system.Array] ($fullAccessPermissionsToThisMailbox | foreach {Get-AzureADUser -ObjectId $_.User} )) +
            ([system.Array] @($azureAdUserWhoOwnsThisMailbox))
        ) | Sort-Object -Property UserPrincipalName
        
        $azureAdUsersThatHaveSendAsPermissionToThisMailbox = (
            ([system.Array] ($recipientPermissionsToThisMailbox | foreach {Get-AzureADUser -ObjectId $_.Trustee} )) +
            ([system.Array] @($azureAdUserWhoOwnsThisMailbox))
        ) | Sort-Object -Property UserPrincipalName
        
        $addressesToWhichThisMailboxIsBeingRedirected = (
            @( 
                ( Get-InboxRule -Mailbox $mailbox.Identity 
                ) | foreach-object{ 
                    $_.RedirectTo; 
                    $_.ForwardTo; 
                    $_.ForwardAsAttachmentTo;  
                } |  Where-Object {
                    $_
                    # we need the "|  Where-Object {$_}" in order to remove
                    # nulls from the pipeline, which happens when RedirectTo is,
                    # essentially, an empty list.
                } | foreach-object { convertRedirectEntryToEmailAddress $_ }
            ) + @(
                Get-TransportRule | where-object {
                    $_.State -eq "Enabled"
                } | where-object {
                    $sentToList = $_.SentTo;
                    @(
                        &{ $sentToList | foreach-object {(get-mailbox -identity $_).Identity} | where-object {$_} }
                    ).Contains($mailbox.Identity  )
                } | foreach-object {
                    $_.CopyTo;
                    $_.BlindCopyTo;
                    $_.RedirectMessageTo;
                }
            )
            # This is probably not a comprehensive way to detect all possible
            # forwarding due to mail flow rules, but it serves the immediate
            # purpose.
        )
        
        
        #TODO: we should also look at the mailbox's ForwardingAddress and
        #ForwardingSMTPAddress properties as possible sources of addresses to
        #which this mailbox is being redirected.
        
        
        $addressesToWhichThisMailboxIsBeingRedirected = $addressesToWhichThisMailboxIsBeingRedirected | Sort-Object
        
        $reportMessage = ""
        $reportMessage += "The mailbox " + $mailbox.PrimarySmtpAddress + " (which is a " + $(if($mailbox.IsShared){"shared"} else {"non-shared"}) +  " mailbox) " 
        
            
        $reportMessage += "`n" + 
        "`t" + "is accessible (full access permission) " + 
        $(
            if($azureAdUsersThatHaveFullAccessToThisMailbox.Length -eq 1){
                "only to " + $azureAdUsersThatHaveFullAccessToThisMailbox[0].UserPrincipalName
            } elseif ($azureAdUsersThatHaveFullAccessToThisMailbox.Length -gt 1){
                "to the following users: " + "`n" +
                [system.String]::Join("`n", ($azureAdUsersThatHaveFullAccessToThisMailbox | Sort-Object | ForEach-Object {"`t`t" + $_.UserPrincipalName}))
            } else {
                "to nobody."
            } 
        ) + "`n" + 
        "`t" + "and is sendable (send-as permission) " + 
        $(
            if($azureAdUsersThatHaveSendAsPermissionToThisMailbox.Length -eq 1){
                "only to " + $azureAdUsersThatHaveSendAsPermissionToThisMailbox[0].UserPrincipalName
            } elseif ($azureAdUsersThatHaveSendAsPermissionToThisMailbox.Length -gt 1){
                "to the following users: " + "`n" +
                [system.String]::Join("`n", ($azureAdUsersThatHaveSendAsPermissionToThisMailbox | Sort-Object | ForEach-Object  {"`t`t" + $_.UserPrincipalName}))
            } else {
                "to nobody."
            } 
        ) + "`n" + 
        "`t" + "and is being redirected " + 
        $(
            if($addressesToWhichThisMailboxIsBeingRedirected.Length -gt 0){
                "to the following addresses: " + "`n" +
                [system.String]::Join("`n", ($addressesToWhichThisMailboxIsBeingRedirected | ForEach-Object {"`t`t" + $_})) 
            } else {
                "nowhere."         
            }
        ) + "`n"
            
        write-output($reportMessage)
        $reportMessage | Out-File -Append -Width 99999  -FilePath $pathOfOutputReportFile 
        
        
        #pause to avoid hitting the Office365 call quota.
        # Start-Sleep -Milliseconds 4000
            
    }

}

