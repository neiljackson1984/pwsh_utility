
import-module (join-path $psScriptRoot "utility.psm1")
function make_email_forwarding_and_access_report(){

    $reportTime = (Get-Date )
    $defaultDomainName = (Get-MgDomain | where-object {$_.IsDefault}).Id

    $pathOfOutputReportFile = "email_forwarding_and_access_report_$($defaultDomainName)_$('{0:yyyy-MM-dd_HH-mm}' -f $reportTime).txt"


    # $allMailboxPermissions = get-mailbox | get-mailboxpermission 
    # $allRecipientPermissions = get-mailbox | get-RecipientPermission 
    # $allMgUsers = Get-MgUser
    $licensedMgUsers = Get-MgUser -All -Property "Id","Guid","UserPrincipalName","AssignedLicenses" | 
        ? {$_.AssignedLicenses}


    "" | Out-File -FilePath $pathOfOutputReportFile
    $reportTime = (Get-Date )


    @(
        "EMAIL FORWARDING AND ACCESS REPORT"
        "$defaultDomainName"
        "Prepared $('{0:yyyy/MM/dd HH:mm}' -f $reportTime)"
        ""
    ) | Out-File  -Width 99999 -Append -FilePath $pathOfOutputReportFile


    foreach($mailbox in (get-mailbox | Sort-Object -Property PrimarySmtpAddress)){
        $mgUserWhoOwnsThisMailbox = $null
        $mgUserWhoOwnsThisMailbox = (Get-MgUser -UserId $mailbox.ExternalDirectoryObjectId -ErrorAction SilentlyContinue)
        
        
        # $fullAccessPermissionsToThisMailbox = @(
        #     $allMailboxPermissions | ? {
        #         ($_.Identity -eq $mailbox.Identity) -and 
        #         ($_.AccessRights.contains( "FullAccess" )) -and
        #         (! $_.Deny) -and
        #         (($licensedMgUsers.UserPrincipalName).contains($_.User))
        #     }
        # )
        $fullAccessPermissionsToThisMailbox = @(
            (
                @{
                    Identity = $mailbox.Guid 
                    
                    # The GroupMailbox switch is required to return Microsoft 365
                    # Groups in the results.
                    # GroupMailbox = $True

                    # The IncludeUnresolvedPermissions switch returns unresolved
                    # permissions in the results.
                    # IncludeUnresolvedPermissions = $True

                    # The SoftDeletedMailbox switch is required to return
                    # soft-deleted mailboxes in the results. Soft-deleted mailboxes
                    # are deleted mailboxes that are still recoverable.
                    # SoftDeletedMailbox = $True

                    # The ResultSize parameter specifies the maximum number of
                    # results to return. If you want to return all requests that
                    # match the query, use unlimited for the value of this
                    # parameter. The default value is 1000.
                    ResultSize = "Unlimited"

                    # The IncludeSoftDeletedUserPermissions switch returns
                    # permissions from soft-deleted mailbox users in the results.
                    # Soft-deleted mailboxes are mailboxes that have been deleted,
                    # but are still recoverable.
                    # IncludeSoftDeletedUserPermissions = $True
                } | % { Get-MailboxPermission @_ }
            ) | 
            ? {
                ($_.AccessRights.contains( "FullAccess" )) -and
                (! $_.Deny) -and
                # ([bool] (Get-MgUser -UserId $_.User -Property "AssignedLicenses").AssignedLicenses)
                ($licensedMgUsers.UserPrincipalName).contains($_.User)
            }
        )
        
        
        # $recipientPermissionsToThisMailbox = @(
        #     $allRecipientPermissions | ? {
        #         ($_.Identity -eq $mailbox.Identity) -and 
        #         ($_.AccessRights.contains( "SendAs" )) -and
        #         ($_.AccessControlType -eq "Allow") -and 
        #         (($licensedMgUsers.UserPrincipalName).contains($_.Trustee))
        #     }
        # )
        $sendAsPermissionsToThisMailbox = @(
            (
               @{
                    Identity = $mailbox.Guid

                    # The AccessRights parameter filters the results by
                    # permission. The only valid value for this parameter is
                    # SendAs.
                    AccessRights = "SendAs"

                    ResultSize = "Unlimited"
               } | % {Get-RecipientPermission @_}
            ) | 
            ? {
                ($_.AccessRights.contains( "SendAs" )) -and
                ($_.AccessControlType -eq "Allow") -and 
                # ([bool] (Get-MgUser -UserId $_.Trustee -Property "AssignedLicenses").AssignedLicenses)
                ($licensedMgUsers.UserPrincipalName).contains($_.Trustee)
            }
        )
        
        $mgUsersThatHaveFullAccessToThisMailbox = @(
            @(
                $fullAccessPermissionsToThisMailbox | % {Get-MgUser -UserId $_.User} 

                if($mgUserWhoOwnsThisMailbox){$mgUserWhoOwnsThisMailbox}
            ) | 
            Sort-Object -Property UserPrincipalName
        )
        
        $mgUsersThatHaveSendAsPermissionToThisMailbox = @(
            @(
                $sendAsPermissionsToThisMailbox | % {Get-MgUser -UserId $_.Trustee} 

                if($mgUserWhoOwnsThisMailbox){$mgUserWhoOwnsThisMailbox}
            ) | 
            Sort-Object -Property UserPrincipalName
        )
        
        $addressesToWhichThisMailboxIsBeingRedirected = @(

            Get-InboxRule -Mailbox $mailbox.Identity | 
                foreach-object{ 
                    $_.RedirectTo
                    $_.ForwardTo 
                    $_.ForwardAsAttachmentTo  
                } |  Where-Object {
                    $_
                    # we need the "|  Where-Object {$_}" in order to remove
                    # nulls from the pipeline, which happens when RedirectTo is,
                    # essentially, an empty list.
                } | foreach-object { convertRedirectEntryToEmailAddress $_ }

            

            Get-TransportRule | 
                where-object {
                    $_.State -eq "Enabled"
                } | 
                where-object {
                    $sentToList = @($_.SentTo) | ? {$_}
                    @(
                        &{ $sentToList | foreach-object {(get-mailbox -identity $_).Identity} | where-object {$_} }
                    ).Contains($mailbox.Identity  )
                } | 
                foreach-object {
                    $_.CopyTo
                    $_.BlindCopyTo
                    $_.RedirectMessageTo
                }

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
            if($mgUsersThatHaveFullAccessToThisMailbox.Length -eq 1){
                "only to " + $mgUsersThatHaveFullAccessToThisMailbox[0].UserPrincipalName
            } elseif ($mgUsersThatHaveFullAccessToThisMailbox.Length -gt 1){
                "to the following users: " + "`n" +
                [system.String]::Join("`n", ($mgUsersThatHaveFullAccessToThisMailbox | Sort-Object | ForEach-Object {"`t`t" + $_.UserPrincipalName}))
            } else {
                "to nobody."
            } 
        ) + "`n" + 
        "`t" + "and is sendable (send-as permission) " + 
        $(
            if($mgUsersThatHaveSendAsPermissionToThisMailbox.Length -eq 1){
                "only to " + $mgUsersThatHaveSendAsPermissionToThisMailbox[0].UserPrincipalName
            } elseif ($mgUsersThatHaveSendAsPermissionToThisMailbox.Length -gt 1){
                "to the following users: " + "`n" +
                [system.String]::Join("`n", ($mgUsersThatHaveSendAsPermissionToThisMailbox | Sort-Object | ForEach-Object  {"`t`t" + $_.UserPrincipalName}))
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

