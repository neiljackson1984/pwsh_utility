#!pwsh
import-module (join-path $psScriptRoot "utility.psm1")

function Expand-Attachments {
    <#
        .SYNOPSIS
            Look at all .msg files in the specified source folder, assumed to be
            email message files as saved by Outlook.  For each, dump attached
            files into the destination folder.

            If appendHashToOutputFileNames is specified, de hash-based file
            names to ensure file name uniqueness. we regard two attached files
            as "the same" iff. they have the same filename and the same hash.

        .DESCRIPTION
            Long description

        .PARAMETER pathOfSourceFolder


        .PARAMETER pathOfDestinationFolder


        .PARAMETER pathOfSourceMessageFile


        .PARAMETER appendHashToOutputFileNames

    #>
    

    
    ## [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", Scope="Function", Target="*")]
    <#  I know, I know: "dump" is not an approved powershell verb.  Ideally, I
        should change "dump" to one of the standard approved verbs, or perhaps
        (probably ill-advised. is this even possible?), add "dump" to the list
        of approved verbs.

        The above Diagnostics.CodeAnalysis.SuppressMessageAttribute does
        suppress the script analyzer warnings in vs code, but has no effect on
        the warning message that powershell displays when importing this module:
        "WARNING: The names of some imported commands from the module
        'neil-utility1' include unapproved verbs that might make them less
        discoverable. "

    #>



    Param(
        [Parameter(Position=0)]
        [String]$pathOfSourceFolder,

        [Parameter(Position=1)]
        [String]$pathOfDestinationFolder,

        [Parameter(Position=2)]
        [String]$pathOfSourceMessageFile,

        [Parameter(Position=3)]
        [Boolean]$appendHashToOutputFileNames = $True
    )

    # $pathOfSourceFolder=(Join-Path $PSScriptRoot "message_files")
    # $pathOfDestinationFolder=(Join-Path $PSScriptRoot "attachments")



    $pathsOfMessageFilesToProcess = @()

    if ($pathOfSourceFolder){
        $pathsOfMessageFilesToProcess = $pathsOfMessageFilesToProcess + @(( Get-Item -Path (Join-Path $pathOfSourceFolder "*.msg") ).FullName)
    }

    if ($pathOfSourceMessageFile){
        $pathsOfMessageFilesToProcess = $pathsOfMessageFilesToProcess +  @((Get-Item -Path $pathOfSourceMessageFile).FullName)
    }

    # Add-Type -assembly "Microsoft.Office.Interop.Outlook"
    # add-type -assembly "System.Runtime.Interopservices"
    # $outlook = [Runtime.Interopservices.Marshal]::GetActiveObject('Outlook.Application')

    $outlook = New-Object -ComObject Outlook.Application

    foreach ($pathOfMessageFile in $pathsOfMessageFilesToProcess){
        write-host "working on $pathOfMessageFile"
        $message = $outlook.CreateItemFromTemplate($pathOfMessageFile)
        Write-Output ('$message.Attachments.Count: ' + $message.Attachments.Count)
        
        foreach ($attachedFile in $message.Attachments) {
            $pathOfStagedFile = (join-path (New-TemporaryDirectory) $attachedFile.Filename)
            
            $pathOfTempFile = [System.IO.Path]::GetTempFileName()
            $attachedFile.SaveAsFile($pathOfStagedFile)
            $hashOfAttachedFile = (Get-FileHash -Path $pathOfStagedFile -Algorithm SHA256).hash

            if($appendHashToOutputFileNames) {
                # $filenameOfDestinationFile = (Split-Path -LeafBase -Path $attachedFile.Filename ) + "--" + $hashOfAttachedFile + (Split-Path -Extension -Path $attachedFile.Filename ) 
                $filenameOfDestinationFile = (split-path -leaf (getStronglyNamedPath $pathOfStagedFile)) 
            } else {
                # $filenameOfDestinationFile = Split-Path -Leaf -Path $attachedFile.Filename 
                $filenameOfDestinationFile = Split-Path -Leaf -Path $pathOfStagedFile
            }

            $pathOfDestinationFile = (Join-Path $pathOfDestinationFolder $filenameOfDestinationFile)
            

            #make the destination folder if it does not already exist
            New-Item -ItemType directory -Path (Split-Path -Path $pathOfDestinationFile -Parent) -ErrorAction SilentlyContinue | out-null
            Move-Item -Path $pathOfStagedFile -Destination $pathOfDestinationFile

            Write-Host ('$attachedFile.Filename: ' + $attachedFile.Filename )
            # Write-Host ('$pathOfStagedFile: ' + $pathOfStagedFile )
            Write-Host ('$pathOfDestinationFile: ' + $pathOfDestinationFile )
            # Write-Host ('$hashOfAttachedFile: ' + $hashOfAttachedFile )
        }
    }
}

<#
    2024-03-24: renamed "dump-attachemnts" to "expand-attachments" in order to
    get rid of the nonstandard verb "dump".

    We now add the alias dump-attachments for backward compatibility.

    Curiously, Powershell does not seem to mind having an alias with a
    non-standard verb.
#>
set-alias dump-attachments Expand-Attachments
