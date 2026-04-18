#!pwsh
import-module (join-path $psScriptRoot "utility.psm1")

function Expand-Attachments {
    <#
        .SYNOPSIS
            Look at all .msg and .eml files in the specified source folder, assumed to be
            email message files as saved by Outlook or similar.  For each, dump attached
            files into the destination folder.

            If appendHashToOutputFileNames is specified, do hash-based file
            names to ensure file name uniqueness. we regard two attached files
            as "the same" iff. they have the same filename and the same hash.

            Returns the path of the folder  into which the attachments were expanded


        .PARAMETER pathOfSourceFolder


        .PARAMETER pathOfDestinationFolder
            Leave nullish to generate a new temporary folder


        .PARAMETER pathsOfSourceMessageFiles


        .PARAMETER appendHashToOutputFileNames

        .PARAMETER recurse
            recurse when scanning the source folder.

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

    <# 2026-04-18-1013

        We have now switched  from  relying on the Outlook COM api, which could
        only handle msg files, to relying on edecoder, a plugin  for 7zip
        produced by some Russian organization called tc4shell.   See
        (https://www.tc4shell.com/en/7zip/edecoder).

        edecoder can be installed (As of 2026-04-18-1015) by doing:
        ```
        choco upgrade edecoder --checksum CBD6C0357DF0D419A6AC4BCF89DCC972A8CCFB8D5BA0CDD2B876AD21EF4217AB  --source chocolatey  --yes
        ```


    #>


    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Position=0)]
        [String]$pathOfSourceFolder,

        [Parameter(Position=1)]
        [String]$pathOfDestinationFolder,

        [Parameter(Position=2)]
        [String[]]$pathsOfSourceMessageFiles,

        [Parameter(Position=3)]
        [switch] $appendHashToOutputFileNames = $false,

        [Parameter(Position=4)]
        [switch] $recurse = $false
    )

    if(-not $pathOfDestinationFolder){
        $pathOfDestinationFolder = $(New-TemporaryDirectory |%  FullName)
    }

    
    if(-not (test-path $pathOfDestinationFolder -pathtype:container)){
        write-error (-join @(
            "The destination folder '$($pathOfDestinationFolder)'  does not exist.  We cannot proceed."
        ))
        return
    }



    $pathsOfMessageFilesToProcess = @()

    if ($pathOfSourceFolder){
        $pathsOfMessageFilesToProcess = $pathsOfMessageFilesToProcess + @(
            ## ( Get-Item -Path (Join-Path $pathOfSourceFolder "*.msg") ).FullName
            
            gci -file -force -path $pathOfSourceFolder -recurse:$recurse |
            ?  {[System.IO.Path]::GetExtension($_).ToLower() -in @(".eml"; ".msg")} |
            %  FullName
        )
        <# 2026-01-27-1240 TODO: figure out how to support eml files in addtion to msg files. #>
    }

    if ($pathsOfSourceMessageFiles){
        $pathsOfMessageFilesToProcess = $pathsOfMessageFilesToProcess +  @(
            ## (Get-Item -Path $pathOfSourceMessageFile).FullName
            $pathsOfSourceMessageFiles
        )
    }

    if($false){
        ## Add-Type -assembly "Microsoft.Office.Interop.Outlook"
        ## add-type -assembly "System.Runtime.Interopservices"
        ## $outlook = [Runtime.Interopservices.Marshal]::GetActiveObject('Outlook.Application')
        
        $outlook = New-Object -ComObject Outlook.Application
    }

    foreach ($pathOfMessageFile in $pathsOfMessageFilesToProcess){
        write-information "working on $pathOfMessageFile"
        
        if($false){
            $message = $outlook.CreateItemFromTemplate($pathOfMessageFile)
            write-information ('$message.Attachments.Count: ' + $message.Attachments.Count)
            
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

                write-information ('$attachedFile.Filename: ' + $attachedFile.Filename )
                # write-information ('$pathOfStagedFile: ' + $pathOfStagedFile )
                write-information ('$pathOfDestinationFile: ' + $pathOfDestinationFile )
                # write-information ('$hashOfAttachedFile: ' + $hashOfAttachedFile )
            }
        }

        $pathOfExpandedArchiveDirectory = $(expandArchiveFile $pathOfMessageFile)
        <# we assume that expandArchiveFile invokes 7zip, and that 7zip uses the edecoder plugin #>

        <#  the edecoder plugin for 7zip does not quite treat the message file
            like an archive file containing exactly the attached files. Rather,
            some other files appear in the archive file,  and the folder
            structure within the archive file is slightly different for a .msg
            message file than for a .eml message file.  Hence, we have to do
            some tests below to  handle the different cases, and at the moment
            (2026-04-18-1029), we are not bothering to filter  out the files in
            the archive that are not strictly attached files (things like html
            images,  etc.).

            For an .msg file, the edecoder plugin sees the msg fdile as an
            archive file containing, in its root, a .eml file and a  folder
            named "Attachments".  That "Attachments" folder contains the
            attached files.  That .eml file seems to be a .eml version of the
            message.  We might convert the .msg file into an .eml file (by
            getting the .eml file that edecoder extracts from the .msg file),
            and then operate on exclusively  .eml files for the final extraction
            of attached files.  However, I think there might be some benefit to
            treating .msg files specially and looking in the Attachments folder;
            this might filter out some of the cruft files that are not true
            attached files.

        #>

        $pathsOfAttachedFiles = @(
            if(test-path -literalpath (join-path $pathOfExpandedArchiveDirectory "Attachments") -pathtype:Container){
                <# in this case, we are dealing with a .msg file. #>
                gci -force -file -literalpath (join-path $pathOfExpandedArchiveDirectory "Attachments") 
            } else {
                gci -force -file -literalpath $pathOfExpandedArchiveDirectory
            }
        )

        foreach ($pathOfStagedFile  in $pathsOfAttachedFiles){
            ## copy-item -force -literalpath $pathOfStagedFile -destination $pathOfDestinationFolder



            if($appendHashToOutputFileNames) {
                $filenameOfDestinationFile = (split-path -leaf (getStronglyNamedPath $pathOfStagedFile)) 
            } else {
                $filenameOfDestinationFile = Split-Path -Leaf -Path $pathOfStagedFile
            }

            $pathOfDestinationFile = (Join-Path $pathOfDestinationFolder $filenameOfDestinationFile)
            

            #make the destination folder if it does not already exist
            New-Item -ItemType directory -Path (Split-Path -Path $pathOfDestinationFile -Parent) -ErrorAction SilentlyContinue | out-null
            Move-Item -force -Path $pathOfStagedFile -Destination $pathOfDestinationFile | out-null

            # write-information ('$pathOfStagedFile: ' + $pathOfStagedFile )
            write-information ('$pathOfDestinationFile: ' + $pathOfDestinationFile )
        }
    }

    return $pathOfDestinationFolder
}

<#
    2024-03-24: renamed "dump-attachemnts" to "expand-attachments" in order to
    get rid of the nonstandard verb "dump".

    We now add the alias dump-attachments for backward compatibility.

    Curiously, Powershell does not seem to mind having an alias with a
    non-standard verb.
#>
set-alias dump-attachments Expand-Attachments
