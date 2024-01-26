#!pwsh
import-module (join-path $psScriptRoot "utility.psm1")
function dump-attachments {
    # Look at all .msg files in the "source folder"
    # for each, dump attached files into the "destination folder", renaming as needed for unique names.
    # actually, we are doing hash-based naming to ensure just as much uniqueness as we need.
    # we regard two attached files as "the same" iff. they have the same filename and the same hash.

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