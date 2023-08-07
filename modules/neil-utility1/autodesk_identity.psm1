
Import-Module (join-path $psScriptRoot "utility.psm1")
Import-Module (join-path $psScriptRoot "connect_to_office_365.psm1")
function Set-ActiveAutodeskIdentity {
    <#
        .DESCRIPTION
        Controls which named "profile" is actively logged in to the Autodesk .
        The names are arbitrary and only meaningful to this function.  If a
        profile does not exist, it will be created.  We are not interacting in
        any intelligent way with the Autodesk identity system -- merely moving
        folders around in the filesystem, with the necessary killing of
        handle-holding processes before doing the folder moving and restarting
        of those processes after the folders have been moved.

        This function will unceremoniously kill most running Autodesk processes.
    #>
        
    [CmdletBinding()]
    [OutputType([Void])]
    Param(
        [Parameter(
            Position=0
        )]
        [String] $identity = ""
    )

    $pathOfAutodeskAppdataFolder        = (join-path $env:localappdata "Autodesk")
    $pathOfLogFile                      = (join-path $pathOfAutodeskAppdataFolder "identity_swap.log")
    $pathOfIdentitiesRepositoryFolder   = (join-path $pathOfAutodeskAppdataFolder "identity_repository")
    $pathOfIdentityFolder               = (join-path $pathOfIdentitiesRepositoryFolder $identity)
    
    
    # $pathOfActiveWebServicesFolder      = (join-path $pathOfAutodeskAppdataFolder "Web Services")
    
    $pathsOfFoldersConstitutingTheActiveIdentity = @(
        (join-path $pathOfAutodeskAppdataFolder "Web Services")
        (join-path $pathOfAutodeskAppdataFolder "Identity Services")
    )
    
    
    
    $pathOfIdentityFile                 = (join-path $pathOfIdentitiesRepositoryFolder "identity.json")
    $robocopyOptions=@(
        "/S"
        # copy subfolders

        "/E" 
        # copy empty subfolders

        "/MOVE" 
        
        "/R:3" 
        # retry 3 times

        "/W:3" 
        # wait 3 seconds between retries

        "/MIR" 
        # mirror - equivalent to /PURGE plus all subfolders (/E)

        "/XF"; "*.log"; "*.log.lock";
        # /XF - exclude files

        "/XD"; "Log" ;
        # /XD - exclude directories
        
        # /NJS /NJH /NDL /NFL /NP -- suppress the output report
    )



    $existingIdentity = $(
        if(Test-Path -PathType Leaf -LiteralPath $pathOfIdentityFile){
            Get-Content -Raw $pathOfIdentityFile | ConvertFrom-Json
        }else{
            $null
        } 
    )  

    if( $existingIdentity -eq $identity ){
        Write-Host "Autodesk identity is already `"$($identity)`".  No need to swap."
    } else {
        Write-Host "Changing Autodesk identity from `"$($existingIdentity)`" $( if(-not $existingIdentity){", which is falsey, "}else{''} ) to `"$($identity)`"."

        #ensure that the identities repository folder exists
        New-Item -ItemType "directory" -Path $pathOfIdentitiesRepositoryFolder -Force | Out-Null

        # ensure that a named folder within the identities repository exists for
        # $identity, creating such a folder from scratch if needed.
        if(-not (Test-Path -PathType Container -LiteralPath $pathOfIdentityFolder)){
            New-Item -ItemType "directory" -Path $pathOfIdentityFolder -Force  | Out-Null
        }

        & { # kill potentially-open autodesk processes.
            # net stop "Autodesk Access Service Host"      2>&1  | Out-Null                                    
            # net stop AdAppMgrSvc                         2>&1  | Out-Null                           
            # net stop AdAppMgrSvc                         2>&1 | Out-Null                           
            # net stop AdskLicensingService                2>&1  | Out-Null                                    
            # net stop AdskLicensingService                2>&1  | Out-Null                                    

            # taskkill /f /t /im AutodeskDesktopApp.exe    2>&1  | Out-Null                                                
            # taskkill /f /t /im AdskAccessUIHost.exe      2>&1  | Out-Null                                                
            # taskkill /f /t /im AdskAccessCore.exe        2>&1  | Out-Null                                                
            # taskkill /f /t /im AdskIdentityManager.exe   2>&1  | Out-Null                                                
            # taskkill /f /im AdAppMgrSvc.exe              2>&1  | Out-Null                                      
            # taskkill /f /im AdskLicensingService.exe     2>&1  | Out-Null                                               
            # taskkill /f /im AutodeskDesktopApp.exe       2>&1  | Out-Null                                             
            # taskkill /f /im AdAppMgrSvc.exe              2>&1  | Out-Null                                      
            # taskkill /f /im AdskLicensingService.exe     2>&1  | Out-Null                                               
            # taskkill /f /im AdSSO.exe                    2>&1  | Out-Null                                
            # taskkill /f /im ADPClientService.exe         2>&1  | Out-Null    
            
                        
            $namesOfServicesToKill = @(
                "AdAppMgrSvc"
                "AdskLicensingService"
                "AdskLicensingAgent"
                "AdskAccessServiceHost"
                "Autodesk Access Service Host"
            )
            $namesOfProcessesToKill = @(
                "revit"
                "autodeskaccess"
                "AdskAccessCore"
                "AdskAccessServiceHost"
                "AdskIdentityManager"
                "AdskLicensingService"
                "AdSSO"
                "ADPClientService"
                "AdskAccessUIHost"
                "AdAppMgrSvc"
            )
            $namesOfServicesToKill  | % {Stop-Service -Name $_ -confirm:$false -force:$true -ErrorAction SilentlyContinue}
            $namesOfProcessesToKill | % {Stop-Process -Name $_ -confirm:$false -force:$true -ErrorAction SilentlyContinue}
            $namesOfServicesToKill  | % {Stop-Service -Name $_ -confirm:$false -force:$true -ErrorAction SilentlyContinue}
            $namesOfProcessesToKill | % {Stop-Process -Name $_ -confirm:$false -force:$true -ErrorAction SilentlyContinue}




        }
        

        if($existingIdentity) {
            # in this case, the existing identity is named, so we will move it "back" to its named repository folder
            
            $pathOfIdentityFolderForExistingIdentity = (join-path $pathOfIdentitiesRepositoryFolder $existingIdentity)
            if(-not (Test-Path -PathType Container -LiteralPath $pathOfIdentityFolderForExistingIdentity)){
                New-Item -ItemType "directory" -Path $pathOfIdentityFolderForExistingIdentity -Force  | Out-Null
            }

            Write-Host "Stashing existing identity '$existingIdentity' to '$pathOfIdentityFolderForExistingIdentity'."
            
            foreach($pathOfFolderConstitutingTheActiveIdentity in $pathsOfFoldersConstitutingTheActiveIdentity){              
                robocopy @(
                    #source: 
                    "$pathOfFolderConstitutingTheActiveIdentity"
                    

                    #destination:
                    # "$(join-path $pathOfIdentityFolderForExistingIdentity (split-path  -Path $pathOfActiveWebServicesFolder -leaf ))"
                    "$(join-path $pathOfIdentityFolderForExistingIdentity (
                        [System.IO.Path]::GetRelativePath([System.IO.Path]::GetPathRoot($pathOfFolderConstitutingTheActiveIdentity),$pathOfFolderConstitutingTheActiveIdentity)
                    ))"

                    $robocopyOptions
                )
            }
        } else {
            # in this case the active identity is not named, so we will delete it
            Write-Host "deleting the currently-active (unnamed) profile".
            foreach($pathOfFolderConstitutingTheActiveIdentity in $pathsOfFoldersConstitutingTheActiveIdentity){
                Get-ChildItem -LiteralPath $pathOfFolderConstitutingTheActiveIdentity -ErrorAction SilentlyContinue |
                    Remove-Item -Force -Recurse -Confirm:$false -ErrorAction:"Continue"
            }
        }

        Write-Host "restoring the profile '$identity' from '$pathOfIdentityFolder'."
        foreach($pathOfFolderConstitutingTheActiveIdentity in $pathsOfFoldersConstitutingTheActiveIdentity){
            robocopy @(
                #source :
                (join-path $pathOfIdentityFolder ([System.IO.Path]::GetRelativePath(
                    [System.IO.Path]::GetPathRoot($pathOfFolderConstitutingTheActiveIdentity),
                    $pathOfFolderConstitutingTheActiveIdentity
                )))

                #destination:
                $pathOfFolderConstitutingTheActiveIdentity

                $robocopyOptions
            )
        }

        #todo: error handling -- the above moves might fail.

        Set-Content -NoNewLine -LiteralPath $pathOfIdentityFile -Value ($identity | ConvertTo-Json -Depth 50) 

        #restart some of the services that we killed above
                
        Start-Service AdAppMgrSvc -ErrorAction SilentlyContinue
        # "Autodesk Desktop App Service"

        Start-Service AdskLicensingService -ErrorAction SilentlyContinue
        # "Autodesk Desktop Licensing Service"


        # start-process "C:\Program Files (x86)\Autodesk\Autodesk Desktop App\AutodeskDesktopApp.exe" 
        # only for testing, so we can confirm by eyeball that the swap has succeeded.
    }
}




function Get-ActiveAutodeskIdentity {
        
    [CmdletBinding()]
    [OutputType([String])]
    Param(
       
    )

    $pathOfAutodeskAppdataFolder        = (join-path $env:localappdata "Autodesk")
    $pathOfIdentitiesRepositoryFolder   = (join-path $pathOfAutodeskAppdataFolder "identity_repository")
    $pathOfIdentityFile                 = (join-path $pathOfIdentitiesRepositoryFolder "identity.json")
    # TODO: make these definitions central rather than redefining them here (this (happens to) duplicates the definitions in Set-AutodeskIdentity)


    $existingIdentity = $(
        if(Test-Path -PathType Leaf -LiteralPath $pathOfIdentityFile){
            Get-Content -Raw $pathOfIdentityFile | ConvertFrom-Json
        }else{
            $null
        } 
    )  

    return $existingIdentity
   
}

