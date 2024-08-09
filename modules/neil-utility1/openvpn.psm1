


function Install-OpenVpnDependencies {
    <# 
        .SYNOPSIS
        Ensures we have the latest verison of the OpenVPN client installed, and
        that relevant commands are on the path: 

        Depends on winget and chocolatey

        It might be useful to have multiple OepnVPN virtual network adapters
        (generally necessary if you want one client computer to connect to
        multiple servers simultaneously.

        To create a new tap adapter, run `tapctl create`.  To create a new
        wintun adapter, run `tapctl  create --hwid wintun`.

        To delete all openvpn virtual adapters, run 
        ```
        tapctl list | % {tapctl delete @($_  -split "\s+")[0]}
        ```
        .

        To create one of each of the three types of virtual adapters, run:
        ```
        "root\tap0901","wintun","ovpn-dco" |% {tapctl create --hwid $_}
        ```
        .



    #>
    
    Install-WingetPackage -Source winget -Id OpenVPNTechnologies.OpenVPN -Mode Silent
    
    @(
        (join-path $env:ProgramFiles "OpenVPN/bin/openvpn.exe")
        (join-path $env:ProgramFiles "OpenVPN/bin/openvpn-gui.exe")
        (join-path $env:ProgramFiles "OpenVPN/bin/tapctl.exe")
    ) |
    %{
        & "${env:ChocolateyInstall}/tools/shimgen.exe" @(
            "--path"; $_
            "--output"; (join-path "${env:ChocolateyInstall}/bin" (split-path -leaf $_ ))
        )
    } 

    <# 

        Needs OpenVPN .

        Needs OpenVPNClient (https://www.powershellgallery.com/packages/OpenVPNClient/0.0.8)

        Install-PSResource OpenVPNClient

        2024-08-08-1201: actually we are not using OpenVPNClient after all.

    #>
    ## Install-PSResource -Name OpenVPNClient -Repository PSGallery 
}

function Connect-OpenVpn {

    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string] $bitwardenItemId
    )



    
    $pathOfOpenVpnGuiConfigurationDirectory = (join-path (resolve-path  "~") "OpenVPN/config")

    $bitwardenItem = Get-BitwardenItem $bitwardenItemId
    $bitwardenAttachment = $(
        $bitwardenItem.attachments | 
        ? {[System.IO.Path]::GetExtension($_.fileName) -eq ".ovpn"} | 
        select -first 1
    )

    $contentOfAttachedFile = $(   
        $bitwardenAttachment |
        % {

            $process = New-Object "System.Diagnostics.Process" -Property @{
                StartInfo = (
                    @{
                        TypeName = "System.Diagnostics.ProcessStartInfo"
                        ArgumentList = @(
                            (Get-Command bw).Path
                            ,@(
                                "--raw" 
                                "get"; "attachment"; $_.fileName
                                "--itemid"; $bitwardenItem.id
                            )
                        )
                        Property = @{
                            RedirectStandardOutput = $True
                        }
                    } | % { New-Object @_} 
                )
            }

            $process.Start() | Out-Null
            # $process.WaitForExit() | Out-Null
            $process.StandardOutput.ReadToEnd()
        }
    )

    $pathOfTemporaryConfigurationDirectory = new-temporaryDirectory
    ##write-host "contentOfAttachedFile: $($contentOfAttachedFile)"
    $tempPathOfOvpnConfigurationFile = join-path $env:temp "$(new-guid).ovpn"



    
    ## Set-Content -Path $tempPathOfOvpnConfigurationFile -Value $contentOfAttachedFile
    
    Set-Content -Path $tempPathOfOvpnConfigurationFile -Value $(
        ## $contentOfAttachedFile
    
        ## @(
        ##     $contentOfAttachedFile -split "`n" |? {-not ($_ -match "^auth-user-pass\b")}
        ##
        ##      $pathOfUsernamePasswordFile = join-path $pathOfTemporaryConfigurationDirectory "username_password"
        ##      Set-Content -Path $pathOfUsernamePasswordFile  -Value (@(
        ##          $bitwardenItem.login.username
        ##          $bitwardenItem.login.password
        ##      ) -join "`n")
        ##
        ##     "auth-user-pass `"$(
        ##         ##$pathOfUsernamePasswordFile -replace "\\","\\"
        ##         $pathOfUsernamePasswordFile -replace "\\","/"
        ##         
        ##     )`""
        ## ) -join "`n"

        @(
            
        
            $contentOfAttachedFile 

            "<auth-user-pass>"
            $bitwardenItem.login.username
            $bitwardenItem.login.password
            "</auth-user-pass>"

            ## "windows-driver wintun"
            ##"windows-driver ovpn-dco"
            ##"allow-compression no"

        ) -join "`n"
    )

    $sha256HashOfOvpnConfigurationFile = Get-FileHash -Algorithm SHA256 -Path $tempPathOfOvpnConfigurationFile | % {$_.Hash.ToLower()}
    $desiredFilenameOfOpenVpnConfigurationFile = "$($sha256HashOfOvpnConfigurationFile).ovpn"
    $desiredFilenameOfOpenVpnConfigurationFile = "$($bitwardenAttachment.fileName)--$($sha256HashOfOvpnConfigurationFile).ovpn"
    

    ##$pathOfOvpnConfigurationFile =  join-path $pathOfTemporaryConfigurationDirectory $desiredFilenameOfOpenVpnConfigurationFile
    $pathOfOvpnConfigurationFile =  join-path $pathOfOpenVpnGuiConfigurationDirectory $desiredFilenameOfOpenVpnConfigurationFile
    
    NEw-Item -ItemType Directory -force -path (split-path -parent $pathOfOvpnConfigurationFile) | out-null
    Move-Item -force  $tempPathOfOvpnConfigurationFile $pathOfOvpnConfigurationFile
    
    

    write-host "pathOfOvpnConfigurationFile: $($pathOfOvpnConfigurationFile)"



    ##openvpn --config $pathOfOvpnConfigurationFile --client --auth-user-pass $pathOfUsernamePasswordFile
    ##openvpn-gui 
    # ensure that openvpn-gui is running, so that the below command will not block.
    ##openvpn-gui @("--command";"connect";"bogusbogusbogus")

    ##start-sleep 30
    ##openvpn-gui @("--command"; "status"; (split-path -leaf $pathOfOvpnConfigurationFile))
    


    ## openvpn-gui @("--command"; "import"; "$($pathOfOvpnConfigurationFile)")

    <# For reasons that I have, as of 2024-08-08-1709, yet to understand, in the
        case where some other OpenVPN-gui-controlled OpenVPN connection is
        already connected and where the file that we just put into the openvpn
        config directory did not previously exist, the below call to
        `openvpn-gui --command connect` has no effect.  It is as if openvpn-gui
        needs some kick (and merely waiting 30 seconds seems to be insufficient)
        in order to realize that this newly-created file exists.
    #>
    openvpn-gui @(
        ##"--connect" ; $pathOfOvpnConfigurationFile

        ## "--config_dir"; (split-path -parent $pathOfOvpnConfigurationFile)
        ## "--connect" ; (split-path -leaf $pathOfOvpnConfigurationFile)

        "--command"; "connect"; (split-path -leaf $pathOfOvpnConfigurationFile)
    )
    


    write-host "finished invoking openvpn-gui."

    # see (https://openvpn.net/community-resources/)
    #
    # see (https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/)

    # see (https://github.com/OpenVPN/openvpn-gui)

    
}

function Disconnect-OpenVpnAllConnections {
    <#
    .SYNOPSIS
    Disconnects all existing OpenVPN connections
    #>
    
    [CmdletBinding()]
    [OutputType([void])]
    Param(
    )


    openvpn-gui --command "disconnect_all" ;  start-sleep 20; openvpn-gui --command "exit"   

    ## get-process "openvpn","openvpn-gui" |% {taskkill /t /f /PID $_.id}
    

}