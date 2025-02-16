
$pathOfOpenVpnGuiConfigurationDirectory = (join-path (resolve-path  "~") "OpenVPN/config")

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

        Needs OpenVPNClient
        (https://www.powershellgallery.com/packages/OpenVPNClient/0.0.8)

        Install-PSResource OpenVPNClient

        2024-08-08-1201: actually we are not using OpenVPNClient after all (but
        we probably should, or should at least somehow take advantage of OpenVPN's
        named-pipe-based IPC control mechanism.

    #>
    ## Install-PSResource -Name OpenVPNClient -Repository PSGallery 
}

function Connect-OpenVpn {

    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string] $bitwardenItemId
    )



    
    

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

    $tempPathOfOvpnConfigurationFile = join-path $env:temp "$(new-guid).ovpn"

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

            if(($bitwardenItem.login.username) -and ($bitwardenItem.login.password)){
                "<auth-user-pass>"
                $bitwardenItem.login.username
                $bitwardenItem.login.password
                "</auth-user-pass>"
            }

            ## "windows-driver wintun"
            ##"windows-driver ovpn-dco"
            ##"allow-compression no"

        ) -join "`n"
    )

    $sha256HashOfOvpnConfigurationFile = Get-FileHash -Algorithm SHA256 -Path $tempPathOfOvpnConfigurationFile | % {$_.Hash.ToLower()}
    $desiredFilenameOfOpenVpnConfigurationFile = "$($bitwardenAttachment.fileName)--$($sha256HashOfOvpnConfigurationFile).ovpn"
    $pathOfOurOvpnConfigurationFile =  join-path $pathOfOpenVpnGuiConfigurationDirectory $desiredFilenameOfOpenVpnConfigurationFile
    write-host "pathOfOurOvpnConfigurationFile: $($pathOfOurOvpnConfigurationFile)"
    
    $openvpnGuiWasAlreadyRunning = [boolean] $(Get-Process -Name "openvpn-gui" 2>$null)
    $ovpnConfigurationFileAlreadyExisted = (test-path $pathOfOurOvpnConfigurationFile)
    write-host "openvpnGuiWasAlreadyRunning: $($openvpnGuiWasAlreadyRunning)"
    write-host "ovpnConfigurationFileAlreadyExisted: $($ovpnConfigurationFileAlreadyExisted)"

    <#  we regardthe collection of ovpn configuration files in
        $pathOfOpenVpnGuiConfigurationDirectory as being a set of openvpn
        connections that we want to have connected.   If openvpn-gui is not
        running, we regard this set of configuration files as completely stale
        and delete them all before proceeding.  

        This strategy is a bit of a hack to work around the fact that I have no
        (currently usable) way to check which vpn configuration files are
        currently connected, and also to work around the fact that openvpn-gui
        doesn't seem to automatically detect the arrival of a new ovpn
        configuration file in the openvpn configuration directory (it seems that
        openvpn-gui scans for new files only when being launched, and in
        response to certain button clicks in the gui interface.  If we put a new
        ovpn file, xxx.ovpn, into the openvpn configuration directory and then
        immediately run `openvpn-gui --command connect xxx.ovpn`, openvpn-gui
        will not connect, presumably because it does not recognize that such a
        file exists.)
    #>

    if($openvpnGuiWasAlreadyRunning -and (-not $ovpnConfigurationFileAlreadyExisted)){
        <#  openvpn-gui is already running, but does not know about the
            configuration file '$($pathOfOurOvpnConfigurationFile)', so we will
            kill openvpn-gui before proceeding (because that's the only way to
            make openvpn-gui recognize the new configuration file.).

            We assume that all ovpn configuration files currently in the openvpn
            configuration directory are vpn connections that are currently open
            (and which we want to continue to be open when we finish here).
        #>
        
        
        write-host (-join@(
            "openvpn-gui is already running, but does not know about"
            " the configuration file '$($pathOfOurOvpnConfigurationFile)', so"
            " we will kill openvpn-gui before proceeding (because that's the"
            " only way to make openvpn-gui recognize the new configuration file.)"
        ))
        
        openvpn-gui --command "disconnect_all" ;  start-sleep 20; openvpn-gui --command "exit"   ;  start-sleep 3
        "openvpn.exe","openvpn-gui.exe" |% {taskkill /t /f /im $_ 2>$null}
    } 
    
    if(-not $openvpnGuiWasAlreadyRunning){

        write-host (-join@(
            "openvpn-gui is not already running.  We will  delete all"
            " openvpn configuration files before proceeding."
        ))

        gci -force -recurse -file -Path $pathOfOpenVpnGuiConfigurationDirectory -filter "*.ovpn" 2>$null |
        %{
            remove-item -force -Path $_
        }
    }
    New-Item -ItemType Directory -force -path $pathOfOpenVpnGuiConfigurationDirectory | out-null

    New-Item -ItemType Directory -force -path (split-path -parent $pathOfOurOvpnConfigurationFile) | out-null
    Move-Item -force  $tempPathOfOvpnConfigurationFile $pathOfOurOvpnConfigurationFile

    foreach($pathOfOvpnConfigurationFile in  @(
        gci -force -recurse -file -Path $pathOfOpenVpnGuiConfigurationDirectory -filter "*.ovpn"
    )){
        write-host  "now working on '$($pathOfOvpnConfigurationFile)'."
        $openvpnGuiProcess = @{
            Wait         = $false
            FilePath     = "openvpn-gui"
            ArgumentList = @(
                "--command";"silent_connection";"1"
            )
            PassThru = $True
            NoNewWindow = $true

        } |% {Start-Process @_}
        
        $openvpnGuiProcess = @{
            Wait         = $false
            FilePath     = "openvpn-gui"
            ArgumentList = @(
                "--command";"silent_connection";"1"
                "--command";"connect";(split-path -leaf $pathOfOvpnConfigurationFile)
                ##"--connect"; (split-path -leaf $pathOfOvpnConfigurationFile)
            )
            PassThru = $True
            NoNewWindow = $true

        } |% {Start-Process @_}
        write-host "finished invocation of openvpn-gui (process id: $($openvpnGuiProcess.Id))."
    }


    <# For reasons that I have, as of 2024-08-08-1709, yet to understand, in the
        case where some other OpenVPN-gui-controlled OpenVPN connection is
        already connected and where the file that we just put into the openvpn
        config directory did not previously exist, the below call to
        `openvpn-gui --command connect` has no effect.  It is as if openvpn-gui
        needs some kick (and merely waiting 30 seconds seems to be insufficient)
        in order to realize that this newly-created file exists.
    #>
    ## openvpn-gui @(
    ##     ##"--connect" ; $pathOfOurOvpnConfigurationFile
    ## 
    ##     ## "--config_dir"; (split-path -parent $pathOfOurOvpnConfigurationFile)
    ##     ## "--connect" ; (split-path -leaf $pathOfOurOvpnConfigurationFile)
    ## 
    ##     "--command"; "connect"; (split-path -leaf $pathOfOurOvpnConfigurationFile)
    ## )
    

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


    openvpn-gui --command "disconnect_all" ;  start-sleep 20; openvpn-gui --command "exit"   ;  start-sleep 3
    "openvpn.exe","openvpn-gui.exe" |% {taskkill /t /f /im $_ 2>$null}

    write-host (-join@(
        "deleting all"
        " openvpn configuration files."
    ))
    
    gci -force -recurse -file -Path $pathOfOpenVpnGuiConfigurationDirectory -filter "*.ovpn" 2>$null |
    %{
        remove-item -force -Path $_
    }

}

function Get-OpenVpnNetAdapter {
    Get-NetAdapter |
    ? {$_.InterfaceAlias -match "(?i)openvpn"} 
    
    ##  |  ? {$_.Status -eq "Up"}
}