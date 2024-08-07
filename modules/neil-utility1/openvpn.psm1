

function Connect-OpenVpn {

    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string] $bitwardenItemId
    )


    if($false){# to enusre latest installed verison of OpenVPN client is installed, and commands are on the path:
        .{# (ensure we have the latest version of OpenVPN client installed):
            Install-WingetPackage -Source winget -Id OpenVPNTechnologies.OpenVPN 
            
            @(
                (join-path $env:ProgramFiles "OpenVPN/bin/openvpn.exe")
                (join-path $env:ProgramFiles "OpenVPN/bin/openvpn-gui.exe")
            ) |
            %{
                & "${env:ChocolateyInstall}/tools/shimgen.exe" @(
                    "--path"; $_
                    "--output"; (join-path "${env:ChocolateyInstall}/bin" (split-path -leaf $_ ))
                )
            } 
        } 
    } 
    


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

    $pathOfUsernamePasswordFile = join-path $pathOfTemporaryConfigurationDirectory "username_password"
    
    Set-Content -Path $pathOfUsernamePasswordFile  -Value (@(
        $bitwardenItem.login.username
        $bitwardenItem.login.password
    ) -join "`n")

    
    ## Set-Content -Path $tempPathOfOvpnConfigurationFile -Value $contentOfAttachedFile
    
    Set-Content -Path $tempPathOfOvpnConfigurationFile -Value (@(
        $contentOfAttachedFile -split "`n" |? {-not ($_ -match "^auth-user-pass\b")}
        "auth-user-pass `"$(
            ##$pathOfUsernamePasswordFile -replace "\\","\\"
            $pathOfUsernamePasswordFile -replace "\\","/"
            
        )`""
    ) -join "`n")

    $sha256HashOfOvpnConfigurationFile = Get-FileHash -Algorithm SHA256 -Path $tempPathOfOvpnConfigurationFile | % {$_.Hash.ToLower()}

    $pathOfOvpnConfigurationFile =  join-path $pathOfTemporaryConfigurationDirectory "$($sha256HashOfOvpnConfigurationFile).ovpn"
    Move-Item $tempPathOfOvpnConfigurationFile $pathOfOvpnConfigurationFile
    
    

    write-host "pathOfOvpnConfigurationFile: $($pathOfOvpnConfigurationFile)"

    ##openvpn --config $pathOfOvpnConfigurationFile --client --auth-user-pass $pathOfUsernamePasswordFile

    openvpn-gui @(
        ##"--connect" ; $pathOfOvpnConfigurationFile

        "--config_dir"; (split-path -parent $pathOfOvpnConfigurationFile)
        "--connect" ; (split-path -leaf $pathOfOvpnConfigurationFile)
        
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


}