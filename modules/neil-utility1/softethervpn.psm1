
Import-Module (join-path $psScriptRoot "utility.psm1")

set-alias  connectVpn Connect-SoftEtherVpn
function Connect-SoftEtherVpn {
    <#
    .SYNOPSIS
    Ensures that we are connected to the specified softether vpn connection.
    Currently, we are specifying the softether vpn connection only by name, and
    relying on an entry of that name existing and being correctly configured.

    # .DESCRIPTION
    # Long description

    # .PARAMETER bitwardenItemIdOfCompanyParameters
    # Parameter description

    # .PARAMETER HostName
    # Parameter description

    # .EXAMPLE
    # An example

    # .NOTES
    # General notes
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(
            Mandatory=$True
        )]
        [String] 
        $nameOfSoftetherVpnConnection
    )

        
    $trialDuration = New-Timespan -Seconds 15
    $giveUpTime = (Get-Date) + $trialDuration
    $attemptsCount = 0
    while(
        (
            (
                Get-Date
            ) -le $giveUpTime
        ) -and
        (
            $(
                vpncmd @(
                    "localhost"
                    "/client"
                    "/cmd", "AccountStatusGet"
                    $nameOfSoftetherVpnConnection
                ) | 
                Out-Null;
                $LASTEXITCODE 
            ) -ne 0
        )
    ) {
        $result = $(
            vpncmd localhost /client  /cmd AccountConnect $nameOfSoftetherVpnConnection | 
                Out-Null

            $LASTEXITCODE 
        )
        $attemptsCount++
        # write-host "result was $($result)."

        if($result -eq 43){
            # error 43 is described thus:
            #
            # Error occurred. (Error code: 43) The Virtual Network Adapter
            # used by the specified VPN Connection Setting is already being
            # used by another VPN Connection Setting. If there is another
            # VPN Connection Setting that is using the same Virtual Network
            # Adapter, disconnect that VPN Connection Setting.

            # Write-Host "disconnecting from all existing softether vpn connections"
            Disconnect-SoftEtherVpnAllConnections

            # we might, alternatively, consider creating a new softether virtual
            # nic and setting the connection to use that nic.
        }

        Start-Sleep 5
    }
    # write-host "attemptsCount: $($attemptsCount)"

}

set-alias  disconnectAllVpnConnections Disconnect-SoftEtherVpnAllConnections
function Disconnect-SoftEtherVpnAllConnections {
    <#
    .SYNOPSIS
    Disconnects all existing Softether VPN connections
    #>
    
    [CmdletBinding()]
    [OutputType([void])]
    Param(
    )

    


    ## vpncmd localhost /client  /cmd AccountList |
    ## % { 
    ##     if($_ -match '^\s*VPN Connection Setting Name\s*\|(.*)$'){
    ##         $Matches[1].Trim()
    ##     }
    ## } |
    ## % { 
    ##     Write-Host "disconnecting from `"$($_)`""
    ##     vpncmd localhost /client  /cmd AccountDisconnect "$($_)" | Out-Null
    ## }


    @( 
        Get-SoftEtherConnectionNames | 
        % {"AccountDisconnect `"$($_)`""}
    ) | vpncmd localhost /client  2>$null | out-null

}

function Get-SoftEtherNicNames {
    <#
    .SYNOPSIS
    gets the names of all existing SoftEther virtual nics.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    vpncmd localhost /client /cmd  NicList | 
    out-string -stream | 
    select-string '(?<=^\s*Virtual Network Adapter Name\s*\|\s*)\b.*\b(?=\s*$)' | 
    % {$_.Matches[0].ToString()}
}

function Get-SoftEtherNextAvailableNicName {
    <#
    .SYNOPSIS
    Gets the next valid softether nic name that is not already assigned to an existing softether nic.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    $allowedNicNames = @(""; 2..127) |% {"VPN$($_)"} 
    $existingNicNames = @(Get-SoftEtherNicNames)
    $nextAvailableNicName = ($allowedNicNames |? {-not ($existingNicNames -contains $_)} | select -first 1)
    return $nextAvailableNicName
}

function Get-SoftEtherNetAdapterFromSoftEtherNicName {
    <#
    .SYNOPSIS
    returns the
    Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter
    object corresponding to the given softetherNicName, or nothing if no such object exists.
    exists.
    #>
    
    [CmdletBinding()]
    # [OutputType([Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter])]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    Param(
        [Parameter(
            Mandatory=$True    
        )]
        [String] 
        $softetherNicName
    )

    $nicGuid = (vpncmd localhost /client /cmd NicGetSetting $softetherNicName | out-string -stream | select-string '(?<=^\s*GUID\s*\|\s*).*(?=\s*$)' | % {$_.Matches[0].ToString()})
    Get-NetAdapter -IncludeHidden |? {$_.InterfaceGuid -eq $nicGuid}
}

function Get-SoftEtherConnectionNames {
    <#
    .SYNOPSIS
    gets the names of all existing SoftEther connections.
    #>
    
    [CmdletBinding()]
    [OutputType([string])]
    Param(
    )

    vpncmd localhost /client /cmd  AccountList | 
    out-string -stream | 
    select-string '(?<=^\s*VPN Connection Setting Name\s*\|\s*)\b.*\b(?=\s*$)' | 
    % {$_.Matches[0].ToString()}
}