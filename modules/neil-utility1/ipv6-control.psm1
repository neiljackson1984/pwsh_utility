#!powershell

function enable-ipv6(){set-ipv6 $true}
function disable-ipv6(){set-ipv6 $false}

function set-ipv6(){
    param (
        [Parameter()]
        [Bool]$desiredState
    )

    <#
        `Disable-NetAdapterBinding  -ComponentID ms_tcpip6 -Name *`  and
        `Eanble-NetAdapterBinding  -ComponentID ms_tcpip6 -Name *` work and a re
        abit faster than my approach, but do not provide the same output telling
        you the initial and final states for each adapter.
    #>

    foreach ($netAdapter in (Get-NetAdapter))
    {
        $initialState = ($netAdapter | Get-NetAdapterBinding -ComponentID ms_tcpip6).Enabled
        
        if($desiredState){
            $netAdapter | Enable-NetAdapterBinding  -ComponentID ms_tcpip6
        } else {
            $netAdapter | Disable-NetAdapterBinding  -ComponentID ms_tcpip6
        } 

        $finalState = ($netAdapter | Get-NetAdapterBinding  -ComponentID ms_tcpip6).Enabled

        Write-Host "$($netAdapter.name): $initialState --> $finalState"
    }
}


Export-ModuleMember -function enable-ipv6
Export-ModuleMember -function disable-ipv6
Export-ModuleMember -function set-ipv6

