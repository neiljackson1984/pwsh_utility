#!powershell

## function enable-ipv6(){set-ipv6 $true}
## function disable-ipv6(){set-ipv6 $false}

function Enable-IPv6    {set-ipversion -ipversion 6 -desiredToBeEnabled $true   }
function Disable-IPv6   {set-ipversion -ipversion 6 -desiredToBeEnabled $false  }

function Enable-IPv4    {set-ipversion -ipversion 4 -desiredToBeEnabled $true   }
function Disable-IPv4   {set-ipversion -ipversion 4 -desiredToBeEnabled $false  }


function set-ipversion(){
    [CmdletBinding()]
    
    param (
        [Parameter()]
        [ValidateSet(4,6)]
        [int] $ipVersion,

        [Parameter()]
        [Bool] $desiredToBeEnabled
    )

    <#
        `Disable-NetAdapterBinding  -ComponentID ms_tcpip6 -Name *`  and
        `Eanble-NetAdapterBinding  -ComponentID ms_tcpip6 -Name *` work and a re
        abit faster than my approach, but do not provide the same output telling
        you the initial and final states for each adapter.
    #>

    $componentId = @{
        4 = 'ms_tcpip'
        6 = 'ms_tcpip6'
    }[$ipVersion]

    foreach ($netAdapter in (Get-NetAdapter))
    {
        $initialState = ($netAdapter | Get-NetAdapterBinding -ComponentID $componentId).Enabled
        
        if($desiredToBeEnabled){
            $netAdapter | Enable-NetAdapterBinding  -ComponentID $componentId
        } else {
            $netAdapter | Disable-NetAdapterBinding  -ComponentID $componentId
        } 

        $finalState = ($netAdapter | Get-NetAdapterBinding  -ComponentID $componentId).Enabled

        Write-Host "$($netAdapter.name) $($componentId): $initialState --> $finalState"
    }
}


Export-ModuleMember -function Enable-IPv6
Export-ModuleMember -function Disable-IPv6
Export-ModuleMember -function Enable-IPv4
Export-ModuleMember -function Disable-IPv4
## Export-ModuleMember -function set-ipv6

