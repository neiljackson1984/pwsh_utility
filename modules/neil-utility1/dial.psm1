
<# define a dial function replacement that works with my new polycom phone (temporary hack, eventually to be integrated into my powershell utility module) #>

<# TODO (DONE 2025-10-17-1525): memoize the initialization of the REST parameters (retrievel of
credentials from Bitwarden, etc.), so we don't have to wait  for it every timne
we load the module. #>

<# see (https://docs.poly.com/bundle/voice-rest-api-reference-manual-current/page/rest-api-commands-and-structure.html) #>

$bitwardenItemIdOfNeilDeskphone = 'c63c4108-b859-45f7-b4a8-b36b0182cfa7'

$script:polycomPhoneRestApiParameters = $null
function Get-PolycomPhoneRestApiParameters {
    [CmdletBinding()]
    [OutputType([HashTable])]
    param(

    )

    if(-not $polycomPhoneRestApiParameters){
        write-information "constructing polycomPhoneRestApiCommonParameters"
        $bitwardenItem = get-bitwardenitem $bitwardenItemIdOfNeilDeskphone


        # define $restApiCommonParameters, which we will use for testing
        # the username for the rest api is "Polycom"
        # this is the url of the web admin interface for our sample phone:

        ## $macAddressOfPhone = $(getFieldMapFromBitwardenItem $bitwardenItem.id).mac_address

        ##$webAdminUrl = "https://phone$macAddressOfPhone.ad.autoscaninc.com"
        $webAdminUrl = $bitwardenItem.login.uris[0].uri
        # this is the url of the web admin interface for our phone:

        $restApiUsername = "Polycom"
        $restApiPassword = $bitwardenItem.login.password

        $script:polycomPhoneRestApiParameters  = @{
            rootUrl  = "$webAdminUrl"
            commonRequestParameters = @{
                Credential = New-Object System.Management.Automation.PSCredential @(
                    <# string username #>
                    $restApiUsername

                    <# secureString password #>
                    (ConvertTo-SecureString $restApiPassword -AsPlainText -Force)
                )
                ContentType = "application/json"
                SkipCertificateCheck = $True
            }

        }
    }

    return $script:polycomPhoneRestApiParameters 
}

if($false){   


    function factoryResetSamplePhone{
        $succeeded = $false
        foreach($credential in $candidateCredentialsForSamplePhoneRestApi){
            # this command relies on the restapi being enabled.  You might have
            # to use the phone's web admin gui (reachable at $webAdminUrlOfSamplePhone) to
            # enable the rest api.

            Write-Host "trying credential"

            $restApiParameters = $restApiCommonParameters.Clone()
            $restApiParameters['Credential'] = $credential

            $response = $null
            $response = @{
                Method = "POST"
                Uri = "$restApiRootUrlOfSamplePhone/api/v1/mgmt/factoryReset"

            } |% {Invoke-WebRequest @restApiParameters @_ -ErrorAction SilentlyContinue 2>$null} -ErrorAction SilentlyContinue 2>$null

            if(
                $response -and
                (ConvertFrom-Json $response.Content) -and
                ((ConvertFrom-Json $response.Content).Status -ceq "2000")
            ){
                $succeeded = $true
                Write-Host "success"
                (ConvertFrom-Json $response.Content)
                break
            } else {
                # Write-Host "failure"
            }
        }
        if(-not $succeeded){
            Write-Host "failed"
            Write-Host $response
        }
    }

        
    function dial_deprecated1 {
        param(
            [string] $digits,
            [switch] $initial = $false
        )


        $commonRequestParameters = (Get-PolycomPhoneRestApiParameters).commonRequestParameters

        if($initial){
            (Invoke-WebRequest @commonRequestParameters -Method POST -Uri "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/callctrl/dial" -Body (ConvertTo-JSON @{data=@{Dest=$digits}}) ).Content | write-information
        }  else {
            (Invoke-WebRequest @commonRequestParameters -Method POST -Uri "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/callctrl/sendDTMF" -Body (ConvertTo-JSON @{data=@{Digits=$digits}}) ).Content | write-information

        }
    }

}

function Set-PolycomPhoneConfiguration {
    [CmdletBinding()]
    param(
        [string] $name, 
        [string] $value
    )
    $commonRequestParameters = (Get-PolycomPhoneRestApiParameters).commonRequestParameters

    $succeeded = $false



    $response = $null
    $response = @{
        Method="POST"
        Uri = "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/mgmt/config/set"
        Body = ConvertTo-JSON @{
            data=@{
                $name = $value
            }
        }
    } | % {Invoke-WebRequest @commonRequestParameters @_  -ErrorAction SilentlyContinue 2>$null} -ErrorAction SilentlyContinue 2>$null

    if(
        $response -and
        ($response.StatusCode -eq 200)
    ){
        $succeeded = $True
    }


    if($succeeded){
        $response |
        select -expand Content |
        convertfrom-json |
        write-output
    } else {
        write-information "failed"; write-information $response
    }
}

function Get-PolycomPhoneConfiguration {
    [CmdletBinding()]
    param(
        [string] $name
    )
    $commonRequestParameters = (Get-PolycomPhoneRestApiParameters).commonRequestParameters
    
    $succeeded = $false



    $response = $null
    $response = @{
        Method="POST"
        Uri = "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/mgmt/config/get"
        Body = ConvertTo-JSON @{
            data=@(
                $name
            )
        }
    } | % {Invoke-WebRequest @commonRequestParameters @_  -ErrorAction SilentlyContinue 2>$null} -ErrorAction SilentlyContinue 2>$null

    if(
        $response -and
        ($response.StatusCode -eq 200) 
    ){
        $succeeded = $True
    } 

    if($succeeded){
        $content = $(
            $response.Content |
            convertfrom-json -AsHashTable
        )

        if($content.ContainsKey('data') -and $($content['data'].ContainsKey($name))){
            write-output ([pscustomobject] $content['data'][$name])
        } else {
            write-warning "expected key '$($name)' is absent"
            write-information $response
        }

    } else {
        write-error "failed"; write-information $response
    }
}


function dial {
    [CmdletBinding()]
    param(
        [string] $digits
    )

    $commonRequestParameters = (Get-PolycomPhoneRestApiParameters).commonRequestParameters

    $state = $(
        @{
            Method="GET" 
            Uri = "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/mgmt/pollForStatus" 
        } | % {Invoke-WebRequest @commonRequestParameters @_} |
        select -expand Content |
        ConvertFrom-Json -depth 50 |
        % data | % State
    )

    write-information "$(get-date): state: $($state). dialing '$($digits)'"

    if($state -eq "Active"){
        (Invoke-WebRequest @commonRequestParameters -Method POST -Uri "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/callctrl/sendDTMF" -Body (ConvertTo-JSON @{data=@{Digits=$digits}}) ).Content | write-information

    } else {
        (Invoke-WebRequest @commonRequestParameters -Method POST -Uri "$((Get-PolycomPhoneRestApiParameters).rootUrl)/api/v1/callctrl/dial" -Body (ConvertTo-JSON @{data=@{Dest=$digits}}) ).Content | write-information
    } 
}

Export-ModuleMember -function @(
    'dial'
    'Get-PolycomPhoneRestApiParameters'
    'Get-PolycomPhoneConfiguration'
    'Set-PolycomPhoneConfiguration'
)