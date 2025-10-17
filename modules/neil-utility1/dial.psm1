
<# define a dial function replacement that works with my new polycom phone (temporary hack, eventually to be integrated into my powershell utility module) #>

<# TODO: memoize the initialization of the REST parameters (retrievel of
credentials from Bitwarden, etc.), so we don't have to wait  for it every timne
we load the module. #>

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

    function samplePhoneConfigSet([string] $name, [string] $value){
        $succeeded = $false
        foreach($credential in $candidateCredentialsForSamplePhoneRestApi){
            # Write-Host "trying credential"
            $restApiParameters = $restApiCommonParameters.Clone()
            $restApiParameters['Credential'] = $credential
            $response = $null
            $response = @{
                Method="POST"
                Uri = "$restApiRootUrlOfSamplePhone/api/v1/mgmt/config/set"
                Body = ConvertTo-JSON @{
                    data=@{
                        $name = $value
                    }
                }
            } | % {Invoke-WebRequest @restApiParameters @_  -ErrorAction SilentlyContinue 2>$null} -ErrorAction SilentlyContinue 2>$null

            if(
                $response -and
                ($response.StatusCode -eq 200)
            ){
                $succeeded = $True
                # Write-Host "success"
                .{
                    $response |
                        select -expand Content |
                        convertfrom-json |
                        write-host
                }
                break
            } else {
                # Write-Host "failure"
                # $response
            }
        }
        if(-not $succeeded){Write-Host "failed"; Write-Host $response}
    }

    function samplePhoneConfigGet([string] $name){
        $succeeded = $false
        foreach($credential in $candidateCredentialsForSamplePhoneRestApi){
            # Write-Host "trying credential"
            $restApiParameters = $restApiCommonParameters.Clone()
            $restApiParameters['Credential'] = $credential
            $response = $null
            $response = @{
                Method="POST"
                Uri = "$restApiRootUrlOfSamplePhone/api/v1/mgmt/config/get"
                Body = ConvertTo-JSON @{
                    data=@(
                        $name
                    )
                }
            } | % {Invoke-WebRequest @restApiParameters @_  -ErrorAction SilentlyContinue 2>$null} -ErrorAction SilentlyContinue 2>$null

            if(
                $response -and
                ($response.StatusCode -eq 200)
            ){
                $succeeded = $True
                # Write-Host "success"
                .{
                    $response |
                        select -expand Content |
                        convertfrom-json |
                        select -expand data |
                        select -expand $name |
                        # select -expand Content |
                        write-output
                }
                break
            } else {
                # Write-Host "failure"
                # $response
            }
        }

        if(-not $succeeded){Write-Host "failed"; Write-Host $response}

    }

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

Export-ModuleMember -function dial
Export-ModuleMember -function Get-PolycomPhoneRestApiParameters