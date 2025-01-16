
<# 2024-07-23-1241:
    It's not great to have these urls hardcoded here, but better here once than a thousand times in various scripts.
#>
## $publicUrlOfMyPubliclyEditableSharepointFolder = "https://autoscaninc-my.sharepoint.com/:f:/p/neil/Es4XlxUoKpNPoQQAVV1RBR0B-E-toUZeyj_lcANK_4McSg"
## $urlOfMyPubliclyEditableSharepointFolder       = "https://autoscaninc-my.sharepoint.com/personal/neil_autoscaninc_com/Documents/Attachments/fa4541d00e6e4ef8b1ade357f0e207e5"
<# I amn hardcoding these urls within the function bodies, which is somewhat bad
practice, in order to make the functions self-contained in order to work with my
naive method of copying fuinction defintions temporarily to remote computers;
M<y naive method does not properyl handle script/module variables. #>


function uploadFileToSpecialPublicSharepointFolder{

    [CmdletBinding()]
    Param(
        [parameter(mandatory=$True)]
        [string] $pathOfSourceFile,

        [parameter(mandatory=$False,HelpMessage="path relative to the publicly-editable sharepoint folder")]
        [string] $pathOfDestinationFile = $null
    )

    $publicUrlOfMyPubliclyEditableSharepointFolder = "https://autoscaninc-my.sharepoint.com/:f:/p/neil/Es4XlxUoKpNPoQQAVV1RBR0B-E-toUZeyj_lcANK_4McSg"
    $urlOfMyPubliclyEditableSharepointFolder       = "https://autoscaninc-my.sharepoint.com/personal/neil_autoscaninc_com/Documents/Attachments/fa4541d00e6e4ef8b1ade357f0e207e5"
    

    $pathOfDestinationFile  = $(
        ## $pathOfDestinationFile ?? (split-path $pathOfSourceFile -leaf)
        <#  We use the equivalent expression below to get rid of the
            "??" to make this code compatible with Windows Powershell 
        #>
    
        @(
            $pathOfDestinationFile
            split-path $pathOfSourceFile -leaf
        ) |
        ?{$_} | 
        select-object -first 1
    )

    
    # hit the $publicUrlOfMyPubliclyEditableSharepointFolder solely for the
    # purpose of collecting the cookies that we will need for the actual
    # uploading:
    $pathOfCookieJarFile = (join-path $env:temp (new-guid))
    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar"; $pathOfCookieJarFile
        "--cookie"; $pathOfCookieJarFile  
        $publicUrlOfMyPubliclyEditableSharepointFolder 
    ) | out-null

    $destinationUrl = (-join @(
        "$($urlOfMyPubliclyEditableSharepointFolder)"
        "/$([System.Web.HttpUtility]::UrlPathEncode($pathOfDestinationFile))"
    ))

    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar";$pathOfCookieJarFile 
        "--cookie"; $pathOfCookieJarFile 
        "--upload-file"; $pathOfSourceFile
        $destinationUrl
    ) | write-host
    $curlExitCode = $lastExitCode
    # todo: deal with illegal filenames.
    Remove-Item $pathOfCookieJarFile | out-null
    if($curlExitCode -eq 0){return $destinationUrl}

    write-warning "curlExitCode ($($curlExitCode)) was non-zero."
    return $null
}

function downloadFileFromSpecialPublicSharepointFolder{
    [CmdletBinding()]
    Param(
        [parameter(mandatory=$True, HelpMessage="path relative to the publicly-editable sharepoint folder")]
        [string] $pathOfSourceFile,

        [parameter(mandatory=$False)]
        [string] $pathOfDestinationFile = $null
    )
    
    
    
    $publicUrlOfMyPubliclyEditableSharepointFolder = "https://autoscaninc-my.sharepoint.com/:f:/p/neil/Es4XlxUoKpNPoQQAVV1RBR0B-E-toUZeyj_lcANK_4McSg"
    $urlOfMyPubliclyEditableSharepointFolder       = "https://autoscaninc-my.sharepoint.com/personal/neil_autoscaninc_com/Documents/Attachments/fa4541d00e6e4ef8b1ade357f0e207e5"


    if(-not $pathOfDestinationFile){
        $pathOfDestinationFile  = (join-path (join-path $env:temp "$(new-guid)") $pathOfSourceFile )
        New-Item -ItemType Directory -force (split-path -parent $pathOfDestinationFile ) | out-null
    }



    # hit the $publicUrlOfMyPubliclyEditableSharepointFolder solely for the
    # purpose of collecting the cookies that we will need for the actual
    # uploading:
    $pathOfCookieJarFile = (join-path $env:temp (new-guid))
    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar"; $pathOfCookieJarFile
        "--cookie"; $pathOfCookieJarFile  
        $publicUrlOfMyPubliclyEditableSharepointFolder 
    ) | out-null

    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar"; $pathOfCookieJarFile 
        "--cookie"; $pathOfCookieJarFile 
        "--output"; $pathOfDestinationFile 

        (-join @(
            "$($urlOfMyPubliclyEditableSharepointFolder)"
            "/$([System.Web.HttpUtility]::UrlPathEncode($pathOfSourceFile))"
        ))
    ) | write-host
    # todo: deal with illegal filenames.
    Remove-Item $pathOfCookieJarFile | out-null


    return $pathOfDestinationFile
}
