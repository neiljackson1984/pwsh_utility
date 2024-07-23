
<# 2024-07-23-1241:
    It's not great to have these urls hardcoded here, but better here once than a thousand times in various scripts.
#>
$publicUrlOfMyPubliclyEditableSharepointFolder = "https://autoscaninc-my.sharepoint.com/:f:/p/neil/Es4XlxUoKpNPoQQAVV1RBR0B-E-toUZeyj_lcANK_4McSg"
$urlOfMyPubliclyEditableSharepointFolder       = "https://autoscaninc-my.sharepoint.com/personal/neil_autoscaninc_com/Documents/Attachments/fa4541d00e6e4ef8b1ade357f0e207e5"


function uploadFileToSpecialPublicSharepointFolder([string] $pathOfSourceFile, [string] $pathOfDestinationFile = $null){

    
    # hit the $publicUrlOfMyPubliclyEditableSharepointFolder solely for the
    # purpose of collecting the cookies that we will need for the actual
    # uploading:
    $pathOfCookieJarFile = (join-path $env:temp (new-guid))
    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar", $pathOfCookieJarFile
        "--cookie", $pathOfCookieJarFile  
        $publicUrlOfMyPubliclyEditableSharepointFolder 
    ) | out-null

    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar",$pathOfCookieJarFile 
        "--cookie", $pathOfCookieJarFile 
        "--upload-file", "$pathOfSourceFile" 


        ## "$($urlOfMyPubliclyEditableSharepointFolder)/$($pathOfDestinationFile ?? (split-path $pathOfSourceFile -leaf))" 
        <# get rid of the "??" to make this code comaptible with Powershell version 5.1 #>
        "$($urlOfMyPubliclyEditableSharepointFolder)/$( $(@($pathOfDestinationFile; (split-path $pathOfSourceFile -leaf)) |?{$_}| select-object -first 1))" 


    ) | write-host
    # todo: deal with illegal filenames.
    Remove-Item $pathOfCookieJarFile
}

function downloadFileFromSpecialPublicSharepointFolder([string] $pathOfSourceFile, [string] $pathOfDestinationFile){
    
    # hit the $publicUrlOfMyPubliclyEditableSharepointFolder solely for the
    # purpose of collecting the cookies that we will need for the actual
    # uploading:
    $pathOfCookieJarFile = (join-path $env:temp (new-guid))
    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar", $pathOfCookieJarFile
        "--cookie", $pathOfCookieJarFile  
        $publicUrlOfMyPubliclyEditableSharepointFolder 
    ) | out-null

    curl.exe @(
        # "--verbose" 
        "--location" 
        "--cookie-jar", $pathOfCookieJarFile 
        "--cookie", $pathOfCookieJarFile 
        "$($urlOfMyPubliclyEditableSharepointFolder)/$pathOfSourceFile" 
        "--output", $pathOfDestinationFile 
    ) | write-host
    # todo: deal with illegal filenames.
    Remove-Item $pathOfCookieJarFile
}
