# 
# 2021-10-31
# Set up psremoting on a Windows server machine, using public key authentication.
# Following https://adamtheautomator.com/ansible-winrm/



$idOfBitwardenItem = '4f884743-3ed9-46df-ac56-aa3a016a4b19'

# as a boot-strapping method, I use psexec to access a powershell console on the server

# unlock the bitwarden vault:
if (! $(bw unlock --check)){ $env:BW_SESSION =  $(pwsh -Command "bw unlock --raw || bw login --raw") }

$bitwardenItem = (bw get item $idOfBitwardenItem | ConvertFrom-Json)

# get a key pair, and generate a corresponding certificate.  Prepare two files:
# one containing the certificate without the private key, and one containing
# both the private key and the certificate.



$desiredContentOfOpensslConfigFile=@"
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$($bitwardenItem.login.username)
"@
$opensslConfigFile = New-TemporaryFile
$desiredContentOfOpensslConfigFile | Out-File -FilePath $opensslConfigFile.FullName -Encoding utf8 -NoNewline
$env:OPENSSL_CONF=$opensslConfigFile.FullName

# $fileContainingPrivateKey = New-TemporaryFile
# $fileContainingCertificateWithoutPrivateKey = New-TemporaryFile

$fileContainingPrivateKey = ([System.IO.FileInfo] (Join-Path 'U:\2021-07-31 new user script' 'private_key.pem'))
$fileContainingCertificateWithoutPrivateKey = ([System.IO.FileInfo] (Join-Path 'U:\2021-07-31 new user script' 'cert.cer'))
$pfxFile = ([System.IO.FileInfo] (Join-Path 'U:\2021-07-31 new user script' 'cert.pfx'))
$passwordOfthePfxFile = ''

# export OPENSSL_CONF=openssl.conf
# openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out cert.pem -outform PEM -keyout cert_key.pem -subj "/CN=ansibletestuser" -extensions v3_req_client
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out $fileContainingCertificateWithoutPrivateKey.FullName -outform PEM -keyout $fileContainingPrivateKey.FullName -subj "/CN=$($bitwardenItem.login.username)" -extensions v3_req_client

#generate a pfx file with an empty password
openssl pkcs12 -export -out $pfxFile.FullName -inkey $fileContainingPrivateKey.FullName -in $fileContainingCertificateWithoutPrivateKey.FullName -passout "pass:$passwordOfthePfxFile"

$scriptToRunOnServer=@"
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value `$true
`$fileContainingCertificateWithoutPrivateKey = New-TemporaryFile
@'
$(Get-Content -Raw $fileContainingCertificateWithoutPrivateKey.FullName)
'@ | Out-File -FilePath `$fileContainingCertificateWithoutPrivateKey.FullName -Encoding utf8 -NoNewline
Get-Content -Raw `$fileContainingCertificateWithoutPrivateKey

`$null = Import-Certificate -FilePath `$fileContainingCertificateWithoutPrivateKey.FullName -CertStoreLocation 'Cert:\LocalMachine\Root'
`$certificate = Import-Certificate -FilePath `$fileContainingCertificateWithoutPrivateKey.FullName -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'
`$fileContainingCertificateWithoutPrivateKey.Delete()
# `$certificate = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' | Where-Object {`$_.Subject -eq 'CN=$($bitwardenItem.login.username)'})[0]

Write-Output "certificate thumbprint is `$(`$certificate.Thumbprint) "

`$existingItems = Get-ChildItem -Path    'WSMan:\localhost\ClientCertificate' | where-object {`$_.Keys.Contains('Subject=$($bitwardenItem.login.username)')}
`$existingItems | Remove-Item -confirm:`$false

New-Item ``
    -Path    'WSMan:\localhost\ClientCertificate' ``
    -Subject '$($bitwardenItem.login.username)'   ``
    -URI     '*'                                  ``
    -Issuer  `$certificate.Thumbprint             ``
    -Credential (New-Object System.Management.Automation.PSCredential ('$($bitwardenItem.login.username)', (ConvertTo-SecureString '$($bitwardenItem.login.password)' -AsPlainText -Force))) ``
    -Force 


return
"@





# # $psDriveInfo = New-PSDrive `
# #     -Credential (New-Object System.Management.Automation.PSCredential ($bitwardenItem.login.username, (ConvertTo-SecureString $bitwardenItem.login.password -AsPlainText -Force))) `
# #     -Name "dummy" `
# #     -Root '\\trinarserver\C$' `
# #     -PSProvider FileSystem `
# #     -Scope Script
# # the above did not work -- stalled endlessly, so I connected to thje C$ share manually using windows explorer, and then was able to run the below command succesfully.
# Copy-Item -Path $fileContainingScriptToRunOnServer.FullName -Destination '\\trinarserver\C$\a.ps1'
# $psDriveInfo | Remove-PsDrive
# # had to do the above manually

# write-host $fileContainingScriptToRunOnServer.FullName 


# notepad $opensslConfigFile.FullName
# notepad $fileContainingPrivateKey.FullName
# notepad $fileContainingCertificateWithoutPrivateKey.FullName
# notepad $fileContainingScriptToRunOnServer.FullName



# rm openssl.conf 
$opensslConfigFile.Delete()
# $fileContainingPrivateKey.Delete()
# $fileContainingCertificateWithoutPrivateKey.Delete()

# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i cmd 
# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i pwsh 
# 
# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i -h powershell -file "C:\a.ps1"
# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i -h powershell -Command "&{. `"C:\a.ps1`" }"

# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i -h powershell -EncodedCommand ([Convert]::ToBase64String(([System.Text.Encoding]::Unicode.GetBytes($scriptToRunOnServer))))

& {
    $fileContainingScriptToRunOnServer = ([System.IO.FileInfo] ((New-TemporaryFile).FullName + '.ps1'))
    $scriptToRunOnServer | Out-File -FilePath $fileContainingScriptToRunOnServer.FullName -Encoding utf8 -NoNewline
    Copy-Item -Path $fileContainingScriptToRunOnServer.FullName -Destination '\\trinarserver\C$\a.ps1'
    psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i -h powershell -file "C:\a.ps1"
    $fileContainingScriptToRunOnServer.Delete()
}


# Import-Certificate -FilePath $fileContainingCertificateWithoutPrivateKey.FullName -CertStoreLocation "cert:\localmachine\my"
Get-ChildItem "cert:\localmachine\my" | where-object {$_.Subject -eq "CN=$($bitwardenItem.login.username)"} | Remove-Item -confirm:$false
$certificate = (
    Import-PfxCertificate `
        -FilePath $pfxFile.FullName `
        -Password $( if( $passwordOfthePfxFile ) {(ConvertTo-SecureString -String $passwordOfthePfxFile -AsPlainText -Force)} else {(New-Object System.Security.SecureString)}  ) `
        -CertStoreLocation "cert:\localmachine\my" `
)
$certificate = Get-ChildItem "cert:\localmachine\my" | where-object {$_.Subject -eq "CN=$($bitwardenItem.login.username)"}
$certificate


$ss = @{
    ComputerName = 'trinarserver.trinar.local';
    # Credential=(New-Object System.Management.Automation.PSCredential ($username, (ConvertTo-SecureString $password -AsPlainText -Force)));
    
    # ConfigurationName="Powershell.7.1.5";
    ConfigurationName="microsoft.powershell";
    # run Get-PSSessionConfiguration  to see a complete list of available configurations
    
    SessionOption=@{
        # OutputBufferingMode=;
    };
    CertificateThumbprint=$certificate.Thumbprint
    # Authentication='Digest';
    # UseSSL=$True;
}

$VerbosePreference = 'Continue'
Invoke-Command @ss -ScriptBlock {write-output ("HELLO FROM " + $env:computername)}






# psexec '\\trinarserver.trinar.local' -u $bitwardenItem.login.username -p $bitwardenItem.login.password -i -h powershell 
# Get-ChildItem -Path 'WSMan:\localhost\ClientCertificate'
# Get-Item -Path 'WSMan:\localhost\ClientCertificate' -Subject 'njacksonadmin@tri-nar.com'
# # then, on trinarserver:
# $psversiontable
# Get-PSSessionConfiguration 
# Get-ChildItem WSMan:\localhost\Listener

# Get-Service -Name "WinRM" | fl
# Get-Service -Name "WinRM"

# Set-Service -Name "WinRM" -StartupType Automatic
# Start-Service -Name "WinRM"

# if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
#     ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
#     ## Use Force to not be prompted if we're sure or not.
#     # Enable-PSRemoting -SkipNetworkProfileCheck -Force
#     Enable-PSRemoting -Force
# }

# Get-Item -Path WSMan:\localhost\Service\Auth\Certificate 
# Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
