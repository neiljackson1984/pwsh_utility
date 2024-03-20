function unlockTheBitwardenVault(){
    #temporary hack to speed things up:
    Write-Debug "blindly assuming that bitwarden vault is unlocked..."; return
    
    Write-Host "Attempting to unlock the bitwarden vault..."
    if ($(bw unlock --check)) {
        Write-Host "The bitwarden vault is already unlocked."
    }
    else { 
        $env:BW_SESSION =  $(pwsh -Command "bw unlock --raw || bw login --raw") 
    }
}

# function getBitwardenItem {
function Get-BitwardenItem {
    [OutputType([HashTable])] # I really want an Optional[HashTable] -- I will return null in case of failure.
    
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item to get")]
        [String]$bitwardenItemId
    )
    
    unlockTheBitwardenVault
    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get item $bitwardenItemId  | ConvertFrom-Json -AsHashtable)
    #todo: error handling

    ## 2023-05-15-1101: 
    #  the type of $bitwardenItem (and the type of any nested objects) at this
    #  point happens to be System.Management.Automation.OrderedHashtable.  If we
    #  were to omit the "-AsHashTable" switch, above, the type of $bitwarenItem
    #  (and the type of any nested objects) would be
    #  System.Management.Automation.PSCustomObject.  These types behave very
    #  similarly, but the hash table has the advantage that all of the original
    #  json properties are represented as keys in the hash table, whereas with
    #  the pscustomobject, I have the sense that there would be some property
    #  names that could appear in the original json but would not be accessible
    #  in the PScustomObject because they would be shadowed by PsCustomObject's
    #  own properties.  In other words, with the hash table, uniquely, we can
    #  always resort to square-bracket member access operator if we need to.


    #todo: a bit of a hack to work around the overhead in calling the bw
    # executable might be to store a private cache of the vault here (or memoize
    # one result at a time).  Not great for security or concurrency, but it
    # might help bring the delay into a tolerable range.  Along the same lines,
    # we might explore the "rbw" client, which is an unofficial bitwardin
    # command-line client written in Rust that purports to be much faster than
    # the official, node.js-based, bitwarden client.
    return $bitwardenItem
}

function Set-BitwardenItem {
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item")]
        [HashTable] $bitwardenItem
    )
    #todo 2023-05-15-1146: accept pipeline input.  think about what the return type should be.
    unlockTheBitwardenVault
    $bitwardenItem | ConvertTo-Json -Depth 99 | bw --nointeraction --raw  encode | bw --nointeraction --raw edit item $bitwardenItem.id

}

function makeNewBitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The name of the bitwarden item")]
        [String] $name = ""
    )

    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get template item | ConvertFrom-Json -AsHashtable)
    $bitwardenItem['name'] = $name
    $bitwardenItem['notes'] = "created programmatically $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss")`nfoo_ef7ba3fce1bc482c8fb5304da2e2a89e" 
    # this magic string is mainly for testing, just to help me find and delete all the new bitwarden items that I created during testing .

    $bitwardenItem['login'] = ( bw --nointeraction --raw get template item.login | ConvertFrom-Json -AsHashtable)
    $bitwardenItem['login']['username'] = ""
    $bitwardenItem['login']['password'] = ""
    $bitwardenItem['login']['totp'] = ""

    unlockTheBitwardenVault
    $result = [System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json -Depth 50)) )  | bw --nointeraction --raw create item 
    $newlyCreatedBitwardenItem = ( $result | ConvertFrom-Json -AsHashtable)
    Write-Host "created new bitwarden item having id $($newlyCreatedBitwardenItem['id'])."
    return (Get-BitwardenItem -bitwardenItemId $newlyCreatedBitwardenItem['id'] )
}



function getFieldMapFromBitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage=  "The bitwarden item id of the bitwarden item whose field map we want",
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )

    [HashTable] $bitwardenItem = Get-BitwardenItem -bitwardenItemId $bitwardenItemId

    $fieldMap = @{}
    

    # ion the case where bitwardenItem has no fields, there will be no "fields"
    # key in the hash table. in this case, $bitwardenItem['fields'] will be
    # $null, and  @($bitwardenItem['fields'])) will not be an empty array (whcih
    # we naively assumed), wut will rather be a single-element array whose one
    # element is $null. Thus, we iterate over $bitwardenItem['fields'] instead
    # of iterating over @($bitwardenItem['fields'])).

    ## foreach($field in @($bitwardenItem['fields'])){
    foreach($field in $bitwardenItem['fields']){
        $fieldMap[$field['name']] = $field['value']
    }

    return $fieldMap
}

function getSshPrivateKeyFromBitwardenItem {
    [OutputType([string])]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage=  {@(
                "The bitwarden item id of the bitwarden item "
                "from which we want to get the private key.  "
                "If the bitwarden item has a field named "
                "`"ssh_private_key_reference`" containing the "
                "id of another bitwarden item, then"
                "we retrieve the contents of the file named "
                "`"id_rsa`" that is attached to that other "
                "bitwarden item.  Otherewise, we retrieve the "
                "contents of the file named `"id_rsa`" that is "
                "attached to this btiwarden item."
            ) -join ""},
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )

    [HashTable] $bitwardenItem = Get-BitwardenItem -bitwardenItemId $bitwardenItemId
    
    ##  $bitwardenItemIdOfItemContainingTheKeyAsAnAttachedFile = (
    ##      (
    ##          $bitwardenItem.fields |
    ##          ? {$_.name -ceq "ssh_private_key_reference"} | 
    ##          select -first 1 |
    ##          % {$_.value} |
    ##          ? {$_}
    ##      ) ?? (
    ##          $bitwardenItem.id
    ##      )
    ##  ) 

    [HashTable] $bitwardenItemContainingTheKeyAsAnAttachedFile = (
        (
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_private_key_reference"} | 
            select -first 1 |
            % {$_.value} |
            ? {$_} |
            % {Get-BitwardenItem -bitwardenItemId $_}
        ) ?? (
            $bitwardenItem
        )
    ) 


    # $sshPrivateKey = bw --raw get attachment id_rsa --itemid $bitwardenItemIdOfItemContainingTheKeyAsAnAttachedFile

    # the above technique to get the $sshPrivateKey is problematic because of
    # the powershell newline-handling problem.
    #
    # I am not sure how I ever used  getSshPrivateKeyFromBitwardenItem() and
    # initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment() without
    # running into this newline problem before.  Was I perhaps using the
    # built-in windows installation of OpenSSH and perhaps the built-in
    # installation tolerates windows-style line endings?  That sounds familiar.
    #
    # see
    # [https://stackoverflow.com/questions/59110563/different-behaviour-and-output-when-piping-in-cmd-and-powershell/59118502#59118502].
    #
    # the workaround is either to use the --ouput option to the bw command so
    # that bw dumps the output to a file rather than stdout, and then read the
    # file (which is not ideal becuase we would like to keep this sensitive
    # plaintext off the disk) or to run the bw command with
    # System.Diagnostics.Process, and capture stdout.
    #
    # CAUTION: In the case where the bw command is coming from the npm package
    # @bitwarden/cli, bw might be a powershell script (bw.ps1) rather than a
    # native executable, and, specifically, the powershell-script version of the
    # bw command evidently subjects the output of the attachment getting command
    # through powershell's chop-into-lines behavior, with the result that the
    # stdout of the below $process might indeed contain windows-style newlines
    # even if the file attached to the bitwarden item contained only linefeeds.
    #
    # This is arguable a failing of the @bitwarden/cli module.  An
    # understandable failing, perhaps, but still.
    #
    # note: if we omit the --raw option, the bw command saves the attached file
    # to the current working directory -- not what we want.

    $namesOfFilesToRegardAsPrivateKeyFiles = @(
        "id_dsa"
        "id_ecdsa"
        "id_ecdsa_sk"
        "id_ed25519"
        "id_ed25519_sk"
        "id_rsa"

        # the entries that end "_sk" are, I think, the "authenticator-hosted"
        # identites mentioned in [the documentation]
        # (https://man.openbsd.org/ssh-keygen.1#FILES]).
    )
    # see [https://man.openbsd.org/ssh-keygen.1#FILES]

    $sshPrivateKey = 
        $bitwardenItemContainingTheKeyAsAnAttachedFile.attachments |
        ? {$_.fileName -cin $namesOfFilesToRegardAsPrivateKeyFiles} |
        select-object -first 1 |
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
                                "--itemid"; $bitwardenItemContainingTheKeyAsAnAttachedFile.id
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

    return $sshPrivateKey
}

function getSshPublicKeyFromPrivateKey {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [parameter()]
        [string] $privateKey,

        [parameter(mandatory=$False)]
        [string] $password = ""
    )

    $pathOfTemporaryFileContainingPrivateKey = New-TemporaryFile
    # I am not a big fan of writing the private key to a file, but I can't
    # figure out how to make ssh-keygen read from stdin.
    #
    # What I am actually trying to achieve with this function is usually to get
    # the public key corresponding to the private key stored in some bitwarden
    # item.  It might be more secure to store the public key as an additional
    # attachment or field in the bitwarden item (At the time of creation), and
    # then, when I want the public key, I wouldn't have to read or download the
    # private key. 
    set-content -Path $pathOfTemporaryFileContainingPrivateKey -Value $privateKey
    $publicKey = $privateKey | ssh-keygen -y -P $password -f $pathOfTemporaryFileContainingPrivateKey
    Remove-Item $pathOfTemporaryFileContainingPrivateKey
    return $publicKey
}

function getSshOptionArgumentsFromBitwardenItem {
    [OutputType([System.Collections.Generic.IEnumerable[string]])]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage=  {@(
                "The bitwarden item id of the bitwarden item "
                "from which we want to get the ssh configuration option args. "
            ) -join ""},
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )

    [HashTable] $bitwardenItem = Get-BitwardenItem -bitwardenItemId $bitwardenItemId

    # obtain the sshHost, sshUsername, and sshPort:

    # find the first uri having the protocol "ssh://", or null if there is no
    # such uri.  An ssh uri encodes the hostname and port number (the port
    # number is implicitly 22 if no explicit port number is given in the ssh
    # uri) and, optionally, the sshUsername.

    # TODO: store public keys of hosts in bitwarden.

    [System.Uri] $sshUri = $(
        $bitwardenItem.login.uris |
        % {[System.Uri] $_.uri} |
        ? {$_.Scheme -eq "ssh"} |
        select -first 1
    )

    $sshHost = $(
        @(
            ${sshUri}?.Host
        
            # TODO: deprecate the ssh_host field -- the ssh_host field is entirely
            # redundant with respect to sshUri.
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_host"} | 
            select -first 1 |
            % {$_.value}
    
            $bitwardenItem.login.uris |
            % { ([System.Uri] $_.uri ).Host } 
        ) |
        ? {$_} |
        select -first 1
    )
    
    $sshUsername = $(
        @(
            ([System.UriBuilder] $sshUri)?.UserName
            # Whereas System.Uri gives us only a UserInfo property, which
            # contains the username and password (if present) separated by a
            # colon, System.UriBuilder has separate properties for the username
            # and the password.  Hence, the conversion to System.UriBuilder,
            # above. 

            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_username"} | 
            select -first 1 | 
            % {$_.value}

            $bitwardenItem.login.username
        ) |
        ? {$_} |
        select -first 1
    )


    $sshPort = $(
        if($sshUri){
            ${sshUri}?.Port | ? {$_ -gt 0}
            # yes, even if ${sshUri}?.Port is null -- If sshUri is non-null, we
            # want sshUri's port specification (even if the port specification
            # is null) to override all other port specifications.
            #
            # the test for port being greater than zero is to work around the
            # fact that System.Uri's port property is of type int, and
            # System.Uri uses -1 as the "null-like" value -- to indicate an
            # absence of a port specification in the original uri string.  
            #
            # this is a bit sloppy on the part of the designer of the System.Uri
            # class.  Ideally, System.Uri would have a more obvious,
            # self-documenting way of encoding the absence of a port
            # specification. perhaps make the type of Port nullable, or have a
            # boolean property named "hasPort" (or similar), or, perhaps, infer
            # a real port number from the scheme defaults.
        }
        else {
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_port"} | 
            select -first 1 |
            % {$_.value} |
            ? {$_}
        }
    )

    $sshConfigurationOptionArgs=@(
        "-o";"StrictHostKeyChecking=no"
    
        # "-o"; "PubkeyAcceptedKeyTypes=+ssh-rsa"
        # "-o"; "HostKeyAlgorithms=+ssh-rsa"
        #temporary work-around for sophos router (I might need to replace my
        # favorite keypair  with a new one that does not rely on the now-deprecated
        # SHA-1 hash algorithm (although I am not entirely sure how the key pair
        # depends on the hash algorithm) -- the source of the dependency might be
        # the hash that is stored by the server in the authorized keys list.
        # possibly, I merely need to recompute a different hash of my public key and
        # store this different hash in the the server. see
        # https://www.openssh.com/txt/release-8.2
    
        # evidently, if we have multiple "-o HostKeyAlgorithms..." options, only the
        # first one is attended to, even when we are using the "+" notation to say
        # "add this item to the existing list". hence, I have combined the sophos
        # router workaround (+ssh-rsa) and the ILO3 workaround (+ssh-dss) into one
        # option argument for each property.  We ought to figure ought a way to
        # encode these options for exceptional cases in bitwarden.
        "-o"; "HostKeyAlgorithms=+ssh-rsa,ssh-dss"
        "-o"; "PubkeyAcceptedKeyTypes=+ssh-rsa,ssh-dss"
        "-o"; "KexAlgorithms=+diffie-hellman-group1-sha1"
        # this is a workaround for ssh'ing into an ILO3 controller on an HP Proliant
        # Gen7 server. allowing this key exchange algorithm constitutes a reduction
        # in security, and probably shouldn't be left here for all time.
        # see [https://unix.stackexchange.com/questions/340844/how-to-enable-diffie-hellman-group1-sha1-key-exchange-on-debian-8-0]
        # see [http://www.openssh.com/legacy.html]
    
        "-o"; "ServerAliveInterval=5"
    
        if($sshPort){"-o"; "Port=${sshPort}" }
        
        "-o"; "User=${sshUsername}"
    
        "-o"; "HostName=${sshHost}"
    )

    # instead of hardcoding, above, the options for special-case workarounds, it
    # would be better to allow the bitwarden item to specify special workaround
    # options.

    return $sshConfigurationOptionArgs
}


function initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment {
    [OutputType([System.Collections.Generic.IDictionary[[string],[string]]])]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage=  {@(
                "The bitwarden item id of the bitwarden item "
                " that describes the ssh connection."
            ) -join ""},
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )

    # ssh-agent pwsh 
    #
    # I would rather set up the environment variables than spawn a new shell
    # process, but at the moment this is easier.  all that matters is that we
    # get the environment variabls populated (I think) -- I don't think there is
    # anything special per se about being a child process of the ssh-agent
    # process.
    #
    # actually, simply jumping into a new shell here is no good, because then
    # none of our below commands run.  Unfortunately, getting the necessary
    # variable values from the output of ssh-agent is a bit of a kludge (and
    # always was -- the standard way to do this within bash is to do 
    #
    # ```
    # eval $(ssh-agent)
    # ```
    #
    # ssh-agent is designed to emit valid bash code (or valid csh code, if you
    # pass the -c option).  We'll pile on another layer of kludge by parsing,
    # with regex, the emitted bash code, to extract the variable values.
    #

   
    

    # $bashCode = "$(ssh-agent -s)"
    # will look something like:
    # ```
    # SSH_AUTH_SOCK=/tmp/ssh-AO9HkgjpqTvL/agent.1545; export SSH_AUTH_SOCK;
    # SSH_AGENT_PID=1546; export SSH_AGENT_PID;
    # echo Agent pid 1546;
    # ```
    #
    # this scheme is slightly non-ideal in that it leaves the ssh-agent process
    # running even after we have exited from the shell. this is the intended
    # behavior of ssh-agent, I think, but I would prefer to have our instance of
    # ssh-agent die when we exit.

    $processStartInfo = New-Object "System.Diagnostics.ProcessStartInfo" @(
        (get-command ssh-agent).Path; 
        (
            @(

                # -s      Generate Bourne shell commands on stdout.  This is the
                # default if SHELL does not look like it’s a csh style of shell.
                "-s" 

                # -D      Foreground mode.  When this option is specified,
                # ssh‐agent will not fork.
                "-D"

                # When we use the -D option, pressing Ctrl-C while a command is
                # running causes ssh-agent to die (the ssh-agent process is a
                # child of the shell process).  This is a bit annoying.

                # On the other hand, when we don't use the -D option, ssh-agent
                # becomes not a child process of the shell, which means that
                # ssh-agent doesn't die even when the shell dies.  This is also
                # a bit annoying.

                # the trick is to set $processStartInfo.RedirectStandardInput to
                # True.
                #
                # this way, ssh-agent is a child process of the shell, dies when
                # the shell dies, and does not die when we press Ctrl-C during a
                # long-running command within the shell.

            ) -join " "
        )
        
    )

    $processStartInfo.RedirectStandardInput = $True
    $processStartInfo.RedirectStandardOutput = $True
    $processStartInfo.RedirectStandardError = $True
    $process = [System.Diagnostics.Process]::Start($processStartInfo)

    # this achieves the desired effect of having the ssh-agent process be a
    # child process of the shell (so that the ssh-agent process dies with the
    # shell).  Notice the -D option to ssh-agent, which tells ssh-agent to run
    # in the foreground and not fork.  

    # Curiously, when we run ssh-agent with the -D option, ssh-agent does not
    # spit out the SSH_AGENT_PID value -- only the SSH_AUTH_SOCK value.
    # ssh-agent does still emit "echo Agent pid 1476;" (for example), so the
    # information about the pid is still extractable, but why wouldn't it just
    # go ahead and emit the line to set the SSH_AGENT_PID environment variable?
    # Admittedly, if we are launching ssh-agent in non-forking mode (by using
    # the - -D option), we probably can figure out the pid of the ssh-agent
    # process by means other than looking at the bash code that ssh-agent emits
    # on stdout, but still, what could be the harm in ssh-agent emitting the
    # "SSH_AGENT_PID=..." code?  There must be some intentional reason for this
    # behavior.
    #
    # Is the SSH_AGENT_PID variable really needed in all cases?  Perhaps
    # SSH_AUTH_SOCK is sufficient for the main funciton of ssh-agent and the
    # realted tools (ssh-add, ssh, etc.).  Maybe the reason the
    # "SSH_AGENT_PID=..." code is emitted at all by ssh-agent is to give us the
    # pid of the agent so that we can kill the ssh-agent process when we want
    # (much like I am wanting to have ssh-agent die with the shell).


    $bashCode = "$($process.StandardOutput.ReadLine())$($process.StandardOutput.ReadLine())"

    # the first ReadLine() returns something like
    # "SSH_AUTH_SOCK=/tmp/ssh-rzPpdq0sEjBX/agent.185; export SSH_AUTH_SOCK;" the
    # second ReadLine() returns something like "echo Agent pid 185;" no further
    # characters are emitted on stdout, and no characters whatsoever are
    # emitted on stderr. 

    $bashStatements = $bashCode -split ";"
    $doExtractSshAgentPidFromEchoCode = $True
    # $doExtractSshAgentPidFromEchoCode = $False
    # it doesn't actually seem to be necessary to have the SSH_AGENT_PID
    # environemtn variable defined.

    $sshAgentEnvironment = @{}
    foreach($bashStatement in $bashStatements) {
        if($bashStatement -match '^\s*(?<name>\w+)=(?<value>.*)$'){
            # Set-Item "env:$($Matches['name'])" -Value $Matches['value']
            $sshAgentEnvironment[$Matches['name']] = $Matches['value']
        } elseif (
            ($bashStatement -match '^\s*echo\s+Agent\s+pid\s+(?<sshAgentPid>\d+)\s*$')
        ) {
            # this case handles the case where we are running ssh-agent with the
            # -D option (i.e. in the foreground, i.e. not forking), in which
            # case ssh-agent does not emit the "SSH_AGENT_PID=..." code.

            if($doExtractSshAgentPidFromEchoCode){
                # Set-Item "env:SSH_AGENT_PID" -Value $Matches['sshAgentPid']
                $sshAgentEnvironment["SSH_AGENT_PID"] = $Matches['sshAgentPid']
            }

            # $sshAgentPid = $Matches['sshAgentPid']
            # this is just for debugging
        }
    }

    <# 
        ```
        ssh-add -l
        ```
        >>>


        see
        [https://github.com/joaojacome/bitwarden-ssh-agent/blob/master/bw_add_sshkeys.py#L154].
        Evidently, ssh-add can be made to read the key from stdin by specifying
        the magic filename "-".  This is not documented in the ssh-add man page
        (although maybe its a broader convention among all the openssh utilities
        or in posix?) . I discovered it by looking at
        [https://github.com/joaojacome/bitwarden-ssh-agent/blob/master/bw_add_sshkeys.py#L154].




        
        see [https://superuser.com/questions/1059781/what-exactly-is-in-bash-and-in-zsh]
        
        see [https://serverfault.com/questions/688645/powershells-equivalent-to-bashs-process-substitution]


        ```
        getSshPrivateKeyFromBitwardenItem -bitwardenItemId $bitwardenItemId | ssh-add -
        ```
        >>>    Identity added: (stdin) ((stdin)) 


        ```
        ssh-add -l
        ```
        >>>    4096 SHA256:LOy8rbkAXKQCFTtRntAUImYCoL2+HXhUgR0nvKf2mmE (stdin)
        >>>    (RSA)

        Hmmm. ssh-add treats "stdin" as the name of this key when you add it via
        stdin rather than a real file name.  Presumably, you could specify a
        meaningful name using command line arguments to ssh-add or maybe with
        specially-crafetd content of the private key string.

        # see [https://man7.org/linux/man-pages/man1/ssh-add.1.html]
    #>
    
    # getSshPrivateKeyFromBitwardenItem -bitwardenItemId $bitwardenItemId | ssh-add - | write-host
    
    # getSshPrivateKeyFromBitwardenItem -bitwardenItemId $bitwardenItemId | 
    # ssh-add "-o" "IdentityAgent=$($sshAgentEnvironment['SSH_AUTH_SOCK'])" "-" | 
    # write-host

    getSshPrivateKeyFromBitwardenItem -bitwardenItemId $bitwardenItemId | 
    & { 
        $initialValues = @{}
        foreach($key in $sshAgentEnvironment.Keys){
            $initialValues[$key] = (get-item "env:$($key)" -errorAction SilentlyContinue).Value
            Set-Item "env:$($key)" -Value $sshAgentEnvironment[$key]
        }
    
        $input | ssh-add - 
        # even though we have (mostly) dealt with the newline problem by fixing
        # the getSshPrivateKeyFromBitwardenItem -- it still might not be a bad
        # idea to filter out any carriage returns that might have gotten into
        # input one way or another.  It's annoying that OpenSSH is so sensitive
        # about windows-style newlines in the key files.
        #
        # I suspect that Windows' built-in installation of OpenSSH might
        # tolerate windows-style newlines -- that might be why I did not
        # immediately encounter the newline problem (I think I only encountered
        # the newline problem when I had my system path set up so as to favor
        # the cygwin version of OpenSSH.


        foreach($key in $initialValues.Keys){
            Set-Item "env:$($key)" -Value $initialValues[$key]
        }
    } | 
    write-host



    return $sshAgentEnvironment;
}



function initializeSshAgentFromBitwardenItem {
    [OutputType([void])]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage=  {@(
                "The bitwarden item id of the bitwarden item "
                " that describes the ssh connection."
            ) -join ""},
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )
    $sshAgentEnvironment = initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment $bitwardenItemId
    
    foreach($key in $sshAgentEnvironment.Keys){
        Set-Item "env:$($key)" -Value $sshAgentEnvironment[$key]
    }
}



function runInSshSession {
    <#
    .SYNOPSIS
    The sshOptionArguments parameter value can be constructed by doing
    something like this:
    ```
        $bitwardenItemId = "e2e86ca2-0933-4e15-b84e-b3967873b49b" 
        $sshOptionArguments = getSshOptionArgumentsFromBitwardenItem -bitwardenItemId $bitwardenItemId 
    ```

    and, for maximum usefullness, you might also want to do:
    ```
    initializeSshAgentFromBitwardenItem -bitwardenItemId $bitwardenItemId 
    ```

    I would like to not have to always pass the sshOptionArguments on the
    commnand line to make the command very short and readable (we typically set
    a two-letter alias for this command).

    One way to do this, which is maybe not quite the most elegant, but at least
    serves the purpose, is to make a closure that captures the value of
    $sshOptionArguments.  Still not the most elegant answer probably, but
    probably better than having runInSshSession depend on a global variable.  In
    the script where we have created the global variable $sshOptionArguments, we
    define the following function ("rr" is just an example of a short
    abbreviation that might be useful for interactive programming and
    readability):
    ```
    function rr { $input | runInSshSession -sshOptionArguments $sshOptionArguments @args }
    ```

    #>
    
    [OutputType([string])]
    [CmdletBinding(
        PositionalBinding=$False

    )]
    Param (
        
        [Parameter(
            ValueFromPipeline=$True,
            Mandatory = $False
        )]
        # [string] 
        # [object]
        [string]
        $inputObject,
        # in spirit, $inputObject should be a string, but, in order to allow a
        # workaround to the powersehll behavior of always appending a newline
        # (and a "\r\n" newline at that) to the end of the last string (or maybe
        # every string) piped into a native program, we want to allow
        # $inputObject to be a byte-like thing (because the workaround is to
        # convert the string to an enmumerable of bytes, and then pipe each byte
        # one at a time into the powershell pipeline.  setting the type here to
        # object serves the purpose.
        #
        # perhaps we should force $inputObject to be a string after all and
        # then do the conversion to an enumerable of bytes within this function.
        #
        # As of 2023-09-19, the latest non-beta release of powershell (version
        # 7.3.6) does not support the byte piping behavior, but the preview
        # version (version 7.4.0-preview.5) does support the byte piping
        # behavior.  If the byte-piping behavior is supported, then we can have
        # $iunputObject be of type string, which is what we want.
        #

                
        [Parameter()]
        # [System.Collections.Generic.Dictionary[[string],[string]]] 
        # [System.Collections.Generic.IDictionary[[string],[string]]] 
        [Hashtable] 
        $sshAgentEnvironment,
                
        [Parameter()]
        [string[]] 
        $sshOptionArguments,
       
        # # idea:
        # [Parameter()][string] $bitwardenItemId,
        
        [Parameter(
            ValueFromRemainingArguments=$True,
            Mandatory = $False #$True 
            # it is valid, I think, to allow rr to be called without any
            # "remaining arguments" -- this has the same effect as calling ssh
            # without any "command" specified, so that we are dropped into an
            # interactive shell.  
            #
            # I am not sure I like this behavior (it's potentially unexpected,
            # and potentially hard to remember that it exists, and hard to
            # recognize in code if you don't already know about it.)

        )]
        [string[]] $argumentList
    )

    <#
        # runInSshSession runs the specified command on the router, using ssh.
        # Think of the name as an abbreviation of RunOnRouTer or,
        # perhaps RunOnRemoTe

        # we only run the ssh command in case some argument was given,
        # because if we run the ssh command without a command argument,
        # ssh launches an interactive shell, which is not what we want.

        if (( \\\${#@} > 0 )); then : ;
            ssh \$sshOptions '' "\\\$@"
        else : ;
            echo "runInSshSession received no command therefore will not do anything." >2
        fi;
    #>

    <#
        You have to be a bit careful about arguments that happen to look like powershell function parameters, because powershell won't put them in $argumentList.
        To get powershell to include them in $argumentList, wrap them in quotes.

        ```
        runInSshSession echo blarg yarg -ErrorAction SilentlyContinue
        ```
        >>>     blarg yarg


        ```
        runInSshSession echo blarg yarg -ErrorgggAction SilentlyContinue
        ```
        >>>   blarg yarg -ErrorgggAction SilentlyContinue  


        ```
        runInSshSession echo blarg yarg "-ErrorAction" SilentlyContinue
        ```
        >>>     blarg yarg -ErrorAction SilentlyContinue


        ```
        runInSshSession "echo blarg yarg -ErrorAction SilentlyContinue"
        ```
        >>>     blarg yarg -ErrorAction SilentlyContinue



    #>

    begin {
        
        # Write-Warning "inputObject: $inputObject"
        # Write-Warning "argumentList.Count: $($argumentList.Count)"
        # Write-Warning "argumentList: $($argumentList)"

        # Write-Warning "within begin: `$inputObject: $inputObject"
        # Write-Warning "within begin: `$PSBoundParameters.Keys: $($PSBoundParameters.Keys)"
        $inputObjects = @()
    }

    # process {
    #     Write-Warning "processing an inputObject: $inputObject"
    #     Write-Warning "`$inputObject.GetType().FullName: $($inputObject.GetType().FullName)"
    #     Write-Warning "`$null -eq `$inputObject: $($null -eq $inputObject)"

    #     $inputObjects += $inputObject
    
    # }

    process {
        # Write-Warning ("within process: `$input.GetType().FullName: " + $input.GetType().FullName)
        # Write-Warning ("within process: `$inputObject.GetType().FullName: " + $inputObject.GetType().FullName)
        # Write-Warning "within process: `$PSBoundParameters.Keys: $($PSBoundParameters.Keys)"

        # Write-Warning "within process: `$input: $input"
        # Write-Warning "within process: `$input.Count: $($input.Count)"
        # Write-Warning "within process: `$inputObject: $inputObject"
        # # Write-Warning "processing an inputObject: $inputObject"
        # Write-Warning "within process: `$null -eq `$inputObject: $($null -eq $inputObject)"
        # # # Write-Warning "within process: `$null -eq `$PSItem: $($null -eq $PSItem)"
        # # $x = $input
        
        

        # # Write-Warning "within process: `$input.GetType().FullName: $($input.GetType().FullName)"
        # Write-Warning "within process: `$x.GetType().FullName: $($x.GetType().FullName)"
        # Write-Warning "within process: `$null -eq `$x: $($null -eq $x)"
        # # Write-Warning "within process: (@(`$input).Count: $(@($input).Count)"

        if( $PSBoundParameters.Keys -contains "inputObject"){
            # strangely, when you invoke a function not in a pipeline (or at
            # the beginning of a pipeline) and when you do not pass the
            # -inputObject parameter, powershell still runs the process
            # block.  This makes no sense to me, because in this case there
            # is no input; the number of input objects is zero.  I expect
            # powershell to run the process block exactly as many times as
            # there are input objects.  If there are zero input objects, I
            # explect powershell to run the process block zero times, but it
            # actually runs the process block exactly one times.

            # the only reliable and specific way I have found to detect when
            # the process block is being run in this special case (where it
            # really shouldn't run) is to see whether
            # $PSBoundParameters.Keys contains "inputObject".
            
            # Within the process block, $PSBoundParameters.Keys contains
            # "inputObject" when, and only when, the process block is
            # running due to an explicit -inputObject parameter having been
            # passed or the process block is running due to an object having
            # been received on the pipeline. 

            # Looking at whether $inputObject is null as a way to detect
            # when we are in the special "unexpected" case is no good in
            # general because the user might want to actually pass $null as
            # a pipeline object or as the value of the -inputObject
            # parameter.  Also, in the case where I have declared the type
            # of inputObject to be string (for instance), powershell will
            # coerce $null to an empty string.  Well, I could look for empty
            # strings, but the user might have wanted to pass an empty
            # string as a first class input object and then we have the same
            # problem.  checking for the presence of "inputObject" in
            # $PSBoundParameters.Keys works regardless of whether the
            # inputObject is null.

            $inputObjects += $inputObject

        }

        
    
    }

    # process {}
    # the mere presence of a process block, even an empty one,
    # causes $input to be empty in the end block.

    end {
        # Write-Warning "reached end"
        # Write-Warning "within end: inputObjects.Count: $($inputObjects.Count)"
        # $input.Reset()
        # Write-Warning "within end: (@(`$input).Count: $(@($input).Count)"
        # Write-Warning "within end: (@(`$input).Count: $(@($input).Count)"
        # Write-Warning "within end: `$input.Count: $($input.Count)"
        # Write-Warning "within end: `$input: $input"
        # Write-Warning "within end: `$inputObject: $inputObject"
        # # Write-Warning "within end: (@(`$input).Count: $(@($input).Count)"
        # # $collectedInput = @($input)
        # # $collectedInput = @($input)
        
        # # Write-Warning "within end: `$input.GetType().FullName: $($input.GetType().FullName)"
        # Write-Warning "within end: `$PSCmdlet.GetType().FullName: $($PSCmdlet.GetType().FullName)"
        # Write-Warning "within end: `$null -eq `$input: $($null -eq $input)"
        # Write-Warning "within end: `$input.Count: $($input.Count)"
        # Write-Warning "within end: `$inputObjects.Count: $($inputObjects.Count)"
        # Write-Warning "within end: (@(`$input).Count: $(@($input).Count)"
        # Write-Warning "within end: `$collectedInput.Count: $($collectedInput.Count)"


        # $inputObjects | ssh @sshOptionArguments "" @argumentList
        if($inputObjects.Count -gt 0){
            # $inputObjects | ssh @sshOptionArguments "" @argumentList
            # ( ,[byte[]] ($inputObjects | % { [System.Text.Encoding]::UTF8.GetBytes($_) })   ) | ssh @sshOptionArguments "" @argumentList
            ( ,[byte[]] ([System.Text.Encoding]::UTF8.GetBytes(($inputObjects -join "`n")))) | ssh "-o" "IdentityAgent=$($sshAgentEnvironment['SSH_AUTH_SOCK'])" @sshOptionArguments "" @argumentList
            # it is a bit of a hack to be hardcoding our line ending conventions
            # here, but for the application that I happen to be working on at
            # the moment, I want unix-style line endings, and I don't care too
            # much about a terminal newline (I would rather have no terminal
            # newline sequence than a \r\n sequence, which is what I would get
            # if I did not do the byte pipe workaround above.)
            #
            #
            # Interactive commands are a bit wonky, I think.  At least, I think
            # I have observed that powershell caches stderr and only prints it
            # once rr has returned.  I think I ahve observed that powershell
            # does not do this weird stderr caching behavior when there is no
            # pipeline input to rr (i.e. when the below "else" clause obtains).
            #
            # the significant differnece between these two cases (this "if"
            # block and the below "else" block), at least insofar as what would
            # affect stream handling, is that in this "if" block, we pipe some
            # input into ssh wheras in the below "else" block we do not pipe
            # anything into ssh.  Therefore, perhaps it is the piping of input
            # that is causing the stderr caching.  (and I suspect the stderr
            # caching has more to do with powershell than ssh).
            #
            # I might be completely wrong about powershell having anything to do
            # with the "stderr caching" behavior. I noticed the "stderr caching
            # behavior" when attempting to run the Sophos interactive "cc"
            # command via an ssh session to a Sophos UTM SG router.  The
            # behavior could have been entirely the result of things happening
            # in bash and ssh daemon within the sophos router.
            #
            # No, never mind, the stderr caching is a powershell thing (or maybe
            # an ssh thing).  look at this:
            #
            # ```
            # rr "bash -c 'echo 1 here is some stderr 1>&2; echo 2 and here is some stdout; echo 3 and here is some more stderr 1>&2; '"
            # ```
            ### 2 and here is some stdout
            ### 1 here is some stderr
            ### 3 and here is some more stderr
            #
            # The following might be relevant:
            # [https://stackoverflow.com/questions/45316295/the-order-of-stdout-and-stderr-in-bash]
            #
            # the "stderr cahching" behaviour might have to do with bash (or
            # perhaps the program running within bash) thinks it is connected to
            # a terminal, and deciding to do line buffereing (iof connected to a
            # terminal) or block buffering (if not connected to a terminal).
            #
            # the following might also be relevant: [https://www.gnu.org/software/bash/manual/bash.html#Interactive-Shells]
        } else {
            # write-host "no inputObjects given"
            ssh "-o" "IdentityAgent=$($sshAgentEnvironment['SSH_AUTH_SOCK'])" @sshOptionArguments "" @argumentList
            # I was hoping that this would run in a way that is fully
            # connected to the terminal, but it does not.
        }
        # we are specifying the "destination" (i.e. host name and port number)
        # by means of the sshOptionArguments rather than with the "destination"
        # positional command line argument to ssh.  Nevertheless, ssh still
        # expects to see some argument in the "destination" position on the
        # command line.  If we just slap on $argumentList without having
        # anything in the "destination" position, ssh will assume that the first
        # word in $argumentList is the destination and will therefore not treat
        # that word as the first word of the command that we want to run within
        # the ssh session.  To deal with this requirement, we pass an empty
        # string in the "destination" position.  (would it also work to pass any
        # arbitrary word (perhaps ssh ignores the destination argument when a
        # destination is speciifed in the option arguments.)?  What about a
        # hyphen?)


    }

}

function getRr {
    [CmdletBinding()]
    [OutputType([ScriptBlock])]
    Param(
        [string] $bitwardenItemId,

        [hashtable] $extraSshOptions =  @{}
    )

    # specify the bitwardenItem corresponding to the computer we want to ssh into
    $bitwardenItem = Get-BitwardenItem $bitwardenItemId
    
    $pathOfTemporaryKnownHostsFile = New-TemporaryFile
    $sshOptionArguments = @(    
        $extraSshOptions.GetEnumerator()  |
        % {
            "-o"; "$($_.Key)=$($_.Value)"
        }

        # these options prevent us from touching our
        # main known_hosts file:
        "-o";"StrictHostKeyChecking=no"
        "-o","UserKnownHostsFile=$($pathOfTemporaryKnownHostsFile)"

        getSshOptionArgumentsFromBitwardenItem -bitwardenItemId $bitwardenItem.id 
    )

    $sshAgentEnvironment = initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment $bitwardenItem.id
    # Set-Alias -Name rr -Value runInSshSession
    $rr = { 
        $input | runInSshSession -sshAgentEnvironment $sshAgentEnvironment -sshOptionArguments $sshOptionArguments @args 
    }.GetNewClosure()

    & $rr 'echo $(date): hello from $(hostname) ' | write-host

    return $rr
}




function putFieldMapToBitwardenItem {
    [OutputType([Void])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The field map.")]
        [HashTable] $fieldMap,

        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item into which we will inject the configuration data.")]
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [String]$bitwardenItemId=""

        # [Boolean]$doMakeNewBitwardenItem=$False,

        # [String]$nameForNewBitwardenItem=""
    )
    
    # [System.Management.Automation.OrderedHashtable] $bitwardenItem = ( bw --nointeraction --raw get item $bitwardenItemId  | ConvertFrom-Json )
    # $bitwardenItemId = "12d90ae7-d294-4a3e-b100-af70002c83e6"

    [HashTable] $bitwardenItem = (
        # if($doMakeNewBitwardenItem){ 
        #     makeNewBitwardenItem -name $nameForNewBitwardenItem
        # } else { 
        #     Get-BitwardenItem -bitwardenItemId $bitwardenItemId 
        # }
        Get-BitwardenItem -bitwardenItemId $bitwardenItemId 
    )
    foreach($key in $fieldMap.keys){
        if(-not $bitwardenItem['fields']){$bitwardenItem['fields'] = @()}
        
        $newFields = @()
        $ourField = $null
        for($i=0; $i -lt $bitwardenItem['fields'].Length; $i++){
            if( $bitwardenItem['fields'][$i]['name'] -eq $key ){
                if($ourField){
                    #don't do anything, which will effectively omit this field from the newFields list.
                } else {
                    $ourField = $bitwardenItem['fields'][$i]
                    $newFields += $ourField
                }
            } else {
                $newFields += $bitwardenItem['fields'][$i]
            }
        }
        if(-not $ourField){
            $ourField = ( bw --nointeraction --raw get template item.field | ConvertFrom-Json -AsHashtable)
            $ourField['name'] = $key
            $newFields += $ourField
        }
        $bitwardenItem['fields'] = $newFields

        # all of the above brain damage is to preserve the existing order of the
        # fields as much as possible, AND ensure that there is only a single
        # field having the name $key.
        
        $ourField['value']=$fieldMap[$key]

    }
    unlockTheBitwardenVault 1> $null
    ([System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json -Depth 50)) ) | bw --nointeraction --raw edit item $bitwardenItem['id'] ) 1> $null
}

function x509Certificate2ToBase64EncodedPfx {
    [OutputType([String])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $certificate,

        [Parameter()]
        [String] $password=""
    )
    $temporaryFile = New-TemporaryFile

    Export-PfxCertificate -Password (stringToSecureString $password) -Cert $certificate -FilePath $temporaryFile.FullName 1> $null
    $pfxBytes = Get-Content -AsByteStream -ReadCount 0 -LiteralPath $temporaryFile.FullName
    Remove-Item -Force -Path $temporaryFile.FullName  1> $null
    return [System.Convert]::ToBase64String( $pfxBytes )
}

function base64EncodedPfxToX509Certificate2 {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $base64EncodedPfx,

        
        [Parameter()]
        [String] $password=""
    )

    $temporaryFile = New-TemporaryFile
    $pfxBytes = [System.Convert]::FromBase64String($base64EncodedPfx)
    Set-Content  -AsByteStream -Value $pfxBytes -LiteralPath $temporaryFile.FullName 1> $null
    $certificate = Get-PfxCertificate -Password (stringToSecureString $password) -FilePath $temporaryFile.FullName
    # it seems that Get-PfxCertificate returns a certificate that has a non-exportable private key.
    Remove-Item -Force -Path $temporaryFile.FullName  1> $null


    return $certificate
}


function stringToSecureString {
    [OutputType([System.Security.SecureString])]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $in
    )
    return (
        [System.Security.SecureString] $(
            if($in -eq ""){
                (new-object System.Security.SecureString)
            } else {
                ConvertTo-SecureString -String $in -AsPlainText -Force 
            }
        )
    )
}


function sendMail($emailAccount, $from, $to = @(), $cc = @(), $bcc = @(), $subject, $body){
    # unlock the bitwarden vault:
    # unlockTheBitwardenVault

    $bitwardenQueryString = "$emailAccount"
    $rawBitwardenItems = bw --nointeraction --raw list items --search "$bitwardenQueryString"
    #unfortunately, the bitwarden command-line tool's search function does not seem to search in notes or in custom fields.
    $exitCodeOfBitwardenCommand = $LastExitCode
    if ($exitCodeOfBitwardenCommand -ne 0){
        unlockTheBitwardenVault
        $rawBitwardenItems = bw --nointeraction --raw list items --search "$bitwardenQueryString"
    }

    # $bitwardenItems = $rawBitwardenItems | ConvertFrom-Json | Where-Object {$_.name -eq 'AzureAD app password' -and $_.login.username -eq $emailAccount}
    $bitwardenItems = $rawBitwardenItems | ConvertFrom-Json 
    $matchingBitwardenItems = $bitwardenItems | 
        where-object { 
            $_.fields | 
                where-object { 
                    $_.name -eq 'record_type' -and 
                    $_.value -eq 'smtp_mail_sending' 
                } 
        }

    $bitwardenItemContainingEmailCredentials = $matchingBitwardenItems[0]
    if (! $bitwardenItemContainingEmailCredentials ){
        Write-Error "unable to find a Bitwarden item corresponding to the email account $emailAccount"
        return
    }
    
    $explicitAppPassword=@($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'app_password'} | Foreach-object {$_.value})[0]
    $password="$(if($explicitAppPassword){$explicitAppPassword} else {$bitwardenItemContainingEmailCredentials.login.password})"

    <#  TODO 2024-02-08: remove dependence on System.Net.Mail.SmtpClient, which is
        somewhat obsolete.  See
        [https://learn.microsoft.com/en-us/dotnet/api/system.net.mail.smtpclient?view=net-8.0#remarks],
        [https://github.com/dotnet/platform-compat/blob/master/docs/DE0005.md],
        [https://github.com/jstedfast/MailKit].

    #>


    $SMTPClient = New-Object System.Net.Mail.SmtpClient(  
        @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_host'} | Foreach-object {$_.value})[0], 
        @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_port'} | Foreach-object {$_.value})[0] 
    )   
    $SMTPClient.EnableSsl = ([bool] ([int] @($bitwardenItemContainingEmailCredentials.fields | Where-Object {$_.name -eq 'smtp_enable_ssl'} | Foreach-object {$_.value})[0]))    
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($bitwardenItemContainingEmailCredentials.login.username, $password) 
    
    if(-not $from){
        $from=$bitwardenItemContainingEmailCredentials.login.username
    }

    $mailMessage = New-Object Net.Mail.MailMessage
    $mailMessage.From = New-Object System.Net.Mail.MailAddress($from)
    foreach ($address in @($to)){ $mailMessage.To.Add($address) }
    foreach ($address in @($cc)){ $mailMessage.CC.Add($address) }
    foreach ($address in @($bcc)){ $mailMessage.Bcc.Add($address) }
    $mailMessage.Subject = $subject
    $mailMessage.Body = $body
    $result = $SMTPClient.Send($mailMessage)
    Write-Host "result of sending the message: $result"

}

function Send-TestMessage(){
    [CmdletBinding()]
    [OutputType([Void])]
    param (   
        [
            Parameter(
                Mandatory = $True
            )
        ]
        [String] 
        $recipientEmailAddress,

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $emailAccount = "neil@autoscaninc.com",

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $senderEmailAddress = "neil@autoscaninc.com"
    )
    process {
        @{
            emailAccount = $emailAccount
            from         = $senderEmailAddress
            to           =  "$recipientEmailAddress"
            subject      = "test message from $($senderEmailAddress) to $($recipientEmailAddress) $('{0:yyyy/MM/dd HH:mm:ss K}' -f [timezone]::CurrentTimeZone.ToLocalTime((Get-Date)))"
            body         = @( 
                "This is a test message sent from $($senderEmailAddress) to $($recipientEmailAddress).  Please disregard."

                ""
                ""

                "Sincerely,"
                "Neil Jackson"
                "neil@autoscaninc.com"
                "425-218-6726 (cell)"
                "206-282-1616 ext. 102 (office)"
                ""
                "Autoscan, Inc."
                "4040 23RD AVE W"
                "SEATTLE WA 98199-1209"
                "206-282-1616"
            ) -Join "`n"

        } | % { sendMail @_ }
    }
}


function getEnabledServicePlansAssignedToUser{
    [CmdletBinding()]
    [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePlanInfo])]

    Param(
        [string] $userId
    )

    $mgUser = get-mguser -UserId $userId 
    if (! $mgUser ){
        Write-Host "No mgUser having id $userId exists."
        return
    } 


    (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
    % {
        $mgAssignedLicense = $_
        Get-MgSubscribedSku -All  |
        ? {$_.SkuId -ceq $mgAssignedLicense.SkuId} |
        select -expand ServicePlans |
        ? { -not ($_.ServicePlanId -in $mgAssignedLicense.DisabledPlans) } |
        
        # select -expand ServicePlanId |
        # select -unique |


        # this will return multiple identical servicePlans if the service plan
        # is provided by more than one of the licenses assigned to the user.
        write-output
    }
}


function setLicensesAssignedToMgUser{
    
    [CmdletBinding()]
    Param(
        [string] $userId,
        [string[]] $skuPartNumbers,

        [parameter(mandatory=$False) ]
        [string[]] $namesOfDisabledPlans = @()
    )
    
    ##{ #  experiment about default values and casting:
    ##    $x =  $null
    ##    $y = ([string[]] $null)
    ##    $z = ([string[]] @())
    ##
    ##    $null -ceq $x
    ##    $null -ceq $y
    ##    $null -ceq $z
    ##    $y.GetType().FullName
    ##    $z.GetType().FullName
    ##}

    $mgUser = get-mguser -UserId $userId 
    if (! $mgUser ){
        Write-Host "No mgUser having id $userId exists."
        return
    } 

    # to view the available sku part numbers, run the following command:
    ## Get-MgSubscribedSku -All | select -expand SkuPartNumber

    # assign licenses:
    #
    # annoyingly, there does not seem to be a good way to buy licenses
    # programmatically 
    $allMgSubscribedSkus = Get-MgSubscribedSku -All

    $desiredSkuIds = @(
        $allMgSubscribedSkus | 
        ?{ $_.SkuPartNumber -in @($skuPartNumbers) } |
        select -expand SkuId |
        select -unique
    )

    $initialSkuIds = @(
        (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
        select -expand SkuId |
        select -unique
    )

    $initialEnabledServicePlans = @( getEnabledServicePlansAssignedToUser $mgUser.Id )
    $initialIdsOfEnabledServicePlans = ( $initialEnabledServicePlans | select -expand ServicePlanId | select -unique )
    $desiredIdsOfEnabledServicePlans = @(
        $allMgSubscribedSkus |
        ? { $_.SkuId -in $desiredSkuIds } |
        select -expand ServicePlans |
        ? { -not ($_.ServicePlanName -in $namesOfDisabledPlans ) } | 
        select -expand ServicePlanId |
        select -unique
    )



    # Naively, you might think (or desire) that DisabledPlans is something that
    # you would set for the user as a whole, rather than for each
    # AssignedLicense, (or, maybe even better, that there would be non notion of
    # a disabledPlan -- only an assigned plan.)
    #
    # But the API is geared towards having the DisabledPlans be a property of
    # each AssignedLicense.
    #
    # We have to therefore be mindful as we construct as
    # $initialIdsOfDisabledServicePlans -- the ids of the service plans that the
    # user would have were it not for the effect of the DisabledPlans
    # property(s) of the AssignedPlans. The user will have each plan that
    # belongs any of the assigned licenses, unless the id of the plan appears in
    # the DisabledPlans property of each assigned license where the license
    # contains that plan.  It's a bit tricky to think about the any-vs.-all
    # logic.
    #
    # We first construct $initialIdsOfEnabledServicePlans, which we use to help
    # us construct $initialIdsOfDisabledServicePlans .



    Write-Host (
        @(
            "Initially, $($mgUser.UserPrincipalName) has the "
            
            "following $($initialSkuIds.Count) skuPartNumbers: " 

            @( 
                $initialSkuIds | % {skuIdToSkuPartNumber $_}
            ) -Join ", "
            
        ) -join ""
    )

    Write-Host (
        @(
            "Initially, $($mgUser.UserPrincipalName) has the "
            
            "following $($initialEnabledServicePlans.Count) enabled service plans: " 

            @( 
                $initialEnabledServicePlans | 
                select -expand ServicePlanName
            ) -Join ", "
            
        ) -join ""
    )
    
    #ensure that licenses are assigned:
    $skuIdsToRemoveFromUser = @($initialSkuIds | ? {-not ($_ -in $desiredSkuIds)})
    $skuIdsToGiveToUser = @($desiredSkuIds | ? {-not ($_ -in $initialSkuIds)})
    
    
    $idsOfServicePlansToGiveTheUser = @( $desiredIdsOfEnabledServicePlans |?{ -not ($_ -in $initialIdsOfEnabledServicePlans) } )
    $idsOfServicePlansToRemoveFromUser = @( $initialIdsOfEnabledServicePlans |?{ -not ($_ -in $desiredIdsOfEnabledServicePlans) } )





    Write-Host ("skuIdsToRemoveFromUser ($($skuIdsToRemoveFromUser.Count)): ", $skuIdsToRemoveFromUser)
    Write-Host ("skuIdsToGiveToUser ($($skuIdsToGiveToUser.Count)):", $skuIdsToGiveToUser)
    Write-Host ("idsOfServicePlansToGiveTheUser ($($idsOfServicePlansToGiveTheUser.Count)): ", $idsOfServicePlansToGiveTheUser)
    Write-Host ("idsOfServicePlansToRemoveFromUser ($($idsOfServicePlansToRemoveFromUser.Count)):", $idsOfServicePlansToRemoveFromUser)
    


    if($skuIdsToRemoveFromUser -or $skuIdsToGiveToUser -or $idsOfServicePlansToGiveTheUser -or $idsOfServicePlansToRemoveFromUser){
        Write-Host "changing the user's license assignment to match the desired configuration"
        
        # make sure that the user has a UsageLocationn defined
        $intialUsageLocation = (get-mguser -UserId $mgUser.Id -Property @("UsageLocation")).UsageLocation
        if($intialUsageLocation){
            Write-Host (@(
                "$($mgUser.UserPrincipalName) already seems to have a UsageLocation "
                "assigned (namely, `"$($intialUsageLocation)`"), so we will not "
                "bother to set UsageLocation."
            ) -join "")
        } else {
            $newUsageLocation = (Get-MgOrganization).CountryLetterCode
            Write-Host (@(
                "$($mgUser.UserPrincipalName) seems to have "
                "no UsageLocation, so we will set UsageLocation "
                "to `"$($newUsageLocation)`"."
            ) -join "")

            Update-MgUser -UserId $mgUser.Id -UsageLocation $newUsageLocation 1> $null
        }



        @{
            UserId = $mgUser.Id
            RemoveLicenses = $skuIdsToRemoveFromUser
            AddLicenses = (
                ## it doesn't hurt to have a license here that the user already has.  The 
                ## DisabledPlans property will be updated to match whatever we give here.

                # [IMicrosoftGraphAssignedLicense[]]
                @(
                    $desiredSkuIds | 
                    % {
                        $skuId = $_
                        $mgSubscribedSku = $allMgSubscribedSkus |? { $_.SkuId -eq  $skuId }
                        
                        # [IMicrosoftGraphAssignedLicense] 
                        @{
                            DisabledPlans = @(
                                $mgSubscribedSku.ServicePlans |
                                select -expand ServicePlanId |
                                ? {-not ($_ -in $desiredIdsOfEnabledServicePlans)}
                            )
                            SkuId = $mgSubscribedSku.SkuId
                        }

                    }
                )
            )
        } | % { Set-MgUserLicense @_ } 1> $null


        $finalSkuIds = @(
            (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
            select -expand SkuId |
            select -unique
        )

        $finalEnabledServicePlans = @( getEnabledServicePlansAssignedToUser $mgUser.Id )

        Write-Host (
            @(
                "After making changes, $($mgUser.UserPrincipalName) has the "
                
                "following $($finalSkuIds.Count) skuPartNumbers: " 
    
                @( 
                    $finalSkuIds | % {skuIdToSkuPartNumber $_}
                ) -Join ", "
                
            ) -join ""
        )
    
        Write-Host (
            @(
                "After making changes, $($mgUser.UserPrincipalName) has the "
                
                "following $($finalEnabledServicePlans.Count) enabled service plans: " 
    
                @( 
                    $finalEnabledServicePlans | 
                    select -expand ServicePlanName
                ) -Join ", "
                
            ) -join ""
        )





    } else {
        Write-Host "no changes need to be made to the user's licenses."
    }

}

function setSmtpAddressesOfMailbox
{

    <#
	.SYNOPSIS
	effectively deletes and replaces all smtp addresses in the EmailAddresses property of a mailbox.

	.DESCRIPTION

	.EXAMPLE
	setSmtpAddressesOfMailbox `
        -mailboxId "f4476753-3c37-4f09-9d62-64955041c411" `
        -desiredSmtpAddresses @(
            # primary address:
            "john@apples.com",

            #secondary addresses:
            "johnny@apples.com",
            "jdog@apples.com"
        )


	#>

	[CmdletBinding()]

    [OutputType([Void])]

    param (   
        [
            Parameter(
                Mandatory = $True
            )
        ]
        [String] 
        $mailboxId,

        [
            Parameter(
                Mandatory = $False,
                HelpMessage = (
                    "The first element will be taken to be the " + 
                    "desired primary smtp address, unless the "  +
                    " desiredPrimarySmtpAddress argument is "    +
                    "present."
                )
            )
        ]
        [String[]] $desiredSmtpAddresses = @(),

        [
            Parameter(
                Mandatory = $False,
                HelpMessage = (
                    "This argument, if present, will be used to " +
                    "forcefully specify which address shall be "  +
                    "primary, rather than implicitly using the "  +
                    "first element of the desiredSmtpAddresses "  +
                    "array."
                )
            )
        ]
        [String] $desiredPrimarySmtpAddress = $null
    )

    process
    {
        $candidateMailboxes = @(Get-Mailbox -Identity $mailboxId -ErrorAction SilentlyContinue)
        if($candidateMailboxes.Count -ne 1){
            Write-Host (
                "we could not find a single mailbox having " +
                "Identity `"$($mailboxId)`".  Therefore, " + 
                "we will stop here."
            )
            return
        } 
        $mailbox = $candidateMailboxes[0]

        Write-Host "setting the email addresses for the mailbox $($mailbox.Identity)."

        # from the arguments, extract one $primarySmtpAddress
        # and an array of $secondarySmtpAddresses, not containing the $primarySmtpAddress .
        [String] $primarySmtpAddress = $(
            if($desiredPrimarySmtpAddress){
                $desiredPrimarySmtpAddress
            } else {
                $desiredSmtpAddresses[0]
            }
        )

        $desiredEmailAddresses = @(
            "SMTP:$($primarySmtpAddress)"

            $desiredSmtpAddresses |
                ? { 
                    $_ -ne  $primarySmtpAddress 
                    # this is not quite right, because we should be doing
                    # case-insensitive comparison.
                } |
                % {"smtp:$($_)"}
        )

        Write-Host "initially, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        
        $emailAddressesToRemove = @($mailbox.EmailAddresses | where-object {
            ($_ -match '(?i)^SMTP:.+$') -and (-not ($_ -in $desiredEmailAddresses)) 
            # it is an smtp address of some sort and it is not in the desiredEmailAddresses List
        })
        $emailAddressesToAdd = @($desiredEmailAddresses | where-object {
            -not ($_ -in $mailbox.EmailAddresses)
            # it is not already in the mailbox's Email Addresses
        })

        if( ([Boolean] $emailAddressesToRemove) -or ([Boolean] $emailAddressesToAdd) ){
            Write-Host "emailAddressesToRemove ($($emailAddressesToRemove.Count)): ", $emailAddressesToRemove
            Write-Host "emailAddressesToAdd ($($emailAddressesToAdd.Count)): ", $emailAddressesToAdd
            $emailAddressesArg = (
                $(
                    if($emailAddressesToRemove.Count -gt 0){
                        @{ Remove=@($emailAddressesToRemove) }
                    } else {
                        @{}
                    }
                ) + 
                $(
                    if($emailAddressesToAdd.Count -gt 0){
                        @{ Add=@($emailAddressesToAdd) }
                    } else {
                        @{}
                    }
                )
            )

            Write-Host "`$emailAddressesArg: $($emailAddressesArg | format-list | Out-String)"
            
            # in the case where $emailAddressesToAdd is empty or
            # $emailAddressesToRemove is empty (or mayube they both have to be
            # empty?), the Set-Mailbox command throws the following  error.
            # Therefore, we have to take pains to avoid passing an empty list.
            #
            # Set-Mailbox: Cannot process argument transformation on parameter
            # 'EmailAddresses'. Cannot convert value
            # "System.Collections.Generic.Dictionary`2[System.String,System.Object]"
            # to type "Microsoft.Exchange.Data.ProxyAddressCollection". Error:
            # "MultiValuedProperty collections cannot contain null values.
            
            @{
                Identity = $mailbox.Guid
                EmailAddresses = $emailAddressesArg
            } | % {Set-Mailbox @_} 

            $mailbox =  Get-Mailbox -Identity $mailbox.Guid
            Write-Host "finally, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        } else {
            Write-Host "email addresses for $($mailbox.Identity) are as desired, so we will not bother to add or remove any."
        }  
    }
}



function grantUserAccessToMailbox(
    $idOfUserToBeGrantedAccess, 
    $idOfMailbox, 
    $sendInstructionalMessageToUsersThatHaveBeenGrantedAccess=$False, 
    $emailAccountForSendingAdvisoryMessages="neil@autoscaninc.com", 
    $dummyAddressForAdvisoryMessages="administrator@autoscaninc.com",
    $sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress=$False,
    $createInboxRuleToRedirect=$False
){


    $mgUserToBeGrantedAccess = Get-MgUser -UserId $idOfUserToBeGrantedAccess
    $mailbox = Get-Mailbox -ID $idOfMailbox

    Write-Host "now giving the user $($mgUserToBeGrantedAccess.UserPrincipalName) full access to the mailbox $($mailbox.PrimarySmtpAddress)."

    Remove-MailboxPermission -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue
    # we first remove any existing permission, as a way (apparently, this is the only way) to be sure that Automapping is turned off
    Add-MailboxPermission    -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Automapping:$false 
    Add-RecipientPermission  -Identity $mailbox.Id   -Trustee $mgUserToBeGrantedAccess.Id -AccessRights SendAs  -confirm:$false

    if($createInboxRuleToRedirect){
        $nameOfInboxRule = "redirect to $($mgUserToBeGrantedAccess.Mail) 5146a9a247d64ef9ba6dcfd1057e00e3"
        Remove-InboxRule -confirm:$false -Mailbox $mailbox.Id -Identity $nameOfInboxRule -ErrorAction SilentlyContinue
        $s = @{
            Mailbox                    = $mailbox.Id 
            Name                       = $nameOfInboxRule      
            RedirectTo                 = $mgUserToBeGrantedAccess.Mail
            StopProcessingRules        = $False
        }; New-InboxRule @s
    }


    # send an email to the user informing them that they now have full access to the mailbox and how to access it.
    $mgUserToBeAdvised = $mgUserToBeGrantedAccess
    $recipientAddress = ($mgUserToBeAdvised.DisplayName + "<" + $mgUserToBeAdvised.Mail + ">")
    if($sendInstructionalMessageToUsersThatHaveBeenGrantedAccess){
        $messageBodyLines = @()
        $messageBodyLines += 
            @( 
                "Dear $($mgUserToBeAdvised.DisplayName), " 

                ""

                "You now have full access to the $($mailbox.PrimarySmtpAddress) mailbox."

                ""

                "You can access this mailbox's webmail interface at https://outlook.office.com/mail/$($mailbox.PrimarySmtpAddress) ."

                ""

                "If so desired, you can add this mailbox to the left sidebar of "    + `
                "Outlook on your computer by doing the following: Within Outlook, "  + `
                "go to File -> Account Settings -> Account Settings -> Change -> "   + `
                " More Settings -> Advanced -> Add .  Then, type " + `
                "'$($mailbox.PrimarySmtpAddress)' as the address of the mailbox that you want to add."

                ""
            )

        if($createInboxRuleToRedirect){
            $messageBodyLines += 
                @( 

                    "In addition to you having full access to the $($mailbox.PrimarySmtpAddress) mailbox, " +
                    "there is an Inbox Rule within the $($mailbox.PrimarySmtpAddress) mailbox " +
                    "that is causing a copy of any message sent to that mailbox to be deposited in your inbox.  " +
                    "If so desired, you can delete the Inbox Rule in the web interface at " + 
                    "https://outlook.office.com/mail/$($mailbox.PrimarySmtpAddress)/options/mail/rules .  " +
                    "The name of the Inbox Rule is `"$($nameOfInboxRule)`".  " +
                    "Deleting the Inbox Rule will cause the automatic forwarding of messages to stop, but will " + 
                    "have no effect on your ability to access the mailbox."

                    ""
                )
        }

        $messageBodyLines += 
            @( 
                ""
                "Sincerely,"
                "Neil Jackson"
                "neil@autoscaninc.com"
                "425-218-6726 (cell)"
                "206-282-1616 ext. 102 (office)"
                ""
                "Autoscan, Inc."
                "4040 23RD AVE W"
                "SEATTLE WA 98199-1209"
                "206-282-1616"
            )
        $messageBody = $messageBodyLines -Join "`n"
        $xx = @{
            emailAccount = $emailAccountForSendingAdvisoryMessages
            from         = $emailAccountForSendingAdvisoryMessages
            to           = $(if($sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress){$dummyAddressForAdvisoryMessages} else {$recipientAddress})
            subject      = $(if($sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress){"(TO: $recipientAddress) " } else {""} ) + "$($mgUserToBeAdvised.DisplayName) now has full access to the $($mailbox.PrimarySmtpAddress) mailbox"
            body         = $messageBody
        } ; sendMail @xx
    }


}



## thanks to https://stackoverflow.com/questions/3281999/format-list-sort-properties-by-name
function Format-SortedList
{
    [OutputType([String[]])]
    

    #Todo: deal properly with multiple pipeline inputs.
    # allow user to pass arguments in to the underlying calls to format-list and sort-object.

    param (
        [Parameter(ValueFromPipeline = $true)]
        [Object]$InputObject

        # [Parameter(Mandatory = $false)]
        # [Switch]$Descending
    )

    process
    {
        # $properties = $InputObject | Get-Member -MemberType Properties

        # if ($Descending) {
        #     $properties = $properties | Sort-Object -Property Name -Descending
        # }

        # $longestName = 0
        # $longestValue = 0

        # $properties | ForEach-Object {
        #     if ($_.Name.Length -gt $longestName) {
        #         $longestName = $_.Name.Length
        #     }

        #     if ($InputObject."$($_.Name)".ToString().Length -gt $longestValue) {
        #         $longestValue = $InputObject."$($_.Name)".ToString().Length * -1
        #     }
        # }

        # Write-Host ([Environment]::NewLine)

        # $properties | ForEach-Object { 
        #     Write-Host ("{0,$longestName} : {1,$longestValue}" -f $_.Name, $InputObject."$($_.Name)".ToString())
        # }


        $initialOutputRendering = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::Ansi
        # $x = ($InputObject | fl | Out-String -Width 999999) -split "`n" | Sort-Object
        $x = @(($InputObject | fl | Out-String) -split "`n" | Sort-Object)
        $PSStyle.OutputRendering = $PSStyle.OutputRendering
        $x
    }
}



#see https://docs.microsoft.com/en-us/answers/questions/3572/change-aad-joined-windows-10-device-ownership-with.html
function setAzureAdDeviceOwner ( $nameOfDevice, $nameOfUser ){
    
    $azureAdDevice=@(Get-AzureADDevice -All 1 | where-object {
            $_.DisplayName -eq $nameOfDevice  # -and $_.DeviceTrustType -eq "AzureAd" 
    })[0]

    $azureAdUser = Get-AzureADUser -ObjectID $nameOfUser

    $existingOwner = Get-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId

    Write-Output "initially, registered owner of $($azureAdDevice.DisplayName): $($existingOwner.UserPrincipalName)"

    if( $existingOwner -and ($existingOwner.Length -eq 1 ) -and ($existingOwner.ObjectID -eq $azureAdUser.ObjectID) ){
        Write-Output "owner is already as desired.  $($existingOwner.UserPrincipalName) owns $($azureAdDevice.DisplayName)"
    } else {
        Write-Output "owner is not as desired, so we will change"

        if ($existingOwner){
            Write-Output "removing the exsting owner(s)"
            foreach ($x in $existingOwner){
                Write-Output "removing the exsting owner $($x.UserPrincipalName)"
                Remove-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId -OwnerId $x.ObjectId
            }
        }

        $s = @{
            ObjectId=$azureAdDevice.ObjectId
            RefObjectId=$azureAdUser.ObjectId
        }; Add-AzureADDeviceRegisteredOwner @s 
    }



    Write-Output (
        "Finally, registered owner of $($azureAdDevice.DisplayName): " +
        (
            Get-AzureADDeviceRegisteredOwner -ObjectId $azureAdDevice.ObjectId
        ).UserPrincipalName
    )



}


function blipNetworkAdapter(){
    # blips any currently-enabled and connected network adapters

    foreach (
        $netAdapter in 
        (
            Get-NetAdapter 
        )
    ){
        Write-Host "now processing netadpater: $($netAdapter.Name)"

        if ( ($netAdapter.AdminStatus -eq "Up") -and ($netAdapter.ifOperStatus -eq "Up") ){
            Write-Host "netadapter $($netAdapter.Name) is enabled and connected, so we will poke at it."

            $netConnectionProfile = $null
            $netConnectionProfile = Get-NetConnectionProfile -InterfaceAlias $netAdapter.Name -ErrorAction SilentlyContinue
            if($netConnectionProfile ){
                Write-Host( "netConnectionProfile: $($netConnectionProfile | Out-String )")
            }

            Disable-NetAdapter -Confirm:0 -InputObject $netAdapter 
            Start-Sleep 1
            Enable-NetAdapter -Confirm:0 -InputObject $netAdapter

        } else {
            Write-Host "netadapter $($netAdapter.Name) is not both enabled and connected, so we will not touch it."
        }



    }
}


function convertRedirectEntryToEmailAddress($redirectEntry){
    # redirectEntry is expected to be a string like the members
    # of an InboxRule's RedirectTo property.

    # we expect redirectEntry to resemble one of the following examples:
    #   example 1: $redirectEntry == '"John Doe" [SMTP:jdoe@acme.com]'
    #   example 2: $redirectEntry == '"John Doe" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe]'
    #   example 3: $redirectEntry == '/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe'
    #   example 4: $redirectEntry == 'jdoe@acme.com'


    $pattern='^(?:"(?<displayName>[^"]*)"\s*\[(?<protocol>[^:]*):(?<address>.*)\]|(?<address>.*))$'
    #when we apply $pattern to redirectEntry, the matching groups will pull out
    # the part between quotes (i.e. the Display name), the protocol name, and
    # the address, respectively. we want to extract, from redirectEntry, three
    # strings: displayName, protocol, and address . We actually don't care about
    # displayName or protocol. Then, we operate on the address with
    # {(Get-Recipient -Identity $args[0]).PrimarySmtpAddress} If this gives a result,
    # we return it.  Else (i.e. in case of Exception or null result), we return
    # address.
    
    # in the case of example 1, the matching groups will be:
    #   - $1: John Doe
    #   - $2: SMTP
    #   - $3: jdoe@acme.com    
    
    # in the case of example 2, the matching groups will be:
    #   - $1: John Doe
    #   - $2: EX
    #   - $3: /o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=39e06be27d4a4e3e813d7ea40b95fa3f-jdoe  
    
    # in case of example 3 or 4, the match will fail, so we take address to be the entire $redirectEntry
    
    #in either case, we can attempt to "convert the address to SMTP by attempting to do (Get-Recipient $3).primarySMTPAddress
    # if this throws a "couldn't find" error, then we return $3 as is.
    $matches = $null
    $result = $redirectEntry -match $pattern
    # we have designed our pattern so that it will match any string.


    $resolvedRecipientSMTPAddress = (Get-Recipient -Identity $matches['address']).PrimarySmtpAddress  2>$null
    $resolvedMailboxSMTPAddress = (Get-Mailbox -Identity $matches['address']).PrimarySmtpAddress  2>$null
    if($resolvedRecipientSMTPAddress){
        $resolvedRecipientSMTPAddress
    } elseif( $resolvedMailboxSMTPAddress) {
        $resolvedMailboxSMTPAddress
    } elseif($matches['address']) {
        $matches['address']
    } else {
        $redirectEntry
    }

    $returnValue
}

function skuIdToSkuPartNumber($skuId){
    # ( Get-AzureADSubscribedSku | where-object { $_.SkuId -eq $skuId }).SkuPartNumber
    ( Get-MgSubscribedSku | where-object { $_.SkuId -eq $skuId }).SkuPartNumber
}
 

function deduplicate($list){
    # returns a new list that is a copy of the input list, but with only the
    # first occurence of each member retained.
    
    $returnValue = @()

    foreach ($item in $list){
        if(-not ($returnValue -contains $item)){
            $returnValue += $item
        }
    }

    $returnValue
}

function addEntryToPSModulePathPersistently($pathEntry){
    $existingPathEntries = @(([Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')) -Split ([IO.Path]::PathSeparator) | Where-Object {$_})
    $desiredPathEntries = deduplicate($existingPathEntries + $pathEntry)


    [Environment]::SetEnvironmentVariable(
        'PSModulePath', 
        ([String]::Join([IO.Path]::PathSeparator, $desiredPathEntries)),
        'Machine'
    )

}


# I grabbed this function from a google search.  Todo: inspect it, clean it, delete it if possible.
function Test-SubPath
{
	<#
	.SYNOPSIS
	Tests whether one path is a subpath of another.

	.DESCRIPTION
	Tests whether one path is a subpath of another.
	The values passed in are compared as file path strings.
	An optional switch allows for checking of the physical existence of the paths.

	.PARAMETER ChildPath
	The path of the child item.

	.PARAMETER ParentPath
	The path of the parent item.

	.PARAMETER Physical
	When the Physical switch is used, the output will be true only if the child item (and therefore also the parent item) actually exists.

	.EXAMPLE
	## Test paths as strings ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistentFolder'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath
	True

	# Returns True because the parent path is a subpath of the child path.

	.EXAMPLE
	## Test paths as strings ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistent'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath
	False

	# Returns False because, although the parent path is a substring of the child path, it is not a subpath.

	.EXAMPLE
	## Test paths as strings and check existence ##

	PS C:\> $childPath  = 'C:\NonExistentFolder\NonExistentFile.txt'
	PS C:\> $parentPath = 'C:\NonExistentFolder'
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath -Physical
	False

	# Returns False because, although the parent path is a subpath of the child path, the child item does not exist.

	.EXAMPLE
	## Test paths as strings and check existence ##

	PS C:\> $childPath  = $Env:HOME
	PS C:\> $parentPath = "$Env:HOMEDRIVE\"
	PS C:\> Test-SubPath -ChildPath $childPath -ParentPath $parentPath -Physical
	True

	# Returns True because the parent path is a subpath of the child path and the child item (and therefore the parent item) exists.

	.INPUTS
	[System.String]
	Accepts string objects via the ChildPath parameter. The output of Get-ChildItem can be piped into Test-SubPath.

	.OUTPUTS
	[System.Boolean]
	Returns a boolean (true/false) object.

	.NOTES
	Author : nmbell

	.LINK
	Test-PowdrgitPath
	.LINK
	about_powdrgit
	.LINK
	https://github.com/nmbell/powdrgit/blob/main/help/about_powdrgit.md
	#>

	# Use cmdlet binding
	[CmdletBinding()]

	# Declare output type
	[OutputType([System.Boolean])]

	# Declare parameters
	Param
	(


		[Parameter(
	  	  Mandatory                       = $false
	  	, Position                        = 0
	  	, ValueFromPipeline               = $true
	  	, ValueFromPipelineByPropertyName = $true
	  	)]
		[Alias('FullName','Path')]
		[String]
		$ChildPath

	,	[Parameter(
	  	  Mandatory                       = $false
	  	, Position                        = 1
	  	, ValueFromPipeline               = $false
	  	, ValueFromPipelineByPropertyName = $true
	  	)]
		[String]
		$ParentPath

	,	[Switch]
		$Physical
	)

	BEGIN
	{
		# $bk = 'B'

		# Common BEGIN:
		Set-StrictMode -Version 3.0
		# $thisFunctionName = $MyInvocation.MyCommand
		# $start            = Get-Date
		# $indent           = ($Powdrgit.DebugIndentChar[0]+'   ')*($PowdrgitCallDepth++)
		$PSDefaultParameterValues += @{ '*:Verbose' = $(If ($DebugPreference -notin 'Ignore','SilentlyContinue') { $DebugPreference } Else { $VerbosePreference }) } # turn on Verbose with Debug
		# Write-Debug "  $(ts)$indent[$thisFunctionName][$bk]Start: $($start.ToString('yyyy-MM-dd HH:mm:ss.fff'))"

		# Function BEGIN:
	}

	PROCESS
	{
		# $bk = 'P'

		$result = $false

		If ($ChildPath.Trim() -and $ParentPath.Trim())
		{
			# Test by the string values of the paths
			$testPath = $ChildPath
			Do {
				If ($testPath -eq $ParentPath)
				{
					$result = $true
					Break
				}
				$testPath = Split-Path -Path $testPath -Parent
			} While ($testPath)

			# Test for physical existence
			If ($result -and $Physical)
			{
				$result = Test-Path -Path $ChildPath
			}
		}

		Write-Output $result
	}

	END
	{
		# $bk = 'E'

		# Function END:

		# Common END:
		# $end      = Get-Date
		# $duration = New-TimeSpan -Start $start -End $end
		# Write-Debug "  $(ts)$indent[$thisFunctionName][$bk]Finish: $($end.ToString('yyyy-MM-dd HH:mm:ss.fff')) ($($duration.ToString('d\d\ hh\:mm\:ss\.fff')))"
		# $PowdrgitCallDepth--
	}
}


function getReferencedAssembliesRecursivelyForReflection([System.Reflection.Assembly] $rootAssembly, $filter={$true}, [String[]] $pathHints = @(), $accumulatedNames = ([System.Collections.ArrayList] @())){
    # write-host "now processing $($rootAssembly.FullName)"
    # the passed assembly is assumed to be in its own "private": load context that we are free to pollute.
    # therefore, when calling this function, you shjould load the rooitAssembly especially in a temporary load context just to be polluted by this function.
    $referencedAssemblyNames = $rootAssembly.GetReferencedAssemblies() 
    

    
    
    foreach(
        $assembly in $(
            @(
                $rootAssembly

                $rootAssembly.GetReferencedAssemblies() | 
                    % {
                        [System.Reflection.AssemblyName] $assemblyName = $_

                        
                        # (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyName($_)
                        try {
                            & {
                                $private:ErrorActionPreference = "Stop"
                                # [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($rootAssembly).LoadFromAssemblyName($assemblyName)
                                (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyName($assemblyName) 2> $null
                            }
                        } catch {
                            # in this case, the runtime has been unable to load
                            # the assembly based on its AssemblyName alone, so
                            # we will look in the pathHints (should we be doing
                            # pathHints first?)
                            $pathsOfMatchingCandidateDllFiles = @(
                                $pathHints |
                                    foreach-object {
                                        (Get-ChildItem `
                                            -Path $_ `
                                            -Recurse `
                                            -File `
                                            -Include "*.dll" 
                                        ) | foreach-object {$_.FullName}
                                    } | 
                                    where-object {
                                        try{
                                            & {
                                                $private:ErrorActionPreference = "Stop"
                                                ([System.Reflection.Assembly]::LoadFile($_)).FullName -eq $assemblyName.FullName 2> $null
                                            }
                                        } catch {
                                            $False
                                        }
                                    }
                            )

                            # (Get-ChildItem `
                            #     -Path (join-path $pathOfRootFolderOfExchangeModule "netCore") `
                            #     -Recurse `
                            #     -Include "*.dll" 
                            # ) | foreach-object {$_.FullName}

                            if($pathsOfMatchingCandidateDllFiles ){
                                (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyPath($pathsOfMatchingCandidateDllFiles[0])
                            }

                        }
                    } 
            ) | where-object $filter 
        )
    ){
        if( -not ($assembly.FullName -in $accumulatedNames ) ){
            # Write-Host "emitting: $($assembly.FullName)"
            $assembly
            $accumulatedNames.Add($assembly.FullName) 1> $null
            # write-host "`$accumulatedNames.Count:  $($accumulatedNames.Count)"
            getReferencedAssembliesRecursivelyForReflection -rootAssembly $assembly -filter $filter -accumulatedNames $accumulatedNames
        }
    }
    
    # $referencedAssemblies | where-object $filter 
}


function getAmazonAddToCartUrl {
    [OutputType([String])]
    
    #example:
    # getAmazonAddToCartUrl @(
    #   ,@("B09S9VWQK1", 1) # NVIDIA RTX A4500 video card ($1145)
    #   ,@("B0BHJF2VRN", 1) # Samsung 990 PRO 1TB PCIe NVMe  SSD M.2
    # )

    param (
        [Parameter()]
        [Object[][]] $asinQuantityPairs

        # [Parameter(Mandatory = $false)]
        # [Switch]$Descending
    )

    # Amazon add-to-cart URL syntax:
    # (see https://webservices.amazon.com/paapi5/documentation/add-to-cart-form.html)
    $url = "https://www.amazon.com/gp/aws/cart/add.html?" + (
            @(
                for ($i=0; $i -lt $asinQuantityPairs.count; $i++ ){
                    if($asinQuantityPairs[$i][1]){
                        "ASIN.$($i+1)=$($asinQuantityPairs[$i][0])"
                        "Quantity.$($i+1)=$($asinQuantityPairs[$i][1])"
                    }
                }
            ) -join "&"
        )

    # Set-Clipboard -Value $url
    $url
}


function sendTestMessage([String] $recipient){
    @{
        emailAccount = "neil@autoscaninc.com"
        from         = "neil@autoscaninc.com"
        to           =  "$recipient"
        subject      = "test message sent to $($recipient) $('{0:yyyy/MM/dd HH:mm:ss K}' -f [timezone]::CurrentTimeZone.ToLocalTime((Get-Date)))"
        body         = @( 
            "This is a test message sent to $($recipient).  Please disregard."

            ""
            ""

            "Sincerely,"
            "Neil Jackson"
            "neil@autoscaninc.com"
            "425-218-6726 (cell)"
            "206-282-1616 ext. 102 (office)"
            ""
            "Autoscan, Inc."
            "4040 23RD AVE W"
            "SEATTLE WA 98199-1209"
            "206-282-1616"
        ) -Join "`n"

    } | % { sendMail @_ }
}

function expandArchiveFile {
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [parameter()]
        [string] $pathOfArchiveFile,

        [parameter(Mandatory=$false)]
        [string] $pathOfDirectoryInWhichToExpand = $null
    )
    

    if( ($null -eq $pathOfDirectoryInWhichToExpand) -or ("" -ceq $pathOfDirectoryInWhichToExpand)  ){
        $pathOfDirectoryInWhichToExpand = [string] (join-path $env:temp (new-guid).guid)
    }

    New-Item -ItemType "directory" -Path $pathOfDirectoryInWhichToExpand -Force | out-null

    
    7z @(
        # eXtract files with full paths    
        "x"

        #Recurse subdirectories for name search
        "-r"

        #-y : assume Yes on all queries
        "-y" 
        
        # -o{Directory} : set Output directory
        "-o$($pathOfDirectoryInWhichToExpand)" 
        
        # <archive_name>
        "$pathOfArchiveFile" 
        
        # <file_names>...
        "*"
    ) | write-host
    return $pathOfDirectoryInWhichToExpand
}


function downloadAndExpandArchiveFile{
    <#
    .SYNOPSIS
    returns the path of the directory in which the arcvhie file was expanded.
    
    .PARAMETER url
    Parameter description
    
    .PARAMETER pathOfDirectoryInWhichToExpand
    Parameter description
    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [parameter()]
        [string] $url,

        [parameter(Mandatory=$false)]
        [string] $pathOfDirectoryInWhichToExpand = $null
    ) 
    
    
    
    # $localPathOfArchiveFile = (join-path $env:temp (New-Guid).Guid)
    # Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile

    # #hack to avoid redownloading:
    # $localPathOfArchiveFile = (join-path (join-path $env:temp "549b0588649a4cb19217ed6fe46c97e4") (split-path $url -leaf))
    # New-Item -ItemType "directory" -Path (Split-Path $localPathOfArchiveFile -Parent) -ErrorAction SilentlyContinue 
    # if(-not (Test-Path -Path $localPathOfArchiveFile -PathType leaf) ){
    #     Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile
    # }

    # New-Item -ItemType "directory" -Path (Split-Path $localPathOfArchiveFile -Parent) -ErrorAction SilentlyContinue 
    # Invoke-WebRequest -Uri $url  -OutFile $localPathOfArchiveFile
    
    # $localPathOfArchiveFile = downloadFileAndReturnPath $url
    
    # New-Item -ItemType "directory" -Path $pathOfDirectoryInWhichToExpand -ErrorAction SilentlyContinue | out-null
    # 7z @(
    #     # eXtract files with full paths    
    #     "x"

    #     #Recurse subdirectories for name search
    #     "-r"

    #     #-y : assume Yes on all queries
    #     "-y" 
        
    #     # -o{Directory} : set Output directory
    #     "-o$($pathOfDirectoryInWhichToExpand)" 
        
    #     # <archive_name>
    #     "$localPathOfArchiveFile" 
        
    #     # <file_names>...
    #     "*"
    # ) | write-host

    # return ([string] $pathOfDirectoryInWhichToExpand)

    return (expandArchiveFile -pathOfArchiveFile (downloadFileAndReturnPath $url) -pathOfDirectoryInWhichToExpand $pathOfDirectoryInWhichToExpand)
}

function downloadFileAndReturnPath {
    <#
    .SYNOPSIS
    Downloads the file from the specified url, to an arbitrary local path
    (arbitrary as far as the caller is concerned, although in fact there is some
    logic to the choice of the destination path). Returns the path of the
    downloaded file.


    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [parameter()]
        [String] $urlOfFile,

        [parameter(mandatory=$False)]
        [string] $hash = "",

        [parameter(mandatory=$False)]
        [string] $hashAlgorithm = "SHA256"

    ) 

    $hash = $hash.ToLower()
    $nameOfDownloadCacheFolder = "3c3562b4c6e84f3a92d110d2da9e08aa"
    # this is a name intended to be specific to this function.
    $pathOfDownloadCacheFolder = (join-path $env:temp $nameOfDownloadCacheFolder)
    $pathOfDedicatedInitialDirectoryToContainDownloadedFile = (join-path $env:temp (new-guid).Guid)
    
    $finalPathOfDownloadedFile = $null
    $hashOfDownloadedFile = $null
    if($hash){  
        Write-Host "checking for already-downloaded files having the specified hash ($hash)"
        # attempt to find an already downloaded file having the specified hash      
        $finalPathOfDownloadedFile =  @(
            if(Test-Path -PathType Container -Path (join-path $pathOfDownloadCacheFolder $hash)){
                gci -file -force (join-path $pathOfDownloadCacheFolder $hash)
            }
        ) | 
        select -expand FullName |
        ? { (Get-FileHash -Algorithm $hashAlgorithm -Path $_).Hash.ToLower() -eq $hash } |
        select -first 1

        if($finalPathOfDownloadedFile){
            Write-Host "found an already-downloaded file ($finalPathOfDownloadedFile) having the specified hash ($hash)."
            $hashOfDownloadedFile = $hash
            # this is a shortcut to avoid recomputing the hash, because, due to
            # the test above, we are already guaranteed that $hash is the hash
            # of the file whose path is $finalPathOfDownloadedFile
        } else {
            Write-Host (-join @(
                "Found no already-downloaded files having the specified hash ($hash).  "
                "Therefore we will have to download anew."
            ))
        }
    }

    if(-not $finalPathOfDownloadedFile){
        New-Item -Force -ItemType Directory $pathOfDedicatedInitialDirectoryToContainDownloadedFile  | out-null
        curl @(
            # "--progress-bar"
            "--remote-name"
            # "--verbose"

            "--remote-header-name"

            # follow redirects:
            "--location"

            # "--header"; 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0'
            
            # "--cookie-jar";$pathOfCookieJarFile
            # "--cookie";$pathOfCookieJarFile  
            # "--cookie"; "`"`""
            # "--cookie"; "$(new-guid)" # a bogus filename guaranteed not to exist
            # "--cookie"; "6fc3c91bf2da4921b775ce3406c549c3=643c8f63135847ee85c130555d3f2441" # a bogus filename guaranteed not to exist
            
            # this option causes curl to use its internal cookie engine to store and
            # transmit cookies between requests.  
            #
            # I do not know how to 
            #
            # The --cookie option causes curl to use its internal cookie engine to
            # store and transmit cookies between requests.  I added this option on
            # 2023-10-26-1708 in order to allow curl to be able to download public
            # files from sharing urls generated by sharepoint.
            #
            # I want to tell curl to use its cookie engine, but don't read from any
            # cookie file.  Rather, start with an empty cache and fill it as you go.
            #
            # But unfortunately, there doesn;t seem to be a straightforward way to
            # do this.  Curl's --cookie option expects to be a value.  If the value
            # contains an equals sign, curl treats it as a literal cookie value,
            # otherwise curl treats it as the ath of a file from which the cookie
            # cache is to be read from (but not written to).
            #
            # I have settled on passing a randomly-generated fresh guid as the
            # value.  This will hopefully be a file that never exists.
            "--cookie"; "$(new-guid)"

            ## "--write-out"; @(
            ##     @(
            ##         "redirect_url"
            ##         "url"
            ##         "filename_effective"
            ##         "urle.path"
            ##     ) |% {"$($_): %{$($_)}"} 
            ## ) -join "`n"


            "--output-dir";$pathOfDedicatedInitialDirectoryToContainDownloadedFile
            $urlOfFile
        )

        <#  2024-03-10-1437: I notice that in the case where there is no
            Content-Disposition header and there is a redirect, curl derives the
            output filename not from the final url in the redirect chain, as you
            might naively expect (and as I would have hoped), but rather derives
            the output file name from the passed-in url.

            This stack overflow post is, I think, complaining about this same
            issue:
            https://stackoverflow.com/questions/6881034/curl-to-grab-remote-filename-after-following-location.

            We might consider a workaround to achieve the desired behavior by
            using curl's --write-output option to have curl write, to stdout,
            the "urle.path" value (see
            [https://curl.se/docs/manpage.html#urlepath]), from which we could
            compute a reasonable file name.  We would also need to do something
            (probably involving more --write-output stuff) to detect when curl
            has pulled the filename from the Content-Disposition header, because
            in that case, in general, we would not want to derive the filename
            from the final url in the redirct chain.
        #>

        # $initialPathOfDownloadedFile = (join-path $pathOfDedicatedInitialDirectoryToContainDownloadedFile $filenameOfDownloadedFile)
        $initialPathOfDownloadedFile = Get-ChildItem -File $pathOfDedicatedInitialDirectoryToContainDownloadedFile | select -first 1 | select -expand FullName

        $hashOfDownloadedFile = Get-FileHash -Algorithm $hashAlgorithm -Path $initialPathOfDownloadedFile | select -expand Hash |% {$_.ToLower()}
        $finalPathOfDownloadedFile = (join-path (join-path $pathOfDownloadCacheFolder $hashOfDownloadedFile) (split-path -leaf $initialPathOfDownloadedFile) )
        New-Item -ItemType Directory -Force (split-path -parent $finalPathOfDownloadedFile) | out-null
        Move-Item -force $initialPathOfDownloadedFile $finalPathOfDownloadedFile

        if($hash -and (-not ($hashOfDownloadedFile -eq $hash))){
            Write-Host "The hash of the downloaded file ($finalPathOfDownloadedFile) ($hashOfDownloadedFile) does not match the specified hash ($hash)."
        }
    }

    if((-not $hash) -or ($hash -eq $hashOfDownloadedFile)){
        return $finalPathOfDownloadedFile
    } else {
        # in this case, the user has specified a hash, but the hash of the
        # downloaded file is not equal to the specified hash.  This is a
        # failure, so we do not return a value.

        # return $null
    }
}

function getPathOfPossiblyNestedFileMatchingPattern{
    <#
        given a pathOfFile and a globPattern: if pathOfFile matches globPattern,
        return pathOfFile.  Else, try to treat $pathOfFile as an archive file.
        Extract the contents of the file and, if, among the contained files,
        there is exactly one file whose name matches filenameRegex, then return
        the path of that file (in its temporary location, extracted).

        This function is useful in case we have a path of a file that might
        itself be, for instance, an .iso file, or it might be an archive file
        containing an iso file, and in either case, we want the path to the .iso
        in our file system, extracting it from the archive file if necessary.)

        TODO (maybe): allow arbitrarily deep nesting.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [parameter()]
        [String] $pathOfFile,

        [parameter()]
        [string] $filenameRegex
    ) 

    if((split-path -leaf $pathOfFile) -match $filenameRegex){
        return $pathOfFile
    } else {
        $pathsOfCandidateNestedFiles = @(
            gci (expandArchiveFile $pathOfFile) -force -recurse -file |
            select -expand FullName |
            ? { (split-path -leaf $_) -match $filenameRegex }
        )
        if($pathsOfCandidateNestedFiles.Count -eq 1){
            return $pathsOfCandidateNestedFiles[0]
        }
    }

}

function installGoodies_deprecated([System.Management.Automation.Runspaces.PSSession] $session){
    Invoke-Command $session {  #ensure that chocoloatey is installed, and install other goodies
        & { #ensure that chocoloatey is installed
            
            #!ps
            #timeout=1800000
            #maxlength=9000000

            Set-ExecutionPolicy Bypass -Scope Process -Force  
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))  
            choco upgrade --acceptlicense --confirm chocolatey  
    
            #ensure that 7zip is installed
            choco install --acceptlicense -y 7zip  
            choco upgrade --acceptlicense -y 7zip 
    
            #ensure that pwsh is installed
            choco install --acceptlicense -y pwsh  
            choco upgrade --acceptlicense -y pwsh  
    
            choco install --acceptlicense -y --force "winmerge"
            choco install --acceptlicense -y --force "spacesniffer"
            choco install --acceptlicense -y --force "notepadplusplus"
            choco install --acceptlicense -y --force "sysinternals"
            # choco install --acceptlicense -y --force "cygwin"
            
            choco install --acceptlicense -y --force "hdtune"
        }
    
    
    }
}


function installGoodies(){
    <#
    .SYNOPSIS
    To run this in a remote session $s, do 
    invoke-command $s -ScriptBlock ${function:installGoodies} 
    or
    invoke-command $s { invoke-expressions ${using:function:installGoodies} } 

    # see [https://stackoverflow.com/questions/14441800/how-to-import-custom-powershell-module-into-the-remote-session]
    # see [https://mkellerman.github.io/Import_custom_functions_into_your_backgroundjob/]
    # see [https://stackoverflow.com/questions/30304366/powershell-passing-function-to-remote-command]
    # see [https://stackoverflow.com/questions/2830827/powershell-remoting-using-imported-module-cmdlets-in-a-remote-pssession]
    # see [https://serverfault.com/questions/454636/how-can-i-use-shared-functions-in-a-remote-powershell-session]
    #>

    & { #ensure that chocolatey is installed, and install other goodies
        
        #!ps
        #timeout=1800000
        #maxlength=9000000

        Set-ExecutionPolicy Bypass -Scope Process -Force  
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))  
        
        @(
            "chocolatey"
            "7zip"
            "pwsh"
            "winmerge"
            "spacesniffer"
            "notepadplusplus"
            "sysinternals"
            "hdtune"
        ) | % {choco upgrade --acceptlicense --yes $_}

        # "upgrade" installs if it is not already installed, so we do not need
        # to do both "install" and "upgrade"; "upgrade" on its own will ensure
        # that we end up with the latest version installed regardless of the
        # initial condition.
    }
}


function runElevatedInActiveSession{
    <#
        .SYNOPSIS
        This is a hack on several levels that gets the job done.  Given a powershell session (typically a remote session),
        this command runs psexec on the remote computer with the arguments passed to this function.

        To run this in a remote session $s, do 
        
        icm $s -ScriptBlock ${function:runElevatedInActiveSession} -ArgumentList @("foo", "bar", "baz")
        OR
        icm $s { 
            & ([ScriptBlock]::Create(${using:function:runElevatedInActiveSession})) foo bar baz
        } 
        OR
        icm $s {
            & ([Scriptblock]::Create(${using:function:runElevatedInActiveSession})) @(
                "foo"
                "bar"
                "baz"
            )
        }
        #%%

        This command relies on the psexec program included in sysinternals.
    #>
    [CmdletBinding()]
    Param(
        [parameter(ValueFromRemainingArguments = $true)]
        [String[][]] $remainingArguments
    ) 
    
    [string[]] $flattenedRemainingArguments = @($remainingArguments |% {$_})
    # the business with errorActionPreference and the "2>&1" redirect is to
    # prevent from powershell from emitting confusing error messages when the
    # PsExec executable emits characters to stderr (empty lines seemt o be
    # specifically problematic).
    #
    # #see [https://stackoverflow.com/questions/2095088/error-when-calling-3rd-party-executable-from-powershell-when-using-an-ide]
    #
    # I am putting the setting of $errorActionPreference inside its own script
    # block in hopes that my setting of errorActionPreference will have effect
    # only within that script block.  Of course this isn;t so simple. see
    # [https://github.com/PowerShell/PowerShell/issues/4568]. Actually, in my
    # case, Powershell does seem to be behaving correctly with respect to the
    # preference variable assignment within a script block.
    & {
        $ErrorActionPreference = "SilentlyContinue"

        $argumentsForPsExec = @(
            # -accepteula This flag suppresses the display of the license dialog.
            "-accepteula"

            # -nobanner   Do not display the startup banner and copyright message.
            "-nobanner"

            # -d         Don't wait for process to terminate (non-interactive).
            "-d"

            # -h         If the target system is Vista or higher, has the
            # process run with the account's elevated token, if available.
            "-h"

            # -i         Run the program so that it interacts with the desktop
            # of the specified session on the remote system. If no session is
            # specified the process runs in the console session.
            "-i",((query session | select-string '(?i)^.*\s+(\d+)\s+active(\s|$)').Matches[0].Groups[1].Value)

            # -s         Run the remote process in the System account.
            "-s"

            #command and arguments: 
            $flattenedRemainingArguments
        )

        PsExec @argumentsForPsExec 2>&1 | out-string -stream
    }
    
}

function runInActiveSession {
    <#
    .SYNOPSIS
    Uses Scheduled Tasks to run the given command in the currently active
    session. If there is no currently active session, we don't run the command
    at all.

    I created this command to overcome a mysterious (but known) problem with
    psexec (see
    [https://superuser.com/questions/361104/psexec-runs-remote-gui-as-black-screen-windows7])
    where, wiht certain executables run by psexec, the window will not display
    correctly, usually with some elements missing.

    This function is mainly intended to be invoked in a psremoting session on a
    remote (Windows) computer where a user is logged in and actively using a
    Windows session, and you want to run some program that will interact with
    the user.

    I don't know what this function does in the case when there are multiple
    simultaneously active windows sessions -- does it run  a separate instance
    of the program in each session?

    To invoke this function in a remote powershell session $ss, do something like:
    ```
    icm $ss ${function:runInActiveSession} -args @("pwsh")
    ```
    or
    ```
    icm $ss ${function:runInActiveSession} -args @("pwsh -NoExit -c Get-Date")
    ```
    or
    ```
    icm $ss {    & ([Scriptblock]::Create(${using:function:runInActiveSession})) "pwsh" "-NoExit" "-c" "get-date"    }
    ```
    #>
    [CmdletBinding()]
    Param(
        [parameter()]
        [string] $pathOfExecutable,

        [parameter(ValueFromRemainingArguments = $true)]
        [string[][]] $remainingArguments
        
        <#
            the reason for having the type of remainingArguments be [string[][]]
            rather than the more sensible [string[]] is to work around the way
            powershell unpacks arrays when parsing argument lists.

            consider the three calls

            1.
            ```
            runInActiveSession foo xxx yyy zzz
            ```

            2.
            ```
            runInActiveSession foo @("xxx"; "yyy"; "zzz")
            ```

            3.
            ```
            runInActiveSession foo xxx @("yyy"; "zzz") 
            ```

            If the type of $remainingArguments were [string[]], then calls 1 and
            2 would result in $remainingArguments.Count being 3, as desired, but
            call 3 would result in $remainingArguments.Count being 2 and the
            elements of $remainingArguments being "xxx" and "yyy zzz".

            By declaring the type of $remainingArguments to be [string[][]], and
            then unpacking the element arrays explicitly within the function
            body, we can achieve the desired results.  IDeally, Powershell would
            have some built-in attribute that we could set for a parameter to
            say, essentially, "please flatten this (possibly nested) array of
            strings into a single flat array of strings).


        #>

    )
    [string[]] $flattenedRemainingArguments = @($remainingArguments |% {$_})

    $nameOfScheduledTask = (New-Guid).Guid
    Unregister-ScheduledTask -Confirm:$false  -TaskName $nameOfScheduledTask -ErrorAction SilentlyContinue | Out-Null
    
    $registeredScheduledTask = $null
    $registeredScheduledTask = (
        @{
            TaskName = $nameOfScheduledTask   
            InputObject = (
                @{
                    Action=(
                        (
                            @{Execute=$pathOfExecutable} +
                            $(
                                # $flattenedRemainingArguments ? 
                                # @{Argument=($flattenedRemainingArguments -join " ")} :
                                # @{}
                                if($flattenedRemainingArguments){ 
                                    @{Argument=($flattenedRemainingArguments -join " ")}
                                } else {
                                    @{}
                                }
                            )
                        ) | % {New-ScheduledTaskAction @_}
                    )
                    # Trigger = @((New-ScheduledTaskTrigger -Once -At ((Get-Date).AddDays(-90))))
                    Principal=(New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users")
                    # Principal= (New-ScheduledTaskPrincipal  -GroupId "BUILTIN\Administrators" -RunLevel Highest)
                    Settings=(New-ScheduledTaskSettingsSet)
                } |% {New-ScheduledTask @_}
            )
        }|%{Register-ScheduledTask  @_}
    )
    Start-ScheduledTask -InputObject $registeredScheduledTask
    Unregister-ScheduledTask -Confirm:$false -InputObject $registeredScheduledTask
}

function runWithPerpetuallyOpenStandardInput(){
    <#
        .SYNOPSIS
        Runs an executable file in such a way that the executable file will see its
        stdin stream be perpetually open, as it would be if the executable were run
        in an interactive shell.

        .DESCRIPTION
        In some cases, notably when running native executables in a remote
        powershell session, when the native executable expects to receive or to wait
        for input on stdin, Powershell runs the executable in such a way that the
        native executable exits as soon as it starts to wait for input on stdin.  I
        presume that this happens because the executable sees that the stdin stream
        is closed.  Conceivably, I think, it could also happen because the
        executable receives a posix kill signal, or similar, causing it to exit. The
        motivation for writing this function was trying to run SoftEther's
        vpncmd.exe executable in a way that vpncmd.exe would wait for a key to be
        pressed on the console (or waiting for the stdin stream to be closed) and
        would then exit.  I wanted to keep vpncmd.exe in the waiting-for-key state
        indefinitely.  This function allowed me to do that.

        .PARAMETER fileName
        A string corresponding to the fileName argument of the
        System.Diagnostics.ProcessStartInfo class's constructor's fileName argument.
        The path of the executable file to be run.

        .PARAMETER arguments
        A single string. -- not an array of strings -- corresponding to the
        System.Diagnostics.ProcessStartInfo class's constructor's arguments
        argument.

        .EXAMPLE
        runWithPerpetuallyOpenStandardInput -fileName (get-command vpncmd).Path -arguments "/TOOLS /CMD TrafficServer"

        .EXAMPLE
        $sl = New-PSSession -ComputerName LocalHost   -ConfigurationName "PowerShell.7"  
        Invoke-Command `
            -Session $sl `
            -ScriptBlock {
                @{
                    fileName  = (get-command vpncmd).Path
                    arguments = "/TOOLS /CMD TrafficServer"
                } | % { & ([Scriptblock]::Create(${using:function:runWithPerpetuallyOpenStandardInput})) @_ }
            }

        .EXAMPLE
        $sl = New-PSSession -ComputerName LocalHost   -ConfigurationName "PowerShell.7"  
        Invoke-Command `
            -Session $sl `
            -ScriptBlock ${function:runWithPerpetuallyOpenStandardInput} `
            -ArgumentList @(
                (get-command vpncmd).Path 
                "/TOOLS /CMD TrafficServer"
            )

        .EXAMPLE
        $sl = New-PSSession -ComputerName LocalHost   -ConfigurationName "PowerShell.7"  
        Invoke-Command `
            -Session $sl `
            -ScriptBlock {
                @(
                    Get-Process -ErrorAction SilentlyContinue   -Name vpncmd
                    Get-Process -ErrorAction SilentlyContinue   -Name vpncmd_x64
                ) | Stop-Process 

                $function:runWithPerpetuallyOpenStandardInput = [Scriptblock]::Create(${using:function:runWithPerpetuallyOpenStandardInput})

                Start-Job {
                    @{
                        fileName  = (get-command vpncmd).Path
                        arguments = "/TOOLS /CMD TrafficServer"
                    } | % { & ([Scriptblock]::Create(${using:function:runWithPerpetuallyOpenStandardInput})) @_ }
                }
                Start-Sleep 3
                Get-Job | Receive-Job

                # running with the function within a job has the 
                # benefit that the death of the job will cause the death of the 
                # process.
            }

        # .NOTES

    #>  
    
    [OutputType([String])]
    # [CmdletBinding()]

    Param(
        [parameter(
            Mandatory = $True

        )]
        [string] $fileName,

        [parameter(
            Mandatory = $False
        )]
        [string] $arguments = ""
    ) 

    $processStartInfo = New-Object -TypeName "System.Diagnostics.ProcessStartInfo" -ArgumentList @(
        ## string fileName 
        [string] $fileName 

        ## string arguments 
        # damn -- this is not geared toward an array of  arguments, but rather
        # one big string.  Welcome to escape hell.
        [string]  $arguments
    )
    $processStartInfo.RedirectStandardOutput = $True
    $processStartInfo.RedirectStandardError = $True
    $processStartInfo.RedirectStandardInput = $True
    $process = [System.Diagnostics.Process]::Start($processStartInfo)

    $standardOutputLineReadingTask = $process.StandardOutput.ReadLineAsync()
    $standardErrorLineReadingTask = $process.StandardError.ReadLineAsync()

    # while( -not ( $process.HasExited  -and $standardOutputLineReadingTask.IsCompleted -and $standardErrorLineReadingTask.IsCompleted )){
    while( $True ){
        # Write-Output "$($process.HasExited)    $($standardOutputLineReadingTask.IsCompleted)    $($standardErrorLineReadingTask.IsCompleted)"
        
        # wait a beat to allow the pending lineReadingTasks to complete if they
        # want to. This is a bit of a hack to work around (my lack of knowledge
        # and) the fact that the line reading tasks can remain uncompoleted
        # indefinitely after the task exits. Ideally, I would like to have line
        # reading tasks that completed unsucessfully when the task had ended and
        # there were no more bytes to read.  Maybe the ReadLineAsync() function
        # relies on a newline character to finish each line, and so remains
        # waiting unless and until that final newline comes, even if the
        # underlying stream is closed.  Not sure.  this is all a hack.  Perhaps
        # some of the other reading functions, other than ReadLine, would have
        # the desired behavior, or perhaps my confusion is related to the
        # behavior of asynchronous tasks in .NET.
        #
        # I notice that the class System.Diagnostics.Process has methods named
        # BeginErrorReadLine, BeginOutputReadLine, CancelErrorRead,
        # CancelOutputRead -- maybe these could be helpful here.
        #
        # Also a method named WaitForInputIdle.  Maybemy problems have been
        # solved before.
        #
        #

        # TODO: We are currently potentially missing final output emitted by the
        # executable perimortem.  Also, waiting for a whole line is not quite
        # right.  BAsically, the buffering strategy needs to be rethought.

        if( $process.HasExited ) { Start-Sleep 1 }
        
        if($standardOutputLineReadingTask.IsCompleted){
            if($standardOutputLineReadingTask.IsCompletedSuccessfully){
                # Write-Output "$(Get-Date): received a line from StandardOutput: $($standardOutputLineReadingTask.Result)"
                Write-Output $standardOutputLineReadingTask.Result
            } else {
                Write-Output "$(Get-Date):Hmmm.  Our standardOutputLineReadingTask did not complete succesfully."
            }
            $standardOutputLineReadingTask = $process.StandardOutput.ReadLineAsync()
        }

        if($standardErrorLineReadingTask.IsCompleted){
            if( $standardErrorLineReadingTask.IsCompletedSuccessfully ){
                # Write-Output "$(Get-Date):received a line from StandardError: $($standardErrorLineReadingTask.Result)"
                Write-Output $standardErrorLineReadingTask.Result
            } else {
                Write-Output "$(Get-Date):Hmmm.  Our standardErrorLineReadingTask did not complete succesfully."
            }
            $standardErrorLineReadingTask = $process.StandardError.ReadLineAsync()
        }

        # Start-Sleep 1

        if( $process.HasExited ) {break}
        # Write-Output "$(Get-Date): iterating."
    }
}



function addEntryToSystemPathPersistently{
    # perhaps this function would be better named "appendEntry..." to make it
    # clear that we are sticking the new entries at the end of the path, so as
    # to override any existing entries.  We ought to also provide a way to
    # prepend.

    Param(
        [Parameter(
            Mandatory=$True
        )]
        [string] $pathEntry,

        [Parameter(
            Mandatory=$False
        )]
        [Switch] $prepend = $False
    )
    $environmentVariableTarget = [System.EnvironmentVariableTarget]::Machine
    
    $existingPathEntries = @(
        [System.Environment]::GetEnvironmentVariable(
            'PATH', 
            $environmentVariableTarget
        ) -Split [IO.Path]::PathSeparator | 
        Where-Object {$_}
    )
    $desiredPathEntries = @(
        @( 
            if($prepend){
                $pathEntry
                @($existingPathEntries)
            } else {
                @($existingPathEntries)
                $pathEntry
            }
        ) | select-object -unique 
    )


    [System.Environment]::SetEnvironmentVariable(
        'PATH', 
        ([String]::Join([IO.Path]::PathSeparator, $desiredPathEntries)),
        $environmentVariableTarget
    )
}


function reportDrives(){

    "Get-Disk ...:"
    Get-Disk | 
        sort Number |
        select @(
            "Number"
            # "IsOffline"
            # "OfflineReason"
            
            # "OperationalStatus"
            @{
                name="status"
                expression={$_.OperationalStatus}
            }
            
            "BusType"
            
            # "UniqueIdFormat"
            # "UniqueId"

            @{
                name="UniqueId"
                expression={"$($_.UniqueIdFormat): $($_.UniqueId)"}
            }

            "Guid"
            
            # "Manufacturer"
            @{
                name="Mfctr."
                expression={$_.Manufacturer}
            }

            "Model"
            "SerialNumber"
            @{
                name="Size"
                expression = {"{0:N} gigabytes" -f ($_.Size/[math]::pow(10,9))}
            }
            "PartitionStyle"
        ) |
        Format-Table 
    ""

    "Get-CimInstance -Class Win32_LogicalDisk...:"
    Get-CimInstance -Class Win32_LogicalDisk |
        ? {$_.DriveType -ne 5} |
        Sort-Object Name | 
        Select-Object @(
            "Name"
            "VolumeName"
            "VolumeSerialNumber"
            "SerialNumber"
            "FileSystem"
            "Description"
            "VolumeDirty"
            @{"Label"="total space`n(gigabytes)";"Expression"={"{0:N}" -f ($_.Size/[math]::pow(10,9)) -as [float]}}
            @{"Label"="used space`n(gigabytes)";"Expression"={"{0:N}" -f ( ( $_.Size - $_.FreeSpace)/[math]::pow(10,9)) -as [float]}}
            @{"Label"="free space`n(gigabytes)";"Expression"={"{0:N}" -f ($_.FreeSpace/[math]::pow(10,9)) -as [float]}}
            @{"Label"="fraction free";"Expression"={"{0:N}" -f ($_.FreeSpace/$_.Size) -as [float]}}
        ) |
        Format-Table -AutoSize
    ""

    "Get-Partition...:"
    Get-Partition  | 
        Sort DiskNumber,PartitionNumber |
        select @(
            "DiskNumber"
            "PartitionNumber"
            "Type"
            # "DriveLetter"
            @{
                name="Drive Letter"
                expression={
                    # if($_.DriveLetter){$_.DriveLetter}
                    # $_.DriveLetter.ToString()
                    # "$($_.DriveLetter)"
                    # $_.DriveLetter -as [String]
                    if($_.DriveLetter){$_.DriveLetter}
                }
                # driveletter is a char, and is a null char to indicate no assigned drive letter.
                # a null char screws up the alignment in the terminal.
            }
            @{
                name="size"
                expression={"{0,9:f1} gigabytes" -f (($_.Size/[math]::pow(10,9) ) -as [float])}
            } 
            @{
                name="offset"
                expression={"{0,9:f1} gigabytes" -f (($_.Offset/[math]::pow(10,9) ) -as [float])}
            } 
            "Guid"
        ) | 
        format-table -autosize | 
        # out-string |
        write-output

}

function Disable-UserAccountControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Account Control (UAC) has been disabled." -ForegroundColor Green    
}
# Set-Alias Disable-UserAccessControl Disable-UserAccountControl
# ${function:Disable-UserAccessControl} = ${function:Disable-UserAccountControl}
${function:Disable-UserAccessControl} = [Scriptblock]::Create(${function:Disable-UserAccountControl}) 
<#  An alias, rather than defining ${function:...}, is probably the right way to
    preserve backwards compatibility in cases like this where is a post-hoc
    spelling correction (When I fisrt introduced this function, I mistakenly
    thought that "UAC" stood for "User Access Control", and I named the function
    accordingly.  In fact,  "UAC" stands for "User AccountControl".  I have now
    updated the name of the function, but don't want to break existing scripts.

    However, I am defining ${function:...} in order to not break scripts that
    might do ${function:Disable-UserAccountControl}.ToString().  If I set the
    alias, these scripts would break.  (The larger fix is to use a more robust
    way of moving functions around rather than converting the scriptblock into a
    string - or doing such a conversion in a more automated controlled way than
    I often currently (2024-01-26) do it.).

    I am calling [Scriptblock]::Create(), especially, in an attempt to avoid
    breaking scripts that do (get-command
    Enable-UserAccessControl).ScriptBlock.Ast.ToString().  Unfortunately, using
    [Scriptblock]::Create() to define ${function:Disable-UserAccessControl}
    causes (get-command Enable-UserAccessControl).ScriptBlock.Ast.ToString() to
    be just the script block instead of the whole function declaration, so this
    isn't really any better than  simply doing
    ${function:Disable-UserAccessControl} =
    ${function:Disable-UserAccountControl}.
#>

function Enable-UserAccountControl {
    Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"  -force:$true
    Write-Host "User Account Control (UAC) has been enabled (or more accurately: reset to default)." -ForegroundColor Green    
}
# Set-Alias Enable-UserAccessControl Enable-UserAccountControl 
# ${function:Enable-UserAccessControl} = ${function:Enable-UserAccountControl}
${function:Enable-UserAccessControl} = [Scriptblock]::Create(${function:Enable-UserAccountControl})


function Get-NeilWindowsUpdateLog {
    <#
        .SYNOPSIS
        The powershell function Get-WindowsUpdateLog that is built into Windows
        dumps the results to a file and provides no straightforward way to write
        the results to stdout.  This function is a wrapper around
        Get-WindowsUpdateLog that writes the result to stdout.
    #>
    [OutputType([String])]
    # I do not know what the proper OutputType declaration is for a function,
    # like this one, that returns "multiple" strings (in the sense of the
    # powershell pipeline).  I don't think String[] is quite the right type
    # because we are not returning a single array of strings.  "returning" is
    # almost the wrong word for the way that a powershell function generates
    # pipeline output.  "Emitting" might be a better word.  At any rate, this
    # confusion is probably at the heart of my chronic confusion in Powershell
    # about arrays vs. single objects (vs. multiple objects "emitted" by a
    # pipeline)

    # see [https://superuser.com/questions/855285/how-can-i-find-out-what-windows-modules-installer-worker-is-doing]
    # $pathOfLogDumpFile = (join-path $env:TEMP ((New-Guid).Guid))
    $pathOfLogDumpFile = (join-path $env:TEMP "d2eeea30b50446219020a2380c237544.log")


    # $(Get-WindowsUpdateLog -LogPath $pathOfLogDumpFile) *> $null
    # re suppressing unwanted output from get-windowsupdatelog,  see [https://powershell.one/code/9.html]

    # temporarily overwrite Out-Default (so that any calls to
    # [Console]::WriteLine(), such as those issued by Get-WindowsUpdateLog, will
    # not cause anything to appear on the console. see
    # [https://powershell.one/code/9.html]
    function Out-Default {}

    Get-WindowsUpdateLog -LogPath $pathOfLogDumpFile
    # restore Out-Default
    Remove-Item -Path function:Out-Default

    # & PsExec -accepteula -nobanner -d -h -s -i 1 "notepad++" "$($pathOfLogDumpFile)"
    # write-host "$($pathOfLogDumpFile)"

    # Get-Content $pathOfLogDumpFile -Tail 40
    Get-Content $pathOfLogDumpFile 

}

function Start-ScriptingJournalTranscript {
    <#
    .SYNOPSIS
    Starts a transcript in a specific way.  This function is expected to be called from
    a Powershell script, so that $MyInvocation.PsCommandPath is defined.
    #>


    # $MyInvocation | fl | out-string | write-host
    # write-host "=============="
    # Write-Host "(Get-Location): $((Get-Location))"
    # Write-Host "PSCommandPath: $PSCommandPath"
    # Write-Host "psScriptRoot: $psScriptRoot"


    $pathOfTranscriptDirectory = (Join-Path (Split-Path -Parent $MyInvocation.PsCommandPath) "transcripts")
    New-Item -ItemType Directory -Path $pathOfTranscriptDirectory -ErrorAction SilentlyContinue | out-null
    $pathOfTranscriptFile = (Join-Path $pathOfTranscriptDirectory "$(split-path $MyInvocation.PsCommandPath -leaf)--$(get-date -format yyyyMMdd_HHmmss).transcript")
    @{
        Path = $pathOfTranscriptFile
        IncludeInvocationHeader=$True
    } | % { Start-Transcript @_ }
}

function getStronglyNamedPath {
    <#
    .SYNOPSIS
    Given a path to an existing, openable file, we return a new path in which
    the filename contains the hash of the file.
    #>

    
    Param(
        [parameter(
            Mandatory = $True
        )]
        [string] $path

    ) 
    [OutputType([String])]

    [string] $hash = (Get-FileHash -Algorithm "SHA256" -Path $path).Hash.Trim().ToLower()

    $delimeter = "--"
    $desiredNamePattern = "(?-i)^.*$($delimeter)$($hash)(\.[^\.]*)?`$"
    $initialName = [System.IO.Path]::GetFileName($path)

    $naiveStrongName = (@(
        [System.IO.Path]::GetFileNameWithoutExtension($initialName)
        $delimeter
        $hash
        [System.IO.Path]::GetExtension($initialName)
    ) -join "")

    $strongName = (
        ($initialName -match $desiredNamePattern) ?
        $initialName :
        $naiveStrongName
    )

    return (join-path (split-path -parent $path) $strongName)
}

function getCommandPath {
    <#
    .SYNOPSIS
    returns the path of the file containing the specified command, along with the relevant line number in that file.
    Intended to be used for commands that are defined as a powershell function in a powershell acript module file.

    #>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [parameter(mandatory=$True)]
        [string] $nameOfCommand
    )

    Get-Command $nameOfCommand | % { "$($_.ScriptBlock.File):$($_.ScriptBlock.StartPosition.StartLine)" }
}

function New-TemporaryDirectory {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    This function is copied from
    [https://stackoverflow.com/questions/34559553/create-a-temporary-directory-in-powershell].

    It works analogously to the built-in powershell function New-TemporaryFile .
    The checking for collisions is probably gratuitous, and, as one of the
    stackoverflow comments points out, there is a race condition between the
    existence test and the creation, but it's close enough for non-critical
    work.

    #>
    $tempDirectoryBase = [System.IO.Path]::GetTempPath();
    $newTempDirPath = [String]::Empty;
    Do {
      [string] $name = [System.Guid]::NewGuid();
      $newTempDirPath = (Join-Path $tempDirectoryBase $name);
    } While (Test-Path $newTempDirPath);
  
    # Return $newTempDirPath;
    return (New-Item -ItemType Directory -Path $newTempDirPath);
}

function Get-HumanReadableRepresentationOfBitwardenItem {
    <#
    .SYNOPSIS
    Generates a string suitable for pasting into an email message or similar
    human-readable prose message, to represent the contents of a bitwarden item
    in a human readable way.  When you need to tell someone what the username
    and password (and login url) of some website.  I always hem and haw about
    the clearest wording to use,. adn about whether to put the username and
    password in quotes, etc.  This function encodes a standard way of doing it.



    #>
    
    [OutputType([string])] 
    
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item to get")]
        [string] $bitwardenItemId
    )

    $bitwardenItem = Get-BitwardenItem $bitwardenItemId

    return (
        @(
            "here are the credentials: "
            "    " + "username: $($bitwardenItem.login.username)"
            "    " + "password: $($bitwardenItem.login.password)"
            "    " + "url of the web interface: $(($bitwardenItem.login.uris | select -first 1).uri)"
        ) -join "`n"
    )
}

# from [https://stackoverflow.com/questions/9368305/disable-ie-security-on-windows-server-via-powershell]:
function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
    Stop-Process -Name Explorer -Force
    Write-Host "IE Enhanced Security Configuration (ESC) has been enabled." -ForegroundColor Green
}


function findFileInProgramFiles {
    <#
    .SYNOPSIS
    Returns the full paths of any files within (recursively) within the
    ${env:ProgramFiles} or ${env:ProgramFiles(x86)} directories. USeful for
    finding executable files that are not locatable by means of the PATH
    environment variable.
    #>
    
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string] $Filter
    )
    @{
        Path = @(
            $env:ProgramFiles
            ${env:ProgramFiles(x86)}
        ) 
        File = $True
        Recurse = $True
        Filter = $Filter
    } | % {Get-ChildItem  @_ } |
    Select -Expand FullName
}

function getCwcPwshWrappedCommand([string] $command){
    # given a command (a string) that is a valid Powershell script block, we
    # return a string that can be inserted into a command to be run via
    # Screenconnect, which will (assuming the "#!ps" magic comment line appears
    # earlier, and assuming that pwsh is installed) execute the command in pwsh.
    
    return -join @(
        <#  ATTEMPT 1 (REJECTED) :

            ##  "pwsh -c "; "{`n"
            ##      $command
            ##  "`n}"

            This version of the wrapping function has a tendency to produce
            a command line that is too long (produces the errer "Program
            'pwsh.exe' failed to run: The filename or extension is too
            long") and therefore does not run reliably.
        #>


        <#  ATTEMPT 2 (REJECTED) :
            
            ##  "pwsh -EncodedCommand "
            ##  [System.Convert]::ToBase64String(
            ##      [system.Text.Encoding]::Unicode.GetBytes(
            ##          $command
            ##      ) 
            ##  )  

            It makes no difference (in general) whether we do the base64
            encoding trick or not -- there is still a trendency to produce
            an overly-long command line that produces the error "Program
            'pwsh.exe' failed to run: The filename or extension is too
            long"
        #>

        <#  ATTEMPT 3 (REJECTED) :

            ##  "[System.Text.Encoding]::UTF8.GetString("
            ##      "[System.Convert]::FromBase64String(" 
            ##          "`""
            ##              [System.Convert]::ToBase64String(
            ##                  [System.Text.Encoding]::UTF8.GetBytes(
            ##                      # $command
            ##  
            ##                      # pwsh has a tendency to echo the command as it
            ##                      # is executing.  by wrapping in a script block,
            ##                      # at least the printout will occur all in one
            ##                      # chunk before any results, rather than having
            ##                      # commands interspersed with results in the
            ##                      # output.
            ##  
            ##                      (
            ##                          @(
            ##                              "&{"
            ##                                  $command
            ##                              "}"
            ##                              ""
            ##                              # the terminal newline seems to be
            ##                              # necessary to make powershell actually
            ##                              # execute the command rather than wait
            ##                              # endlessly for further input.
            ##                          ) -join "`r`n"
            ##                      )
            ##                  ) 
            ##              )  
            ##          "`""
            ##      ")"
            ##  ")"
            ##  "|"
            ##  "pwsh -NoLogo"
        
            this version of the wrapping function overcomes the problem
            of the overly-long command line but reveals a new potential
            problem -- if the code in $command contains a Param() block
            that contains a comment line followed by an empty line, the
            pwsh parser detects this as a Parser Error (essentially a
            syntax error).  Curiously, Powershell's parser only regards
            this as a syntax error when the code is being piped into
            pwsh's stdin, but not in any other case. See
            [https://github.com/orgs/PowerShell/discussions/21109].  I
            suspect that a comment line followed by an empty line is not
            a syntax error according to the official PowerShell language
            specification.

        #>

        "[System.Text.Encoding]::UTF8.GetString("
            "[System.Convert]::FromBase64String(" 
                ## "`""
                # single quote instead of double-quote doesn't have any effect
                # on using this function to create strings to pass to
                # screenconnect, but does gives slightly improved reliability in
                # cases where double quotes are not properly escaped (I
                # sometimes use this function to create the "Script" parameter
                # for Invoke-WUJob.)
                "'"
                    [System.Convert]::ToBase64String(
                        [System.Text.Encoding]::UTF8.GetBytes(
                            $command
                        ) 
                    )  
                ## "`""
                "'"
            ")"
        ")"
        " | "
        "pwsh -NoLogo -c '(@(`$input) -join ([char] 10)) | Invoke-Expression'"

        <#  Instead of having pwsh read the code directly from standard
            input, we instead run a little command that assembles the entire
            contents of standard input into a single string, which we then
            pipe into Invoke-Expression.  Invoke-Expression is
            (inexplicably) immune from the aforementioned weird
            sometimes-syntax-error of a comment lin e followed by an empty
            line in a Param() block.

            I am using "([char] 10)" rather than "`"``n`"" because the
            latter (specifically, the double quotes, I think) tends to cause
            problems.

            The base64 encoding/decoding is probably not necessary.
        #>
    )
}



function runInCwcSession {
    [OutputType([string])]
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter()]
        [string] $bitwardenItemIdOfScreenconnectCredentials, 

        [Parameter(Mandatory=$False)] 
        [string] $nameOfGroup, 

        [Parameter()] 
        [string] $nameOfSession,
        

        <#
            if $pwsh is set, then we will attempt to run the command in pwsh, by
            means of the somewhat baroque technique involving the
            getCwcPwshWrappedCommand function.  We will blindly assume that pwsh
            is installed and available on the path.
        #>
        [Parameter(Mandatory=$False)] 
        [switch] $pwsh = $False,


        [Parameter(Mandatory=$False)] 
        [int] $timeout,

        ## [Parameter(Mandatory=$False)] 
        ## [System.TimeSpan] $timeout,

        [Parameter(
            Position=0,
            Mandatory=$False, 
            HelpMessage="preambleCommand will be prepended to command (with a linefeed separator) before submitting the request to Screenconnect"
        )] 
        [string[]] $preambleCommand,

        [Parameter(
            Position=1,
            Mandatory=$False
        )] 
        [string[]] $command,

        [Parameter(
            Position=2,
            Mandatory=$False,
            HelpMessage="postambleCommand will be appended to command (with a linefeed separator) before submitting the request to Screenconnect"
        )] 
        [string[]] $postambleCommand


        # The only reason for having these three distinct parameters (rather
        # than just a single (array) command parameter) is to facilitate
        # splatting.
    )
    Import-Module ConnectWiseControlAPI
    <#
        We can't use version 0.3.5.0 of the ConnectWiseControlAPI module (whcih
        is the latest version as of 2024-01-11-1118) because that version
        assumes a newer version of the Screenconnect API than is running on our
        screenconnect server.
        ```
        Uninstall-Module ConnectWiseControlAPI
        Update-Module ConnectWiseControlAPI -MaximumVersion 0.3.1.0
        ```
    #>


    ## ensure connection to screenconnect:
    $bitwardenItem = Get-BitwardenItem -bitwardenItemId $bitwardenItemIdOfScreenconnectCredentials
    @{
        Server      = "$(([System.Uri] $bitwardenItem.login.uris[0].uri ).Host)"
        Credentials = (
            New-Object System.Management.Automation.PSCredential (
                $bitwardenItem.login.username, 
                (ConvertTo-SecureString $bitwardenItem.login.password -AsPlainText -Force)
            )
        )
        # Force       = $True
    } | % { Connect-CWC  @_ } | 
    Write-Host

    $screenconnectSearchString = "## NAME = '$($nameOfSession)'"
    ## retrieve the specified session
    
    $candidateCwcSessions = @(
        (
            @{
                Type="Access" 
                Search=$screenconnectSearchString 
            } +
            $(
                if($nameOfGroup){
                    @{
                        Group=$nameOfGroup
                    }
                } else {
                    @{}
                }
            )
        ) |%{ Get-CWCSession @_} 
    )

    if($candidateCwcSessions.Count -eq 0){
        write-warning "found no matching cwc sessions."
    } elseif($candidateCwcSessions.Count -gt 1){
        write-warning (
            "found more than one matching cwc sessions, namely: " + 
            (
                @(
                    $candidateCwcSessions |
                    %{ "$($_.SessionId) $($_.Name)" }
                ) -join ", "
            ) +
            "."
        )
    }
    
    $cwcSession = [System.Linq.Enumerable]::Single(
        (
            [System.Collections.Generic.List[object]]  $candidateCwcSessions
        )
    )

    $augmentedCommand = @(
        @(
            $preambleCommand
            $command
            $postambleCommand
        ) |
        ? {$_}
    ) -join "`n"

    ## run the command
    (
        @{
            GUID = $cwcSession.SessionID 
            
            Powershell = $True 
            Command =  (
                @(
                    "#maxlength=1000000"
                    $pwsh ? (getCwcPwshWrappedCommand $augmentedCommand) : $augmentedCommand
                ) -join "`n"
            )
        } +
        $(if($timeout){@{Timeout = $timeout}} else {@{}})
    ) | % { Invoke-CWCCommand @_ }
}

function Get-EncodedPowershellCommand {
    <#
        .SYNOPSIS
        Generates a string suitable for passing to Powershell as the value of the "EncodedCommand" argument.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [parameter()]
        [string]
        $powershellCommand
    )

    [System.Convert]::ToBase64String( 
        [system.Text.Encoding]::Unicode.GetBytes( 
            ([string] $powershellCommand)
        )
    )
}

function Get-LastLoggedOnUserSID {
    [OutputType([string])]
    [CmdletBinding()]
    Param(
    )
    (Get-Item -Path "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI").GetValue("LastLoggedOnUserSID")
}

function publishFile {
    <#
    .SYNOPSIS
    copies the specified file to a publicly-accessible (read-only) Sharepoint
    folder, gives it a strong, hash-based name (ideally in such a way that it
    re-uses an existing copy if it exists), and returns the publicly-accessible
    url to the file.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [parameter()]
        [string] $pathOfFile,

        [parameter()]
        [string] $bitwardenItemIdOfCredentials,

        [parameter()]
        [string] $destination
        # I don't know exactly what this will do yet
    )
    # $pathOfFile = "S:\Microsoft\Microsoft Office 2013\SW_DVD5_NTRL_Office_Professional_Plus_2013_W32_English_MSI_FPP_X18-65189.ISO"
    $strongFilename = (split-path -leaf (getStronglyNamedPath $pathOfFile))
    # $pathOfDestinationDirectory = (join-path $env:OneDriveCommercial Attachments)
    # $pathOfDestinationFile = (join-path $pathOfDestinationDirectory $strongFilename)
    # Copy-Item $pathOfFile $pathOfDestinationFile | out-null
    # return $pathOfDestinationFile

    $totalLength = gi $pathOfFile | select -expand Length


    # AS OF 2023-11-01: WE ARE, OUT OF LAZINESS, NOT LOOKING AT THE BITWARDEN
    # ITEM ID, but merely calling Connect-MgGraph and hoping for the best.
    # Connect-MgGraph will do an interactive sign-in if it needs to, and tends
    # to cache the credentials somewhere (and caches them in a way that survives
    # the current shell process.  This caching behavior is slightly scary,
    # particularly being the default behavior, but at the moment, this caching
    # behavior is saving me from having to do an interactive login.
    #
    # to do read credentials (private key) from Bitwarden.
    Connect-MgGraph -Scopes Files.ReadWrite.All, Sites.ReadWrite.All | out-null

    ## UPLOAD the FILE: 

    #### $drive = @{
    ####     Method        = "GET"
    ####     Uri           = "v1.0/drives/me"
    ####     ContentType   = 'multipart/form-data'
    #### } | % {Invoke-MgGraphRequest @_} 


    ## $x = @{
    ##     Method        = "PUT"
    ##     Uri           = "v1.0/drives/me/items/root:/Attachments/$($strongFilename):/content"
    ##     InputFilePath = $pathOfFile
    ##     ContentType   = 'multipart/form-data'
    ## } | % {Invoke-MgGraphRequest @_}

    ### $x = @{
    ###     # DriveId = $drive.id
    ###     DriveId = "me"
    ###     InFile = $pathOfFile
    ###     DriveItemId = "root:/Attachments/$($strongFilename):"
    ### } | % {Set-MgDriveItemContent @_}

    # neither of the above two techniques handle large files (but they both work for small files.


    ## $attachmentsFolder = @{
    ##     Method        = "GET"
    ##     Uri           = "v1.0/drives/$($drive.id)/root:/Attachments"
    ##     InputFilePath = $pathOfFile
    ##     ContentType   = 'multipart/form-data'
    ## } | % {Invoke-MgGraphRequest @_}
    ## 
    ## @{
    ##     DriveId = $drive.id
    ##     ContentInputFile = $pathOfFile
    ##     Name = $strongFilename
    ##     ParentReference = @{
    ##         Id = $attachmentsFolder.Id
    ##     }
    ## } |% {New-MgDriveItem @_}

    $sizeThresholdForSignlePut = 20
    # the main point of this is to be able to handle zero-byte files, whcih the uploadsession technique can't handle.
    

    if($totalLength -lt $sizeThresholdForSignlePut){    
        $x = @{
            Method        = "PUT"
            Uri           = "v1.0/drives/me/items/root:/Attachments/$($strongFilename):/content"
            InputFilePath = $pathOfFile
            ContentType   = 'multipart/form-data'
        } | % {Invoke-MgGraphRequest @_}
    } else {

        $sliceSizeDivisor = (320 * 1024)
        $maximumAllowedContentLengthPerRequest = 50 * [math]::pow(2,20)
        # the real maximum allowed value is 60 mebibytes, according to [https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0#create-an-upload-session]
        # but I am setting mine a bit lower mainly in order to make the progress messages more frequent.
        $sliceSize = $sliceSizeDivisor * [math]::floor($maximumAllowedContentLengthPerRequest/$sliceSizeDivisor)

        ## $fileStream = [System.IO.File]::OpenRead($pathOfFile)
        ##  $totalLength = $fileStream.Length
        


        # see [https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0#create-an-upload-session]
        $uploadSession = @{
            DriveId = "me"
            DriveItemId = "root:/Attachments/$($strongFilename):"
        } | % {New-MgDriveItemUploadSession @_}

        ## $uploadSession.GetType()

        # see [https://learn.microsoft.com/en-us/graph/sdks/large-file-upload?tabs=csharp]

        ##$lastByteIndexUploaded = -1
        ##while($lastByteIndexUploaded -lt ($totalLength - 1)){
        ##    $sliceStart = $lastByteIndexUploaded
        ##    $sliceStop = [math]::min( $sliceStart + $sliceSize, $totalLength )
        ##    # we will upload the bytes at indices $sliceStart, $sliceStart + 1, ..., $sliceStop - 1 .
        ##
        ##    
        ##    $x = @{
        ##        Method        = "PUT"
        ##        Uri           = $uploadSession.UploadUrl
        ##        # ContentType   = 'multipart/form-data'
        ##        Headers = @{
        ##            "Content-Length" = "$($sliceStop - $sliceStart)"
        ##            "Content-Range" = "bytes $($sliceStart)-$($sliceStop - 1)/$($totalLength)"
        ##        }
        ##        Body = $fileStream.ReadExactly
        ##    } | % {Invoke-MgGraphRequest @_}
        ##
        ##    $lastByteIndexUploaded = $sliceStop - 1
        ##    Write-Host ("$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f ($lastByteIndexUploaded + 1),($totalLength),(($lastByteIndexUploaded + 1)/($totalLength)))
        ##}
        ##$fileStream.Close()

        $countOfBytesUploaded = 0
        
        # get-content is quite slow, I think compared to lower-level file stream operations.

        Get-Content -AsByteStream -ReadCount $sliceSize $pathOfFile |
        % {
            
            # $chunk = $_
            [byte[]] $chunk = $_
        
            

            ## $x = @{
            ##     Method               = "PUT"
            ##     Uri                  = $uploadSession.UploadUrl
            ##     # ContentType          = 'application/octet-stream'
            ##     ContentType          = 'application/octet-stream'
            ##     # SkipHeaderValidation = $True
            ##     Headers              = @{
            ##         "Content-Range"  = "bytes $($countOfBytesUploaded)-$($countOfBytesUploaded + $chunk.Count - 1)/$($totalLength)"
            ##         # "Content-Length" = "$($chunk.Count)"
            ##         # "Content-Type"   = 'application/octet-stream'
            ##     }
            ##     Body = $chunk
            ## } | % {Invoke-MgGraphRequest @_}

            $x = @{
                Method = "PUT"
                ContentType          = 'application/octet-stream'
                Headers              = @{
                    "Content-Range"  = "bytes $($countOfBytesUploaded)-$($countOfBytesUploaded + $chunk.Count - 1)/$($totalLength)"
                    # "Content-Length" = "$($chunk.Count)"
                    # "Content-Type"   = 'application/octet-stream'
                }
                Uri = $uploadSession.UploadUrl
                Body = $chunk
            } |% {Invoke-WebRequest @_}
        
        
            $countOfBytesUploaded += $chunk.Count
        
            Write-Host (
                "$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f @(
                    $countOfBytesUploaded
                    $totalLength
                    100 * $countOfBytesUploaded/$totalLength
                )
            )
        }

        ## $x = @{
        ##     Method        = "PUT"
        ##     Uri           = $uploadSession.UploadUrl
        ##     InputFilePath = $pathOfFile
        ##     ContentType   = 'multipart/form-data'
        ## } | % {Invoke-MgGraphRequest @_}

        ## curl @(
        ##     "--location"
        ##     "--upload-file"; $pathOfFile
        ##     ## "--data-binary"; "@$($pathOfFile)"
        ##     ## "--header"; "Content-Type: application/octet-stream"
        ##     ## "--request"; "PUT"
        ##     $uploadSession.UploadUrl
        ## )

    }

    ## CREATE the LINK:
    $z = @{
        Method = "POST"
        Uri    = "v1.0/drives/me/items/root:/Attachments/$($strongFilename):/createLink"
        Body   = @{
            type="view"
            scope="anonymous"
        }
    } |% { Invoke-MgGraphRequest @_}
    $a = ([System.UriBuilder] $z.link.webUrl)
    $a.Query += "$($a.Query ? '&' : '')download=1"

    # perhaps see [https://learn.microsoft.com/en-us/microsoft-365/community/query-string-url-tricks-sharepoint-m365]

    <#
        It would be nice to (optionally) return something that is not just the
        raw url, but is something like some html that could be pasted into an
        email message or similar, that would include a hyperlink, with filename.
    #>

    # $x.Name
    return $a.Uri.AbsoluteUri

}

function getInstalledAppsFromRegistry {
    # This is the data that appwiz.cpl draws from:
    return @(
        Get-ItemProperty "registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
        Get-ItemProperty "registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"             # 64 Bit
        Get-ItemProperty "registry::HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
        Get-ItemProperty "registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"             # 64 Bit
    )
}

function formattedObjectToClipboard {
    <#
        puts a string on the clipboard that is a valid powershell block comment 
        that describes the piped-in object.  Useful for exploring classes (and recording the 
        reports in-line with the exploratory code.
    #>
    
    end {
        $input | 
        fl | 
        out-string | 
        % {
            @(
                $_ -split "`n" |
                % { "    $_" }
            ) -join "`n"
        } |
        % {"<#$_`n#>"} | 
        set-clipboard
    }
}

function Send-SettingChange {
    <#
        copied with slight modification from
        [https://gist.github.com/alphp/78fffb6d69e5bb863c76bbfc767effda].

        see
        [https://serverfault.com/questions/8855/how-do-you-add-a-windows-environment-variable-without-rebooting].
        see
        [https://gist.github.com/alphp/78fffb6d69e5bb863c76bbfc767effda].
    #>
    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition (
        @(
            '[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]'
            'public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
        ) -join "`n"
    )

    $HWND_BROADCAST = [IntPtr] 0xffff;
    $WM_SETTINGCHANGE = 0x1a;
    $result = [UIntPtr]::Zero

    [void] ([Win32.Nativemethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref] $result))
}

function Select-Enumerated {
    <#
        wraps each object in the pipeline in a KeyValuePair whose Value is the
        input object and whose Key is a sequential integer starting from 0.

        This function is intended to be similar to Python's Enumerate()
        function.

        It would seem natural for powershell to have a function like this built
        in, but it does not.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.KeyValuePair[int, object]])]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [object] $InputObject
    )

    begin {
        [int] $key = 0
    }

    process {
        [System.Collections.Generic.KeyValuePair[int, object]]::New($key++, $InputObject)
    }

    end {

    }
}
Set-Alias Enumerate Select-Enumerated

##function getVmKeyboard {
##    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
##    [CmdletBinding()]
##    Param(
##        [Parameter(Mandatory=$True)]
##        [Alias("VM")]
##        [Microsoft.HyperV.PowerShell.VirtualMachine]
##        $virtualMachine
##    )  
##    
##    $ComputerSystem = Get-CimInstance -ClassName Msvm_ComputerSystem -Namespace "root\virtualization\v2" -Filter "ElementName = '$($virtualMachine.Name)'"        
##    return (Get-CimAssociatedInstance -InputObject $ComputerSystem -ResultClassName Msvm_Keyboard -Namespace "root\virtualization\v2")
##}


function sendKeystrokesToVm {
    <#
        sends the string to the virtual machine in the form of keystrokes.

        * see [http://justanotheritblog.co.uk/send-keystrokestext-to-a-vm-through-the-host-os/]
        * see [https://richardspowershellblog.wordpress.com/2014/03/23/discovering-cimwmi-methods-and-parameters/]
        * see [https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-keyboard]
        * see [https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes]
        * see [https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/typekey-msvm-keyboard]
        * see [https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.keysconverter?view=windowsdesktop-8.0]
        * see [https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapvirtualkeya]

    #>



    ## (Get-CimClass Msvm_Keyboard -Namespace "root\virtualization\v2" ).CimClassMethods |? {$_.Name -eq "TypeText"} | select -expand Parameters
    ## (Get-CimClass Msvm_Keyboard -Namespace "root\virtualization\v2" ).CimClassMethods |? {$_.Name -eq "TypeKey"} | select -expand Parameters

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Alias("VM")]
        [Microsoft.HyperV.PowerShell.VirtualMachine]
        $virtualMachine,

        [Parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [string] $stringToSend,

        [Parameter(Mandatory=$False)]
        [uint32[]] $keyCodesToSend = @(),

        [Parameter(Mandatory=$False)]
        [Switch] $CtrlAltDel = $false,

        [Parameter(Mandatory=$False)]
        [Switch] $SendWithShifts = $false
    )

    begin {

        $keySpecsByCharacter = @{
            ## [char] 0x0d = @{   keyCode =  0x0d ; shift = $False    ; description = "carriage return"  }  # [System.Windows.Forms.Keys]::Enter
            [char] 0x09 = @{   keyCode =  0x09 ; shift = $False    ; description = "tab"              }  # [System.Windows.Forms.Keys]::Tab              
            [char] 0x0a = @{   keyCode =  0x0d ; shift = $False    ; description = "linefeed"         }  # [System.Windows.Forms.Keys]::Enter            
            [char] 0x20 = @{   keyCode =  0x20 ; shift = $False    ; description = "space"            }  # [System.Windows.Forms.Keys]::Space            
            [char] 0x21 = @{   keyCode =  0x31 ; shift = $True     ; description = "'!'"              }  # [System.Windows.Forms.Keys]::D1               
            [char] 0x22 = @{   keyCode =  0xde ; shift = $True     ; description = "'`"'"             }  # [System.Windows.Forms.Keys]::OemQuotes        
            [char] 0x23 = @{   keyCode =  0x33 ; shift = $True     ; description = "'#'"              }  # [System.Windows.Forms.Keys]::D3               
            [char] 0x24 = @{   keyCode =  0x34 ; shift = $True     ; description = "'`$'"             }  # [System.Windows.Forms.Keys]::D4               
            [char] 0x25 = @{   keyCode =  0x35 ; shift = $True     ; description = "'%'"              }  # [System.Windows.Forms.Keys]::D5               
            [char] 0x26 = @{   keyCode =  0x37 ; shift = $True     ; description = "'&'"              }  # [System.Windows.Forms.Keys]::D7               
            [char] 0x27 = @{   keyCode =  0xde ; shift = $False    ; description = "'''"              }  # [System.Windows.Forms.Keys]::OemQuotes        
            [char] 0x28 = @{   keyCode =  0x39 ; shift = $True     ; description = "'('"              }  # [System.Windows.Forms.Keys]::D9               
            [char] 0x29 = @{   keyCode =  0x30 ; shift = $True     ; description = "')'"              }  # [System.Windows.Forms.Keys]::D0               
            [char] 0x2a = @{   keyCode =  0x6a ; shift = $False    ; description = "'*'"              }  # [System.Windows.Forms.Keys]::Multiply         
            [char] 0x2b = @{   keyCode =  0x6b ; shift = $False    ; description = "'+'"              }  # [System.Windows.Forms.Keys]::Add              
            [char] 0x2c = @{   keyCode =  0xbc ; shift = $False    ; description = "','"              }  # [System.Windows.Forms.Keys]::Oemcomma         
            [char] 0x2d = @{   keyCode =  0x6d ; shift = $False    ; description = "'-'"              }  # [System.Windows.Forms.Keys]::Subtract         
            [char] 0x2e = @{   keyCode =  0xbe ; shift = $False    ; description = "'.'"              }  # [System.Windows.Forms.Keys]::OemPeriod        
            [char] 0x2f = @{   keyCode =  0x6f ; shift = $False    ; description = "'/'"              }  # [System.Windows.Forms.Keys]::Divide           
            [char] 0x30 = @{   keyCode =  0x30 ; shift = $False    ; description = "'0'"              }  # [System.Windows.Forms.Keys]::D0               
            [char] 0x31 = @{   keyCode =  0x31 ; shift = $False    ; description = "'1'"              }  # [System.Windows.Forms.Keys]::D1               
            [char] 0x32 = @{   keyCode =  0x32 ; shift = $False    ; description = "'2'"              }  # [System.Windows.Forms.Keys]::D2               
            [char] 0x33 = @{   keyCode =  0x33 ; shift = $False    ; description = "'3'"              }  # [System.Windows.Forms.Keys]::D3               
            [char] 0x34 = @{   keyCode =  0x34 ; shift = $False    ; description = "'4'"              }  # [System.Windows.Forms.Keys]::D4               
            [char] 0x35 = @{   keyCode =  0x35 ; shift = $False    ; description = "'5'"              }  # [System.Windows.Forms.Keys]::D5               
            [char] 0x36 = @{   keyCode =  0x36 ; shift = $False    ; description = "'6'"              }  # [System.Windows.Forms.Keys]::D6               
            [char] 0x37 = @{   keyCode =  0x37 ; shift = $False    ; description = "'7'"              }  # [System.Windows.Forms.Keys]::D7               
            [char] 0x38 = @{   keyCode =  0x38 ; shift = $False    ; description = "'8'"              }  # [System.Windows.Forms.Keys]::D8               
            [char] 0x39 = @{   keyCode =  0x39 ; shift = $False    ; description = "'9'"              }  # [System.Windows.Forms.Keys]::D9               
            [char] 0x3a = @{   keyCode =  0xba ; shift = $True     ; description = "':'"              }  # [System.Windows.Forms.Keys]::OemSemicolon     
            [char] 0x3b = @{   keyCode =  0xba ; shift = $False    ; description = "';'"              }  # [System.Windows.Forms.Keys]::OemSemicolon     
            [char] 0x3c = @{   keyCode =  0xbc ; shift = $True     ; description = "'<'"              }  # [System.Windows.Forms.Keys]::Oemcomma         
            [char] 0x3d = @{   keyCode =  0xbb ; shift = $False    ; description = "'='"              }  # [System.Windows.Forms.Keys]::Oemplus          
            [char] 0x3e = @{   keyCode =  0xbe ; shift = $True     ; description = "'>'"              }  # [System.Windows.Forms.Keys]::OemPeriod        
            [char] 0x3f = @{   keyCode =  0xbf ; shift = $True     ; description = "'?'"              }  # [System.Windows.Forms.Keys]::OemQuestion      
            [char] 0x40 = @{   keyCode =  0x32 ; shift = $True     ; description = "'@'"              }  # [System.Windows.Forms.Keys]::D2               
            [char] 0x41 = @{   keyCode =  0x41 ; shift = $True     ; description = "'A'"              }  # [System.Windows.Forms.Keys]::A                
            [char] 0x42 = @{   keyCode =  0x42 ; shift = $True     ; description = "'B'"              }  # [System.Windows.Forms.Keys]::B                
            [char] 0x43 = @{   keyCode =  0x43 ; shift = $True     ; description = "'C'"              }  # [System.Windows.Forms.Keys]::C                
            [char] 0x44 = @{   keyCode =  0x44 ; shift = $True     ; description = "'D'"              }  # [System.Windows.Forms.Keys]::D                
            [char] 0x45 = @{   keyCode =  0x45 ; shift = $True     ; description = "'E'"              }  # [System.Windows.Forms.Keys]::E                
            [char] 0x46 = @{   keyCode =  0x46 ; shift = $True     ; description = "'F'"              }  # [System.Windows.Forms.Keys]::F                
            [char] 0x47 = @{   keyCode =  0x47 ; shift = $True     ; description = "'G'"              }  # [System.Windows.Forms.Keys]::G                
            [char] 0x48 = @{   keyCode =  0x48 ; shift = $True     ; description = "'H'"              }  # [System.Windows.Forms.Keys]::H                
            [char] 0x49 = @{   keyCode =  0x49 ; shift = $True     ; description = "'I'"              }  # [System.Windows.Forms.Keys]::I                
            [char] 0x4a = @{   keyCode =  0x4a ; shift = $True     ; description = "'J'"              }  # [System.Windows.Forms.Keys]::J                
            [char] 0x4b = @{   keyCode =  0x4b ; shift = $True     ; description = "'K'"              }  # [System.Windows.Forms.Keys]::K                
            [char] 0x4c = @{   keyCode =  0x4c ; shift = $True     ; description = "'L'"              }  # [System.Windows.Forms.Keys]::L                
            [char] 0x4d = @{   keyCode =  0x4d ; shift = $True     ; description = "'M'"              }  # [System.Windows.Forms.Keys]::M                
            [char] 0x4e = @{   keyCode =  0x4e ; shift = $True     ; description = "'N'"              }  # [System.Windows.Forms.Keys]::N                
            [char] 0x4f = @{   keyCode =  0x4f ; shift = $True     ; description = "'O'"              }  # [System.Windows.Forms.Keys]::O                
            [char] 0x50 = @{   keyCode =  0x50 ; shift = $True     ; description = "'P'"              }  # [System.Windows.Forms.Keys]::P                
            [char] 0x51 = @{   keyCode =  0x51 ; shift = $True     ; description = "'Q'"              }  # [System.Windows.Forms.Keys]::Q                
            [char] 0x52 = @{   keyCode =  0x52 ; shift = $True     ; description = "'R'"              }  # [System.Windows.Forms.Keys]::R                
            [char] 0x53 = @{   keyCode =  0x53 ; shift = $True     ; description = "'S'"              }  # [System.Windows.Forms.Keys]::S                
            [char] 0x54 = @{   keyCode =  0x54 ; shift = $True     ; description = "'T'"              }  # [System.Windows.Forms.Keys]::T                
            [char] 0x55 = @{   keyCode =  0x55 ; shift = $True     ; description = "'U'"              }  # [System.Windows.Forms.Keys]::U                
            [char] 0x56 = @{   keyCode =  0x56 ; shift = $True     ; description = "'V'"              }  # [System.Windows.Forms.Keys]::V                
            [char] 0x57 = @{   keyCode =  0x57 ; shift = $True     ; description = "'W'"              }  # [System.Windows.Forms.Keys]::W                
            [char] 0x58 = @{   keyCode =  0x58 ; shift = $True     ; description = "'X'"              }  # [System.Windows.Forms.Keys]::X                
            [char] 0x59 = @{   keyCode =  0x59 ; shift = $True     ; description = "'Y'"              }  # [System.Windows.Forms.Keys]::Y                
            [char] 0x5a = @{   keyCode =  0x5a ; shift = $True     ; description = "'Z'"              }  # [System.Windows.Forms.Keys]::Z                
            [char] 0x5b = @{   keyCode =  0xdb ; shift = $False    ; description = "'['"              }  # [System.Windows.Forms.Keys]::OemOpenBrackets  
            [char] 0x5c = @{   keyCode =  0xdc ; shift = $False    ; description = "'\'"              }  # [System.Windows.Forms.Keys]::OemPipe          
            [char] 0x5d = @{   keyCode =  0xdd ; shift = $False    ; description = "']'"              }  # [System.Windows.Forms.Keys]::OemCloseBrackets 
            [char] 0x5e = @{   keyCode =  0x36 ; shift = $True     ; description = "'^'"              }  # [System.Windows.Forms.Keys]::D6               
            [char] 0x5f = @{   keyCode =  0xbd ; shift = $True     ; description = "'_'"              }  # [System.Windows.Forms.Keys]::OemMinus         
            [char] 0x60 = @{   keyCode =  0xc0 ; shift = $False    ; description = "'`'"              }  # [System.Windows.Forms.Keys]::Oemtilde         
            [char] 0x61 = @{   keyCode =  0x41 ; shift = $False    ; description = "'a'"              }  # [System.Windows.Forms.Keys]::A                
            [char] 0x62 = @{   keyCode =  0x42 ; shift = $False    ; description = "'b'"              }  # [System.Windows.Forms.Keys]::B                
            [char] 0x63 = @{   keyCode =  0x43 ; shift = $False    ; description = "'c'"              }  # [System.Windows.Forms.Keys]::C                
            [char] 0x64 = @{   keyCode =  0x44 ; shift = $False    ; description = "'d'"              }  # [System.Windows.Forms.Keys]::D                
            [char] 0x65 = @{   keyCode =  0x45 ; shift = $False    ; description = "'e'"              }  # [System.Windows.Forms.Keys]::E                
            [char] 0x66 = @{   keyCode =  0x46 ; shift = $False    ; description = "'f'"              }  # [System.Windows.Forms.Keys]::F                
            [char] 0x67 = @{   keyCode =  0x47 ; shift = $False    ; description = "'g'"              }  # [System.Windows.Forms.Keys]::G                
            [char] 0x68 = @{   keyCode =  0x48 ; shift = $False    ; description = "'h'"              }  # [System.Windows.Forms.Keys]::H                
            [char] 0x69 = @{   keyCode =  0x49 ; shift = $False    ; description = "'i'"              }  # [System.Windows.Forms.Keys]::I                
            [char] 0x6a = @{   keyCode =  0x4a ; shift = $False    ; description = "'j'"              }  # [System.Windows.Forms.Keys]::J                
            [char] 0x6b = @{   keyCode =  0x4b ; shift = $False    ; description = "'k'"              }  # [System.Windows.Forms.Keys]::K                
            [char] 0x6c = @{   keyCode =  0x4c ; shift = $False    ; description = "'l'"              }  # [System.Windows.Forms.Keys]::L                
            [char] 0x6d = @{   keyCode =  0x4d ; shift = $False    ; description = "'m'"              }  # [System.Windows.Forms.Keys]::M                
            [char] 0x6e = @{   keyCode =  0x4e ; shift = $False    ; description = "'n'"              }  # [System.Windows.Forms.Keys]::N                
            [char] 0x6f = @{   keyCode =  0x4f ; shift = $False    ; description = "'o'"              }  # [System.Windows.Forms.Keys]::O                
            [char] 0x70 = @{   keyCode =  0x50 ; shift = $False    ; description = "'p'"              }  # [System.Windows.Forms.Keys]::P                
            [char] 0x71 = @{   keyCode =  0x51 ; shift = $False    ; description = "'q'"              }  # [System.Windows.Forms.Keys]::Q                
            [char] 0x72 = @{   keyCode =  0x52 ; shift = $False    ; description = "'r'"              }  # [System.Windows.Forms.Keys]::R                
            [char] 0x73 = @{   keyCode =  0x53 ; shift = $False    ; description = "'s'"              }  # [System.Windows.Forms.Keys]::S                
            [char] 0x74 = @{   keyCode =  0x54 ; shift = $False    ; description = "'t'"              }  # [System.Windows.Forms.Keys]::T                
            [char] 0x75 = @{   keyCode =  0x55 ; shift = $False    ; description = "'u'"              }  # [System.Windows.Forms.Keys]::U                
            [char] 0x76 = @{   keyCode =  0x56 ; shift = $False    ; description = "'v'"              }  # [System.Windows.Forms.Keys]::V                
            [char] 0x77 = @{   keyCode =  0x57 ; shift = $False    ; description = "'w'"              }  # [System.Windows.Forms.Keys]::W                
            [char] 0x78 = @{   keyCode =  0x58 ; shift = $False    ; description = "'x'"              }  # [System.Windows.Forms.Keys]::X                
            [char] 0x79 = @{   keyCode =  0x59 ; shift = $False    ; description = "'y'"              }  # [System.Windows.Forms.Keys]::Y                
            [char] 0x7a = @{   keyCode =  0x5a ; shift = $False    ; description = "'z'"              }  # [System.Windows.Forms.Keys]::Z                
            [char] 0x7b = @{   keyCode =  0xdb ; shift = $True     ; description = "'{'"              }  # [System.Windows.Forms.Keys]::OemOpenBrackets  
            [char] 0x7c = @{   keyCode =  0xdc ; shift = $True     ; description = "'|'"              }  # [System.Windows.Forms.Keys]::OemPipe          
            [char] 0x7d = @{   keyCode =  0xdd ; shift = $True     ; description = "'}'"              }  # [System.Windows.Forms.Keys]::OemCloseBrackets 
            [char] 0x7e = @{   keyCode =  0xc0 ; shift = $True     ; description = "'~'"              }  # [System.Windows.Forms.Keys]::Oemtilde         
        }

        ## $shiftKeyKeyCode = [uint32] [System.Windows.Forms.Keys]::ShiftKey
        $shiftKeyKeyCode = 0x10


        ## $Keyboard = getVmKeyboard $virtualMachine
        $ComputerSystem = Get-CimInstance -ClassName Msvm_ComputerSystem -Namespace "root\virtualization\v2" -Filter "ElementName = '$($virtualMachine.Name)'"        
        $Keyboard = (Get-CimAssociatedInstance -InputObject $ComputerSystem -ResultClassName Msvm_Keyboard -Namespace "root\virtualization\v2")
    }

    process {
        # $Keyboard.InvokeMethod("TypeText","Hello world!") # Type 'Hello World!'
        # $Keyboard.InvokeMethod("TypeKey","13") # Press enter
        # Invoke-CimMethod -InputObject $Keyboard -MethodName "TypeKey" -Arguments @{KeyCode=13}


        if($stringToSend){
            if($SendWithShifts){
                # we assume that we are starting from a state where caps lock is off, and no modifier keys are being held down.

                foreach($c in ([char[]] $stringToSend)){
                    if($c -in $keySpecsByCharacter.Keys){
                        $keySpec = $keySpecsByCharacter[$c]

                        if($keySpec.shift){
                            Invoke-CimMethod -InputObject $Keyboard -MethodName "PressKey" -Arguments @{keyCode=$shiftKeyKeyCode} | out-null
                        }
                        Invoke-CimMethod -InputObject $Keyboard -MethodName "PressKey" -Arguments @{keyCode=$keySpec.keyCode}  | out-null
                        if($keySpec.shift){
                            Invoke-CimMethod -InputObject $Keyboard -MethodName "ReleaseKey" -Arguments @{keyCode=$shiftKeyKeyCode}  | out-null
                        }
                    }
                }
            } else {
                Invoke-CimMethod -InputObject $Keyboard -MethodName "TypeText" -Arguments @{AsciiText=$stringToSend} | out-null
            }
        }

        foreach($keyCode in $keyCodesToSend){
            Invoke-CimMethod -InputObject $Keyboard -MethodName "TypeKey" -Arguments @{KeyCode=$keyCode} | out-null
        }

        if($CtrlAltDel){
            Invoke-CimMethod -InputObject $Keyboard -MethodName "TypeCtrlAltDel" -Arguments @{} | out-null
        }
    }
}


function New-Scratchpad {
    <#
        Creates (and opens) a new "scratchpad" - a Powershell script file with a
        date-based file name, in a particular place in my filesystem (which I am
        hardcoding here for lack of a more systematic method of specification),
        with a little bit of boilerplate code at the beginning of the file.

        TODO: get rid of (i.e. replace with a more general source) as much of
        the hardcoded information below as possible.
    #>

    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [string] $title="scratchpad"
    )

    $preamble = @(
        "#!pwsh"
        ". { #initialize"
        "    import-module neil-utility1"
        "    Start-ScriptingJournalTranscript"
        "}; return"
    ) -join "`n"

    $pathOfScratchpadDirectory = "U:/scripting_journal/scratchpads"

    $meaningfulPartOfNameOfScratchpadFile = $title

    $nameOfScratchpadFile = "$(get-date -format "yyyy-MM-dd-HHmm")_$($meaningfulPartOfNameOfScratchpadFile).ps1"

    $pathOfScratchpadFile = (join-path $pathOfScratchpadDirectory $nameOfScratchpadFile)

    #TODO (maybe): verify that the scratchpad file does not already exist.
    #TODO (maybe): create parent directories file does not already exist.

    Set-Content -Path $pathOfScratchpadFile -Value $preamble
    # code $pathOfScratchpadFile
    code --goto "$($pathOfScratchpadFile):9999999999" "U:/scripting_journal"
}

function grantEveryoneFullAccessToFile {
    [outputType([void])]
    [CmdletBinding()]
    Param(
        [parameter()]
        [string]
        $path
    )

    # Write-Host "now working on $pathOfFile"
    if(-not (test-path -Path $path -PathType Leaf)){
        Write-Error "'$($path)' is not a file."
    } else {
        $acl = Get-Acl -Path $path
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")))
        Set-Acl  -Path "\\?\$($path)" -AclObject $acl
        # The "\\?\" prefix is necessary to handle the case where
        # $pathOfFile exceeds the 260-character path-length limit.
        # see [https://github.com/PowerShell/PowerShell/issues/10805]
        #
        # see [https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry]
    }
}

function Invoke-WUJob2 {
    <#
        .SYNOPSIS
        This is a wrapper around the Invoke-WUJob command from the
        PSWindowsUpdate module, which behaves like a synchronous command, and
        hides the complexity of the scheduled task creation (actually, the
        Invoke-WUJob command already goes a long way toward hiding that
        complexity -- this command merely adds a few niceties.)

        Because we are using getCwcPwshWrappedCommand, this requires having
        powershell core installed and available on the path as "pwsh".
    #>
    
    [CmdletBinding()]
    [OutputType([object])]
    Param(
        ## [ScriptBlock] $Script
        [string] $Script
    )
    
    import-module PSWindowsUpdate
    $taskName = "PSWindowsUpdate--$(new-guid)" 
    $pathOfLogFile = (join-path $env:temp "$($taskName).log")
    "" >> $pathOfLogFile
    $innerScript = (
        @(
            "`$pathOfLogFile = '$($pathOfLogFile)'"
            {"$(Get-Date): starting"  >> $pathOfLogFile}
            "import-module '$( (Get-Module PSWindowsUpdate).Path )' *>&1 >> `$pathOfLogFile"
            "`$("
                $Script 
            ") *>&1 >> `$pathOfLogFile"
            {"$(Get-Date): finished" >> $pathOfLogFile}
        ) -join "`n"
    )
    "=============================" >> $pathOfLogFile
    $innerScript >> $pathOfLogFile
    "=============================" >> $pathOfLogFile
    

    $result = @{
        TaskName = $taskName
        Confirm = $false 
        verbose = $true
        RunNow = $true 
        Script = (
            <#  getCwcPwshWrappedCommand is here to work around a quote-escaping
                problem, probably within PSWindowsUpdate, that tends to cause
                the task to fail when there are double quotes in the command.
                Wrapping with getCwcPwshWrappedCommand ensures that there are no
                double quotes in the command that Invoke-WUJob sees.
            #>
            getCwcPwshWrappedCommand $innerScript

        )
    
    } | % { invoke-WUJob @_ } 

    $logReaderJob = Start-Job -ScriptBlock ([ScriptBlock]::Create("gc -wait `$using:pathOfLogFile"))
    while( (Get-WUJob -TaskName $taskName 2>$null).StateName -ceq "Running" ){
        Receive-Job $logReaderJob
        Start-Sleep 2
    }
    Start-Sleep 2
    Stop-Job $logReaderJob
    Receive-Job -Wait -AutoRemoveJob $logReaderJob
    Remove-Item $pathOfLogFile
    #TODO: delete the WUJob.
}

Function Merge-HashTables {  
    <#
        .SYNOPSIS
        Merges the specified hashtables, with the hashtables later in the list
        taking precedence.  No recursive merging is attempted -- nameValue pairs
        from the later hashtables overwrites a nameValue pair from an earlier
        hashtable that has the same name.

        Accepts input from the pipeline and input from unnamed arguments.  



        .EXAMPLE
        #%%
        &{
            $h1 = @{common="h1"; h1Unique=$True } + @{x=44; y=55        }
            $h2 = @{common="h2"; h2Unique=$True } + @{x=66; y=77        } 
            $h3 = @{common="h3"; h3Unique=$True } + @{z=3               } 
            $h4 = @{common="h4"; h4Unique=$True } + @{x=55; y=999;      }
            $h5 = @{common="h5"; h5Unique=$True } + @{w=-6; q=-4        }
            $h6 = @{common="h6"; h6Unique=$True } + @{x=-6; y=-4        }
            $h7 = @{common="h7"; h7Unique=$True } + @{x=-6; y=-4        }
            $h8 = @{common="h8"; h8Unique=$True } + @{x=-6; y=-4        }
            
            @(
                {   Merge-Hashtables                           }         
                {   Merge-Hashtables     $h1                   }        
                {   $h1 | Merge-Hashtables                     }         
                {   Merge-Hashtables     $h1   $h2             }         
                {   Merge-Hashtables     $h1   $h2  $h3        }         
                {   Merge-Hashtables     $h1   $h2  $h3  $h4   }         
                {   Merge-Hashtables     $h1 @($h2; $h3; $h4)  }         
                {   Merge-Hashtables   @($h1;  $h2; $h3) $h4   }         
            ) |
            %{
                $_
                & $_ |% {$_.GetEnumerator()} | sort Name | select Name, Value | ft -auto
            }
        }
        #%%

        .NOTES

        I would like to allow flexibility in passing any combination of zero or
        more hashtables and enumerables thereof as any combination of pipeline
        input and parameter input.  Achieving this requires some thought.  Not
        all combinations are yet supported, but the simple ones are. 
        

        TODO: allow this function to ingest any combination of hashtables,
        keyvalue pairs, DictionaryEntrys, and enumerables thereof.

        See
        [https://stackoverflow.com/questions/8800375/merging-hashtables-in-powershell-how].

    #>

    [CmdletBinding(PositionalBinding=$False)]
    [OutputType([HashTable])]
    Param(
        [parameter(Position=0)]
        [HashTable[]] $HashTablesToMerge,


        [parameter(ValueFromRemainingArguments=$True)]
        [HashTable[]] $HashTablesFromRemainingArguments,

        
        [parameter(ValueFromPipeline=$True)]
        [HashTable] $InputObject
    )


    begin {
        [HashTable[]] $allHashTablesToMerge = @()
        $countOfAllHashtablesMerged = 0
        $returnValue = @{}
    }

    process {
        if(-not ($null -eq $InputObject)) {$countOfAllHashtablesMerged++}
        ## if(-not ($null -eq $InputObject)) {Write-Host $InputeObject.GetType().FullName}
        ForEach ($key in $InputObject.Keys) {
            ## if($returnValue.Contains($key)){$returnValue.Remove($key)}
            # the above if statement is only useful for debugging, where we
            # return an ordered dictionary, to get an idea of the order in which
            # the arguments are being processed.
            $returnValue[$key] = $InputObject[$key]
        }
    }

    end {
        $allHashTablesToMerge += $HashTablesToMerge
        ForEach ($hashtable in ($HashTablesToMerge + $HashTablesFromRemainingArguments)) {
            if(-not ($null -eq $hashtable)) {$countOfAllHashtablesMerged++}
            ## if(-not ($null -eq $hashtable)) {Write-Host $hashtable.GetType().FullName}
            ForEach ($key in $hashtable.Keys) {
                ## if($returnValue.Contains($key)){$returnValue.Remove($key)}
                # the above if statement is only useful for debugging, where we
                # return an ordered dictionary, to get an idea of the order in which
                # the arguments are being processed.
                $returnValue[$key] = $hashtable[$key]
            }
        }
        ## Write-Host "`$countOfAllHashtablesMerged: $($countOfAllHashtablesMerged)"
        return $returnValue
    }
}