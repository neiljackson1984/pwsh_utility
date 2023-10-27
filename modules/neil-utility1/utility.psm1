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
    
    foreach($field in @($bitwardenItem['fields'])){
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
    
    $sshPrivateKey = bw --raw get attachment id_rsa --itemid (
        (
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_private_key_reference"} | 
            select -first 1 |
            % {$_.value} |
            ? {$_}
        ) ?? (
            $bitwardenItem.id
        )
    ) 

    return $sshPrivateKey
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
    

    $sshHost = @(
        @(
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_host"} | 
            select -first 1 |% {$_.value}
    
    
            $bitwardenItem.login.uris |
            % { ([System.Uri] $_.uri ).Host } 
        ) |
        ? {$_}
    ) | select -first 1
    
    $sshUsername = (
        (
            $bitwardenItem.fields |
            ? {$_.name -ceq "ssh_username"} | 
            select -first 1 | % {$_.value} | 
            ? {$_}
        ) ?? (
            $bitwardenItem.login.username
        )
    )
    
    $sshPort = $bitwardenItem.fields |? {$_.name -ceq "ssh_port"} | select -first 1 |% {$_.value} |? {$_}

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
    as of 2023-09-19: expects global variable $sshOptionArguments to exist,
    having been assigned for instance by running something like
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
        # perhaps we should force $inputObject top be a string after all and
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
            # it is a bit of a hack to be specifying our line ending conventions
            # hardcoded here, but for the application that I happen to be
            # working on at the moment, I want unix-style line endings, and I
            # don't care too much about a terminal newline (I would rather have
            # no terminal newline sequence than a \r\n sequence, which is what I
            # would get if I did not do the byte pipe workaround above.

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


    $SMTPClient = New-Object Net.Mail.SmtpClient(  
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

function setLicensesAssignedToMgUser($userId, $skuPartNumbers){
    # $azureAdUser = Get-AzureADUser -ObjectId $objectIdOfAzureAdUser
    # $mgUser = Get-MgUser -UserId  $userId
    
    # $propertyNames = @(get-mguser -UserId $userId  | get-member -MemberType Property | foreach-object {$_.Name}) 
    # $mgUser = get-mguser -UserId $userId -Property $propertyNames
    
    # $mgUser = get-mguser -UserId $userId -Property @("UsageLocation", "AssignedLicenses") 
    $mgUser = get-mguser -UserId $userId 
    if (! $mgUser ){
        Write-Host "No mgUser having id $userId exists."
        return
    } 

    # to view the available sku part numbers, run the following command:
    # # (Get-AzureADSubscribedSku).SkuPartNumber
    # (Get-MgSubscribedSku).SkuPartNumber

    $mgSubscribedSku = Get-MgSubscribedSku

    # assign licenses:
    # annoyingly, there does not seem to be a good way to buy licenses programmatically 
    $desiredSkuIds = @(
        $mgSubscribedSku | 
            where-object { $_.SkuPartNumber -in @($skuPartNumbers) } |
            foreach-object { $_.SkuId }
    )
    $initialExistingSkuIds = @(
        # Get-MgUserLicenseDetail -UserId $mgUser.Id | 
        # $mgUser.AssignedLicenses | 
        (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
            where-object { $_ } | 
            foreach-object {$_.SkuId}
    )
    Write-Host (
        @(
            "Initially, $($mgUser.UserPrincipalName) has the "
            "following $($initialExistingSkuIds.Length) skuPartNumbers: " 
            ( 
                @( 
                    # $mgSubscribedSku |
                    # where-object { $_.SkuId -in $initialExistingSkuIds } |
                    # foreach-object {$_.SkuPartNumber}

                    $initialExistingSkuIds | % {skuIdToSkuPartNumber $_}


                ) -Join ", "
            )
        ) -join ""
    )
    
    #ensure that licenses are assigned:
    $skuIdsToRemoveFromUser = @($initialExistingSkuIds | where-object {-not ($_ -in $desiredSkuIds)});
    $skuIdsToGiveToUser = @($desiredSkuIds | where-object {-not ($_ -in $initialExistingSkuIds)});
    
    Write-Host ("skuIdsToRemoveFromUser ($($skuIdsToRemoveFromUser.Length)): ", $skuIdsToRemoveFromUser)
    Write-Host ("skuIdsToGiveToUser ($($skuIdsToGiveToUser.Length)):", $skuIdsToGiveToUser)
    
    if($skuIdsToRemoveFromUser -or $skuIdsToGiveToUser){
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
            # $mgUser = get-mguser -UserId $userId -Property @("UsageLocation", "AssignedLicenses") 
        }

        # if($skuIdsToRemoveFromUser){
        #     # # $assignedLicenses.RemoveLicenses = @($skuIdsToRemoveFromUser | foreach-object {$x = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense; $x.SkuId = $_; $x })
        #     $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
        #     $assignedLicenses.RemoveLicenses = $skuIdsToRemoveFromUser
        #     Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses


        # }
        
        # foreach($skuIdToGiveToUser in $skuIdsToGiveToUser){
        #     $assignedLicense = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense;
        #     $assignedLicense.SkuId = $skuIdToGiveToUser;
        #     $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses;
        #     $assignedLicenses.AddLicenses = $assignedLicense;
        #     $azureAdUser | Set-AzureADUser -UsageLocation "US"
        #     Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        # }

        # if($skuIdsToGiveToUser){
            # $assignedLicenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            # $assignedLicenses.AddLicenses = $skuIdsToGiveToUser
            # Set-AzureAdUserLicense -ObjectId $azureAdUser.ObjectId -AssignedLicenses $assignedLicenses
        # }



        $s = @{
            UserId = $mgUser.Id
            RemoveLicenses = $skuIdsToRemoveFromUser
            AddLicenses = (
                # [IMicrosoftGraphAssignedLicense[]]
                @(
                    $skuIdsToGiveToUser | 
                        foreach-object {
                            (
                                # [IMicrosoftGraphAssignedLicense] 
                                @{
                                    DisabledPlans = @()
                                    SkuId = $_
                                }
                            )
                        }
                )
            )
        }; Set-MgUserLicense @s 1> $null

        $finalExistingSkuIds = @(
            # Get-MgUserLicenseDetail -UserId $mgUser.Id |
            # $mgUser.AssignedLicenses | 
            (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses |
                where-object { $_ } | 
                foreach-object {$_.SkuId}
        )
        Write-Host (
            @(
                "After making changes, $($mgUser.UserPrincipalName) "
                "has these $($finalExistingSkuIds.Length) skuPartNumbers: " 
                ( 
                    @(
                        # $mgSubscribedSku | 
                        #     where-object { $_.SkuId -in $finalExistingSkuIds } | 
                        #     foreach-object {$_.SkuPartNumber}

                        $finalExistingSkuIds | % {skuIdToSkuPartNumber $_}

                    ) -Join ", "
                )
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


function downloadAndExpandArchiveFile{
    <#
    .SYNOPSIS
    returns the path of the directory in which the arcvhie file was expanded.
    
    .PARAMETER url
    Parameter description
    
    .PARAMETER pathOfDirectoryInWhichToExpand
    Parameter description
    #>
    
    Param(
        [parameter()]
        [string] $url,

        [parameter(Mandatory=$false)]
        [string] $pathOfDirectoryInWhichToExpand = [string] (join-path $env:temp (new-guid).guid)
    ) 
    
    [OutputType([String])]
    
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
    
    $localPathOfArchiveFile = downloadFileAndReturnPath $url
    
    New-Item -ItemType "directory" -Path $pathOfDirectoryInWhichToExpand -ErrorAction SilentlyContinue | out-null
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
        "$localPathOfArchiveFile" 
        
        # <file_names>...
        "*"
    ) | write-host

    return ([string] $pathOfDirectoryInWhichToExpand)
}

function downloadFileAndReturnPath {
    <#
    .SYNOPSIS
    Downloads the file from the specified url, to an arbitrary local path
    (perhaps in a unique-named-folder in the downloads folder?) Returns the path
    of the downloaded file.

    #>
    
    Param(
        [parameter()]
        [String] $urlOfFile
    ) 

    [OutputType([String])]
    
    
    # $filenameOfDownloadedFile = (split-path -leaf $urlOfFile )
    # todo: deal with the case where the above expression produces an invalid
    # file name. one strategy would be to extract a reasonable filename from the
    # metadata returned by the web request.

    $pathOfDedicatedDirectoryToContainDownloadedFile = (join-path $env:temp (new-guid).Guid)
    New-Item -ItemType Directory $pathOfDedicatedDirectoryToContainDownloadedFile -ErrorAction SilentlyContinue | out-null

    # $temporaryPathOfDownloadedFile = (join-path $env:temp (new-guid).Guid)
    # New-Item -ItemType "directory" -Path (Split-Path $temporaryPathOfDownloadedFile -Parent) -ErrorAction SilentlyContinue | out-null


  

    # # $downloadJobScriptBlock = ([Scriptblock]::Create("pwsh -c `"```$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -UserAgent 'Mozilla' -Uri '$($urlOfFile)'  -OutFile '$($localPathOfDownloadedFile)' `"  "))
    # # $downloadJobScriptBlock = ([Scriptblock]::Create("pwsh -c `"```$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '$($urlOfFile)'  -OutFile '$($localPathOfDownloadedFile)' `"  "))
    # $downloadJobScriptBlock = {
    #     $result = @{
    #         uri = $args[0].urlOfFile
    #         OutFile = $args[0].temporaryPathOfDownloadedFile
    #         PassThru = $True
    #     } | % { Invoke-WebRequest @_ }

    #     $FileName = [Net.Http.Headers.ContentDispositionHeaderValue]::Parse($result.Headers.'Content-Disposition').FileName
    #     Write-Output "FileName is $FileName"

    #     New-Item -ItemType "directory" -Path ($args[0].pathOfDedicatedDirectoryToContainDownloadedFile) -ErrorAction SilentlyContinue | out-null
        
    #     $source = $args[0].temporaryPathOfDownloadedFile
    #     $destination = (join-path ($args[0].pathOfDedicatedDirectoryToContainDownloadedFile) $FileName)
        
    #     Write-Output "source: $source"
    #     Write-Output "destination: $destination"

    #     Move-Item $source $destination 
    # }
    # Write-Host "temporaryPathOfDownloadedFile: $temporaryPathOfDownloadedFile"
    # # Write-Host "downloadJobScriptBlock: $downloadJobScriptBlock"
    # $downloadJob = @{
    #     ScriptBlock = $downloadJobScriptBlock
    #     ArgumentList = @(
    #         @{
    #             urlOfFile = $urlOfFile
    #             temporaryPathOfDownloadedFile = $temporaryPathOfDownloadedFile
    #             pathOfDedicatedDirectoryToContainDownloadedFile = $pathOfDedicatedDirectoryToContainDownloadedFile
    #         }
    #     )
    # } | % { Start-Job  @_ }
    

    # while ( -not ((Get-Job -InstanceId $downloadJob.InstanceId).JobStateInfo.State -eq [System.Management.Automation.JobState]::Completed) ) {
    #     write-host "$(get-date): size of $($temporaryPathOfDownloadedFile): $(if(Test-Path -Path $temporaryPathOfDownloadedFile -PathType leaf){(get-item $temporaryPathOfDownloadedFile).Length}else{ "(file does not exist)" })"
    #     start-sleep 6
    # }
    # $pathOfCookieJarFile = (join-path $env:temp (new-guid))

    curl @(
        # "--progress-bar"
        "--remote-name"
        # "--verbose"

        # "--remote-header-name"

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


        "--output-dir";$pathOfDedicatedDirectoryToContainDownloadedFile
        $urlOfFile
    )

    # $localPathOfDownloadedFile = (join-path $pathOfDedicatedDirectoryToContainDownloadedFile $filenameOfDownloadedFile)
    $localPathOfDownloadedFile = Get-ChildItem -File $pathOfDedicatedDirectoryToContainDownloadedFile | select -first 1 | select -expand FullName


    return $localPathOfDownloadedFile
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
        choco upgrade --acceptlicense --confirm chocolatey  

        #ensure that 7zip is installed
        choco upgrade --acceptlicense --yes 7zip 

        #ensure that pwsh is installed
        choco upgrade --acceptlicense --yes pwsh  

        choco upgrade --acceptlicense --yes --force "winmerge"
        choco upgrade --acceptlicense --yes --force "spacesniffer"
        choco upgrade --acceptlicense --yes --force "notepadplusplus"
        choco upgrade --acceptlicense --yes --force "sysinternals"
        
        choco upgrade --acceptlicense --yes --force "hdtune"

        # "upgrade" installs if it is not already installed, so we do not need
        # to do both "install" and "upgrade"; "upgrade" on its own will ensure
        # that we end up with the latest version installed regardless of the
        # initial condition.
    }
}


function runElevatedInActiveSession(){
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
    
    Param(
        # [System.Management.Automation.Runspaces.PSSession] $session,

        [parameter(ValueFromRemainingArguments = $true)]
        [String[]] $remainingArguments
    ) 
    
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
        # $ErrorActionPreference = "Continue"

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
            $remainingArguments
        )

        # PsExec @argumentsForPsExec 2>&1 |% {"$_"}
        PsExec @argumentsForPsExec 2>&1 | out-string -stream
        # PsExec @argumentsForPsExec
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
        [string[]] $remainingArguments
    )
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
                                # $remainingArguments ? 
                                # @{Argument=($remainingArguments -join " ")} :
                                # @{}
                                if($remainingArguments){ 
                                    @{Argument=($remainingArguments -join " ")}
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
        Runs an exeutable file in such a way that the executable file will see its
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
    
    $existingPathEntries = @(([System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)) -Split ([IO.Path]::PathSeparator) | Where-Object {$_})
    # $desiredPathEntries = deduplicate($existingPathEntries + $pathEntry)
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
        [System.EnvironmentVariableTarget]::Machine
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

function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}

function Enable-UserAccessControl {
    Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"  -force:$true
    Write-Host "User Access Control (UAC) has been enabled (or more accurately: reset to default)." -ForegroundColor Green    
}

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


    $strongNameOfFile = (@(
        [System.IO.Path]::GetFileNameWithoutExtension($path)
        
        "--"
        
        (Get-FileHash -Algorithm "SHA256" -Path $path).Hash.Trim().ToLower()

        [System.IO.Path]::GetExtension($path)
    ) -join "")

    return (join-path (split-path -parent $path) $strongNameOfFile)
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

function runInCwcSession {
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [Parameter()] [string] $bitwardenItemIdOfScreenconnectCredentials, 

        [Parameter(Mandatory=$False)] [string] $nameOfGroup, 
        [Parameter()] [string] $nameOfSession,
        
        [Parameter()] [string] $command,
        [Parameter(Mandatory=$False)] [int] $timeout
    )
    Import-Module ConnectWiseControlAPI

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

    ## run the command
    (
        @{
            GUID = $cwcSession.SessionID 
            
            Powershell = $True 
            Command =  (
                @(
                    "#maxlength=1000000"
                    $command
                ) -join "`n"
            )
        } +
        $(if($timeout){@{Timeout = $timeout}} else {@{}})
    ) | % { Invoke-CWCCommand @_ }
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

    $strongName = (split-path -leaf (getStronglyNamedPath $pathOfFile))
    $pathOfDestinationDirectory = (join-path $env:OneDriveCommercial Attachments)
    $pathOFDestinationFile = (join-path $pathOfDestinationDirectory $strongName)
    Copy-Item $pathOfFile $pathOFDestinationFile | out-null
    return $pathOFDestinationFile

    ## THIS FUNCTION IS NOT COMPLETE AS OF 2023-10-14-1231
}