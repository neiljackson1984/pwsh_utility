function unlockTheBitwardenVault(){
    #temporary hack to speed things up:
    Write-Debug "blindly assuming that bitwarden vault is unlocked..."; return
    
    Write-Information "Attempting to unlock the bitwarden vault..."
    if ($(bw unlock --check)) {
        Write-Information "The bitwarden vault is already unlocked."
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

    <#  # 2023-05-15-1101: 
        The type of $bitwardenItem (and the type of any nested objects) at this
        point happens to be System.Management.Automation.OrderedHashtable.  If
        we were to omit the "-AsHashTable" switch, above, the type of
        $bitwarenItem (and the type of any nested objects) would be
        System.Management.Automation.PSCustomObject.  These types behave very
        similarly, but the hash table has the advantage that all of the original
        json properties are represented as keys in the hash table, whereas with
        the pscustomobject, I have the sense that there would be some property
        names that could appear in the original json but would not be accessible
        in the PScustomObject because they would be shadowed by PsCustomObject's
        own properties.  In other words, with the hash table, uniquely, we can
        always resort to square-bracket member access operator if we need to. 
    #>


    <#  todo: a bit of a hack to work around the overhead in calling the bw
        executable might be to store a private cache of the vault here (or
        memoize one result at a time).  Not great for security or concurrency,
        but it might help bring the delay into a tolerable range.  Along the
        same lines, we might explore the "rbw" client, which is an unofficial
        bitwardin command-line client written in Rust that purports to be much
        faster than the official, node.js-based, bitwarden client. 
    #>
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
    $bitwardenItem | ConvertTo-Json -Depth 99 | bw --nointeraction --raw  encode | bw --nointeraction --raw edit item $bitwardenItem.id | out-null
    return (Get-BitwardenItem -bitwardenItemId $bitwardenItem['id'] )
}

Set-Alias makeNewBitwardenItem New-BitwardenItem
function New-BitwardenItem {
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The name of the bitwarden item")]
        [String] $name = "THIS IS AN AUTOMATICALLY GENERATED NAME $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss") c0f223d7178f4e4c85f7e1b902bc3739"
        <#  Evidently, the name field is not allowed to be an empty string the
            hardocded guid in the default name above, is to allow me to easily
            find (and delete) accidentally programmatically created bitwarden
            items, created by this function (and then, for whatever reason, never
            modified later to change the name) 
        #>
    )

    [HashTable] $bitwardenItem = ( bw --nointeraction --raw get template item | ConvertFrom-Json -AsHashtable)
    $bitwardenItem['name'] = $name
    $bitwardenItem['notes'] = "created programmatically $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss")`nfoo_ef7ba3fce1bc482c8fb5304da2e2a89e" 
    # this magic string is mainly for testing, just to help me find and delete all the new bitwarden items that I created during testing .

    ## $bitwardenItem['login'] = ( bw --nointeraction --raw get template item.login | ConvertFrom-Json -AsHashtable)
    ## $bitwardenItem['login']['username'] = ""
    ## $bitwardenItem['login']['password'] = ""
    ## $bitwardenItem['login']['totp'] = ""

    $bitwardenItem['login'] =  @{}
    <#
        Annoyingly, the template login object returned by `bw --nointeraction
        --raw get template item.login` contains not minimal null-ish field
        values, but rather bogus example values, like "jdoe" for the username.

        The template "item" object returned by `bw --nointeraction --raw get
        template item` has the same problem: the value of the "name" field is
        "Item name", and the value of the notes field is "Some notes about this
        item.".  But, we are overwriting both the notes field and the name field
        here.

        the template that we want is equivalent to what you would get if you
        created a new bitwarden item in the GUI, and saved it without filling in
        any of the fields -- most of the fields would then be null or the empty
        string.

        fortunately, it seems to suffice to specify the "login" property of the
        bitwarden item to be an empty hashtable.  I suspect we might be able to
        get away specifying the entire new item as an empty hashtable (with the
        possible exceptionof requiring a truthy "name" field).

        It might make sense to generate a random password and fill in the
        password field, or provide an option to do this.
    #>

    unlockTheBitwardenVault
    $result = [System.Convert]::ToBase64String( ([system.Text.Encoding]::UTF8).GetBytes(($bitwardenItem | ConvertTo-Json -Depth 50)) )  | bw --nointeraction --raw create item 
    $newlyCreatedBitwardenItem = ( $result | ConvertFrom-Json -AsHashtable)
    Write-Information "created new bitwarden item having id $($newlyCreatedBitwardenItem['id'])."
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

    $fieldMap = [ordered] @{}
    

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

Set-Alias Open-BitwardenItem Show-BitwardenItem
function Show-BitwardenItem {
    <#
        .SYNOPSIS
        Opens the specified Bitwarden item for viewing in the GUI.

        This is a bit of a hack -- depends on having Firefox with the Bitwarden
        plugin installed, with the correct hardcoded plugin id, which I am not
        at all sure is consistent across installations.  Works on my machine.
    #>
    [CmdletBinding()]
    Param(

        [Parameter(
            HelpMessage=  "The bitwarden item id of the bitwarden item we want to view",
            Mandatory = $True
        )]
        [String] $bitwardenItemId 
    )

    $idOfFirefoxExtension = "0516f8c4-cf97-4186-b8d6-403e911d48ab"
    <#  it is a bit of a hack to hardcode this here.  It tends to vary every
        time the bitwarden extension is updated, and possibly also varies across
        machines.
    #>

    $resolvedBitwardenItemId = $((Get-BitwardenItem $bitwardenItemId).id 2>$null)
    <#  This business about "resolving" the bitwarden item id is because,
        whereas each bitwarden item has a formal, opaque, id that is a guid, the
        bitwarden cli (but not the firefox extension's url syntax) lets you
        treat the name of a bitwarden item, if that name is unique among all
        bitwarden items, as a bitwarden item id.  In order to preserve these
        same semantics, I "resolve" the specified bitwarden item id, which might
        be a unique name rather than a formal guid-based id, into the
        corresponding formal, guid-based id.
    #>

    if($resolvedBitwardenItemId){
        @{
            FilePath = "firefox" 
            ArgumentList = @(
                "moz-extension://$($idOfFirefoxExtension)/popup/index.html?uilocation=popout#/view-cipher?cipherId=$($resolvedBitwardenItemId)"
            )
        } |% {Start-Process  @_}
    } else {
        write-error "Could not resolve the specified bitwarden item id ('$($bitwardenItemId)') to a valid bitwarden item id."
    }
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

    <#  the above technique to get the $sshPrivateKey is problematic because of
        the powershell newline-handling problem.

        I am not sure how I ever used  getSshPrivateKeyFromBitwardenItem() and
        initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment()
        without running into this newline problem before.  Was I perhaps using
        the built-in windows installation of OpenSSH and perhaps the built-in
        installation tolerates windows-style line endings?  That sounds
        familiar.

        see
        [https://stackoverflow.com/questions/59110563/different-behaviour-and-output-when-piping-in-cmd-and-powershell/59118502#59118502].

        the workaround is either to use the --ouput option to the bw command so
        that bw dumps the output to a file rather than stdout, and then read the
        file (which is not ideal becuase we would like to keep this sensitive
        plaintext off the disk) or to run the bw command with
        System.Diagnostics.Process, and capture stdout.

        CAUTION: In the case where the bw command is coming from the npm package
        @bitwarden/cli, bw might be a powershell script (bw.ps1) rather than a
        native executable, and, specifically, the powershell-script version of
        the bw command evidently subjects the output of the attachment getting
        command through powershell's chop-into-lines behavior, with the result
        that the stdout of the below $process might indeed contain windows-style
        newlines even if the file attached to the bitwarden item contained only
        linefeeds.

        This is arguable a failing of the @bitwarden/cli module.  An
        understandable failing, perhaps, but still.

        note: if we omit the --raw option, the bw command saves the attached
        file to the current working directory -- not what we want. 
    #>

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
        <#  temporary work-around for sophos router (I might need to replace my
            favorite keypair  with a new one that does not rely on the
            now-deprecated SHA-1 hash algorithm (although I am not entirely sure
            how the key pair depends on the hash algorithm) -- the source of the
            dependency might be the hash that is stored by the server in the
            authorized keys list. possibly, I merely need to recompute a
            different hash of my public key and store this different hash in the
            the server. 

            see https://www.openssh.com/txt/release-8.2 

        #>
    
        <#  evidently, if we have multiple "-o HostKeyAlgorithms..." options,
            only the first one is attended to, even when we are using the "+"
            notation to say "add this item to the existing list". hence, I have
            combined the sophos router workaround (+ssh-rsa) and the ILO3
            workaround (+ssh-dss) into one option argument for each property.
            We ought to figure ought a way to encode these options for
            exceptional cases in bitwarden. 
        #>
        
        ## "-o"; "HostKeyAlgorithms=+ssh-rsa,ssh-dss"
        ## "-o"; "PubkeyAcceptedKeyTypes=+ssh-rsa,ssh-dss"
        <#  as of OpenSSH_9.9p1, OpenSSL 3.0.15 3 Sep 2024, which I noticed on
            2025-01-20, the ssh-dss  algorithm is no longer supported.
            Therefore, I have removde these from the list.  AS a result, I
            suspect that ssh into ILO3 will no longer work.
        #>
        "-o"; "HostKeyAlgorithms=+ssh-rsa"
        "-o"; "PubkeyAcceptedKeyTypes=+ssh-rsa"


        "-o"; "KexAlgorithms=+diffie-hellman-group1-sha1"
        <#  this is a workaround for ssh'ing into an ILO3 controller on an HP
            Proliant Gen7 server. allowing this key exchange algorithm
            constitutes a reduction in security, and probably shouldn't be left
            here for all time.

            see
            [https://unix.stackexchange.com/questions/340844/how-to-enable-diffie-hellman-group1-sha1-key-exchange-on-debian-8-0]

            see [http://www.openssh.com/legacy.html] 
        #>
    
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

    <#  this achieves the desired effect of having the ssh-agent process be a
        child process of the shell (so that the ssh-agent process dies with the
        shell).  Notice the -D option to ssh-agent, which tells ssh-agent to run
        in the foreground and not fork.  

        Curiously, when we run ssh-agent with the -D option, ssh-agent does not
        spit out the SSH_AGENT_PID value -- only the SSH_AUTH_SOCK value.
        ssh-agent does still emit "echo Agent pid 1476;" (for example), so the
        information about the pid is still extractable, but why wouldn't it just
        go ahead and emit the line to set the SSH_AGENT_PID environment
        variable? Admittedly, if we are launching ssh-agent in non-forking mode
        (by using the - -D option), we probably can figure out the pid of the
        ssh-agent process by means other than looking at the bash code that
        ssh-agent emits on stdout, but still, what could be the harm in
        ssh-agent emitting the "SSH_AGENT_PID=..." code?  There must be some
        intentional reason for this behavior.

        Is the SSH_AGENT_PID variable really needed in all cases?  Perhaps
        SSH_AUTH_SOCK is sufficient for the main funciton of ssh-agent and the
        realted tools (ssh-add, ssh, etc.).  Maybe the reason the
        "SSH_AGENT_PID=..." code is emitted at all by ssh-agent is to give us
        the pid of the agent so that we can kill the ssh-agent process when we
        want (much like I am wanting to have ssh-agent die with the shell). 
    #>


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
    Write-Information



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
    command line to make the command very short and readable (we typically set
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
        <#  in spirit, $inputObject should be a string, but, in order to allow a
            workaround to the powersehll behavior of always appending a newline
            (and a "\r\n" newline at that) to the end of the last string (or
            maybe every string) piped into a native program, we want to allow
            $inputObject to be a byte-like thing (because the workaround is to
            convert the string to an enmumerable of bytes, and then pipe each
            byte one at a time into the powershell pipeline.  setting the type
            here to object serves the purpose.

            perhaps we should force $inputObject to be a string after all and
            then do the conversion to an enumerable of bytes within this
            function.

            As of 2023-09-19, the latest non-beta release of powershell (version
            7.3.6) does not support the byte piping behavior, but the preview
            version (version 7.4.0-preview.5) does support the byte piping
            behavior.  If the byte-piping behavior is supported, then we can
            have $iunputObject be of type string, which is what we want.
        #>

                
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
            <#  it is valid, I think, to allow rr to be called without any
                "remaining arguments" -- this has the same effect as calling ssh
                without any "command" specified, so that we are dropped into an
                interactive shell.  

                I am not sure I like this behavior (it's potentially unexpected,
                and potentially hard to remember that it exists, and hard to
                recognize in code if you don't already know about it.) 
            #>

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
            <#  strangely, when you invoke a function not in a pipeline (or at
                the beginning of a pipeline) and when you do not pass the
                -inputObject parameter, powershell still runs the process block.
                This makes no sense to me, because in this case there is no
                input; the number of input objects is zero.  I expect powershell
                to run the process block exactly as many times as there are
                input objects.  If there are zero input objects, I explect
                powershell to run the process block zero times, but it actually
                runs the process block exactly one times.

                the only reliable and specific way I have found to detect when
                the process block is being run in this special case (where it
                really shouldn't run) is to see whether $PSBoundParameters.Keys
                contains "inputObject".

                Within the process block, $PSBoundParameters.Keys contains
                "inputObject" when, and only when, the process block is running
                due to an explicit -inputObject parameter having been passed or
                the process block is running due to an object having been
                received on the pipeline. 

                Looking at whether $inputObject is null as a way to detect when
                we are in the special "unexpected" case is no good in general
                because the user might want to actually pass $null as a pipeline
                object or as the value of the -inputObject parameter.  Also, in
                the case where I have declared the type of inputObject to be
                string (for instance), powershell will coerce $null to an empty
                string.  Well, I could look for empty strings, but the user
                might have wanted to pass an empty string as a first class input
                object and then we have the same problem.  checking for the
                presence of "inputObject" in $PSBoundParameters.Keys works
                regardless of whether the inputObject is null. 
            #>

            $inputObjects += $inputObject

        }

        
    
    }

    # process {}
    <#  the mere presence of a process block, even an empty one, causes $input
        to be empty in the end block. 
    #>

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

        ## $dummyDestination = ""
        $dummyDestination = "dummyHostname"
        $sshArguments =  @(
            "-o"; "IdentityAgent=$($sshAgentEnvironment['SSH_AUTH_SOCK'])" 
            ## "-o"; "StdinNull=yes"
            $sshOptionArguments 
            $dummyDestination 
            $argumentList
        )

                
        <#  we are specifying the "destination" (i.e. host name and port number)
            by means of the sshOptionArguments rather than with the
            "destination" positional command line argument to ssh. Nevertheless,
            ssh still expects to see some argument in the "destination" position
            on the command line.  If we just slap on $argumentList without
            having anything in the "destination" position, ssh will assume that
            the first word in $argumentList is the destination and will
            therefore not treat that word as the first word of the command that
            we want to run within the ssh session.  To deal with this
            requirement, we pass an empty string in the "destination" position.
            (would it also work to pass any arbitrary word (perhaps ssh ignores
            the destination argument when a destination is speciifed in the
            option arguments.)?  What about a hyphen?) 

            2025-01-21-1811: we are now passing the string "dummyHostname"  in
            order to  be better tolerate various quoting or escape conventions,
            which might convert our empty string of a hostname into an omitted
            item from the listof arguments rather than a present (but empty)
            string.
        #>

        switch("strategy2"){
            strategy1 {
                # $inputObjects | ssh @sshOptionArguments "" @argumentList
                if($inputObjects.Count -gt 0){
                    ## $inputObjects | ssh @sshOptionArguments "" @argumentList
                    ## ( ,[byte[]] ($inputObjects | % { [System.Text.Encoding]::UTF8.GetBytes($_) })   ) | ssh @sshOptionArguments "" @argumentList
                    
                    ( 
                        ,[byte[]] ([System.Text.Encoding]::UTF8.GetBytes(($inputObjects -join "`n")))
                    ) | 
                    ssh $sshArguments

                    <#  it is a bit of a hack to be hardcoding our line ending
                        conventions here, but for the application that I happen to be
                        working on at the moment, I want unix-style line endings, and I
                        don't care too much about a terminal newline (I would rather
                        have no terminal newline sequence than a \r\n sequence, which is
                        what I would get if I did not do the byte pipe workaround
                        above.)


                        Interactive commands are a bit wonky, I think.  At least, I
                        think I have observed that powershell caches stderr and only
                        prints it once rr has returned.  I think I ahve observed that
                        powershell does not do this weird stderr caching behavior when
                        there is no pipeline input to rr (i.e. when the below "else"
                        clause obtains).

                        the significant differnece between these two cases (this "if"
                        block and the below "else" block), at least insofar as what
                        would affect stream handling, is that in this "if" block, we
                        pipe some input into ssh wheras in the below "else" block we do
                        not pipe anything into ssh.  Therefore, perhaps it is the piping
                        of input that is causing the stderr caching.  (and I suspect the
                        stderr caching has more to do with powershell than ssh).

                        I might be completely wrong about powershell having anything to
                        do with the "stderr caching" behavior. I noticed the "stderr
                        caching behavior" when attempting to run the Sophos interactive
                        "cc" command via an ssh session to a Sophos UTM SG router.  The
                        behavior could have been entirely the result of things happening
                        in bash and ssh daemon within the sophos router.

                        No, never mind, the stderr caching is a powershell thing (or
                        maybe an ssh thing).  look at this:

                        ```
                        rr "bash -c 'echo 1 here is some stderr 1>&2; echo 2 and here is some stdout; echo 3 and here is some more stderr 1>&2; '"
                        ```
                        ## 2 and here is some stdout
                        ## 1 here is some stderr
                        ## 3 and here is some more stderr

                        The following might be relevant:
                        [https://stackoverflow.com/questions/45316295/the-order-of-stdout-and-stderr-in-bash]

                        the "stderr cahching" behaviour might have to do with bash (or
                        perhaps the program running within bash) thinks it is connected
                        to a terminal, and deciding to do line buffereing (iof connected
                        to a terminal) or block buffering (if not connected to a
                        terminal).

                        the following might also be relevant:
                        [https://www.gnu.org/software/bash/manual/bash.html#Interactive-Shells] 

                    #>
                } else {
                    # write-host "no inputObjects given"
                    ssh $sshArguments
                    <#  I was hoping that this would run in a way that is fully
                        connected to the terminal, but it does not. 
                    #>
                }
            }

            strategy2  {
                <#  2025-01-21-1827: With the latest version of openssh
                    (OpenSSH_9.9p1, OpenSSL 3.0.15 3 Sep 2024), I have noticed
                    that, when I pipe the output of ssh (or, equivalently (i
                    think), pipe the output of runInSshSession) to anything
                    other than Out-Default (or similarly attempt to capture the
                    output of the command in a variable), an apparent race
                    condition kicks in, where (it seems) ssh waits for
                    powershell to read its stderr before dying or emitting more
                    stuff on stdout, and powershell waits for ssh to emit more
                    stuff on stdout or die.  

                    Curiously, wrapping the invocation in "bash -c" doesn't
                    help.

                    I suspect that the essential problem is the "deadlock"
                    condition due to synchronous io operations, as  described at
                    (https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standarderror?view=net-9.0#remarks).

                    Specifically, quoting from that document:

                    """
                    A deadlock condition results if the parent process calls
                    p.StandardOutput.ReadToEnd followed by
                    p.StandardError.ReadToEnd and the child process writes
                    enough text to fill its error stream. The parent process
                    would wait indefinitely for the child process to close its
                    StandardOutput stream. The child process would wait
                    indefinitely for the parent to read from the full
                    StandardError stream.
                    """

                    The problem is possibly exacerbated by some idiosyncratic
                    behvaior by ssh; I don't remember encountering this  problem
                    on the older version of ssh that I have been running until
                    now (and I cannot remember exactly what version of ssh that
                    was -- it was some version earlier than OpenSSH 9.7, I
                    think.).

                    To work around this problem, we are now invoking ssh by
                    means of System.Diagnostics.Process.

                    This should produce the correct, desired, behavior in cases
                    where we are capturing the output of  runInSshSession (by
                    piping it to another command, for example).  However, it
                    will prevent the occasionally-desirable behavior, which we
                    had before this fix, that we could run runInSshSession with
                    $argumentList being empty, and not attempting to capture the
                    output, and running in an interactive powershell session,
                    and we would then be dropped into an interactive remote
                    shell session (just like calling ssh without specifying a
                    remote command).

                    To recover this lost functionality,  I should probably try
                    to detect when we are running interactively (i.e. when our
                    output is not being captured), which should be detectable,
                    in some cases by looking  at
                    $PSCmdlet.MyInvocation.PipelinePosition and
                    $PSCmdlet.MyInvocation.PipelineLength , and then in that
                    case not use the work-around (when our output is not being
                    captured, the deadlock condition does not occur, even when
                    we don't use the workaround).  I am reluctant to attempt
                    this because I don't have a good sense of a generally
                    correct way to detect when we are running interactively.

                    This whole business of interactive consoles is always a
                    major headache.

                    I think I basaically blame powershell for not doing
                    something approximating asynchronously reading stderr and
                    stdout when capturing the output.  For most executables,
                    Powershell's laziness is probably tolerable, but something
                    finicky about ssh (which may also perhaps deserve a bit of
                    blame) exposes the underlying deficiency in powershell's
                    stream-reading behavior when capturing stdout.

                    Perhaps there is some kind of shim program (possiblyt a
                    built-in powershell command ?) which could run ssh and
                    buffer/read stdout and stderr correctly so as to prevent the
                    deadlock.

                    see
                    (https://www.google.com/search?q=powershell+does+not+read+stderr+of+a+command+whose+output+is+being+captured)

                    see
                    (https://stackoverflow.com/questions/8184827/powershell-capture-the-output-from-external-process-that-writes-to-stderr-in-a)

                    2025-06-10-1113:  This might have been fixed as of Openssh
                    version (indicated by `ssh -V`): "OpenSSH_10.0p2, OpenSSL
                    3.0.16 11 Feb 2025"

                    2025-06-15-1258: I think I might have jsut observed that
                    this is still happening, wven with "OpenSSH_10.0p2, OpenSSL
                    3.0.16 11 Feb 2025", which seemed initially to be immune
                    from the problem.
                #>

                $startInfo  = [System.Diagnostics.ProcessStartInfo] @{
                    FileName = "ssh"    
                    RedirectStandardOutput = $True
                    ##RedirectStandardInput = $(if($inputObjects.Count -gt 0){$True}else{$False})
                    RedirectStandardInput = $True
                    RedirectStandardError = $True
                }
                $sshArguments |% {$startInfo.ArgumentList.Add($_)}

                $process = [System.Diagnostics.Process]  @{
                    StartInfo = $startInfo
                }
                $process.Start()| out-null

                write-debug "process.CommandLine: $($process.CommandLine)"

                ## if($inputObjects.Count -gt 0){
                ##     $standardInputWritingTask = $process.StandardInput.WriteAsync(($inputObjects -join "`n"))
                ##     ##$standardInputFlushingTask = $standardInputWritingTask.ContinueWith($process.StandardInput.Flush)
                ##     $standardInputFlushingTask = $standardInputWritingTask.ContinueWith(  ([System.Action[System.Threading.Tasks.Task]] { $process.StandardInput.Flush()} ))
                ## }  else {
                ##     $process.standardInput.Close()
                ## }

                $standardInputWritingTask = (
                    $process.StandardInput.
                    WriteAsync(($inputObjects -join "`n")).ContinueWith(  ([System.Action[System.Threading.Tasks.Task]] { $process.StandardInput.Flush()} ))
                    <# I  have a sense that I should somehow be using the asynchronous  flush  function here, if the fluish function is needed at  all. #>
                    ## ContinueWith(  ([System.Action[System.Threading.Tasks.Task]] { $process.StandardInput.Close()} ))
                    ##  ContinueWith(  ([System.Action[System.Threading.Tasks.Task]] { $process.StandardInput.Flush()} )).
                    ## ContinueWith(  ([System.Action[System.Threading.Tasks.Task]] { $process.StandardInput.Close()} ))
                )


                $standardErrorLineReadingTask = $process.StandardError.ReadLineAsync()
                $standardOutputLineReadingTask = $process.StandardOutput.ReadLineAsync()
                $weHaveReachedTheEndOfStandardOutput = $False
                $weHaveReachedTheEndOfStandardError = $False
                $weHaveFinishedWritingToStandardInput = $False


                do{
                    
                    
                    [System.Threading.Tasks.Task]::WaitAny(@(
                        if(-not $weHaveReachedTheEndOfStandardError ){$standardErrorLineReadingTask}
                        if(-not $weHaveReachedTheEndOfStandardOutput ){$standardOutputLineReadingTask}
                        if(-not $weHaveFinishedWritingToStandardInput ){$standardInputWritingTask}
                    ))  |  out-null
                    
                    if(-not $weHaveReachedTheEndOfStandardError ){
                        if($standardErrorLineReadingTask.IsCompleted){
                            $standardErrorLine = $standardErrorLineReadingTask.Result
                            if($null -eq $standardErrorLine ){
                                write-debug  "encountered a null standardErrorLine"
                                $weHaveReachedTheEndOfStandardError = $True
                            } else  {
                                write-debug "capturing a standardErrorLine: '$($standardErrorLine)'"
                                <# should we strip the newline sequence from the end of the
                                line?  No, the ReadLine(or ReadLineAsync()) function does  this
                                already. #>
                                write-error -ErrorId NativeCommandError -Message $standardErrorLine
                                ##write-error -Message $standardErrorLine
                                $standardErrorLineReadingTask = $process.StandardError.ReadLineAsync()
                            } 
                            ##$standardErrorLineReadingTask = $process.StandardError.ReadLineAsync()
                            write-debug  "process.StandardError.EndOfStream:$($process.StandardError.EndOfStream)"
                        }
                    }

                    if(-not $weHaveReachedTheEndOfStandardOutput ){
                        if($standardOutputLineReadingTask.IsCompleted){
                            $standardOutputLine = $standardOutputLineReadingTask.Result
                            if($null -eq $standardOutputLine ){
                                write-debug  "encountered a null standardOutputLine"
                                $weHaveReachedTheEndOfStandardOutput = $True
                            } else {
                                write-debug "capturing a standardOutputLine: '$($standardOutputLine)'"
                                <# should we strip the newline sequence from the end of the
                                line?  No, the ReadLine(or ReadLineAsync()) function does  this
                                already. #>
                                write-output $standardOutputLine
                                $standardOutputLineReadingTask = $process.StandardOutput.ReadLineAsync()
                            }
                            ##$standardOutputLineReadingTask = $process.StandardOutput.ReadLineAsync()
                            ## $endOfOutput = $($process.StandardOutput.EndOfStream)
                            ## if(-not $endOfOutput){
                            ##     write-debug  "not at end"
                            ## }
                            write-debug  "process.StandardOutput.EndOfStream:$($process.StandardOutput.EndOfStream)"

                            ##write-debug  "process.StandardOutput.EndOfStream: $(&{try{$errorActionPreference  = 'Stop'; $process.StandardOutput.EndOfStream}catch{$_}})"
                        }
                    }

                    if(-not $weHaveFinishedWritingToStandardInput ){
                        if($standardInputWritingTask.IsCompleted){
                            $weHaveFinishedWritingToStandardInput  = $True
                            write-debug  "weHaveFinishedWritingToStandardInput: $($weHaveFinishedWritingToStandardInput)"
                            $process.StandardInput.Close()
                        }
                    }

                } until (
                    ## $standardOutputLineReadingTask.IsCompleted -and
                    ## $standardErrorLineReadingTask.IsCompleted -and
                    ## $process.StandardError.EndOfStream -and 
                    ## $process.StandardOutput.EndOfStream -and 

                    $weHaveReachedTheEndOfStandardOutput -and
                    $weHaveReachedTheEndOfStandardError -and
                    $weHaveFinishedWritingToStandardInput
                )
                write-debug "reached end of reading and writing loop"
                ##  write-debug  "process.StandardOutput.EndOfStream: $(&{try{$errorActionPreference  = 'Stop'; $process.StandardOutput.EndOfStream}catch{$_}})"

                <# I am sure I have grossly mis-used the asynchronous constructs.  This
                needs to be cleaned up  massivley, but I think it is at least correct
                and functional.#>
            }
        }    
    }
}

function getRr {
    <#
    .SYNOPSIS
    "rr" is, in my mind, short for "remote runner" -- a function that sends
    commands to a particular ssh endpoint (the details of the endpoint are baked
    into the function) and outputs the results.  

    In practice, in scripts, you should assign the function returned by getRr to
    a short name, for example:
    ```
    $function:rkk = getRr -bitwardenItemId "my super great router"
    ```

    For documentation of the ssh option arguments, see [https://man.openbsd.org/ssh_config.5].

    #>
    [CmdletBinding()]
    [OutputType([ScriptBlock])]
    Param(
        [parameter()]
        [string] $bitwardenItemId,

        [parameter()]
        [hashtable] $extraSshOptions =  @{},

        [parameter()]
        [switch] $scp = $false
        # this parameter really ought to be an enum having values ssh and scp (and possibly others).
    )

    # specify the bitwardenItem corresponding to the computer we want to ssh into
    $bitwardenItem = Get-BitwardenItem $bitwardenItemId
    


    $sshAgentEnvironment = initializeSshAgentFromBitwardenItemAndReturnSshAgentEnvironment $bitwardenItem.id

    $pathOfTemporaryKnownHostsFile = New-TemporaryFile
    $sshOptionArguments = @(    
        $extraSshOptions.GetEnumerator()  |
        % {
            "-o"; "$($_.Key)=$($_.Value)"
        }

        <#  these options prevent us from touching our main known_hosts file: #>
        ## "-o";"StrictHostKeyChecking=no"
        "-o";"UserKnownHostsFile=$($pathOfTemporaryKnownHostsFile)"
        "-o";"IdentityAgent=$($sshAgentEnvironment['SSH_AUTH_SOCK'])"
        <#  I think it makes more sense to push the IdentityAgent option in to
            the list of ssh options here, rather than in getSshSession.  At the
            moment (2024-05-13-1144), we are also doing this in getSshSession,
            but I think I will remove that from getSshSession (and maybe will
            refactor/rethink/possibly-delete getSshSession altogether).  In the
            interim, it shouldn't hurt to have the same option  get passed twice
            to ssh (I hope). 

            2025-01-20-1613: update upon re-reading the above comment: when I
            wrote "getSshSession", above, I think I must have meant
            "getSshOptionArgumentsFromBitwardenItem" .
        #>

        getSshOptionArgumentsFromBitwardenItem -bitwardenItemId $bitwardenItem.id 
    )

    # Set-Alias -Name rr -Value runInSshSession
    if($scp){
        <#
            whereas runInSshSession is like a curried form of ssh, we want a
            similar function that is a smiilarly-curried form of scp. ideally,
            we want our curried form of scp to use the same sshAgent as our
            curried form of ssh (for the same host).  In other words, we want to
            obtain a pair of <curriedSsh, curriedScp> for a given host (really,
            for a given bitwarden item specifying a connection to a host).

            Actually, the thing returned by getRr is like a curried a form of
            runInSshSession, with all of the (slow) bitwarden lookups and ssh
            agent initialization finished and baked into the thing returns by
            getRr.

            As I write this (2024-05-13-1129), I cannot entirely remember why
            getRr bothers to call runInSshSession instead of calling ssh
            directly -- probably the purpose of runInSshSession in the context
            of getRr (and generally) is to encapsulate all the
            byteArray-vs.-string weirdness and powershell-extra-newline
            weirdness (both manifestations of powershell's attitude that the
            thing that flows through a pipeline is an object rather than a
            byte.).  Another purpose of runInSshSession might be to encapsulate
            the ssh-argumnet-parsing weirdness that requires explictly passing
            an empty string as the final argument in the case when you want to
            run ssh as an interactive terminal (and don;t want to pass any
            "command" arguments to ssh).


            TODO [DONE]: unify getRr and getCurriedScp -- both these functions
            are essentially identical except for the final executable that (the
            curried function) calls (in the case of getRr, it's ssh (indirectly
            through runInSshSession).  In the case of getCurriedScp, it's scp.)

            2024-05-13-1139: I have accomplished the above TODO (almost as soon
            as I conceived of it) by adding the $scp switch parameter to getRr,
            which causes getRr to behave like getCurriedScp (which I deleted).

            TODO: deal with filesystem paths containing colons (e.g. as happens
            with windows-style paths).  scp tends to treat the colon as a
            delimeter between hostname and filesystem path.
        #>
        $rr = { 
            $input | scp @sshOptionArguments @args
            <#  does scp ever meaningfully take piped input?

                TODO: address the known weirdness with scp where you have to
                have some kind of a host name in the sourcepath or
                destinationpath arguments even if the host name has already been
                specified in option arguments.  The essential purpose for
                needing something like a host name in one of the source or
                destination arguments even when a hostname has been specified in
                the option arguments is probably to specify which of the source
                or destination is on the remote machine.

                There's not much to address, except to remember that, if the
                host has been specified by means of the "hostname" option, then
                you can use any name whatsoever in the source or destination
                arguments to stand in as a "dummy" hostaname.

                It's mopderately irritating that scp decided to invent its own
                extension of the filesystem path concept to embed the hostname
                (and the specification of which of the two paths is remote) into
                the source and target arguments.

                Ideally, scp should have arguments that always accept plain old
                filesystem paths, and then additional arguments would specify
                which path is on which machine.
            #>

        }.GetNewClosure()

    } else {
        $rr = { 
            $input | 
            runInSshSession -sshAgentEnvironment $sshAgentEnvironment -sshOptionArguments $sshOptionArguments @args 
        }.GetNewClosure()

        ## & $rr 'echo $(date): hello from $(hostname) ' | write-host
        <#
            The above running of a little identifying "hello" message from the
            machine being ssh'ed into is intended as a verification (for the user to
            see) that (1) we are able to succesfully ssh into the machine and (2)
            the machine we have ssh'ed into is the machine we intended to ssh into.

            This is usefule so far as it goes, but in practice, particularly when
            generating several "rr" functions, and particularly when the target
            machine(s) happen to be unreachable at the time you generate the rr
            functions, the above sanity check takes a long time to run, and is an
            annoyance to wait for.

            Therefore, I have commented it out.
        #>
    }

    return $rr
}


function Get-LazilyConstructedFunction{
    <#
        .SYNOPSIS
        given a script block that emits a function, we return a function
        that will act like the function returned by the aforementioned
        script block.  On the first call, our returned function will run the
        script block to create the function, and store the result for use by
        subsequent calls.
    #>
    [OutputType([ScriptBlock])]
    [cmdletBinding()]
    Param(
        [ScriptBlock] $constructor
    )

    <#  not sure if it's useful to get a closure for the $constructor here.
    maybe.   I am also not sure if our later calling of .GetNEwClosure()
    does essentially the same thing. #>
    ## $constructor = $constructor.GetNewClosure()

    return {
        if(-not $script:mainFunction){
            Write-Information "initializing mainFunction"
            $script:mainFunction = & $constructor
        }
        $input | & $script:mainFunction @args
    }.GetNewClosure()
}


function putFieldMapToBitwardenItem {
    [OutputType([Void])]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage=  "The field map.")]
        ## [HashTable] $fieldMap,
        ## [System.Collections.Specialized.OrderedDictionary] $fieldMap,
        [Object] $fieldMap,
        # really we want and expect that $fieldMap is either a [HashTable] or a
        # [System.Collections.Specialized.OrderedDictionary] (which is what you
        # get when you evaluate `[ordered] @{}`. unfortunately, the constructor
        # of [System.Collections.Specialized.OrderedDictionary] (or whatever the
        # powershell automatic  type conversion machinery uses) will not simply
        # "upgrade" a [HashTable] to a
        # [System.Collections.Specialized.OrderedDictionary] .  Thus, in order
        # to allow passing either an OrderedDictionary or a HashTable, we
        # specify the type as [Object], which is a bit of a hack.
        

        [Parameter(HelpMessage=  "The bitwarden item id of the bitwarden item into which we will inject the configuration data.")]
        # [String]$pathOfTheConfigurationFile = "config.json" # (Join-Path $PSScriptRoot "config.json")
        [String] $bitwardenItemId=""

        # [Boolean]$doMakeNewBitwardenItem=$False,

        # [String]$nameForNewBitwardenItem=""
    )
    
    # this function ought to be called something like "update-fieldmap" or
    # "appendto-fieldmap" because it does not completely overwrite the exiting
    # fields.

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

Set-Alias sendMail Send-Mail
function Send-Mail{
    [CmdletBinding()]
    param(
        [string] $emailAccount,
        
        [AllowEmptyString()]
        [string] $from = $null,
        
        [string[]] $to = @(),
        
        [string[]] $cc = @(), 
        
        [string[]] $bcc = @(), 
        
        [string] $subject, 
        
        [string] $body,

        [bool] $IsBodyHtml = $False
    )
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

    Write-Information "using the email account defined in bitwarden item $($bitwardenItemContainingEmailCredentials.id)"
    
    $username=$(
        @(
            $bitwardenItemContainingEmailCredentials.fields | 
            ? {
                $_.name -in @(
                    'smtp_username'
                )
            } | 
            % {$_.value}

            $bitwardenItemContainingEmailCredentials.login.username
        ) | 
        ? {$_} |
        select -first 1
    )
    
    $password=$(
        @(
            $bitwardenItemContainingEmailCredentials.fields | 
            ? {
                $_.name -in @(
                    'app_password'
                    'smtp_password'
                )
            } | 
            % {$_.value}

            $bitwardenItemContainingEmailCredentials.login.password
        ) | 
        ? {$_} |
        select -first 1
    )

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
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($username, $password) 
    
    if(-not $from){
        $from=$bitwardenItemContainingEmailCredentials.login.username
        Write-Information "we have set the from address to '$($from)'"
    }

    $mailMessage = New-Object Net.Mail.MailMessage
    $mailMessage.From = New-Object System.Net.Mail.MailAddress($from)
    foreach ($address in @($to)){ $mailMessage.To.Add($address) }
    foreach ($address in @($cc)){ $mailMessage.CC.Add($address) }
    foreach ($address in @($bcc)){ $mailMessage.Bcc.Add($address) }
    $mailMessage.Subject = $subject
    $mailMessage.Body = $body
    $mailMessage.IsBodyHtml = $IsBodyHtml

    <# begin  experiment 2025-03-02-1302 #>
    ## $mailMessage.Headers['X-6202f375f55149cabf0fc89d1734cfac'] = "yakfak"
    ## $mailMessage.Headers['Message-ID'] = "$(new-guid)@myid.rattnow.com"
    <# end experiment 2025-03-02-1302 #>

    $result = $SMTPClient.Send($mailMessage)
    Write-Information "result of sending the message: $result"

}

set-alias sendTestMessage Send-TestMessage
function Send-TestMessage(){
    [CmdletBinding()]
    [OutputType([Void])]
    param (   
        [
            Parameter(
                Mandatory = $True
            )
        ]
        [Alias("recipientEmailAddress")]
        [String[]] 
        $To,

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String[]] 
        $Cc,


        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String[]] 
        $Bcc,

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $emailAccount = "neil@autoscaninc.com",

        [Alias("senderEmailAddress")]
        [
            Parameter(
                Mandatory = $False
            )
        ]
        [AllowEmptyString()]
        [String] 
        $From = $null,

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $subjectPrefix = "",
        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $subjectSuffix = "",

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $bodyPrefix = "",

        [
            Parameter(
                Mandatory = $False
            )
        ]
        [String] 
        $bodySuffix = ""
    )
    process {

        if(-not $From){
            $From = $emailAccount
            Write-Information "From: '$($From)'"
        }

        $now = (Get-Date)
        $timeStampText = "$('{0:yyyy/MM/dd HH:mm:ss K}' -f [timezone]::CurrentTimeZone.ToLocalTime($now))"
        
        $sendMailParameters = (
            $(if($Cc){@{cc = $Cc}}else{@{}}) +
            $(if($Bcc){@{bcc = $Bcc}}else{@{}}) +
            @{
                emailAccount = $emailAccount
                from         = $From
                to           = $To

                ##subject      = "test message from $($From) to $($To) $($timeStampText)"
                subject      = "$($timeStampText): test message from $($From) to $($To)" |% {"$($subjectPrefix)$($_)$($subjectSuffix)"}
                body         = @( 
                    
                    "$($timeStampText)"
                    ""
                    "This is a test message sent from $($From) to $($To), cc ($Cc), bcc ($Bcc).  Please disregard."

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
                ) -Join "`n" |
                % {"$($bodyPrefix)$($_)$($bodySuffix)"}


            } 
        )
        
        write-information "From: $($sendMailParameters['from'])"
        write-information "To: $($sendMailParameters['to'])"
        write-information "Cc: $($sendMailParameters['cc'])"
        write-information "Bcc: $($sendMailParameters['bcc'])"
        write-information "Subject: $($sendMailParameters['subject'])"

        $sendMailParameters | % { Send-Mail @_ }
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
        Write-Information "No mgUser having id $userId exists."
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
        Write-Information "No mgUser having id $userId exists."
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



    Write-Information (
        @(
            "Initially, $($mgUser.UserPrincipalName) has the "
            
            "following $($initialSkuIds.Count) skuPartNumbers: " 

            @( 
                $initialSkuIds | % {skuIdToSkuPartNumber $_}
            ) -Join ", "
            
        ) -join ""
    )

    Write-Information (
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





    Write-Information (-join @("skuIdsToRemoveFromUser ($($skuIdsToRemoveFromUser.Count)): "; $skuIdsToRemoveFromUser))
    Write-Information (-join @("skuIdsToGiveToUser ($($skuIdsToGiveToUser.Count)):"; $skuIdsToGiveToUser))
    Write-Information (-join @("idsOfServicePlansToGiveTheUser ($($idsOfServicePlansToGiveTheUser.Count)): "; $idsOfServicePlansToGiveTheUser))
    Write-Information (-join @("idsOfServicePlansToRemoveFromUser ($($idsOfServicePlansToRemoveFromUser.Count)):"; $idsOfServicePlansToRemoveFromUser))
    


    if($skuIdsToRemoveFromUser -or $skuIdsToGiveToUser -or $idsOfServicePlansToGiveTheUser -or $idsOfServicePlansToRemoveFromUser){
        Write-Information "changing the user's license assignment to match the desired configuration"
        
        # make sure that the user has a UsageLocationn defined
        $intialUsageLocation = (get-mguser -UserId $mgUser.Id -Property @("UsageLocation")).UsageLocation
        if($intialUsageLocation){
            Write-Information (@(
                "$($mgUser.UserPrincipalName) already seems to have a UsageLocation "
                "assigned (namely, `"$($intialUsageLocation)`"), so we will not "
                "bother to set UsageLocation."
            ) -join "")
        } else {
            $newUsageLocation = (Get-MgOrganization).CountryLetterCode
            Write-Information (@(
                "$($mgUser.UserPrincipalName) seems to have "
                "no UsageLocation, so we will set UsageLocation "
                "to `"$($newUsageLocation)`"."
            ) -join "")

            Update-MgUser -UserId $mgUser.Id -UsageLocation $newUsageLocation 1> $null
        }
        ## write-information "ahoo"
        ## write-information "$($skuIdsToRemoveFromUser.GetType().FullName)"
        ## write-information "$($skuIdsToRemoveFromUser.Count)"

        if($false){
            @(
                @{UserId = $mgUser.Id}
                @{removeLicenses = $skuIdsToRemoveFromUser}
                @{addLicenses = (
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
                }
            ) | merge-hashtables | 
            % { Set-MgUserLicense @_ } 1> $null
        }

        if($false){
            foreach($param in @(
                    @{RemoveLicenses = $skuIdsToRemoveFromUser}
                    @{AddLicenses = (
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
                }
            )){
                @(
                    @{UserId = $mgUser.Id}
                    $param
                ) | merge-hashtables | 
                % { Set-MgUserLicense @_ } 1> $null
            }
        }

        if($false){
            @(
                @{UserId = $mgUser.Id}
                
                @{
                    BodyParameter = @{
                        ##removeLicenses = $(if($skuIdsToRemoveFromUser.Count -gt 0){$skuIdsToRemoveFromUser} else {$null})
                        removeLicenses = $skuIdsToRemoveFromUser
                        addLicenses = (
                            <# it doesn't hurt to have a license here that the user already has.  The 
                                DisabledPlans property will be updated to match whatever we give here. 
                            #>

                            # [IMicrosoftGraphAssignedLicense[]]
                            @(
                                $desiredSkuIds | 
                                % {
                                    $skuId = $_
                                    $mgSubscribedSku = $allMgSubscribedSkus |? { $_.SkuId -eq  $skuId }
                                    
                                    # [IMicrosoftGraphAssignedLicense] 
                                    @{
                                        disabledPlans = @(
                                            $mgSubscribedSku.ServicePlans |
                                            select -expand ServicePlanId |
                                            ? {-not ($_ -in $desiredIdsOfEnabledServicePlans)}
                                        )
                                        skuId = ([guid] $mgSubscribedSku.SkuId)
                                    }

                                }
                            )
                        )
                    }
                }
            ) | merge-hashtables | 
            % { Set-MgUserLicense @_ } 1> $null
        }

        if($false){
            $response = @{
                Method = "POST"
                Uri = "v1.0/users/$($mgUser.Id)/assignLicense"
                Body = @{
                    removeLicenses = $skuIdsToRemoveFromUser
                    addLicenses = (
                        <# it doesn't hurt to have a license here that the user already has.  The 
                            DisabledPlans property will be updated to match whatever we give here. 
                        #>

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
                                    SkuId = ([guid] $mgSubscribedSku.SkuId)
                                }

                            }
                        )
                    )
                }
            } |% { Invoke-MgGraphRequest @_ }
        }
        <# see (https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3229) #>

        ##  works: 
        if($true){
            $response = @{
                Method = "Get"
                Uri = "v1.0/subscribedSkus"
                OutputType = 'HttpResponseMessage'
            } |% { Invoke-MgGraphRequest @_ }
            $authorizationHeaderValue = $response.RequestMessage.Headers.Authorization
            
            foreach($body in @(
                    ## @{
                    ##     RemoveLicenses = @(
                    ##         
                    ##         @(
                    ##             $skuIdsToRemoveFromUser
                    ##             $desiredSkuIds
                    ##         ) | 
                    ##         select -unique
                    ##     )
                    ##     AddLicenses  = @()
                    ##     
                    ## }
                    @{
                        RemoveLicenses  = @($skuIdsToRemoveFromUser)
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
                                        
                                        disabledPlans = @(
                                            $mgSubscribedSku.ServicePlans |
                                            select -expand ServicePlanId |
                                            ? {-not ($_ -in $desiredIdsOfEnabledServicePlans)}
                                        )

                                        skuId = $mgSubscribedSku.SkuId
                                        <#  2025-03-23-1756:  If either of the
                                            keys "skuId" or "disabledPlans" is
                                            changed so that the first letter is
                                            capitalized, the call fails.  I
                                            suspect that this is a new
                                            development, and I suspect that this
                                            might be responsible for the error
                                            which I have been encountering when
                                            trying to call Set-MgUserLicense,
                                            and which I believe is the same
                                            error as that described at
                                            (https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3229).
                                        #>
                                    }

                                }
                            )
                        )
                }
            )){
                ## $response = @{
                ##     Method = "POST"
                ##     Uri = "v1.0/users/$($mgUser.Id)/assignLicense"
                ##     Body = $body
                ## } |% { Invoke-MgGraphRequest @_ }


                $response = @{
                    Uri        = "https://graph.microsoft.com/v1.0/users/$($mgUser.Id)/assignLicense"
                    Method     = "POST"
                    ContentType = "application/json"
                    Headers  = @{
                        Authorization = $authorizationHeaderValue
                    }
                    Body = $body | convertto-json -depth 50
                } | % {Invoke-WebRequest @_}
            }

            <#  #>
        }



        $finalSkuIds = @(
            (get-mguser -UserId $mgUser.Id -Property @("AssignedLicenses")).AssignedLicenses | 
            select -expand SkuId |
            select -unique
        )

        $finalEnabledServicePlans = @( getEnabledServicePlansAssignedToUser $mgUser.Id )

        Write-Information (
            @(
                "After making changes, $($mgUser.UserPrincipalName) has the "
                
                "following $($finalSkuIds.Count) skuPartNumbers: " 
    
                @( 
                    $finalSkuIds | % {skuIdToSkuPartNumber $_}
                ) -Join ", "
                
            ) -join ""
        )
    
        Write-Information (
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
        Write-Information "no changes need to be made to the user's licenses."
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
            Write-Information (
                "we could not find a single mailbox having " +
                "Identity `"$($mailboxId)`".  Therefore, " + 
                "we will stop here."
            )
            return
        } 
        $mailbox = $candidateMailboxes[0]

        Write-Information "setting the email addresses for the mailbox $($mailbox.Identity)."

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

        Write-Information "initially, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        
        $emailAddressesToRemove = @($mailbox.EmailAddresses | where-object {
            ($_ -match '(?i)^SMTP:.+$') -and (-not ($_ -in $desiredEmailAddresses)) 
            # it is an smtp address of some sort and it is not in the desiredEmailAddresses List
        })
        $emailAddressesToAdd = @($desiredEmailAddresses | where-object {
            -not ($_ -in $mailbox.EmailAddresses)
            # it is not already in the mailbox's Email Addresses
        })

        if( ([Boolean] $emailAddressesToRemove) -or ([Boolean] $emailAddressesToAdd) ){
            Write-Information "emailAddressesToRemove ($($emailAddressesToRemove.Count)): ", $emailAddressesToRemove
            Write-Information "emailAddressesToAdd ($($emailAddressesToAdd.Count)): ", $emailAddressesToAdd
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

            Write-Information "`$emailAddressesArg: $($emailAddressesArg | format-list | Out-String)"
            
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
            Write-Information "finally, mailbox.EmailAddresses: ", $mailbox.EmailAddresses
        } else {
            Write-Information "email addresses for $($mailbox.Identity) are as desired, so we will not bother to add or remove any."
        }  
    }
}



function grantUserAccessToMailbox(
    $idOfUserToBeGrantedAccess, 
    $idOfMailbox, 
    [switch] $sendInstructionalMessageToUsersThatHaveBeenGrantedAccess       = $False,
    [string] $emailAccountForSendingAdvisoryMessages                         = "neil@autoscaninc.com",
    [string] $dummyAddressForAdvisoryMessages                                = "administrator@autoscaninc.com",
    [switch] $sendAdvisoryMessageToDummyAddressInsteadOfRealRecipientAddress = $False,
    [switch] $createInboxRuleToRedirect                                      = $False,
    [switch] $automapping                                                    = $false
){


    $mgUserToBeGrantedAccess = Get-MgUser -UserId $idOfUserToBeGrantedAccess
    $mailbox = $( 
        $(Get-Mailbox -identity $idOfMailbox) ?? 
        $(Get-Mailbox -PublicFolder -identity $idOfMailbox)
    )

    Write-Information "now giving the user $($mgUserToBeGrantedAccess.UserPrincipalName) full access to the mailbox $($mailbox.PrimarySmtpAddress)."

    Remove-MailboxPermission -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue
    <#  We first remove any existing permission, as a way (apparently, this is
        the only way) to set the value of the Automapping property (we can't
        read the current value of automapping) 
    #>
    Add-MailboxPermission    -Identity $mailbox.Id   -User    $mgUserToBeGrantedAccess.Id -AccessRights FullAccess -Automapping:$automapping
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
        } ; Send-Mail @xx
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
        $PSStyle.OutputRendering = $initialOutputRendering
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


function blipNetworkAdapter {
    # blips any currently-enabled and connected network adapters

    foreach (
        $netAdapter in 
        (
            Get-NetAdapter 
        )
    ){
        Write-Information "now processing netadpater: $($netAdapter.Name)"

        if ( ($netAdapter.AdminStatus -eq "Up") -and ($netAdapter.ifOperStatus -eq "Up") ){
            Write-Information "netadapter $($netAdapter.Name) is enabled and connected, so we will poke at it."

            $netConnectionProfile = $null
            $netConnectionProfile = Get-NetConnectionProfile -InterfaceAlias $netAdapter.Name -ErrorAction SilentlyContinue
            if($netConnectionProfile ){
                Write-Information( "netConnectionProfile: $($netConnectionProfile | Out-String )")
            }

            Disable-NetAdapter -Confirm:0 -InputObject $netAdapter 
            Start-Sleep 1
            Enable-NetAdapter -Confirm:0 -InputObject $netAdapter

        } else {
            Write-Information "netadapter $($netAdapter.Name) is not both enabled and connected, so we will not touch it."
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
    <#
    .SYNOPSIS
    generates an Amazon "add-to-cart" url for the specified ASIN's and
    quantities.


    .PARAMETER asinQuantityPairs
    A list of (asin, quantity) pairs

    .EXAMPLE

    This example shows how you might generate some html containing a link to the 
    generated add-to-cart url, and then send this html to the clipboard as
    rich-text (for pasting into an email, perhaps)
    ```
    getAmazonAddToCartUrl @(
        ,@("B07JJTVGZM", 1) # nvme to pcie carrier card. $10
        ## ,@("B0BHJJ9Y77", 1) # Samsung MZ-V9P2T0B/AM. 990 PRO without heat sink. $180
        ,@("B0BHJDY57J", 1) # Samsung MZ-V9P2T0CW. 990 PRO with heat sink. $199
    ) | 
    % {
        "<a href=`"$_`">CLick here to buy the stuff from Amazon.</a>" 
    } | powershell -c {[string[]] $x = $input; $x | set-clipboard -ashtml; $x}
    ```




    .NOTES
    General notes
    #>
    



    
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

    <#  Amazon add-to-cart URL syntax:

        see
        [https://webservices.amazon.com/paapi5/documentation/add-to-cart-form.html].

        As of 2024-03-29, and for many months prior, I have observe that the
        add-to-cart API almost rarely works, and usually redirects to a 404
        error page (or similar).  I suspect that the problem is that I have been
        omitting the "AssociateTag" parameter from my query string.

        On
        [https://webservices.amazon.com/paapi5/documentation/add-to-cart-form.html],
        the "AssociateTag" parameter is listed as being mandatory.

        In an attempt to be able to make functional add-to-cart urls, I have
        signed up for an associate id (which, I suspect is the same as the
        "Associate tag").  My associate id is: "6c1690888e2c4-20".  I have
        observed that including this associate id in the add-to-cart url seems
        to eliminate the problem of being redirected to an error page.

        Experimenting, it seems that even a bogus, made-up associate tag also
        serves to eliminate the error.  For my purposes, I want to avoid a
        conflict of interest when I send people an add-to-cart url.  Therefore,
        I will use the bogus, made-up value "intentional-null" as the
        ASsociateTag parameter of my add-to-cart urls.  This should make it
        clear to anyone who bothers to manually read the URL that the associate
        tag is intentionally bogus.

    #>
    ## $myRealAssociateTag         = "6c1690888e2c4-20"
    $arbitraryFakeAssociateTag  = "intentional-null"
    
    ## $associateTag               = $myRealAssociateTag
    $associateTag               = $arbitraryFakeAssociateTag


    $url = 
        "https://www.amazon.com/gp/aws/cart/add.html?" + 
        (
            @(
                "AssociateTag=$($associateTag)"
            
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
    ) | Write-Information
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

Set-Alias -Name download -Value downloadFileAndReturnPath
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
        [string] $hashAlgorithm = "SHA256",

        [parameter(mandatory=$False)]
        [string[]] $extraCurlArguments = @()

    ) 

    $hash = $hash.ToLower()
    $nameOfDownloadCacheFolder = "3c3562b4c6e84f3a92d110d2da9e08aa"
    # this is a name intended to be specific to this function.
    $pathOfDownloadCacheFolder = (join-path $env:temp $nameOfDownloadCacheFolder)
    $pathOfDedicatedInitialDirectoryToContainDownloadedFile = (join-path $env:temp (new-guid).Guid)
    
    $finalPathOfDownloadedFile = $null
    $hashOfDownloadedFile = $null
    if($hash){  
        Write-Information "checking for already-downloaded files having the specified hash ($hash)"
        # attempt to find an already downloaded file having the specified hash      
        $finalPathOfDownloadedFile =  @(
            if(Test-Path -PathType Container -Path (join-path $pathOfDownloadCacheFolder $hash)){
                gci -file -force (join-path $pathOfDownloadCacheFolder $hash)
            }
        ) | 
        select -expand FullName |
        ? { (Get-FileHash -Algorithm $hashAlgorithm -LiteralPath $_).Hash.ToLower() -eq $hash } |
        select -first 1

        if($finalPathOfDownloadedFile){
            Write-Information "found an already-downloaded file ($finalPathOfDownloadedFile) having the specified hash ($hash)."
            $hashOfDownloadedFile = $hash
            # this is a shortcut to avoid recomputing the hash, because, due to
            # the test above, we are already guaranteed that $hash is the hash
            # of the file whose path is $finalPathOfDownloadedFile
        } else {
            Write-Information (-join @(
                "Found no already-downloaded files having the specified hash ($hash).  "
                "Therefore we will have to download anew."
            ))
        }
    }

    # see (https://stackoverflow.com/questions/6881034/curl-to-grab-remote-filename-after-following-location)

    if(-not $finalPathOfDownloadedFile){
        New-Item -Force -ItemType Directory $pathOfDedicatedInitialDirectoryToContainDownloadedFile  | out-null
        $result = $(
            curl @(
                # "--progress-bar"
                "--remote-name"
                ## "--verbose"

                "--remote-header-name"

                # fixes a pathological case where a url contains square brackets:
                "--globoff"

                # follow redirects:
                "--location"

                "--user-agent"; 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
                # including a user-agent header seems to improve reliability with some servers.
        
                ## "--header"; "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                ## "--header"; "Accept-Language: en-US,en;q=0.5"
                ## "--header"; "Accept-Encoding: gzip, deflate, br"
                "--header"; "Accept-Encoding: *"
                # I have observed at least one server that requires the Accept-Encoding to be present.

                # "--cookie-jar";$pathOfCookieJarFile
                # "--cookie";$pathOfCookieJarFile  
                # "--cookie"; "`"`""
                # "--cookie"; "$(new-guid)" # a bogus filename guaranteed not to exist
                # "--cookie"; "6fc3c91bf2da4921b775ce3406c549c3=643c8f63135847ee85c130555d3f2441" # a bogus filename guaranteed not to exist
                
                <#  The --cookie option causes curl to use its internal cookie
                    engine to store and transmit cookies between requests.  

                    The --cookie option causes curl to use its internal cookie
                    engine to store and transmit cookies between requests.  I added
                    this option on 2023-10-26-1708 in order to allow curl to be able
                    to download public files from sharing urls generated by
                    sharepoint.

                    I want to tell curl to use its cookie engine, but don't read
                    from any cookie file.  Rather, start with an empty cache and
                    fill it as you go.

                    But unfortunately, there doesn;t seem to be a straightforward
                    way to do this.  Curl's --cookie option expects to be a value.
                    If the value contains an equals sign, curl treats it as a
                    literal cookie value, otherwise curl treats it as the path of a
                    file from which the cookie cache is to be read from (but not
                    written to).

                    I have settled on passing a randomly-generated fresh guid as the
                    value.  This will hopefully be a file that never exists. 
                #>
                "--cookie"; "$(new-guid)"

                ## "--write-out"; @(
                ##     @(
                ##         "redirect_url"
                ##         "url"
                ##         "filename_effective"
                ##         "urle.path"
                ##     ) |% {"$($_): %{$($_)}"} 
                ## ) -join "`n"

                "--write-out"; "{`"json`":%{json}, `"header_json`":%{header_json}}"

                "--output-dir";$pathOfDedicatedInitialDirectoryToContainDownloadedFile
                $urlOfFile

                $extraCurlArguments
            ) | ConvertFrom-Json -depth 50
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

        <# computing $preferredFileName here is done to workaround the aforem,entioned problem where,
            in the absence of a content-disposition header, curl takes the filename from the first, rather than the last, url in the redirect chain.
        #>
        $preferredFileName = $(
            &{
                if (($result.json.num_redirects -gt 0) -and (-not $result.header_json.'content-disposition')){
                    split-path -leaf $result.json.'urle.path'
                }


                    <#  as  of 2025-04-10-1746, curl "does not yet support the
                        "filename*" field (filenames with explicit character
                        sets)."  in the content-disposition header value. (see
                        (https://curl.se/docs/manpage.html)).  

                        Therefore, I am polyfilling by  means of .NET's
                        System.Net.Http.Headers.ContentDispositionHeaderValue
                        class.
                    #>

                if($result.header_json.'content-disposition'){
                    foreach($headerValue in $result.header_json.'content-disposition' ){
                    
                        $contentDispositionHeaderValue = $(
                            [System.Net.Http.Headers.ContentDispositionHeaderValue] $headerValue
                        )

                        if (-not $contentDispositionHeaderValue){continue}

                        $contentDispositionHeaderValue.FileNameStar

                        $contentDispositionHeaderValue.FileName

                    }
                }

                <# 2025-04-10-1755:  TODO: think through the interactions of
                redirections and content-disposition header  -- I still don't
                think I am correctly handling all cases. #>

                split-path -leaf $initialPathOfDownloadedFile 
            } | 
            ?{$_} |
            select -first 1
        )
        write-verbose "preferredFilename: $($preferredFilename)"

        $hashOfDownloadedFile = Get-FileHash -Algorithm $hashAlgorithm -LiteralPath $initialPathOfDownloadedFile | select -expand Hash |% {$_.ToLower()}
        <# using -LiteralPath  rather than -Path fixed a pathological case where the filename contained square brackets. #>

        ## $finalPathOfDownloadedFile = (join-path (join-path $pathOfDownloadCacheFolder $hashOfDownloadedFile) (split-path -leaf $initialPathOfDownloadedFile) )
        $finalPathOfDownloadedFile = (join-path (join-path $pathOfDownloadCacheFolder $hashOfDownloadedFile) $preferredFileName )
        New-Item -ItemType Directory -Force (split-path -literalpath $finalPathOfDownloadedFile) | out-null
        Move-Item -force -LiteralPath $initialPathOfDownloadedFile -Destination $finalPathOfDownloadedFile

        if($hash -and (-not ($hashOfDownloadedFile -eq $hash))){
            Write-Information "The hash of the downloaded file ($finalPathOfDownloadedFile) ($hashOfDownloadedFile) does not match the specified hash ($hash)."
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
        ensures that chocolatey and other goodies are isntalled:

        To run this in a remote session $s, do 
        invoke-command $s -ScriptBlock ${function:installGoodies} 
        or
        invoke-command $s { invoke-expressions ${using:function:installGoodies} } 

        * see (https://stackoverflow.com/questions/14441800/how-to-import-custom-powershell-module-into-the-remote-session)
        * see (https://mkellerman.github.io/Import_custom_functions_into_your_backgroundjob/)
        * see (https://stackoverflow.com/questions/30304366/powershell-passing-function-to-remote-command)
        * see (https://stackoverflow.com/questions/2830827/powershell-remoting-using-imported-module-cmdlets-in-a-remote-pssession)
        * see (https://serverfault.com/questions/454636/how-can-i-use-shared-functions-in-a-remote-powershell-session)
    #>
    [CmdletBinding()]
    param()
    
    write-information "$($PSCmdlet.MyInvocation.MyCommand.Name) $(get-date -format o): Now attempting to install (or upgrade) chocolatey itself."
    Set-ExecutionPolicy Bypass -Scope Process -Force  
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))  

    foreach($package in @(
        "chocolatey"
        "7zip"
        ## "winmerge"
        ## "spacesniffer"
        "notepadplusplus"
        "sysinternals"
        ## "hdtune"

        "pwsh"
    )){
        ## write-information "$($MyInvocation.MyCommand.Name) $(get-date -format o): Now attempting to install (or upgrade) the chocolatey package '$($package)'."
        write-information "$($PSCmdlet.MyInvocation.MyCommand.Name) $(get-date -format o): Now attempting to install (or upgrade) the chocolatey package '$($package)'."
        choco upgrade $package --source 'https://chocolatey.org/api/v2/' --yes 
    }
    

    <#  "choco upgrade" installs if it is not already installed, so we do not need to
        do both "install" and "upgrade"; "upgrade" on its own will ensure that
        we end up with the latest version installed regardless of the initial
        condition. 
    #>

    [System.Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT","1","Machine")
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

    $nameOfScheduledTask = "runInActiveSession--$((New-Guid).Guid)"
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

    <#
        2024-03-26-1609: I am encountering error in the scheduled tasks log.

        I suspect I have encountered this error before, but this is the first
        time I have actually troubleshot it.

        see
        [https://serverfault.com/questions/559288/what-causes-scheduled-task-error-2147942402].

        I suspect this might simply be that the command I was trying to run is
        not on the path.
    #>
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
        
        <#  wait a beat to allow the pending lineReadingTasks to complete if
            they want to. This is a bit of a hack to work around (my lack of
            knowledge and) the fact that the line reading tasks can remain
            uncompoleted indefinitely after the task exits. Ideally, I would
            like to have line reading tasks that completed unsucessfully when
            the task had ended and there were no more bytes to read.  Maybe the
            ReadLineAsync() function relies on a newline character to finish
            each line, and so remains waiting unless and until that final
            newline comes, even if the underlying stream is closed.  Not sure.
            this is all a hack.  Perhaps some of the other reading functions,
            other than ReadLine, would have the desired behavior, or perhaps my
            confusion is related to the behavior of asynchronous tasks in .NET.

            I notice that the class System.Diagnostics.Process has methods named
            BeginErrorReadLine, BeginOutputReadLine, CancelErrorRead,
            CancelOutputRead -- maybe these could be helpful here.

            Also a method named WaitForInputIdle.  Maybemy problems have been
            solved before.



            TODO: We are currently potentially missing final output emitted by
            the executable perimortem.  Also, waiting for a whole line is not
            quite right.  BAsically, the buffering strategy needs to be
            rethought. 
        #>

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
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord
    ## Write-Host "User Account Control (UAC) has been disabled." -ForegroundColor Green    
    Write-Information "User Account Control (UAC) has been disabled."   
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
    <#  see
        (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=intune)
    #>

    @(
        "ConsentPromptBehaviorAdmin"  
        "ConsentPromptBehaviorUser" 
        "EnableInstallerDetection"
        "EnableLUA"  
        "EnableSecureUIAPaths"
        "EnableUIADesktopToggle"
        "EnableVirtualization"
        "FilterAdministratorToken"
        "PromptOnSecureDesktop"
        "ValidateAdminCodeSignatures"
    ) |% {
        Remove-ItemProperty "registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -force:$true -Name $_
    }

    ## Write-Host "User Account Control (UAC) has been enabled (or more accurately: reset to default)." -ForegroundColor Green    
    Write-Information "User Account Control (UAC) has been enabled (or more accurately: reset to default)."    
}
# Set-Alias Enable-UserAccessControl Enable-UserAccountControl 
# ${function:Enable-UserAccessControl} = ${function:Enable-UserAccountControl}
${function:Enable-UserAccessControl} = [Scriptblock]::Create(${function:Enable-UserAccountControl})

function Show-UserAccountControl {
    # report on uac-related registry values
    
    [CmdletBinding()]
    param()
    $key = Get-Item "registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    @(
        "ConsentPromptBehaviorAdmin"  
        <# ConsentPromptBehaviorAdmin: 
            * 0 = Elevate without prompting
            * 1 = Prompt for credentials on the secure desktop
            * 2 = Prompt for consent on the secure desktop
            * 3 = Prompt for credentials
            * 4 = Prompt for consent
            * 5 = Prompt for consent for non-Windows binaries (default)

            see (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)

            from (https://www.tenforums.com/user-accounts-family-safety/178831-how-do-i-disable-administrator-notifications.html).

            see (https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2015-06-16/finding/V-14235)

        
        #>

        "ConsentPromptBehaviorUser" 
        <#  ConsentPromptBehaviorUser: 
            see (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/15f4f7b3-d966-4ff4-8393-cb22ea1c3a63)
        #>


        "EnableInstallerDetection"
        "EnableLUA"  
        
        "EnableSecureUIAPaths"
        <#  EnableSecureUIAPaths: 

            * https://www.stigviewer.com/stig/windows_10/2019-01-04/finding/V-63827
        #>

        "EnableUIADesktopToggle"
        "EnableVirtualization"
        "FilterAdministratorToken"
        "PromptOnSecureDesktop"
        "ValidateAdminCodeSignatures"
    ) |
    sort |
    %  {
    [pscustomobject] @{
            name  = $_
            exists = ($_ -in $key.GetValueNames())
            type  = $(if($_ -in $key.GetValueNames()){$key.GetValueKind($_)})
            value = $(if($_ -in $key.GetValueNames()){$key.GetValue($_)})
        }
    } 
    
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

    $script:pathOfScriptingJournalTranscriptFile = $pathOfTranscriptFile
}

function Get-PathOfScriptingJournalTranscriptFile {
    return $( $script:pathOfScriptingJournalTranscriptFile )
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
    ##$desiredNamePattern = "(?-i)^.*$($delimeter)$($hash)(\.[^\.]*)?`$"
    $desiredNamePattern = "(?-i)^(.*$($delimeter))?$($hash)(\.[^\.]*)?`$"
    $initialName = [System.IO.Path]::GetFileName($path)

    $naiveStrongName = (@(
        [System.IO.Path]::GetFileNameWithoutExtension($initialName)
        $delimeter
        $hash
        [System.IO.Path]::GetExtension($initialName)
    ) -join "")

    $strongName = $(
        if($initialName -match $desiredNamePattern) {
            $initialName
        } else  {
            $naiveStrongName
        }
    )

    return (join-path (split-path -parent $path) $strongName)
}

function getCommandPath {
    <#
    .SYNOPSIS
    returns the path of the file containing the specified command, along with
    the relevant line number in that file. Intended to be used for commands that
    are defined as a powershell function in a powershell script module file (or
    for commands that are aliases pointing to such commands)

    #>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [parameter(mandatory=$True)]
        [string] $nameOfCommand
    )

    $commandInfo = $(Get-Command $nameOfCommand)
    if($commandInfo){
        if($commandInfo.CommandType -ceq [System.Management.Automation.CommandTypes]::Alias){
            getCommandPath $commandInfo.Definition
        } else {
            # here, we are basically assuming that the command is a function or a cmdlet.
            return "$($commandInfo.ScriptBlock.File):$($commandInfo.ScriptBlock.StartPosition.StartLine)"
        }
    }
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
    ## Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
    Write-Information "IE Enhanced Security Configuration (ESC) has been disabled."
}
function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
    Stop-Process -Name Explorer -Force
    ## Write-Host "IE Enhanced Security Configuration (ESC) has been enabled." -ForegroundColor Green
    Write-Information "IE Enhanced Security Configuration (ESC) has been enabled." 
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

function Connect-ToScreenconnectByMeansOfBitwardenItem {
    
    Param(
        [Parameter()]
        [string] $bitwardenItemIdOfScreenconnectCredentials
    )
    
    ## ensure connection to screenconnect:

    <# Ideally, we ought to check not just whether an existing connection
        exists, but also that the existing connection is the connection
        specified by the bitwarden item.  As of 2024-09-19-1136, out of
        laziness, we are not bothering to do this.
    #>

    ## if($null -eq $cwcModule){$cwcModule = $((Get-Command connect-cwc).Module)}
    $cwcModule = $((Get-Command connect-cwc).Module)
    write-verbose "cwcModule: $($cwcModule)"

    $cwcServerConnection = $($cwcModule.Module.SessionState.PSVariable?.GetValue("CWCServerConnection"))
    <#  I am not sure this is a reliable way to detect whether there is an
        existing connection. 
    #>
    write-verbose "cwcServerConnection: $($cwcServerConnection)"


    if($cwcServerConnection){
        write-verbose "reusing apparent existing connection: $($cwcServerConnection)"
    } else {
        write-verbose "connecting fresh."
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
        Write-Information
    }
}

function runInCwcSession {
    [OutputType([string])]
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter()]
        [string] $bitwardenItemIdOfScreenconnectCredentials, 

        [Alias("Group")]
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
        [System.TimeSpan] $timeout,

        [Parameter(Mandatory=$False)] 
        [int] $timeoutMilliseconds,

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
        [string[]] $postambleCommand,

        [Parameter(Mandatory=$False)] 
        [switch]$NoWait = $false


        # The only reason for having these three distinct parameters (rather
        # than just a single (array) command parameter) is to facilitate
        # splatting.
    )

    $timeout ??= New-Timespan -Milliseconds $timeoutMilliseconds



    ## Import-Module ConnectWiseControlAPI
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


    Connect-ToScreenconnectByMeansOfBitwardenItem $bitwardenItemIdOfScreenconnectCredentials

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
            NoWait = $NoWait
        } +
        $(if($timeout.TotalMilliseconds){@{Timeout = $timeout.TotalMilliseconds}} else {@{}})
    ) | % { Invoke-CWCCommand @_ }
}

function Get-ComputerStatusFromScreenconnect {
    <#
        .SYNOPSIS
        Lists computer names, along with associated user names, from
        screenconnect. We retrieve various ideas about the username -- both from
        Screenconnect's database and by attempting to run a command on the
        computer in question.
    #>
    [CmdletBinding()]
    param(
        [string] $bitwardenItemIdOfScreenconnectCredentials,
        [string] $nameOfScreenconnectGroup,
        [ScriptBlock] $scriptBlock
    )

    Connect-ToScreenconnectByMeansOfBitwardenItem $bitwardenItemIdOfScreenconnectCredentials

    # ensure we're connected to screenconnect:

    foreach($cwcSession in @(Get-CWCSession -Type Access -Group $nameOfScreenconnectGroup)){
        $guestIsConnected = [Boolean] $cwcSession.ActiveConnections
        <# This simple test, where we simply look to see if any
            "ActiveConnections" exist, does not distinguish between hosts
            and guests.  Thus, we are, blindly, and generally incorrectly,
            assuming that no hosts are connected to any session.  This is
            not striuctly correct, but it serves our purpose, which is to
            not waste time polling a machine that will not respond because
            it is disconnected.
        #>




        [pscustomobject] $(
            @(
                @{
                    Name = $cwcSession.Name

                    guestIsConnected = $guestIsConnected

                    GuestLoggedOnUserName = $cwcSession.GuestLoggedOnUserName

                    LastLoggedOnUserName = $(
                        if($guestIsConnected){
                            Write-Information "$($cwcSession.Name) is reachable.  Now looking up name of LastLoggedOnUser "
                            @{
                                GUID       = $cwcSession.SessionID
                                Powershell = $True
                                Command    = (
                                    @(
                                        @(
                                        @(
                                            "Get-LastLoggedOnUserSID"
                                        )| % {(get-command $_).ScriptBlock.Ast}
                                        )
                                        {
                                            New-Object System.Security.Principal.SecurityIdentifier (Get-LastLoggedOnUserSID) |
                                            % {$_.Translate([System.Security.Principal.NTAccount])} |
                                            % {$_.Value}
                                        }
                                    ) -join "`n"
                                )
                                Timeout = 25000
                                NoWait  = $False
                            } |% { Invoke-CWCCommand @_}
                        } else {
                            Write-Information "$($cwcSession.Name) is unreachable via Screenconnect."
                        }
                    )

                    GuestOperatingSystemName = $cwcSession.GuestOperatingSystemName
                    GuestOperatingSystemVersion = $cwcSession.GuestOperatingSystemVersion

                    cwcSession = $cwcSession
                }

                
                if($false){
                    @{
                    
                        RemoteDesktopReport = $(
                            if($guestIsConnected){
                                Write-Information "$($cwcSession.Name) is reachable.  Now looking up remote desktop enablement status "
                                @{
                                    GUID       = $cwcSession.SessionID
                                    Powershell = $True
                                    Command    = (
                                        @(
                                            @(

                                            )
                                            {
                                                $env:computername
                                                Get-NetFirewallRule -DisplayGroup "Remote Desktop" | 
                                                select Name,Enabled  | 
                                                ft -auto |
                                                out-string

                                                "fDenyTSConnections: $(Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections")"
                                            }
                                        ) -join "`n"
                                    )
                                    Timeout = 25000
                                    NoWait  = $False
                                } |% { Invoke-CWCCommand @_}
                            } else {
                                Write-Information "$($cwcSession.Name) is unreachable via Screenconnect."
                            }
                        ) | out-string

                        
                    }
                }
                
                if($scriptBlock){
                    @{
                        result = $(
                            if($guestIsConnected){
                                Write-Information "$($cwcSession.Name) is reachable.  Now running the specified scriptblock via screenconnect. "
                                @{
                                    GUID       = $cwcSession.SessionID
                                    Powershell = $True
                                    Command    = (
                                        @(
                                            @(

                                            )
                                            $scriptBlock
                                        ) -join "`n"
                                    )
                                    Timeout = 25000
                                    NoWait  = $False
                                } |% { Invoke-CWCCommand @_}
                            } else {
                                Write-Information "$($cwcSession.Name) is unreachable via Screenconnect."
                            }
                        ) | out-string

                        
                    }
                }
            ) | merge-hashtables
        )

    }
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

    (Get-Item -Path "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    ).GetValue("LastLoggedOnUserSID")
}

function Get-LastLoggedOnUserName {
    [OutputType([string])]
    [CmdletBinding()]
    Param(
    )
    
    New-Object System.Security.Principal.SecurityIdentifier (Get-LastLoggedOnUserSID) |
    % {$_.Translate([System.Security.Principal.NTAccount])} |
    % {$_.Value}
}
function Get-LastLoggedOnUserProfile {
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_UserProfile')]
    [CmdletBinding()]
    Param(
    )
    ## return $(get-ciminstance win32_userprofile |? {$_.SID -eq (Get-LastLoggedOnUserSID)})
    return $(get-ciminstance win32_userprofile -filter "SID='$(Get-LastLoggedOnUserSID)'")
}

function Get-LastLoggedOnUserVolatileEnvironment {
    <#
        .SYNOPSIS
        returns a hashtable containing the "Volatile Environment" values of the
        last logged on user.  This is useful for retrieving the values of
        APPDATA, LOCALAPPDATA, and USERPROFILE, for example.

        I think that the "Volatile Environment" registry key that his function
        relies on might only exist when there is an active Windows session --
        this makes this function less useful than first anticipated.
    #>
    
    [OutputType([HashTable])]
    [CmdletBinding()]
    Param(
    )

    $registryKey = $(get-item (join-path (join-path "registry::HKEY_USERS" (Get-LastLoggedOnUserSID)) "Volatile Environment" ))
    return $(
        $registryKey.GetValueNames() |
        % {
            @{
                $_ = $registryKey.GetValue(
                    $_,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
            }
        } |
        merge-hashtables
    )
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
        [string] $bitwardenItemIdOfCredential,

        [parameter()]
        [string] $destination
        # overrides the default destination.  This is a relative path within the "Attachments" folder.
    )
    # $pathOfFile = "S:\Microsoft\Microsoft Office 2013\SW_DVD5_NTRL_Office_Professional_Plus_2013_W32_English_MSI_FPP_X18-65189.ISO"
    ## $strongFilename = (split-path -leaf (getStronglyNamedPath $pathOfFile))
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

    if($false){ # bad technique:
        $drive = @{
            Method        = "GET"
            Uri           = "v1.0/drives/me"
            ContentType   = 'multipart/form-data'
        } | % {Invoke-MgGraphRequest @_} 


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
    }

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


    ##$relativePathOfDestination = $(if($destination){$destination}else{$strongFilename})
    $relativePathOfDestination = $(if($destination){$destination}else{(split-path -leaf (getStronglyNamedPath $pathOfFile))})


    $sizeThresholdForNonChunkedUpload = 20
    <#  the only reason for doing a non-chunked upload for very small files
        (files of size less than $sizeThresholdForNonChunkedUpload) is to be
        able to handle zero-byte files, which the uploadsession technique can't
        handle. 
    #>
    if($totalLength -lt $sizeThresholdForNonChunkedUpload){    
        @{
            Method        = "PUT"
            Uri           = "v1.0/drives/me/items/root:/Attachments/$($relativePathOfDestination):/content"
            InputFilePath = $pathOfFile
            ContentType   = 'multipart/form-data'
        } | % {Invoke-MgGraphRequest @_} | 
        out-null
    } else {

        $sliceSizeDivisor = (320 * 1024)
        $maximumAllowedContentLengthPerRequest = 50 * [math]::pow(2,20)
        <#  the real maximum allowed value is 60 mebibytes, according to
            [https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0#create-an-upload-session]
            but I am setting mine a bit lower mainly in order to make the
            progress messages more frequent. 
        #>
        $preferredSliceSize = $sliceSizeDivisor * [math]::floor($maximumAllowedContentLengthPerRequest/$sliceSizeDivisor)
        <#  This rigamarole with sliceSizeDivisor  ensures that our preferredSliceSize is
            a multiple of $sliceSizeDivisor .  At the moment (2025-04-11-1429),
            I can't remember why I did this.s
        #>


        <# see [https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0#create-an-upload-session] #>
        $uploadSession = @{
            DriveId = "me"
            DriveItemId = "root:/Attachments/$($relativePathOfDestination):"
        } | % {New-MgDriveItemUploadSession @_}


        if($false){
            $x = @{
                Method        = "PUT"
                Uri           = $uploadSession.UploadUrl
                InputFilePath = $pathOfFile
                ContentType   = 'multipart/form-data'
            } | % {Invoke-MgGraphRequest @_}
        }

        if($false){
            <# curl does not have built-in support for the kind of multi-request chunked upload that we need to do. #>
            curl @(
                "--verbose"
                "--location"
                "--upload-file"; $pathOfFile
                ## "--data-binary"; "@$($pathOfFile)"
                ## "--header"; "Content-Type: application/octet-stream"
                ## "--request"; "PUT"
                $uploadSession.UploadUrl
            )
        }


        <# see [https://learn.microsoft.com/en-us/graph/sdks/large-file-upload?tabs=csharp] #>
        if($false){
            $fileStream = [System.IO.File]::OpenRead($pathOfFile)
            $totalLength = $fileStream.Length
            



            $lastByteIndexUploaded = -1
            while($lastByteIndexUploaded -lt ($totalLength - 1)){
                $sliceStart = $lastByteIndexUploaded
                $sliceStop = [math]::min( $sliceStart + $preferredSliceSize, $totalLength )
                <# we will upload the bytes at indices $sliceStart, $sliceStart + 1, ..., $sliceStop - 1 . #>
                
                
                $x = @{
                    Method        = "PUT"
                    Uri           = $uploadSession.UploadUrl
                    # ContentType   = 'multipart/form-data'
                    Headers = @{
                        "Content-Length" = "$($sliceStop - $sliceStart)"
                        "Content-Range" = "bytes $($sliceStart)-$($sliceStop - 1)/$($totalLength)"
                    }
                    Body = $fileStream.ReadExactly
                } | % {Invoke-MgGraphRequest @_}
               
                $lastByteIndexUploaded = $sliceStop - 1
                Write-Information ("$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f ($lastByteIndexUploaded + 1),($totalLength),(($lastByteIndexUploaded + 1)/($totalLength)))
            }
            $fileStream.Close()
        }
        
        if($false){
            <#  get-content is quite slow, I think compared to lower-level file stream operations. 

                [System.Net.Http.StreamContent] might be a way to pass streaming input to Invoke-WebRequest.
                
                We  might also use curl instead of Invoke-WebRequest
            #>

            $countOfBytesUploaded = 0
            Get-Content -AsByteStream -ReadCount $preferredSliceSize $pathOfFile |
            % {
                [byte[]] $chunk = $_

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
            
                Write-Information (
                    "$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f @(
                        $countOfBytesUploaded
                        $totalLength
                        100 * $countOfBytesUploaded/$totalLength
                    )
                )
            }
        }
        if($false){
            $fileStream = [System.IO.File]::OpenRead($pathOfFile)
            $totalLength = $fileStream.Length

            $countOfBytesUploaded = 0
            while($countOfBytesUploaded -lt $totalLength){
                $sliceStart = $countOfBytesUploaded
                $sliceStop  = [math]::min( $sliceStart + $preferredSliceSize, $totalLength )
                <#  we will upload the bytes at indices 

                    $sliceStart, $sliceStart + 1, ..., $sliceStop - 1 . 
                #>
            
                ## $fileContent = [System.Net.Http.StreamContent]::new($fileStream)

                $x = @{
                    Method = "PUT"
                    ContentType = 'application/octet-stream'
                    Headers              = @{
                        "Content-Range"  = "bytes $($sliceStart)-$($sliceStop - 1)/$($totalLength)"
                        # "Content-Length" = "$($sliceStop - $sliceStart)"
                    }
                    Uri = $uploadSession.UploadUrl
                    ## Body = $fileStream 
                    <#  The problem is that there is no straightforward way to
                        construct a stream-like object that can be passed to
                        Invoke-WebRequest as the Body parameter that will expose
                        just the desired slice of the whole file stream.

                    #>
                } |% {Invoke-WebRequest @_}
            




                $countOfBytesUploaded = $sliceStop
                Write-Information (
                    "$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f @(
                        $countOfBytesUploaded
                        $totalLength
                        100 * $countOfBytesUploaded/$totalLength
                    )
                )
            }
            $fileStream.Close()

        }
        if($true){
            $fileStream = [System.IO.File]::OpenRead($pathOfFile)
            $totalLength = $fileStream.Length

            write-information "preferredSliceSize: $($preferredSliceSize)"

            $countOfBytesUploaded = 0
            $chunk = New-Object byte[] $preferredSliceSize

            while($countOfBytesUploaded -lt $totalLength){
                $sliceStart = $countOfBytesUploaded
                <#  we will upload the bytes at indices $sliceStart, $sliceStart
                    + 1, ..., $sliceStart + $chunk.Count -1 . 

                    $chunk.Count is determined below based on exactly how many
                    bytes $fileStream.Read() reads from the fileStream.  We
                    expect $chunk.Count to be preferredSliceSize for all chunks
                    with the possible exception of the final chunk, which might
                    be smaller than $preferredSliceSize.
                #>

                $countOfBytesRead = $fileStream.Read(
                    <# buffer: #>
                    $chunk,
                    
                    <# offset  (offset within the buffer at which the bytes are to be placed): #>
                    0,

                    <# count (maximum number of  bytes to read): #>
                    $preferredSliceSize
                )

                if($countOfBytesRead -ne $preferredSliceSize){
                    write-information "resizing chunk: changing size from $($chunk.Count) to $($countOfBytesRead)"
                    [array]::Resize[byte]([ref] $chunk, $countOfBytesRead)
                }
            
                Write-Information (
                    "$(get-date): invoking webrequest"
                )
                @{
                    Method = "PUT"
                    ContentType = 'application/octet-stream'
                    Headers              = @{
                        "Content-Range"  = "bytes $($sliceStart)-$($sliceStart + $chunk.Count - 1)/$($totalLength)"
                        # "Content-Length" = "$($chunk.Count)"
                    }
                    Uri = $uploadSession.UploadUrl
                    Body = $chunk
                } |% {Invoke-WebRequest @_} |  
                out-null
                <# TODO: error handling and retries #>

                $countOfBytesUploaded += $chunk.Count

                Write-Information (
                    "$(get-date): uploaded {0:}/{1:} bytes ({2:f1} %)" -f @(
                        $countOfBytesUploaded
                        $totalLength
                        100 * $countOfBytesUploaded/$totalLength
                    )
                )
            }
            $fileStream.Close()

        }



    }

    <# CREATE the LINK: #>
    $z = @{
        Method = "POST"
        Uri    = "v1.0/drives/me/items/root:/Attachments/$($relativePathOfDestination):/createLink"
        Body   = @{
            type="view"
            scope="anonymous"
        }
    } |% { Invoke-MgGraphRequest @_}
    $a = ([System.UriBuilder] $z.link.webUrl)
    $a.Query += "$($a.Query ? '&' : '')download=1"

    <# The "x-name" query parameter is my own invention (and hopefully is
    ignored by sharepoint).  It is purely annotative, meant for the human that
    might read the url. #>
    $a.Query += "$($a.Query ? '&' : '')x-name=$([System.Web.HttpUtility]::UrlPathEncode((split-path -leaf $relativePathOfDestination)))"

    <# perhaps see [https://learn.microsoft.com/en-us/microsoft-365/community/query-string-url-tricks-sharepoint-m365] #>

    <#
        It would be nice to (optionally) return something that is not just the
        raw url, but is something like some html that could be pasted into an
        email message or similar, that would include a hyperlink, with filename.
    #>
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

    [CmdletBinding()]
    Param(

        [parameter(ValueFromPipeline=$True)]
        [Object] $InputObject,

        [parameter()]
        [Alias("PassThrough")]
        [switch] $Passthru = $False,

        [parameter()]
        [int] $IndentLevel = 0


    )
    begin {


        <#  Can we get the very line of code that called us (so that we can
            infer the correct indentLevel from that line)?  This would be useful
            for the way that I often invoke this function, interactively in
            vscode.

            Almost -- `$myInvocation.Line` almost gives us what we need, except
            that the vscode function that sends the current line to the
            interactive terminal strips leading whitespace, so
            $myInvocation.line does not have the leading white space that we
            would need in order to infer the correct indentation level.

        #>
        ## write-host "`$MyInvocation.Line: '$($MyInvocation.Line)'"



        $singleIndent = ' '*4
    }

    end {

        <#  see
            (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_ansi_terminals?view=powershell-7.4) 
        #>
        $initialOutputRendering = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText

        

        $input | 
        fl | 
        out-string | 
        % {
            @(
                @(
                    '<#'
                    @(
                        '```'
                        $_ -split "\n"
                        '```'
                    )| %{ "$($singleIndent*1)$($_)" } 

                    '#>'
                ) | %{ "$($singleIndent*$IndentLevel)$($_)" } 
            )-join "`n"
        } | 
        set-clipboard 

        $PSStyle.OutputRendering = $initialOutputRendering

        if($Passthru){$input}
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
        "    `$informationPreference = 'Continue'"
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
    if(-not (
            (test-path -Path $path -PathType Leaf)  -or 
            (test-path -Path $path -PathType Container)  
        )
    ){
        Write-Error "'$($path)' is not a file or a directory."
    } else {
        $acl = Get-Acl -Path $path
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")))
        
        Set-Acl  -Path "\\?\$($path)" -AclObject $acl
        <#  The "\\?\" prefix is necessary to handle the case where
        $pathOfFile exceeds the 260-character path-length limit.
        see [https://github.com/PowerShell/PowerShell/issues/10805]
        
        see [https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry] 
        #>

        <# As of 2024-07-20-1518, I have observed a case where the "\\?\" is not working, so let us also use the regular path. #>

        Set-Acl  -Path $path -AclObject $acl
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

Set-Alias Install-WingetOnWindows10 Install-Winget
Function Install-Winget {
    <#
    .SYNOPSIS
    Install ( or upgrade ) winget on the widest range of machines (including
    hopefully windows server 2019 or windows 10 ), inlcuding the powershell
    module Microsoft.Winget.Client, including some functionality even when
    running under the SYSTEM account.

    Trying ewverything we can in order to end up with a working installation of
    winget (and the powershell module Microsoft.Winget.Client)
    #>

    [CmdletBinding()]
    Param(

    )
    # todo: check windows build number to confirm that we are running on 
    # a version of windows for which this technique is required.

    # todo: check for existing winget.

    # todo: check that we acutally have chocolatey installed, which we need below.

    # todo perhaps: put all of this logic in the chocolatey winget package.
    
    if($env:ChocolateyInstall){
        $pathOfWingetShimFile = (join-path $env:ChocolateyInstall  "bin/winget.exe")
        if(Test-Path -LiteralPath $pathOfWingetShimFile -PathType leaf){
            write-information "removing existing winget shim file at '$($pathOfWingetShimFile)'."
            remove-item -force (join-path $env:ChocolateyInstall  "bin/winget.exe")
        }
    }
    
    $doModifyPermissionsOfWingetFiles     = $true
    $doMakeChocolateyShimPointingToWinget = $true
    $doAddWingetDirectoryToSystemPath     = $false
    

    if($false){

        choco upgrade winget --yes --source chocolatey --no-progress


        <#  It seems that the only thing we need to do differently or special (I
            think) when using Chocolatey to install winget on Windows server 2019
            and Windows 10 compared with windows 11, is take pains to get the
            winget.exe executable file on the path (it seems that App Execution
            Aliases -- the normal mechanism for winget to get added to the path --
            do not work in Windows 10 and Windows Server 2019.  Or, at any rate,
            when we install the AppX Package named 'Microsoft.DesktopAppInstaller',
            version '2024.227.1731.0', the App Execution Aliases (i.e. NTFS reparse
            points in (join-path $env:localappdata "Microsoft/WindowsApps") seem to
            get created on Windows 11, but not on Windows 10 or Windows server 2019
            (probably because the process-starting api function in the Windows 10
            kernel does not support the "app execution alias" ntfs reparse points. ) 

            The below creation of a chocolatey shim is one way to make winget
            effectively available on the path.

            We probably  ought to create the chocolatey shim when and only when we
            are running in a version of windows that is too old to support app
            execution aliases, but I do not at the moment (2024-11-08-1615) have a good
            way to test for this condition
        #>
    }


    <#  we install the vcredist-all choco package, in the hopes of fixing the
        problem  of the missing visual c++ redistributable.  This is overkill
        because winget relies  only  on visual c++ redistributable 2015  (as of
        2024-11-12-1713), I think.
    #>

    <#  see (https://github.com/microsoft/winget-cli/issues/2748) This talks
        about winget.exe returning exit code 0XC0000135 (which I think, based on
        googling, is an exit code defined by .NET  (or maybe Windows) that means
        that a dll could not be found)

        It sounds like the fix, roughly, is to install the relevant version of
        the Visual C++ runtime.  But its weird that winget runs correctly when
        launched from  the app execution alias.  There must be something about
        launching from the app execution alias that helps winget find the visual
        c++ dll files.
    #>

    choco upgrade vcredist-all --yes --source chocolatey --no-progress

    . {
        $release = (Invoke-WebRequest -UseBasicParsing  "https://api.github.com/repos/microsoft/winget-cli/releases/latest").Content | ConvertFrom-Json
    

        $mainMsixAsset            = $($release.assets | ? {$_.name -eq "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"     }  | select -first 1)
        $licenseAsset             = $($release.assets | ? {$_.name -match "license"                                                 }  | select -first 1)
        $dependenciesArchiveAsset = $($release.assets | ? {$_.name -eq "DesktopAppInstaller_Dependencies.zip"                       }  | select -first 1)
        $dependenciesJsonAsset    = $($release.assets | ? {$_.name -eq "DesktopAppInstaller_Dependencies.json"                      }  | select -first 1)
    
        $pathOfTemporaryDirectory = (join-path $env:temp "$(new-guid)")
    
        $pathOfMainMsixFile                         = (join-path $pathOfTemporaryDirectory $mainMsixAsset.name)
        $pathOfLicenseFile                          = (join-path $pathOfTemporaryDirectory $licenseAsset.name)
        $pathOfDependenciesArchiveFile              = (join-path (join-path $env:temp "$(new-guid)") $dependenciesArchiveAsset.name)
        $pathOfDependenciesJsonFile                 = (join-path (join-path $env:temp "$(new-guid)") $dependenciesJsonAsset.name)
    
    

        New-Item -itemtype directory -force -path (split-path -parent $pathOfMainMsixFile) | out-null
        Invoke-WebRequest -UseBasicParsing -Uri $mainMsixAsset.browser_download_url             -OutFile $pathOfMainMsixFile

        New-Item -itemtype directory -force -path (split-path -parent $pathOfLicenseFile) | out-null
        Invoke-WebRequest -UseBasicParsing -Uri $licenseAsset.browser_download_url              -OutFile $pathOfLicenseFile

        New-Item -itemtype directory -force -path (split-path -parent $pathOfDependenciesArchiveFile) | out-null
        Invoke-WebRequest -UseBasicParsing -Uri $dependenciesArchiveAsset.browser_download_url  -OutFile $pathOfDependenciesArchiveFile

        New-Item -itemtype directory -force -path (split-path -parent $pathOfDependenciesJsonFile) | out-null
        Invoke-WebRequest -UseBasicParsing -Uri $dependenciesJsonAsset.browser_download_url     -OutFile $pathOfDependenciesJsonFile

        ## $dependencies = $(gc $pathOfDependenciesJsonFile | ConvertFrom-Json) 
        
        $pathOfExpandedDependenciesArchiveDirectory = (join-path $pathOfTemporaryDirectory ([io.path]::GetFileNameWithoutExtension($dependenciesArchiveAsset.name)))
        Expand-Archive -Path $pathOfDependenciesArchiveFile -DestinationPath $pathOfExpandedDependenciesArchiveDirectory 
        $pathsOfDependencyFiles = @(
            gci -file -recurse $pathOfExpandedDependenciesArchiveDirectory 
        )

        @{
            Online      = $true
            LicensePath = $pathOfLicenseFile
            PackagePath = $pathOfMainMsixFile
            ##DependencyPackagePath = @(
            ##    gci -file -recurse $pathOfExpandedDependenciesArchiveDirectory |
            ##    ? {$_.Name -match "x64"} |
            ##    select -expand FullName
            ##)
            DependencyPackagePath = $pathsOfDependencyFiles
        } |% {Add-AppxProvisionedPackage @_} | out-null


        if($false){ <# This is an attempt to make the visual c++  runtime accessible to the winget executable when not run from the app execution alias: #>
            foreach($pathOfDependencyFile in $pathsOfDependencyFiles ){
                write-information "attempting to do add-appxprovisionedpackage with packagePath '$($pathOfDependencyFile)'."
                @{
                    Online      = $true
                    PackagePath = $pathOfDependencyFile
                    SkipLicense = $True
                } |% {Add-AppxProvisionedPackage @_} | out-null
            }
        }


    }


    if($doModifyPermissionsOfWingetFiles){
        @(
            gi -force (join-path $env:ProgramFiles "WindowsApps/Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe")

            gci -force (join-path $env:ProgramFiles "WindowsApps") -directory -filter "*vclibs*"
            <#  2024-11-12-1741: it probably is not necessary to tweak the
                permissions for the vclibs folders. 
            #>

        ) | 
        ? {$_.PSIsContainer} |
        % {
            write-information "taking ownership of '$($_)'"
            TAKEOWN /F $_ /R /A /D Y | out-null
            write-information ("exit code: 0X{0:X8} ({0:})" -f $LastExitCode)

            write-information "granting administrators full control for '$($_)'"
            ICACLS $_ /grant Administrators:F /T | out-null
            write-information ("exit code: 0X{0:X8} ({0:})" -f $LastExitCode)
        }
    }



    # see (https://www.reddit.com/r/PowerShell/comments/18lxtfo/run_winget_from_a_central_point_on_many_machines/)
    # see (https://github.com/microsoft/winget-cli/issues/1627)
    
    <# try to make the Install-PsResource command available in Windows Powershell: #>
    write-information "trying to make the Install-PsResource command available in Windows Powershell."

    powershell  -c {
        Install-PackageProvider -Confirm:$false -Name NuGet -Force | out-null

        0..1 |%  {
            foreach($acceptLicenseArg in @(
                @{}
                @{AcceptLicense=$True}
            )){
                foreach($scopeArg in @(
                    ## @{} 
                    @{Scope="AllUsers"}
                )){
                    foreach($nameArg in @(
                        @{Name="PowerShellGet"}
                        @{Name="Microsoft.PowerShell.PSResourceGet"}
                        ## @{Name="Microsoft.WinGet.Client"}
                    )){
                        Install-Module -Repository PSGallery -AllowClobber:$true -Force:$true -confirm:$false @acceptLicenseArg @scopeArg @nameArg
                    }
                }
            }
        }
    }

    <# try to install Microsoft.WinGet.Client #>
    write-information "trying to install the powershell module 'Microsoft.WinGet.Client'."
    foreach($shell in "powershell", "pwsh"){
        write-information "trying shell '$($shell)'."

        & $shell -c  {

            foreach($acceptLicenseArg in @(
                @{}
                @{AcceptLicense=$True}
            )){
                foreach($scopeArg in @(
                    @{} 
                    @{Scope="AllUsers"}
                )){
                    foreach($nameArg in @(
                        @{Name="Microsoft.WinGet.Client"}
                    )){
                        Install-PSResource @nameArg @acceptLicenseArg -TrustRepository  -Repository PSGallery @scopeArg -Reinstall
                    }
                }
            }
        }
        
    }

    if($false){
        
        <#  copied with slight adaptation from (https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox):  #>

        ## &{# copied with slight adaptation from (https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox): 
        ##    $pathOfTemporaryDirectory = New-TemporaryDirectory
        ##    @(
        ##    
        ##        @{
        ##            uri      = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        ##            filename = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
        ##        } 
        ##        @{
        ##            uri      = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        ##            filename = "Microsoft.UI.Xaml.2.8.x64.appx"
        ##        } 
        ##        @{
        ##            uri      = "https://aka.ms/getwinget"
        ##            filename = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        ##        } 
        ##    ) |
        ##    %{
        ##        Invoke-WebRequest -Uri $_.uri -OutFile (join-path $pathOfTemporaryDirectory $_.filename)
        ##        powershell -c "Add-AppxPackage '$(join-path $pathOfTemporaryDirectory $_.filename)'"
        ##    }
        ## }
    }

    write-information "downloading the source.msix file."
    $pathOfSourceMsixFile = (join-path (New-TemporaryDirectory) "source.msix")
    Invoke-WebRequest -UseBasicParsing -Uri "https://cdn.winget.microsoft.com/cache/source.msix" -OutFile $pathOfSourceMsixFile


    write-information "doing Add-AppxPackage for '$($pathOfSourceMsixFile)' and '$($pathOfMainMsixFile)'."
    foreach($shell in "powershell", "pwsh"){
        write-information "trying shell '$($shell)'."

        & $shell -c  (@(
            "Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
            "Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe"
            "Add-AppxPackage '$($pathOfSourceMsixFile)'"
            "Add-AppxPackage '$($pathOfMainMsixFile)'"
        ) -join "`n" )  
    }




    # see (https://github.com/microsoft/winget-cli/issues/3303)
    # see (https://www.pc-tips.info/en/tips/windows-tips/failed-in-attempting-to-update-the-source-winget/)
    write-information "doing Repair-WinGetPackageManager."
    foreach($shell in "powershell", "pwsh"){
        write-information "trying shell '$($shell)'."
        
        & $shell -c  {


            Repair-WinGetPackageManager  -allusers 
            ##Repair-WinGetPackageManager  

            Repair-WinGetPackageManager  -allusers  -Latest -Force
            ##Repair-WinGetPackageManager   -IncludePreRelease -Latest -Force

            Repair-WinGetPackageManager  -Latest -Force

        }
    }

    $pathOfwingetDirectory = $((gi (join-path $env:ProgramFiles "WindowsApps/Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe") | sort Name | select -last 1))

    if($doMakeChocolateyShimPointingToWinget ){
        write-information "making a chocolatey shim for winget.exe."

        # add "winget" to the path (effectively) by making a chocolatey shim:
        gci -force -recurse (join-path $env:ProgramFiles "WindowsApps/Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe") -filter "winget.exe" |
        ? {-not $_.PSIsContainer} |
        %{
            & "${env:ChocolateyInstall}/tools/shimgen.exe" @(
                "--path"; $_
                "--output"; (join-path "${env:ChocolateyInstall}/bin" (split-path -leaf $_ ))
            )
        }
    }

    if($doAddWingetDirectoryToSystemPath){
        write-information "adding winget directory ('$($pathOfwingetDirectory)') to system path."

        addEntryToSystemPathPersistently $pathOfwingetDirectory
        Import-Module (join-path $env:ChocolateyInstall "helpers\chocolateyProfile.psm1"); refreshenv
        
    }
    ##Install-PSResource -Name "Microsoft.WinGet.Client" -AcceptLicense -TrustRepository  -Repository PSGallery -Scope CurrentUser
    .{# acknowledge the one-time acknowledgement
        <#  the  piping of "y" into winget is a one-time acceptance of some kind
            of agreement that winget forces you to acknowledge once before you can use
            winget.  doing it here gets it out of the way. 
        #>
        write-information "acknowledging the one-time acknowledgements."

        Get-Command -all -CommandType Application -name winget |
        ? {$_} |
        %{
            & $_ source reset --force
            & $_ list --accept-source-agreements | out-null
            & $_ source reset --force
            "y" | & $_ list  | out-null 
            "y" | & $_ list --accept-source-agreements   | out-null 
            "y" | & $_ search Microsoft.Office   | out-null 
            "y" | & $_ search Microsoft.Office  --accept-source-agreements | out-null 
        }

    }

    ## Get-WinGetSource |% {Reset-WinGetSource -Name $_.Name}
    <# see  (https://github.com/PowerShell/PowerShell/issues/13138#issuecomment-1820195503) #>


}

function Convert-MacAddressToLinkLocalIpv6Address {
    <#
    .SYNOPSIS
    Converts a 48-bit IEEE MAC address (in the form of a hex string (arbitrary
    non-hex characters allowed)) into a link-local ipv6 address with the
    interface identifier constructed according to the "Modified EUI-64 Format"
    mentioned in RFC4291, Appendix A.

    .EXAMPLE
    ```
    "$(Convert-MacAddressToLinkLocalIpv6Address 90:58:51:11:3b:e2)"
    ```
    fe80::9258:51ff:fe11:3be2


    .NOTES
    General notes
    #>
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    Param(
        [parameter()]
        [string] $MacAddress
        
        ## ,
        ## [parameter(mandatory=$false)]
        ## [Int64] $ScopeId
    )
    $sanitizedMacAddress = $MacAddress.ToLower() -replace "[^0123456789abcdef]",""
    $macAddressBytes = $([System.Convert]::FromHexString($sanitizedMacAddress))
    if( -not ($macAddressBytes -and $macAddressBytes.Count -eq 6)){
        Write-Error "we were expecting a 48-bit mac address"
        return
    }
    # see [https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.1]
    #
    # see [https://datatracker.ietf.org/doc/html/rfc4291#appendix-A]
    #
    # see [https://ben.akrin.com/mac-address-to-ipv6-link-local-address-online-converter/]

    $eui64Bytes = [byte[]] @(
        $macAddressBytes[0..2]
        0xff
        0xfe
        $macAddressBytes[3..5]
    )

    # possibly, we should  not be calling this the eui64Bytes, because, as
    # mentioned in the Note at the end of Appenmdix A in RFC4291, the IEEE
    # EUI-64 standard defines 0xff, 0xff (NOT 0xff, 0xfe) as the bytes to be
    # inserted in the middle of the 48-bit IEEE MAC-48 identifier to generate
    # the equivalent EUI-64 identifier.  Apparently, a writer of an earlier
    # version of the RFC4291 standard (or one of its predecessors) mistakenly
    # specified 0xfe due to confusion about the difference between IEEE MAC-48
    # and IEEE EUI-48. Because 0xfe became enshrined in the IETF standard,  and
    # because the mistake doesn't cause any problems in this context (as long as
    # everyone agrees on the mistake), the IETF decided to leave the 0xfe value
    # as part of RFC4291.
    #
    # I wonder if any implementers DO use the "correct" 0xff, 0xff sequence.

    $modifiedEui64Bytes = [byte[]] @(
        $eui64Bytes[0] -bxor 0x02
        $eui64Bytes[1..7]
    )

    $ipv6AddressBytes =  [byte[]] @(
        0xfe; 0x80
        0x00; 0x00
        0x00; 0x00
        0x00; 0x00
        $modifiedEui64Bytes
    )

    $ipv6Address = [System.Net.IPAddress] $ipv6AddressBytes
    ## if($ScopeId){$ipv6Address.ScopeId = $ScopeId}
    return $ipv6Address
}


function Convert-FromBase64EncodedStringToByteArray{
    [CmdletBinding()]
    [OutputType([Byte[]])]
    
    Param(
        [parameter(ValueFromPipeline=$True)]
        [string[]] $base64EncodedString,

        [parameter()]
        [switch] $strictSymbols = $False,

        [parameter()]
        [switch] $strictPadding = $False
    )

    # we ought to add the ability to detect a urlsafe base64 string (and to
    # detect a string that is neither a url-safe base64 string nor a
    # non-url-safe base64 string (e.g. contains both "-" and "_").

    #TODO: ponder whether  the parameter tagged "ValueFromPipeline" should
    #really be of array type?

    <# TODO: Handle tha case where the input string has excessive padding (i.e.
        more than two trailing padding characters.  the fix is basically to chop
        off padding until the string length is 0 mod 4. Then, if the string ends
        with "===", change this to "A=="
    #>

    process {
        $paddingCharacter = "="

        foreach($s in $base64EncodedString){
            if(-not ($strictPadding)){
                # add padding characters to make the length of the string 0 mod 4.
                # 
                # see [https://stackoverflow.com/questions/34278297/how-to-add-padding-before-decoding-a-base64-string].

                <#  In base64, each character encodes 6 bits of information.
                    Each chunk of 4 characters encodes 3 bytes of information.
                    The final chunk of 4 characters is allowed to be incomplete,
                    in which case it is padded with the padding character
                    (typically "=").

                    If the length of the sequence of bytes to be encoded is 0
                    mod 3, do not append any padding characters.  In other
                    words, having exactly zerop trailing padding characters
                    means that the length of the byte sequence is 0 mod 3.

                    if it is 1 mod 3, encode the final byte using the first two
                    characters in the final chunk (with the unused high-order
                    bits set to zero in the ecnoding process and ignored in then
                    decoding process), and append two padding characters.  In
                    other words, having exactly two trailing padding characters
                    means that the length of the byte sequence is 1 mod 3.

                    If it is 2 mod 3, encode the final two bytes using the first
                    3 characters in the final chunk (with the unused high-order
                    bits set to zero in the ecnoding process and ignored in then
                    decoding process), and append a single padding character. In
                    other words, having exactly one trailing padding character
                    means that the length of the byte sequence is 2 mod 3.

                    To reconstruct missing padding characters: 

                    if the length of the "unpadded" string is 0 mod 4, this
                    means the byte sequence length is 0 mod 3.  append zero
                    padding characters.

                    If the length of the unpadded string is 2 mod 4, this means
                    the byte sequence length is 1 mod 3.  Append two padding
                    characters.

                    If the length of the unpadded string is 3 mod 4, this means
                    the byte sequence length is 2 mod 3.  Append one padding
                    character.

                    If the length of the unpadded string is 1 mod 4, this is,
                    strictly speaking, an invalid length for the unpadded
                    string.  It is, strictly speaking, invalid to have more than
                    two trailing padding characters.  There is no perfect
                    answer.  The options that I can think of are,:
                      1. throw an exception (i.e. give up)
                      2. assume a particular length of the byte sequence mod 3
                         (probably either 1 or 2), and assume some reaonable
                         value (probably zero) for the missing high-order bits
                         encoded by the final (unpadded) chunk of characters.
                         Concretely: 

                         a. Assume the length of the byte sequence is 1 mod 3
                            and that the missing high order bits are all zero.
                            Therefore, append the chaaracter that encodes 6 "0"
                            bits, and then append two padding characters.

                        b. Assume the length of the byte sequence
                            is 2 mod 3 and that the missing high order bits are all
                            zero.  Therefore, append two chaaracter that encodes 6
                            "0" bits, and then append one padding characters.

                    Strategy 2a is probably the most reasonable, so that is what
                    I will do.
                #>

                ## $s += $paddingCharacter * (( (- $s.Length % 4) + 4 ) % 4) 


                $s += $(
                    switch($s.Length % 4){
                        0 {""}
                        1 { [string] [System.Convert]::ToBase64String(0)[0] + ($paddingCharacter * 2)}
                        2 {$paddingCharacter * 2}
                        3 {$paddingCharacter * 1}
                    }
                )

            }

            if(-not ($strictSymbols)){
                $s = $s.Replace('-','+').Replace('_','/')
            }
            write-debug "s: $s"
            return (, [System.Convert]::FromBase64String($s))
            <# The crazy comma, above, prevents powershell form expanding the
            enumerable, as it is so fond of doing, and thereby serves to ensure
            that we send a gestalt byteArray down the pipeline rather than sending one byte after
            another. #>
        }
    }
}


function Convert-FromBase64EncodedStringToString{
    [CmdletBinding()]
    [OutputType([string])]
    
    Param(
        [parameter(ValueFromPipeline=$True)]
        [string[]] $base64EncodedString,

        [parameter()]
        [switch] $strictSymbols = $False,

        [parameter()]
        [switch] $strictPadding = $False,

        <# I would like the default values for the urlSafe and nonStrictPadding
            parameters to automatically match the defaults defined in
            Convert-FromBase64EncodedStringToByteArray, becuase this function is
            just a wrapper around that one.
        #>

        [parameter()]
        [System.Text.Encoding] $textEncoding = [System.Text.Encoding]::UTF8

        ## possibly, we should take the default encoding from the environment rather than hardcoding utf8.
    )

    process {
        foreach($s in $base64EncodedString){
            $textEncoding.GetString(
                (
                    Convert-FromBase64EncodedStringToByteArray -base64EncodedString $s -strictPadding:$strictPadding -strictSymbols:$strictSymbols
                )
            )
        }
    }
}

Set-Alias toCode Show-InVscode
function Show-InVscode {
    <#
        .SYNOPSIS
        This function is an extension of vscode's behavior where you can pipe
        bytes into `code -` to cause vscode to create and open a new temporary
        file and then write the piped-in input into the file.

        The main added functionality is that this function lets you, optionally,
        specify the desired name of the (temporary) file that we open in vscode
        and fill with the piped-in input.

        Being able to specify the file name (rather than using the random
        filename that `code -` generates) is useful for two reasons: 
        1. Specifying a particular extension will cause vscode to recognize the
           file as being of the desired type (for syntax highlighting, etc.).
        2. Particularly when you have several such temporary files open in
           vscode, you want vscode to display the (meaningful) file name in its
           tabbed interface so you can keep the files straight.

        This function  might be affected by Powershell's
        bytestream-vs.object-stream weirdness; when piping to a native program
        (like `code -`), especially (I think) when the expression producing the
        stream (of bytes) to be piped is itself a native program, powershell
        (sometimes? when?) sends the byte stream through unaltered without
        parsing the stream into powershell objects (i.e. strings) and then back
        into bytes.  Therefore, I anticipate the usual set of newline/terminal
        width/encoding/etc. weirdness that happens when using powershell to pipe
        (what should be) byte streams around.  TODO: be on the lookout for this.
        Perhaps the type of our "$input" argument should be a byte array rather
        than a string (array).  Because of this bytestream-vs.object-stream
        weirdness, the content of the file produced by piping something into
        this command might not be identical to what you would get if you were to
        pipe into `code -`, I suspect.

    #>
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [parameter(Position=0)]
        [string] $desiredNameOfFile = $null,

        [parameter(ValueFromPipeline = $True)]
        [string[]] $input 
    )

    begin {
        $pathOfTemporaryFile = join-path $env:temp "$(new-guid)/$( $desiredNameOfFile ? $desiredNameOfFile : (new-guid) )"
        New-Item -ItemType File -Path $pathOfTemporaryFile -Force | out-null
        Write-Information "opening in vscode, then writing stdin into the file:  $($pathOfTemporaryFile)"
        Start-Process -NoNewWindow -FilePath code -ArgumentList @($pathOfTemporaryFile)
    }

    process {
        $input >> $pathOfTemporaryFile
    }

    end {

    }


}


function Convert-XmlDocumentToFormattedXml {
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline=$True)]
        [System.Xml.XmlDocument]  $xmlDocument,

        [System.Xml.XmlWriterSettings] $xmlWriterSettings = @{
            Indent = $True
            NewLineOnAttributes = $True
            ## Encoding = [System.Text.Encoding]::UTF8
        }
    )

    
    ## # strategy 1:
    ## $xmlWriterSettings.Encoding = [System.Text.Encoding]::UTF8
    ## $stringWriter = New-Object System.IO.StringWriter
    ## $xmlWriter = [System.Xml.XmlWriter]::Create(
    ##     $stringWriter,
    ##     $xmlWriterSettings
    ## )
    ## $xmlDocument.Save($xmlWriter)
    ## $xmlWriter.Close()
    ## $stringWriter.GetStringBuilder().ToString()



    ## # strategy 2 (attempting to control the "encoding" attribute)
    ## $memoryStream = New-Object System.IO.MemoryStream
    ## $streamWriter = New-Object System.IO.StreamWriter $memoryStream
    ## $streamReader = New-Object System.IO.StreamReader $memoryStream
    ## $xmlWriter = [System.Xml.XmlWriter]::Create(
    ##     $streamWriter,
    ##     $xmlWriterSettings
    ## )
    ## $xmlDocument.Save($xmlWriter)
    ## $xmlWriter.Close()
    ## $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | out-null
    ## $streamReader.ReadToEnd()
    ## $streamReader.Close()

    # strategy 3 (streamlined version of strategy 2)
    $memoryStream = New-Object System.IO.MemoryStream
    $streamReader = New-Object System.IO.StreamReader $memoryStream
    $xmlWriter = [System.Xml.XmlWriter]::Create(
        (New-Object System.IO.StreamWriter $memoryStream),
        $xmlWriterSettings
    )
    $xmlDocument.Save($xmlWriter)
    $xmlWriter.Close()
    $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | out-null
    $streamReader.ReadToEnd()
    $streamReader.Close()

    # strategy 4:
    ## $xmlDocument.InnerXml
}

function getParentInterfaces([System.Type]  $type){
    <#
    .SYNOPSIS
    System.Type::GetInterfaces() returns all the interfaces that the type
    implements  (a.k.a. "inherits from"), buy says nothing about which
    interfaces the type inherits from directly, and which transitively.  I
    suspect that such a multi-generational inheritance tree is not a
    well-defined concept in .NET for interface inheritance in the way that it is
    for class inheritance.  My thinking in those terms is based on the fact
    that, in C# code, when declaring a class, you declare a list of interfaces
    that your class will implement, but you don't have to declare ALL the
    interfaces that your class will implement -- only the first "generation" of
    interfaces.  It is implicit that your class will implement any interfaces
    that those interfaces inherit from, on and on.

    I suspect that this concept of multi-generational interface inheritance is a
    compile-time convenience and does not really exist after compilation.

    Nevertheless, by looking at which interfaces a type implements, and by
    looking at which interfaces those interfaces implement (a.k.a. inherit
    from), we can construct a plausible minimal set of interfaces that the code
    for the type would have had to declare as "parents".

    I haven't fully thought through whether there is always exactly one, unique,
    such minimal set of "parent" interfaces.

    #>
    # see (https://stackoverflow.com/questions/3416496/how-do-i-find-the-interface-inheritance-hierarchy-for-a-type)

    $ancestorInterfaces = $type.GetInterfaces()

    $ancestorInterfacesExcludingParents = @( $ancestorInterfaces |% {$_.GetInterfaces()} | select -unique )

    $parentInterfaces = @($ancestorInterfaces |? {-not ($_ -in $ancestorInterfacesExcludingParents)})

    return $parentInterfaces
}





function Get-SelfElevatingScriptBlock {
    <#
    .DESCRIPTION
    Generates and returns a modified version of $inputScriptBlock which will elevate itself.

    #>
    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    param(
        [String] $inputScriptBlock
    )




    $elevatingPreamble  =  {
        $informationPreference  = 'Continue'
        # elevate thineself:

        if (
            (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole(
                ([Security.Principal.WindowsBuiltInRole] "Administrator")
            )
        ) {
            Write-Information "We are already elevated"
        } else {  
            Write-Information "We are not elevated.  Attempting to re-launch this script with an elevated token."
            ## Write-Host "`$myinvocation.mycommand.definition: $($myinvocation.mycommand.definition)"
            
            if($false){
                @{
                    FilePath = [Diagnostics.Process]::GetCurrentProcess().Path
                    Verb     = "RunAs"
                    ArgumentList =  @(
                        "-noexit"
                        "-EncodedCommand"
                        (Get-EncodedPowershellCommand $myinvocation.mycommand.definition)
                    )
                    Wait = $true
                } |% {Start-Process @_}

                # this will fail for long script blocks that exceed the allowed command line length.
            }

            if($false){
                @{
                    RunAsAdministrator = $True
                    ScriptBlock        = [ScriptBlock]::Create($myinvocation.mycommand.definition)
                    ComputerName       = "localhost"
                } |% {Invoke-Command @_}

                # it looks like -RunAsAdministrator is specific to containers --
                # this is not the answer.
            }

            $pathOfTemporaryScriptFile = (join-path $env:temp "$(new-guid).ps1")

            ## $myinvocation.mycommand.definition | Out-File -FilePath $pathOfTemporaryScriptFile -Encoding UTF8
            <#  We are blindly assuming that $myInvocation.myCommand is a
                scriptblock (i.e. has $_.CommandType -eq "Script") rather than a
                script file (i.e. has $_.CommandType -eq "ExternalScript").

                We ought to handle both cases.

                One potential way to do this is to use
                $myinvocation.mycommand.ScriptBlock rather than
                $myinvocation.mycommand.Definition.

                I think the "ScriptBlock" property  is a script block regardless
                of whether $_.CommandType is "Script" or "ExternalScript".

                It might be good to have some kind of guard against an infinite
                loop, in case the start-process call, below, somehoe manages to
                start the process without an eleveated token.
            #>

            $myinvocation.mycommand.ScriptBlock | Out-File -FilePath $pathOfTemporaryScriptFile -Encoding UTF8 | out-null

            @{
                FilePath = [Diagnostics.Process]::GetCurrentProcess().Path
                Verb     = "RunAs"
                ArgumentList =  @(
                    ##"-noexit"
                    "-ExecutionPolicy"; "Bypass"
                    "-File"
                    $pathOfTemporaryScriptFile 
                )
                Wait = $true
            } |% {Start-Process @_}

            Write-Information "finished attempt to run the script with an elevated token."

            return
        } 
    }

    $outputScriptBlock = [ScriptBlock]::Create((@(
        $elevatingPreamble
        $inputScriptBlock
    ) -join "`n"))

    return $outputScriptBlock

}

function Get-SelfElevatingOneLiner {
    <#
    .DESCRIPTION
    Generates and returns a oneliner, suitable foir pasting into most
    Windows shells, that will run the specified scriptblock with elevation.

    #>
    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    param(
        [String] $inputScriptBlock
    )

    $encodedCommand = &{
        $inputScriptBlock |
        % {Get-SelfElevatingScriptBlock $_} |
        % {Compress-ScriptBlock $_} |
        % {Get-EncodedPowershellCommand $_} |
        write-output
    }

    <# `Compress-ScriptBlock` comes from the PSMinifier package:
        ```
        Install-PSResource -Repository  PSGallery -Name PSMinifier -Version 1.1.3
        ```
    
    #>

    $powershellExecutable = "pwsh"
    <# We might be more intelligent about finding a maximally-likely-to-work
    powershell executable name.  At the moment, I am simply hardcoding the
    name, and we are blindly assuming that some reasonable version of
    powershell will be invocable in the shell that the user pastes the
    oneLiner into. #>

    $oneLiner = "$($powershellExecutable) -EncodedCommand $($encodedCommand)"

    return $oneLiner
}

function Get-HostedOneLiner  {
    <#
        .DESCRIPTION
        Generates and returns a oneliner, suitable foir pasting into most
        Windows shells, that will run the specified scriptblock.

        This publishes the script block as a file.   The returned one-liner
        downloads and invokes the file.

    #>
    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    param(
        [String] $inputScriptBlock,

        [Switch] $selfElevate = $false
    )


    $pathOfTemporaryFile  =  New-TemporaryFile
    Set-Content -Path $pathOfTemporaryFile -Value $(
        if($selfElevate){
            Get-SelfElevatingScriptBlock $inputScriptBlock
        } else {
            $inputScriptBlock
        }
    )

    $pathOfStrongNamedScriptFile = (join-path (new-temporarydirectory) "$(get-filehash -algorithm sha256 -path $pathOfTemporaryFile |% {$_.hash.ToLower()})" )
    Copy-Item $pathOfTemporaryFile $pathOfStrongNamedScriptFile
    $longUrlOfScriptFile = publishFile $pathOfStrongNamedScriptFile

    Remove-Item $pathOfStrongNamedScriptFile
    Remove-Item $pathOfTemporaryFile
    ##$urlOfScriptFile = $longUrlOfScriptFile
    
    # see (https://app.bitly.com/settings/api)
    #
    # see (https://dev.bitly.com/api-reference/#createBitlink)
    $bitwardenItemIdOfBitlyCredential  = "2d7a786d-7135-49f0-b504-aaaf002fa4df"
    $bitlyApiToken = (getFieldMapFromBitwardenItem $bitwardenItemIdOfBitlyCredential)['api_token']
    
    $response = @{
        Uri            = "https://api-ssl.bitly.com/v4/shorten"
        Method         = "POST"
        Authentication = "Bearer"
        Token          = (ConvertTo-SecureString $bitlyApiToken -AsPlainText -Force  )
        ContentType    = "application/json"
        Body           = @{
            long_url = $longUrlOfScriptFile
        } | ConvertTo-Json -depth 50
    } |% {Invoke-WebRequest @_}
    $responseData = $response.Content | ConvertFrom-Json -depth 50 -ashashtable
    $shortUrlOfScriptFile = $responseData.link

    ## $urlOfScriptFile = $longUrlOfScriptFile
    $urlOfScriptFile = $shortUrlOfScriptFile ?? $longUrlOfScriptFile



    
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -c `"Set-ExecutionPolicy Bypass -Scope Process -Force;iex (Invoke-WebRequest '$($urlOfScriptFile)')`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ExecutionPolicy Bypass -c `"Invoke-WebRequest '$($urlOfScriptFile)' | iex`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ExecutionPolicy Bypass -c `" iex (Invoke-WebRequest '$($urlOfScriptFile)')`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ExecutionPolicy Bypass -c `"iex (Invoke-WebRequest '$($urlOfScriptFile)')`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ExecutionPolicy Bypass -c `"iwr '$($urlOfScriptFile)' | iex`""     
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex Bypass -c `"iwr '$($urlOfScriptFile)' | iex`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [Microsoft.PowerShell.ExecutionPolicy]::Bypass ) -c `"iwr '$($urlOfScriptFile)' | iex`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Bypass ) -c `"iwr '$($urlOfScriptFile)' | iex`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Unrestricted ) -c `"iwr '$($urlOfScriptFile)' | iex`"" 

    ##$quotedUrl = $(if($urlOfScriptFile.Contains('&') ){"'$($urlOfScriptFile)'"}else {"$($urlOfScriptFile)"})


    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Unrestricted ) -c `"iex(iwr '$($urlOfScriptFile)')`"" 
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Unrestricted ) -en $(Get-EncodedPowershellCommand "iex(iwr '$($urlOfScriptFile)')")" 
    $onelinerToDownloadAndInvokeTheScript = "powershell -ex $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Bypass ) -en $(Get-EncodedPowershellCommand "iex(iwr -usebasic '$($urlOfScriptFile)')")" 
    <#  The -UseBasicParsing switch is necessary in order to avoit the error "iwr
        : The response content cannot be parsed because the Internet Explorer engine is
        not available, or Internet Explorer's first-launch configuration is not
        complete. Specify the UseBasicParsing parameter and try again. " 

        This error tends to happen when running under Windows Powershell (a.k.a. the "Desktop edition" of powershell.)
        
    #>

    ## $unencodedCommand = "Set-ExecutionPolicy $( [long] [Microsoft.PowerShell.ExecutionPolicy]::Unrestricted ) $( [long] [Microsoft.PowerShell.ExecutionPolicyScope]::Process ) -f;iex(iwr '$($urlOfScriptFile)')"
    ## write-host "unencodedCommand:  $($unencodedCommand)"
    ## $onelinerToDownloadAndInvokeTheScript = "powershell -en $(Get-EncodedPowershellCommand $unencodedCommand)" 

    return $onelinerToDownloadAndInvokeTheScript 
    
}




function Get-RandomPrivateNetwork{
    <#
        .DESCRIPTION
        Generates a random ULA or RFC1918 network (depending on whether you
        specify -IPVersion 4 or -IPVersion 6)
    #>
    
    [cmdletbinding()]
    [OutputType([System.Net.IPNetwork])]
    param(
        [ValidateRange(0,128)]
        [int] $PrefixLength,
        
        [ValidateSet(4,6)]
        [int] $IPVersion = 6 

        <#  this really ought to be an enum.  the logical choice would be
            [System.Net.Sockets.AddressFamily], but, that enum uses the
            names "InterNetwork" and "InterNetworkV6", respectively, for
            ipv4 and ipv6.  I do not like those names.  Also, that enum has
            a a whole bunch of other values, whereas I want something that
            specifically relates to ipv4 and ipv6.
        #>
    )

    function getMask([int] $prefixLength){
        [byte[]] @(
            0..15 |
            % { 
                $prefixLengthWithinThisByte  = [math]::max(0, [math]::min(8, $prefixLength - ($_ * 8) ))
                
                0xff -band (
                    0xff -shl ( 8 - $prefixLengthWithinThisByte)
                )
            } 
        )
    }

    $baseNetwork = switch($IPVersion){
        4 {
            # RFC1918's "24-bit block".
            [System.Net.IPNetwork]::Parse("10.0.0.0/8")
        }
        6 {
            # the well-known "ULA" prefix for site-local addresses that are locally assigned.
            [System.Net.IPNetwork]::Parse("fd00::/8")
        }
    }
        
    
    return [System.Net.IPNetwork]::new(
            [System.Net.IPAddress]::new((
            [byte[]] @( 
                0..$(switch($IPVersion){4 {3}; 6 {15}}) |
                % {
                    (
                        # zero the basePrefix bits and the upper bits:
                        ([byte]  (get-random -Minimum 0 -Maximum 0xff)) -band 
                        (-bnot  (getMask $baseNetwork.PrefixLength)[$_] ) -band
                        ((getMask $PrefixLength)[$_]) 
                    ) -bor (
                        # add the base ula prefix
                        $baseNetwork.BaseAddress.GetAddressBytes()[$_]
                    )
                }
            )
        )),
        $PrefixLength
    )
}

function Get-SubnetMask{
    
    [cmdletbinding()]
    [OutputType([System.Net.IPAddress])]
    param(
        [Parameter(Mandatory=$False,ParameterSetName='main')]
        [ValidateRange(0,128)]
        [int] $PrefixLength,
        
        [Parameter(Mandatory=$False,ParameterSetName='main')]
        ##[ValidateSet(4,6)]
        [int] $IPVersion = 6,

        [Parameter(Mandatory=$False,ParameterSetName='IPNetwork')]
        [System.Net.IPNetwork] $IPNetwork 
    )

    if(-not ($null  -eq $IPNetwork)){
        $IPVersion = switch($IPNetwork.BaseAddress.AddressFamily){
            ([System.Net.Sockets.AddressFamily]::InterNetwork) {4}
            
            ([System.Net.Sockets.AddressFamily]::InterNetworkV6) {6}
        }

        $PrefixLength = $IPNetwork.PrefixLength
    }

    function getMask([int] $prefixLength){
        [byte[]] @(
            0..15 |
            % { 
                $prefixLengthWithinThisByte  = [math]::max(0, [math]::min(8, $prefixLength - ($_ * 8) ))
                
                0xff -band (
                    0xff -shl ( 8 - $prefixLengthWithinThisByte)
                )
            } 
        )
    }



    [System.Net.IPAddress]::new((
        [byte[]] @( 
            0..$(switch($IPVersion){4 {3}; 6 {15}}) |
            % {(getMask $PrefixLength)[$_]}
        )
    ))
}


function Dismount-AllMountedIsoImages {
    $mountedDiskImages = @(Get-Volume | % { Get-DiskImage -Volume $_ } )  
    
    $mountedDiskImages | 
    ? {[System.Io.Path]::GetExtension($_.ImagePath).ToLower() -eq ".iso"} |
    % { 
        Write-Information "dismounting $($_)"
        Dismount-DiskImage -InputObject $_
    }
}


function Remove-OrphanedSids {
    <#  remove the "orphaned" sids from various (hardocoded) local groups, 
        to fix the error "Get-LocalGroupMember: Failed to 
        compare two elements in the array." thrown by Get-LocalGroupMember 
        when trying to list the members of the group. 

        see (https://github.com/PowerShell/PowerShell/issues/2996) 

        see (https://superuser.com/questions/1131901/get-localgroupmember-generates-error-for-administrators-group) 


    #>


    $env:computername
    foreach($nameOfLocalGroup in @("Administrators";"Users";"Remote Desktop Users")){
        $members = @(
            ([System.DirectoryServices.DirectoryEntry] "WinNT://./$($nameOfLocalGroup)").psbase.Invoke('Members') |
            % { 
            $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null) 
            }
        ) -match '^WinNT';   
        $members = $members -replace "WinNT://",""
        ## $members

        foreach ($member in $members)
        {
            Write-Information "Considering member '$($member)' of local group '$($nameOfLocalGroup)'."

            if ($member -match "^S-1\b") #checking for empty/orphaned SIDs only
            {
                Write-Information "Removing an orphaned-SID member '$($member)' from the local group '$($nameOfLocalGroup)'."
                Remove-LocalGroupMember -group $nameOfLocalGroup -member $member
            }
        }
    }
}

function Import-VeeamExecutableAliases {
    gci -recurse -file (join-path $env:programfiles "Veeam") -filter "*.exe" | 
    select -expand FullName |
    % {
        Set-Alias -Scope Global -Name ([IO.Path]::GetFileNameWithoutExtension($_)) -Value $_
    }
}

function Set-ScreenSaveTimeOut {
    <# 
        .DESCRIPTION
        Sets the preferred screenSaveTimeout, by default given as a TimeSpan
        object, for the current user.  (A value of zero means "infinite
        duration" )

        I am slightly annoyed at the default conversion behavior of
        System.TimeSpan, which is to convert a Long to a timeSpan having that
        many ticks.  It would make eminently more sense for this to be seconds.

        The optional -seconds parameter, here, is a workaround for the user that
        wants to supply a count of seconds, but it is almost more confusing than
        its worth to have the -seconds parameter, because the user will naively
        assume that `Set-ScreenSaveTimeout 99` and `Set-ScreenSaveTimeout
        -seconds 99` are equivalent, which they are not.

        TODO: ScreenSaveTimeOut, as it is saved in the registry is really a
        nullable string (I have no idea why it's a string and not a DWORD).  It
        is nullable in the sense that it is valid for the value to not exist (in
        which case the system uses a default value defined elsewhere, I
        presume.)  We ought to give the user some way of achieiving the "null"
        state (i.e. the state where the ScreenSaveTimeout value does not exist).

        We also probably ought to have a `Get-ScreenSaveTimeout` function, but
        this is really becoming ridiculous.
    #>
    
    [OutputType([void])]
    [CmdLetBinding(PositionalBinding=$false)]
    param(
        [Parameter(Position=0,  Mandatory=$true, parameterSetName="timeSpan_parameterSet")]
        [TimeSpan] $timeSpan,

        
        [Parameter(Mandatory=$true, parameterSetName="seconds_parameterSet")]
        [long] $seconds
    )

    $desiredScreenSaveTimeOut = $( 
        if($null -ne $timeSpan){
            $timeSpan
        } else {
            New-TimeSpan -Seconds $seconds 
        }
    )

    ##write-host "timeSpan $( $null -eq $timeSpan ? "is null" : "is not null" )."
    ##write-host "seconds $( $null -eq $timeSpan ? "is null" : "is not null" )."

    $literalPath = "registry::HKEY_CURRENT_USER\Control Panel\Desktop"
    $name = "ScreenSaveTimeOut"




    $initialScreenSaveTimeOut = $(
        try{
            New-TimeSpan -Seconds $(
                @{
                    LiteralPath = $literalPath
                    Name        = $name
                } |%{Get-ItemPropertyValue @_}
            )
        } catch {
            $null
        }
    )

    
    Write-Information "initialScreenSaveTimeOut.TotalSeconds: $($initialScreenSaveTimeOut.TotalSeconds)"
    Write-Information "desiredScreenSaveTimeOut.TotalSeconds: $($desiredScreenSaveTimeOut.TotalSeconds)"

    @{
        LiteralPath = $literalPath
        Name        = $name
        Type        = "String"
        Value       = "$([long] $desiredScreenSaveTimeOut.TotalSeconds)"
    } |% {Set-ItemProperty @_ }
    

    

    $finalScreenSaveTimeOut = $(
        try{
            New-TimeSpan -Seconds $(
                @{
                    LiteralPath = $literalPath
                    Name        = $name
                } |%{Get-ItemPropertyValue @_}
            )
        } catch {
            $null
        }
    )

    Write-Information "finalScreenSaveTimeOut.TotalSeconds: $($finalScreenSaveTimeOut.TotalSeconds)"
}

function neverSleep {
    <# Set the computer never to sleep while running on AC power #>
    write-information "setting the computer to never sleep while running on AC power"

    $getState = {powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | sls "Current AC Power Setting Index"}
    $initialState = $(& $getState)
    powercfg /change standby-timeout-ac 0
    $finalState = $(& $getState)

    write-information "initial state: $($initialState)"
    write-information "final state: $($finalState)"

    
}

function  Invoke-Periodically {

    [CmdletBinding()]
    param(
        [ScriptBlock] $ScriptBlock,
        [TimeSpan] $period=(New-TimeSpan -Seconds 60),
        [Switch] $prependDate  = $False
    )


    .{
        while($True){
            $startTime = (Get-Date)
            if($prependDate ){
                Write-Output "$(Get-Date): $( & $ScriptBlock |? {$_} )"
            } else {
                & $ScriptBlock
            }
            $endTime = (Get-Date)
            Start-Sleep -Seconds ([math]::max(0, ($period - ($endTime - $startTime) ).TotalSeconds)) | Out-Null
        }
    } |? {$_}

}


function Show-Printers {
    <#  
        .DESCRIPTION
        This will bring up the real list of Windows printers, with no combining of printers that have the same driver.
        This list of printers is different than and more useful than the list that appears in the 'Devices and Printers' 
        control panel.

        See https://support.microsoft.com/en-us/kb/2015694 

        See also http://www.eightforums.com/tutorials/13591-clsid-key-guid-shortcuts-list-windows-8-a.html 
        
    #>

    start "shell:::{863aa9fd-42df-457b-8e4d-0de1b8015c60}"
}

Set-Alias Convert-EntraObjectIdToSid Convert-AzureAdObjectIdToSid 
function Convert-AzureAdObjectIdToSid {
    <#
    .SYNOPSIS
    Convert an Azure AD (a.k.a. Entra) Object ID to SID
     
    .DESCRIPTION
    Converts an Azure AD Object ID to a SID.
    Author: Oliver Kieselbach (oliverkieselbach.com)
    The script is provided "AS IS" with no warranties.
     
    .PARAMETER ObjectID
    The Object ID to convert


    .EXAMPLE
    
    $objectId = "73d664e4-0886-4a73-b745-c694da45ddb4"
    $sid = Convert-AzureAdObjectIdToSid -ObjectId $objectId
    Write-Output $sid
    
    # Output:

    # S-1-12-1-1943430372-1249052806-2496021943-3034400218


    .NOTES
    see (https://github.com/okieselbach/Intune/blob/master/Convert-AzureAdObjectIdToSid.ps1)

    see (https://github.com/okieselbach/Intune/blob/e485876f69a30e9ecf30864f447f0506f00ce953/Convert-AzureAdObjectIdToSid.ps1)

    This function probably ought to be refactored to work with the [System.Security.Principal.SecurityIdentifier] class.

    #>
    [OutputType([String])]
    param([String] $ObjectId)

    $bytes = [Guid]::Parse($ObjectId).ToByteArray()
    $array = New-Object 'UInt32[]' 4

    [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
    $sid = "S-1-12-1-$array".Replace(' ', '-')

    return $sid
}

Set-Alias Convert-EntraSidToObjectId Convert-AzureAdSidToObjectId
Set-Alias Convert-SidToEntraObjectId Convert-AzureAdSidToObjectId
function Convert-AzureAdSidToObjectId {
    <#
    .SYNOPSIS
    Convert an Azure AD (a.k.a. Entra) SID to Object ID
     
    .DESCRIPTION
    Converts an Azure AD SID to Object ID.
    Author: Oliver Kieselbach (oliverkieselbach.com)
    The script is provided "AS IS" with no warranties.
     
    .PARAMETER ObjectID
    The SID to convert

    .EXAMPLE
        
    $sid = "S-1-12-1-1943430372-1249052806-2496021943-3034400218"
    $objectId = Convert-AzureAdSidToObjectId -Sid $sid
    Write-Output $objectId
    
    # Output:
    
    # Guid
    # ----
    # 73d664e4-0886-4a73-b745-c694da45ddb4



    .NOTES
    see (https://github.com/okieselbach/Intune/blob/master/Convert-AzureAdSidToObjectId.ps1)

    see (https://github.com/okieselbach/Intune/blob/e485876f69a30e9ecf30864f447f0506f00ce953/Convert-AzureAdSidToObjectId.ps1)

    This function probably ought to be refactored to work with the [System.Security.Principal.SecurityIdentifier] class.


    #>
    [OutputType([Guid])]
    param([String] $Sid)

    $text = $sid.Replace('S-1-12-1-', '')
    $array = [UInt32[]]$text.Split('-')

    $bytes = New-Object 'Byte[]' 16
    [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
    [Guid]$guid = $bytes

    return $guid
}

function Get-HostnameFromBitwardenItem {
    <#
        .SYNOPSIS
        Tries to extract the hostname from a bitwarden item
    #>
   
    [OutputType([String])] 
    
    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $bitwardenItemId
    )

    ## (
    ##     (getFieldMapFromBitwardenItem $bitwardenItem.id)['hostname'] ?? 
    ##     ([System.Uri] @($bitwardenItem.login.uris)[0].uri).Host ??
    ##     @($bitwardenItem.login.uris)[0].uri
    ## )

    @(
        (GetFieldMapFromBitwardenItem $bitwardenItemId).hostname 
        
        (Get-BitwardenItem $bitwardenItemId -erroraction silentlycontinue).login.uris |
        %{$_.uri} |
        % {
            try{
                ([UriBuilder] $_).Host
            }catch{}
        }
    ) |? {$_} | select -first 1
}

function Get-CredentialFromBitwardenItem {
    <#
        .SYNOPSIS
        creates, based on the information in the bitwarden item,
        a System.Management.Automation.PSCredential object
    #>

    [OutputType([System.Management.Automation.PSCredential])] 

    [CmdletBinding()]
    Param (
        [Parameter()]
        [String] $bitwardenItemId
    )

    $bitwardenItem = Get-BitwardenItem $bitwardenItemId
    ##$formattedUsername = "$(Get-HostnameFromBitwardenItem $bitwardenItemId)\$($bitwardenItem.login.username)"
    $formattedUsername = $bitwardenItem.login.username

    <#   We might consider adding a paramter to control the formatting of the
        username to accomodate the several username formats that Windows
        sometimes expects.

        e.g. an NT2000 formatted username, with hostname prepended with back
        slash separator.
     #>


    ## (
    ##     @{
    ##         TypeName = "System.Management.Automation.PSCredential"
    ##         ArgumentList = @(
    ##             $formattedUsername,
    ##             (ConvertTo-SecureString $bitwardenItem.login.password -AsPlainText -Force)
    ##         )
    ##     } | % { New-Object @_ } 
    ## )

    [System.Management.Automation.PSCredential]::new(
        $formattedUsername,
        (ConvertTo-SecureString $bitwardenItem.login.password -AsPlainText -Force)  
    )

}

<# it is probably not ideal to import the DnsClient module here, but
I am doing it in order to ensure that the [Microsoft.DnsClient.Commands.RecordType] enum is
available for the following function. #>
Import-Module DnsClient
function Save-InHostsFile (){
    <# 
        .DESCRIPTION
        looks up the specified A or AAAA record (possibly reached via
        some chain of CNAME records) from the dns  (the first record)
        and saves it in the hosts file.
    #>
    [cmdletBinding()]
    param(
        [string] $HostName,
        ## [validateSet("A","AAAA")]
        [Microsoft.DnsClient.Commands.RecordType] $RecordType = "A_AAAA"
    )
    

    $ipAddress = $(
        resolve-dnsname -dnsonly -Name $HostName -Type $RecordType  |
        ? {$_.Type -eq $RecordType} |
        select -expand IPAddress |
        ? {$_} |
        select -first 1
    )

    if(-not $ipAddress){
        write-error "Could not resolve HostName '$($HostName)' to a valid $($RecordType) record."
        return
    }
    Set-CHostsEntry -HostName $HostName -IPAddress $ipAddress

}

function cslmgr {
    <#
    The slmgr.vbs script tends to produce popup gui boxes rather than text output to stdout.

    This function is a wrapper around slmgr.exe that invokes it using cscript, so that it emits its output on stdout.

    Use this function  in place  of slmgr.

    #>
    ## $input | cscript /NoLogo (get-command slmgr).Path @args
    $input | cscript /NoLogo (get-command -CommandType Application -Name slmgr).Path @args

}

function Get-ShortPath {
    <#
    .SYNOPSIS
    attempts to convert the given path into  the equivalent "8.3" style path.
    This is useful for working around problems related to long paths.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [string] $Path
    )

    return (
        (New-Object -ComObject Scripting.FileSystemObject).GetFile($Path).ShortPath 
    )
}


function Select-Single {
    <#
        .DESCRIPTION
        Very similar to `select-object -index 0`, except we throw an error if
        there is not exactly one element piped in.  Conceptually similar to
        [System.Linq.Enumerable]::SelectSingle().

        TODO: add parameter(s) to let us achieve SingleOrDefault() behavior.

        I am surprised that this functionality does not exist in some built-in
        standard powershell function already, and maybe it does, but I can't
        find it.

        This function does not behave expectedly when you both pipe at least one
        object into it and pass an explicit -InputObject parameter.  In that
        case, we would like it to produce no output.  however, it instead emits
        exactly one object, namely the object was passed in as the -InputObject
        parameter.  In  this case, the body of the process block runs.  Rather,
        the interpreter  tries to  run it once for each piped-in object, but
        fails (that is, the process block run attempt fails, but not the whole
        function) with an error, and we have no good way to know whether the
        interpreter tried to run the process block.

        We could  look at $myInvocation.ExpectingInput but that will be true
        whenever there is an upstream part of the pipeline, even if that
        upstream part  of the pipeline happens not to emit  any objects, and we
        want this function to  emit exactly one object when it is given an
        explicit -InputObject parameter and when it is receiving input from an
        upstream pipeline that happens to emit zero objects.  In other words,
        when this function is given an explicit -InputObject parameter, we
        (Still) want to distinguish between being piped zero objects and being
        piped more than nonzero objects, but powershell doesn'st seem to have
        any straightforward way to so distinguish.

        Also, trying to manipulate ErrorActionPreference is problematic because
        the caller can override our internal manipulations it by passing the
        -ErrorAction:Continue parameter.

        Oh well, that's an edge case.

        I think I would prefer to not  have any explicitly-declared parameter
        with ValueFromPipelineInput=$True, but, when we are using
        CmdletBinding(), we have to have one parameter with the
        ValueFromPipeline=$true argument in order for the function  to take
        pipeline input at all.  Maybe I could get away with having
        CmdletBinding().
    #>

    [CmdletBinding()]
    [OutputType([Object])]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Object] $InputObject
    )

    begin {
        ##$ErrorActionPreference = 'Stop'
        ## write-debug "beginning"
        [long] $countOfObjectsEncountered = 0
        ##[long] $countOfProcessIterations = 0
        if($PSBoundParameters.ContainsKey('InputObject')){
            ## write-debug "encountered object $($countOfObjectsEncountered)"
            $countOfObjectsEncountered  += 1
            ##$lastObjectEncountered = $InputObject
        }
        
    }
    process {
        ## write-debug "processing"
        ##  $countOfProcessIterations += 1
        ## write-debug "input type: $($input.GetType().FullName)"

        ##$_input = $input
        ##$_inputObject = $InputObject
        ##write-debug "_input type: $($_input.GetType().FullName)"
        ##write-debug "_input.Count: $($_input.Count)"
        ##write-debug "_input: $(out-string -inputobject $_input)"
        ##write-debug "_inputObject type: $($_inputObject.GetType().FullName)"
        ##write-debug "_inputObject: $(out-string -inputobject $_inputObject)"
        ## 
        ## 
        ## 
        ## $_InputObject
        ## ##$InputObject
        ## ## $input

        <# 
           $input is always of type ArrayList 

            when there is no input piped in, the process block runs once, with
            $input.Count being zero.  

            Therefore,we  can't just count the number of times the process block
            run to know how many input objects were piped in.
        #>
        foreach($item in $input){
            $countOfObjectsEncountered  += 1
            ##if($countOfObjectsEncountered -eq 2){
            if($countOfObjectsEncountered -gt 1 ){
                ## write-error "more than one objects encountered.  We were expecting exactly one object."
                ## return
                <# see (https://dille.name/blog/2016/02/04/careful-when-using-return-in-advanced-powershell-functions/) #>
            
                throw "more than one objects encountered.  We were expecting exactly one object."
                write-error "more than one objects encountered.  We were expecting exactly one object."
                return
            }
            ##write-debug "encountered object $($countOfObjectsEncountered)"
           
           ## $lastObjectEncountered = $InputObject
        }
    }
    end  {
        ##  write-debug "ending"
        #### write-debug "countOfObjectsEncountered: $($countOfObjectsEncountered)"
        ##  write-debug "countOfProcessIterations: $($countOfProcessIterations)"
        ##  write-debug "myInvocation.PipelinePosition: $($myInvocation.PipelinePosition)"
        ##  write-debug "myInvocation.PipelineLength: $($myInvocation.PipelineLength)"
        ##  write-debug "myInvocation.ExpectingInput: $($myInvocation.ExpectingInput)"
        ##  $_input = $input
        ##  $_inputObject = $InputObject
        ##  write-debug "_input type: $($_input.GetType().FullName)"
        ##  write-debug "_input.Count: $($_input.Count)"
        ##  write-debug "_input: $(out-string -inputobject $_input)"
        ##  write-debug "_inputObject type: $($_inputObject.GetType().FullName)"
        ##  write-debug "_inputObject: $(out-string -inputobject $_inputObject)"
        if($countOfObjectsEncountered -eq 0 ){
            throw "zero objects encountered.  We were expecting exactly one object."
            write-error "zero objects encountered.  We were expecting exactly one object."
            return
        }
        
        
        ##  return $lastObjectEncountered
        <#  strangely, in some cases (apparently when the input is coming form a
            function rather  than a literal value not quite  -- buyt something
            like this)), the throw statements do not cause an immediate
            termination of the whole function , whereas, when, for instnace, we
            are piping an array into this function, the throw statements cause
            an immediate termination of the whle function.  Thus, it is
            sometimes possible, in cases where we have received multiople  piped
            in objects, to  end up arriving at the current point in the
            execution.  HEnce, the need to test whether
            $countOfObjectsEncountered -eq 1.

            that's also why, in the process block, I am iterating
            countOfObjectsEncountered before the return/throw statement rather
            than after it.
        #>

        if($countOfObjectsEncountered -eq 1){
            #### write-debug "about to return succesfully"
            return $InputObject
        }
    }
}

function Select-SingleOrDefault {
    <# 
        Similar to Selct-Single, except when there are zero objects, we retturn
        $Default instead of throwing an exception.

        TODO 2025-02-25-1410: fix the code repetition between
        Select-SingleOrDefault and Select-Single.
    #>
    [CmdletBinding()]
    [OutputType([Object])]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Object] $InputObject,

        [Parameter(Mandatory=$False)]
        [Object] $Default = $null
    )

    begin {
        [long] $countOfObjectsEncountered = 0
        if($PSBoundParameters.ContainsKey('InputObject')){
            $countOfObjectsEncountered  += 1
        }  
    }
    process {
        foreach($item in $input){
            $countOfObjectsEncountered  += 1
            if($countOfObjectsEncountered -gt 1 ){           
                throw "more than one objects encountered.  We were expecting exactly one object."
                write-error "more than one objects encountered.  We were expecting exactly one object."
                return
            }
        }
    }
    end  {
        if($countOfObjectsEncountered -eq 0 ){
            ## throw "zero objects encountered.  We were expecting exactly one object."
            ## write-error "zero objects encountered.  We were expecting exactly one object."
            ## return
            return $Default
        }

        if($countOfObjectsEncountered -eq 1){
            return $InputObject
        }
    }
}


function Enable-RemoteDesktop {
    Set-ItemProperty -Path 'registry::HKLM\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

function Get-MicrosoftProductNamesAndServicePlansTable {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.IEnumerable[HashTable]])]
    param()
    <# see (https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference) #>
    $urlOfProductNamesAndServicePlansCsvFile = "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv"
    $productNamesAndServicePlansTableWithPossibleDuplicateRows = (import-csv (downloadFileAndReturnPath $urlOfProductNamesAndServicePlansCsvFile))

    $groupedRows = @(
        $productNamesAndServicePlansTableWithPossibleDuplicateRows | 
        group -Property ($productNamesAndServicePlansTableWithPossibleDuplicateRows[0] | get-member -MemberType:NoteProperty | select -expand Name ) 
    )

    $productNamesAndServicePlansTable = @(
        $groupedRows |
        % {$_.Group[0]}
    )

    $groupsHavingDuplication  =  @($groupedRows |? {$_.Count -ne 1})

    if($groupsHavingDuplication){
        write-warning (-join @(
            "found $($groupsHavingDuplication.Count) duplicate rows, "
            "namely: "
            @(
                foreach($groupInfo in $groupsHavingDuplication ){
                    ##Add-Member -PassThru -InputObject $groupInfo.Group[0].Clone() -NotePropertyMembers @{count = $groupInfo.Count}


                    $groupInfo.Group[0] |
                    select @(
                        @{
                            n="count"
                            e={$groupInfo.Count}
                        }
                        ($groupInfo.Group[0] | get-member -MemberType:NoteProperty | select -expand Name | sort) 
                    )
                }
            ) |
            ft -auto |
            out-string
        ))
    }

    return $productNamesAndServicePlansTable
}

function Get-MicrosoftProductsTable {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.IEnumerable[HashTable]])]
    param()
    $productNamesAndServicePlansTable = Get-MicrosoftProductNamesAndServicePlansTable 


    $productDatumsWithNonUniqueKeys = @()
    $productsTable = @(
        foreach($groupInfo in @($productNamesAndServicePlansTable | group GUID )){
            $productKeys = @(
                'Product_Display_Name'
                'String_Id'
                'GUID'
            )

            $productDatums = @(
                $groupInfo.Group |
                select $productKeys |
                group $productKeys |
                % {$_.Group[0]}
            )


            if($productDatums.Count -ne 1){
                write-warning (-join @(
                    "For product GUID '$($groupInfo.Name)', "
                    "we were expecting to find exactly one (distinct) datum, "
                    "but instead we found exactly $($productDatums.Count) datums."
                ))
                $productDatumsWithNonUniqueKeys += $productDatums
                continue
            }

            $includedServicePlansIdsWithPossibleDuplicates = @(
                $groupInfo.Group |% {$_.Service_Plan_Id} | sort
            )

            $includedServicePlansIds = @($includedServicePlansIdsWithPossibleDuplicates | select -unique |  sort)

            if($includedServicePlansIdsWithPossibleDuplicates.Count -ne $includedServicePlansIds.Count){
                write-warning (-join @(
                    "For product GUID '$($groupInfo.Name)', "
                    "we found $($includedServicePlansIdsWithPossibleDuplicates.Count - $includedServicePlansIds.Count) "
                    "duplicate service plan ids."
                ))
            }

            $productDatum = $productDatums[0]
            Add-Member -InputObject $productDatum -NotePropertyMembers @{includedServicePlansIds = $includedServicePlansIds}
            $productDatum
        } 
    )


    return $productsTable
}

function Show-MicrosoftGraphLicenseReport {
    [CmdletBinding()]
    param(
        [switch] $reportOnComponents
    )
    
    ## connectToOffice365 -bitwardenItemIdOfTheConfiguration $companyParameters['idOfBitwardenItemContainingMicrosoftGraphManagementConfiguration']


   ##  $mgSubscribedSkus = @((Get-MgSubscribedSKU -Property * ))
    $productNamesAndServicePlansTable = Get-MicrosoftProductNamesAndServicePlansTable 

    $servicePlanNamesByServicePlanId =  @{}

    $data = @(
        foreach($mgUser in @(Get-MgUser -all)){
            $assignedLicenses  = $(
                (
                    Get-MgUser -UserId $mgUser.Id -Property "AssignedLicenses"
                ).AssignedLicenses
            )
            $assignedPlans  = $(
                (
                    Get-MgUser -UserId $mgUser.Id -Property "AssignedPlans"
                ).AssignedPlans
            )

            if(-not $assignedLicenses){continue}

            
            
            ([pscustomobject] (
                @(
                    @{
                        UserPrincipalName = $mgUser.UserPrincipalName
                        DisplayName       = $mgUser.DisplayName
                        skuPartNumbers = (
                            @(
                                foreach($assignedLicense in $assignedLicenses){
                                    skuIdToSkuPartNumber $assignedLicense.SkuId
                                }
                            ) | sort
                        )
                    } 

                    if($reportOnComponents){
                        @{
                            servicePlans = (
                                @(
                                    @(
                                        foreach($assignedPlan in $assignedPlans){
                                            if(-not $servicePlanNamesByServicePlanId.ContainsKey($assignedPlan.servicePlanId)){
                                                $servicePlanNamesByServicePlanId[$assignedPlan.servicePlanId] =  @(

                                                    $productNamesAndServicePlansTable |
                                                    ? {$_.Service_Plan_Id -eq $assignedPlan.servicePlanId} |
                                                    % { $_.Service_Plan_Name, $_.Service_Plans_Included_Friendly_Names }
                                                    select -unique |
                                                    sort
                                                ) 
                                            }
                                            
                                            

                                            @(
                                                # $assignedPlan.Service
                                                ##"$($assignedPlan.Service) ($($assignedPlan.servicePlanId)): $($assignedPlan.CapabilityStatus)"
                                                
                                                (
                                                    @(
                                                        $assignedPlan.servicePlanId

                                                        (-join @(
                                                            "("
                                                                @(
                                                                    @(
                                                                        $servicePlanNamesByServicePlanId[$assignedPlan.servicePlanId]
                                                                        $assignedPlan.Service
                                                                    ) |
                                                                    select -unique  |
                                                                    sort
                                                                ) -join ", "
                                                            ")"
                                                        ))
                                                        
                                                        ": $($assignedPlan.CapabilityStatus)"
                                                    ) -join "`t"
                                                )

                                                <#  see
                                                    [https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference]
                                                    for a list of servicePlan guids.  
                                                #>
                                                
                                                # $mgSubscribedSkus.ServicePlans | 
                                                #     ? { $_.ServicePlanId -eq $assignedPlan.ServicePlanId } |
                                                #     % { $_.ServicePlanName } |
                                                #     Select-Object -First 1
                                            )
                                        } 
                                    ) | 
                                    Select -Unique | 
                                    Sort 
                                ) -join "`n"
                            ) 
                        }
                    }
                )  | merge-hashtables 
            ) ) |
            select @(
                'UserPrincipalName'
                'DisplayName'
                'skuPartNumbers'
                if($reportOnComponents){'servicePlans'}
            )
        }
    )


    $data | format-table -autosize:$True -Wrap:$True

    Get-MgSubscribedSKU | select SkuId, SkuPartNumber, {$_.PrepaidUnits.Enabled}, ConsumedUnits | ft -auto

}

function Get-CurriedSoftetherVpncmdFunction {
    <#
        .SYNOPSIS
        Given a bitawrden item id of a bitwarden item containing the credential
        for (and address of) a softethervpn server, we return a function that is
        a curried form of Softether's vpncmd utility, curried to bake in several
        command-line arguments that vpncmd expects, namely the server address,
        "/SERVER", and "/PASSWORD:...", and accepting its own parameters AdminHub
        and Command, which it passes through to vpncmd in the appropriate way.

        #TODO: suppress the "banner" that vpncmd emits before the real output.
    #>

    [OutputType([ScriptBlock])]
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$True)]
        [string] $bitwardenItemIdOfSoftetherServerCredential
    )

    
    $bitwardenItemContainingSoftetherVpnServerCredentials = Get-BitwardenItem $bitwardenItemIdOfSoftetherServerCredential
    $vpnServerAddress = $(
        @(
            ($bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[0]
            ":"
            ( $bitwardenItemContainingSoftetherVpnServerCredentials.login.uris[0].uri -split ":")[1]
        ) -join ""
    )
    $vpnServerPassword = $($bitwardenItemContainingSoftetherVpnServerCredentials.login.password)


    return  {
        <#
            .SYNOPSIS
            This is a  curried form of vpncmd, with the address, "/SERVER",
            "/PASSWORD:...", and "/CMD" arguments baked in.

            Supports passing an optional AdminHub parameter
        #>

        [CmdletBinding(PositionalBinding=$False)]
        param(
            ##[parameter(Mandatory=$False)]
            [string] $AdminHub,

            [parameter(ValueFromRemainingArguments=$True,Mandatory=$True)]
            [string[]] $Command
            ## [string] $command
        )
        ## write-information "command: '$command'"
        ## write-information "command.Count: $($command.Count)"

        <# piping an empty array into vpncmd prevents vpncmd from going into
        interactive mode. #>
        @() | vpncmd @(
            $vpnServerAddress
            "/SERVER" 
            "/PASSWORD:$($vpnServerPassword)"
            if($AdminHub){"/ADMINHUB:$($AdminHub)"}
            ## if($commandWords){"/CMD:"; $commandWords}
            ##  "/CMD"; $command
            ## "/CMD:$($command)"
            "/CMD"; $Command
        ) 

    }.GetNewClosure()
    

}


function Find-Intersect {
    <#
        finds all files among those specified by $Path that contain all of the
        specified regex patterns.  

        There is probably some more canonical way to do this with standard
        functions, but  if there is, it always escapes me.  Hence, the need for
        this function.
    #>
    
    [CmdletBinding()]
    param(
        [string[]] $Patterns,
        [string[]] $Path
    )
    $candidateFiles = @(gi -Path $Path)

    foreach($pattern in $patterns){
        $candidateFiles = @(
            Select-String -LiteralPath $candidateFiles  -pattern $pattern  -List:$true  | 
            select -expand Path |
            select -unique
        )
    }
    gi -LiteralPath $candidateFiles | select -expand FullName | select  -unique | sort
}

function Get-LocalAccountTokenFilterPolicy {
    [CmdletBinding()]
    param()

    $Name = 'LocalAccountTokenFilterPolicy'
    $Path = 'registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    return $(
        (Get-Item -Path $Path).GetValue($Name) 
    )
}

function Set-LocalAccountTokenFilterPolicy {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Nullable[long]] $value
    )
    $Name = 'LocalAccountTokenFilterPolicy'
    $Path = 'registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    write-information "initially, LocalAccountTokenFilterPolicy is $(Get-LocalAccountTokenFilterPolicy |% {if($null -eq $_){"null"}else{$_}})"

    if($value -eq (Get-LocalAccountTokenFilterPolicy)){
        write-information "LocalAccountTokenFilterPolicy is already as desired."
    } elseif($null -eq $value){
        write-information "removing the itemproperty"
        @{
            Name = $Name 
            Path = $Path 
            Confirm = $False
        } |% { 
            Remove-ItemProperty @_ 
        }
    } else {
        @{
            Name = $Name 
            Path = $Path 
            Type = 'DWord'
            Value = $value
        } |% { 
            Set-ItemProperty @_ 
        }
    }

    write-information "finally, LocalAccountTokenFilterPolicy is $(Get-LocalAccountTokenFilterPolicy |% {if($null -eq $_){"null"}else{$_}})"

}


function tryGetE164FormattedPhoneNumber([string] $freeFormPhoneNumber){
    
    .{# install and load Google.LibPhoneNumber assembly (this is a very hacky way to manage dependencies)
        if(-not $(& {[com.google.i18n.phonenumbers.PhoneNumberUtil]} -erroraction silentlycontinue 2>$null)){  
            # see https://github.com/google/libphonenumber
            push-location (new-temporarydirectory)
            dotnet new console
            dotnet add package Google.LibPhoneNumber --version 1.0.0 --source "https://api.nuget.org/v3/index.json"
            dotnet build
            ## gci . -file -force -recurse -filter "*.dll" | select -expand FullName
    
    
            ##gi ".\bin\Debug\net8.0\*.dll" |% {Add-Type -Path $_ }
            gi ".\bin\Debug\net*\*.dll" |% {Add-Type -Path $_ }
            pop-location
            ##copy-item ".\bin\Debug\net8.0\runtimes\win-x64\native\*.dll" (split-path -parent ([System.Runtime.Loader.AssemblyLoadContext]::Default.Assemblies |? {$_.GetName().Name -eq "Microsoft.Data.Sqlite"}).Location)
            ##copy-item ".\bin\Debug\net8.0\runtimes\win-x64\native\*.dll" .
    
        }
    } | write-information
    
    
    $phoneNumberUtil = $([com.google.i18n.phonenumbers.PhoneNumberUtil]::getInstance())
    
    
    return $( 
        $(
            try {
                "$($phoneNumberUtil.format($phoneNumberUtil.parse($freeFormPhoneNumber, "US"), "E164"))"
            } catch {
                
            }
        ) |
        ? {$_}
    )
}


function Get-NegatedTransportRuleCondition  ([hashtable] $positiveCondition){
    <#  CAUTION: This is only meaningful if positiveCondition is "atomic"
        (my own term) (i.e. not a composition of atomic conditions).   
        
        TODO:
        handle the case where the specified "positiveCondition" is an exceptif...
        condition (so that two negations (as performed by this function) will
        be the identity)
    #>
    
    $namesOfPositiveConditionParameters = @(
        get-command new-transportrule |%  {$_.Parameters.Values} |%  {$_.Name} |
        % {[regex]::Match($_, "(?i)(?<=^ExceptIf).+`$")}  |
        ? {$_.Success} |
        % {$_.Value}
    )

    $positiveCondition.GetEnumerator() |
    % {
        @{
            $(
                if($_.Key -in $namesOfPositiveConditionParameters){
                    "ExceptIf$($_.Key)"
                } else {
                    $_.Key
                } 
            ) = $_.Value
        }
    } |
    Merge-HashTables
}

function Get-TransportRuleSpecsToEvaluateConditions {
    <# 
        returns a secuence of (parameters to  create) transport rules
        that will set the specified header to a "signature" of the
        specified conditions.  The signature is a string consisting of
        exactly $conditions.Count  characters, where the cahracter  at
        index i is 1 if $condition i is true, else 0.

        The condition signature can be tested by subsequent rules to
        effectively achieve AND logic (which is otherwise exceedingly
        difficult to achieve in a general way with Exchange Online
        transport rules) (well, the algorithm herein is itself in some
        sense "exceedingly difficult", but this function at least
        encapsulates that exceeding difficulty -- that's the whole point
        of this function.
    #>
    
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$True)]
        [System.Collections.Generic.List[Hashtable]] $conditions,

        [parameter(Mandatory=$false)]
        [string]  $uniqueHeaderNamePrefix = "X-$(new-guid)",

        [parameter(Mandatory=$false)]
        [string] $nameOfConditionSignatureHeader = "",

        [parameter(Mandatory=$false)]
        [string] $nameOfVersionHeader = "",

        [parameter(Mandatory=$false)]
        [string] $version =  "$(get-date -format o)",

        [switch] $doStampVersionHeader = $false,

        [switch] $doNotCleanup = $false,

        [switch] $doStageSpecificSignatureHeaders = $false
    )

   
    if(-not $nameOfConditionSignatureHeader) {$nameOfConditionSignatureHeader = "$($uniqueHeaderNamePrefix)-condition-signature"}
    if(-not $nameOfVersionHeader){$nameOfVersionHeader = "$($uniqueHeaderNamePrefix)-version"}

    write-information  "nameOfConditionSignatureHeader: '$($nameOfConditionSignatureHeader)'"
    write-information  "nameOfVersionHeader: '$($nameOfVersionHeader)'"
    write-information  "version: '$($version)'"

    $headerNamePrefixForPositiveMarker  = "$($uniqueHeaderNamePrefix)-condition"
    $headerValueForPositiveMarker = "1"
    <#  The exact choice  for this value is totally arbitrary.   We
        only want to test whether each marker is present, not what its
        particular value is, but the rules are easier to understand if
        we have a fixed constant value for every marker header. 
    #>

    $namesOfHeadersToBeRemovedDuringCleanup = @()
    $transportRuleSpecs = @()

    $namesOfPartialSignatureHeaders = @(
        0..($conditions.Count) |%  {
            if($doStageSpecificSignatureHeaders -and ($_ -le $conditions.Count)){
                "$($uniqueHeaderNamePrefix)-partial-signature$($_)"
            } else {
                $nameOfConditionSignatureHeader
            }
        }
    )

    <# This brain damage (using a distinct header name for the i'th partial
        signature header), seems to be encessary to avaoid out-of-order rule
        evalutation that occurs if we try to us the same single name for the
        signature header throught the entire flow.

        $namesOfPartialSignatureHeaders[$i] is the name of the header that will
        contain the partial signature obtained by evaluating the first i
        conditions
    #>


    if($doStampVersionHeader){
        $transportRuleSpecs += @(
                
            @(
                @{Comments = "set the version header"}
                @{
                    SetHeaderName  = $nameOfVersionHeader
                    SetHeaderValue = $version
                }
            ) | merge-hashtables

            ##  $namesOfHeadersToBeRemovedDuringCleanup +=  $nameOfVersionHeader     
        
        )
        <# the version header is just for debugging, so that I can detect
        when the transport rule changes have updated.  i.e. which version of
        these transport rules are in effect. #>
    }

    <#  the idea is that, as long as each of  our conditions
        does not have both a positive header value test and a negative
        header value test,  we can choose a positive header value test
        or a negative value test to be combined with our test  .....
        never mind that's not quite right.

        What I want to combine is a positive  header value test to test
        the accumulated partial condition signature, and another header
        test (either a negative header value test or maybe a pattern
        test (are we allowed to have both a pattern match header test
        and a literal value header test in the same rule? -- if so that
        would be more intelligible than theis negative-sense business.)
        to test my condition of interest (or a marker of my condition of
        interest).

        The enabling hack here is that even though we can't have a
        condition of the form (header A exists and header B exists), we
        CAN have condtion of the form (header A exists and header b does
        not exist.)

        It occurs to me that this all works just as well if our marker
        headers are positive-sense.
    #>

    <# set each positive-sense marker header according to whether the
        correspondng condition obtains. 

        For many conditions, we could evaluate the conditions directly in the
        rules that construct the condition signature.  However, by "converting"
        the original conditions into header values, we are guranteed that the
        rules that  construct the signature will be valid (e.g. won't try to
        include two different HeaderContainsMessageHeader parameters).

        The whole point of this entire exercise is to overcome (by creating a
        nearly unbounded, (combinatorially exploding) quantity of transport
        rules that work together) the annoying limitation that Exchange
        transport rules do not let you have a single rule that tests for, for
        instance, the presence of two header values (with AND logic).

    #>
    for($conditionIndex=0; $conditionIndex -lt $conditions.Count; $conditionIndex++){
        $transportRuleSpecs += @(
            @(
                @{Comments = "Selectively set positive-sense marker for condition $($conditionIndex)"}
                $conditions[$conditionIndex]
                @{
                    SetHeaderName  = "$($headerNamePrefixForPositiveMarker)$($conditionIndex)"
                    SetHeaderValue = $headerValueForPositiveMarker
                }
            ) | merge-hashtables
            $namesOfHeadersToBeRemovedDuringCleanup += "$($headerNamePrefixForPositiveMarker)$($conditionIndex)"
        )
    }


    if($false){
        <# We  do not need to explicitly set the condition signature to
        empty. We  can just assume that its  empty  when  we are working
        on condition 0. #>
        <# initialize the condition signature #>
        $transportRuleSpecs  += (@(
        @{Comments="initialize the condition signature to empty"}
        @{
            SetHeaderName  = $namesOfPartialSignatureHeaders[0]

            ##SetHeaderValue = ""
            <#  oops we can't set a header value to the empty string,
                but fortuantely we can set a header to a string
                containing a single space, which will work for our
                application (provided I adjust the relevant regex below
                so that we ignore spaces) 
            #>
            ##SetHeaderValue = " "
            <# Yes, but when we  set the ehader value to s ingle  string
                (or probabyl to any value consiting of  only spaces),
                this header is apparently removed after the transport
                rules are processed and before the message ends up in
                the destination mailbox.  Therefore,  I will use a dummy
                character.  any character will do as long is it is not a
                space and is not 0 and is not 1.
            #>
            SetHeaderValue = "w"
        
        }
        )  | merge-hashtables)
    }


    for($conditionIndex=0; $conditionIndex -lt $conditions.Count; $conditionIndex++){
        <#  Our goal is to append rules as necessary to
            trasnportRuleSpecs so that, after the message has flowed
            through the rules that we add, the value of the header
            $nameOfHeaderToContainConditionSignature will be modifed by
            appending a character -- 1 if thisCondition, else 0.  

            In other words, our ultimate goal is that we want the value
            of $nameOfHeaderToContainConditionSignature to be a string that
            is a sequence of characters, where character i reports the
            state of condition i: 0 for false and 1 for true. (We can
            then use subsequent rules look for any of several values (or
            values matching a regex pattern) to respond to any arbitrary
            state of truth or falseness for each of our conditions.
            (This whole thing is a hack to work around Exchange
            Transport Rules' lack of a way to have rule that tests
            whether (header value A is present AND header value B is
            present) (and will also be useful for other missing logical
            combinations --any arbitrary combination  pattern in fact.).

            Unfortunately, Exchange tranport rule actions provide no way
            to set the value of a header  to anything except a hardcoded
            value. There is no "appendToHeader" action for instance, and
            there is (as far as I can tell) no way to interpolate any
            dynamic value (like the existing value) in the value that
            you write to a header --  it's just a static hardcoded
            value.

            However, we should be able to acheive the desired behavior
            provided we are free to create huge numbers of transport
            rules; we can have one transport rule for every possible
            existing value of the header.

            But its even messier, because we can not, in a single rule,
            have a condition that is the logical union of two
            header-value rules.  

            For this test, we will assume that all of our conditions are
            headerContainsWords conditions.
        #>
        $conditionWhereThisConditionIsMarkedTrue = @{
            HeaderContainsMessageHeader = "$($headerNamePrefixForPositiveMarker)$($conditionIndex)"
            HeaderContainsWords         = $headerValueForPositiveMarker
        }

        foreach($partialConditionSignature in @(
            <#  every number from 0  up to and including
                2^$conditionIndex - 1, written as a
                $conditionIndex-digit binary number (but the -f operator
                does not properly handle printing in 0-digit form (which
                just means the empty string), so  we handle that one
                explicitly)
            #>
            0..((1 -shl $conditionIndex) - 1) |
            % {
                if($conditionIndex  -eq 0){""}
                else {"{0:b$($conditionIndex)}" -f $_ }
            }
        )){
            $conditionWherePartialConditionSignatureObtains = $(
                if($conditionIndex  -eq 0){@{}}
                else{
                    @{
                        ## HeaderMatchesMessageHeader  = $nameOfHeaderToContainConditionSignature
                        HeaderMatchesMessageHeader  = $namesOfPartialSignatureHeaders[$conditionIndex]
                        HeaderMatchesPatterns       = @(
                            <# evidently, Exchange regards "^\s*\s*`$" as an
                            invalid regex, so we adapt:#>
                            ##if($partialConditionSignature  -eq ""){"^w*`$"}
                            ##else  {"^w*$($partialConditionSignature)w*`$"}

                            if($partialConditionSignature  -eq ""){"^\s*`$"}
                            else  {"^\s*$($partialConditionSignature)\s*`$"}

                        )
                        <# we might get away doing this with HeaderContainsWords
                            instead -- I am just not sure that
                            HeaderContainsWords  
                            looks for whole words or partial words
                        #>
                    }
                }
            )

            $transportRuleSpecs  += @(
                @(
                    @{Comments  =  "for condition $($conditionIndex) not being marked true, append a 0 to the condition signature" }
                    $conditionWherePartialConditionSignatureObtains
                    
                    Get-NegatedTransportRuleCondition $conditionWhereThisConditionIsMarkedTrue
                    <#  WE could just omit the
                        `Get-NegatedTransportRuleCondition
                        $conditionWhereThisConditionIsMarkedTrue` and
                        blindly append a 0 to the signature.  This would
                        then be conditionally overwritten by the next
                        rule, which includes (the positive)
                        $conditionWhereThisConditionIsMarkedTrue  .  I
                        am leaving if in almost as a  test or for
                        symmetry  (and to  see if it improves the weird
                        ordering of trasnport  rules that occurs in the
                        output  of Get-MessageTraceDetail.
                    #>


                    @{
                        SetHeaderName  = $namesOfPartialSignatureHeaders[$conditionIndex + 1]
                        SetHeaderValue = "$($partialConditionSignature)0"
                    }
                ) | merge-hashtables
                if(-not ($namesOfPartialSignatureHeaders[$conditionIndex + 1]  -eq  $namesOfPartialSignatureHeaders[-1])){
                    $namesOfHeadersToBeRemovedDuringCleanup += $namesOfPartialSignatureHeaders[$conditionIndex + 1]
                }

                @(
                    @{Comments  =  "for condition $($conditionIndex) being marked true, append a 1 to the condition signature" }
                    $conditionWherePartialConditionSignatureObtains
                    $conditionWhereThisConditionIsMarkedTrue

                    @{
                        SetHeaderName  = $namesOfPartialSignatureHeaders[$conditionIndex + 1]
                        SetHeaderValue = "$($partialConditionSignature)1"
                    }
                ) | merge-hashtables
                if(-not ($namesOfPartialSignatureHeaders[$conditionIndex + 1]  -eq  $namesOfPartialSignatureHeaders[-1])){
                    $namesOfHeadersToBeRemovedDuringCleanup += $namesOfPartialSignatureHeaders[$conditionIndex + 1]
                }
            ) 
        }
    }
      

    if(-not $doNotCleanup){
        foreach($nameOfHeaderToBeRemoved in @($namesOfHeadersToBeRemovedDuringCleanup | select  -unique)){
            $transportRuleSpecs += @(     
                @(
                    @{Comments = "cleanup: remove a leftover header named  '$($nameOfHeaderToBeRemoved)'"}
                    @{
                        RemoveHeader  = $nameOfHeaderToBeRemoved
                    }
                ) | merge-hashtables

                $namesOfHeadersToBeRemovedDuringCleanup +=  $nameOfOurVersionHeader     
            )
        }
    }

    return $transportRuleSpecs
}

function Set-GroupNameMangling {
    <# 
        .DESCRIPTION
        ensures that the values of the identifiers of all distribution  groups
        do (or do not -- depending on $manglingDesired) start with the
        herein-hardcoded manglingPrefix.

        This is useful when you want to create a transport rule that refers to
        groups (or even create any transport rule (even one that has nothing to
        do with groups) when a group-referencing transport rule happens to
        already exist), which Exchange Online makes difficult: you run this
        function with -desiredMangling:$true to mangle the group names, make
        your modifications to the transport rules (using the unmangled smtp
        address of the group), then run this function again with
        -desiredMAngling:$false to unmangle the group names.

        This scheme will be a boon when you want to have a transport rule that
        has an SentTo predicate or a RedirectMesssageTo action that references a
        group, but I am not sure exactly how such a process will affect an
        attempt to make a transport rule that has an "is sent to a member of a
        group" (or similar).  In the invocation of New-TransportRule (or
        Set-TransportRule), you would have to use some identifier for the group
        that New-TransportRule (or Set-TransportRule) would accept (i.e. not
        throw an error about) while group names were mangled, and which would
        result in a transport rule that would give the desired behavior once
        group names had been unmangled.  I am hoping that we could use an
        identifier like the GUID, that is unaffected (and does not need to be
        affected) by the mangling process. The only question is whether Exchange
        would resolve the GUID  to an smtp address at the time of transport rule
        creation or, alternatively, at the time of transport-rule evalutation.
        If the former, then we'd have difficulty creating a transport rule  with
        an isSentToAMemberOf predicate (or similar).   (TODO:  figure out when
        exactly the string passed as the -SentTo or  -SentoToAMemberOf (or
        similar) parameter to NEw-TransportRule (or Set-TransportRule) is
        resolved to a known recipient -- does this happen at rule-creation time
        or at rule-evaluation time?).

        You can pretty-well work around the group-reference restriction (thereby
        eliminating the need for all of this name-mangling rigamarole) in the
        case of a SentTo predicate, by using a RecipientAddressMatchesPatterns
        predicate instead.  However, there does not seem to be any analagous
        workaround in the case of a RedirectMessageTo action or a BlindCopyTo
        action.  (TODO: experiment to confirm this  -- maybe wrapping the
        address in angle brackets or prefixing with "smtp:" or using a
        plus-address might do the trick.)

        TODO: We are currently (as of 2025-03-08-1336) only handling
        unifiedGroups.  We ought to extend this to other types of distribution
        group.

        TODO: We are currently (as of 2025-03-08-1337) probably not dealing with
        all possible $namesOfIdentifiers (i.e. the fields whose values you can
        pass as the -Identity parameter to Get-UnifiedGroup,  Get-Recipient,
        etc. (and other similar  Exchange Online Powershell functions) to return
        the object in question.  In practice, we only care about identifiers
        that might ever resemble an smtp address, because it is the smtp address
        of a group that we wish to insert into the definition of a transport
        rule (at least for my particular current application as of
        2025-03-08-1339).  

        For example, the "Name" property of a unified group.  Get-UnifiedGroup
        considers the "Name" property as one possible "Identity" of a
        unifedGroup, but we are not currently (as of 2025-03-08-1348) mangling
        the Name property asa part of our mangling process (mainly because
        Set-UnifiedGroup cannot modify the Name of a unified group (I suspect
        you'd have to use the Microsoft Graph API to do it)) 

        This name-mangling scheme might not work when applied to Microsoft 365
        Groups that have isAssignableToRole being true.  Such groups are strange
        objects, and are subject to some weird restrictions (e.g. not being able
        to modify the smtp address after creation -- which would of course
        prevent us from achieving complete name mangling, because the smtp
        address is one of the identifiers of a group).  I suspect that a lot of
        the counter-intutive restrictions with Microsoft 365 Groups (like the
        restrictions that apply to a group having isAssignableToRole being true,
        and the restriction that a Microsoft 365 Group can neither be a member
        of a group nor have a group as a member) are motivated by a concern for
        security.  The system seems to be designed with the goal of  eliminating
        any possibility of inadvertently granting administrative rights to a
        user (including the (administrative) right to grant administrative
        rights to other users); any group construct that is even remotely
        involved in conferring administrative rights (like a group having
        isAssignableToRole being true) is severely restricted.  These
        restrictions certainly interfere with intuitive usability of groups, and
        I wonder whether there might be some more elegant and intuitive way to
        achieve tight security.

        MAYBE TODO: allow control over which groups are processed, rather than
        blindly processing all groups.

        MAYBE TODO: allow control over the manglingPrefix, rather than using a
        built-in hardcoded value.

        MAYBE TODO [DONE 2025-03-08-1450]: After modifying the groups, wait
        until the changes sink in (i.e. wait until the old identifier values
        will no longer retrieve the group when passed as the -Identity paramter
        to Get-UnifiedGroup, Get-Recipient, and the similar Exchange Online
        Powershell functions.) If you mangle a group name and then immediately
        (within a few seconds) attempt to create a transport rule whose
        succesfull creation depends on the name mangling, the attempt to create
        the transport rule sometimes fails because the name-mangling has not
        completely propagated.

    #>



    <#  Comment from an early variation of this function:

        Exchange Online powershell (or maybe Exchange Online itself), prevents
        us from creating a transport rule that has either a SentTo condition or
        a RedirectMessageTo action that references a distribution group.
        However, Exchange Online is perfectly happy to have such a rule (once
        the rule exists), and the rule does behave as expected, and as desired
        in our application.  The only trick is how to convince Exchange Online
        to  let us create the rule in the first place.

        Therefore, we must contrive that, at the instant when we create the
        rule, no distribution group identified by our desired SentTo value or
        our desired RediretMessageTo value exists.   We can do this by
        temporarily ensuring that the email address in question does not belong
        to the group, either as a primary or a non-primary address.  We will do
        this by temporarily changing any matching address belonging to our group
        (or I suppose, more generally, any group, but in this case it suffices
        to look only at the group we're currently dealing with) by prepending
        $setasidePrefix .
    #>
            

    [CmdletBinding()]
    Param(
        [bool] $manglingDesired = $true
    )
    $manglingPrefix = "485247d-mangled-"

    $namesOfIdentifiers = @(
        'PrimarySmtpAddress'
        'DisplayName'
        'Alias'

        ##  'Name'
    )

    $unifiedGroupsToProcess = @(Get-UnifiedGroup -ResultSize:Unlimited)

    ##$identitiesWeWantToBeUnresolvable  = @()
    $desiredIdentityToGuidMap  = @{}

    foreach($unifiedGroup in $unifiedGroupsToProcess){
        write-information "now $($manglingDesired ? "mangling" : "unmangling") the group '$($unifiedGroup.PrimarySmtpAddress)'."
        
        $unmangledIdentity  =  @{}
        $mangledIdentity  =  @{}
        
        foreach($nameOfIdentifier  in  $namesOfIdentifiers){
            $match = [regex]::Match(
                <#### string input: #>
                ## ($(Get-UnifiedGroup -Identity $unifiedGroup.GUID).$nameOfIdentifier) ,
                <#  I can probably get away without re-looking-up the unified
                    group, since we just looked it up above, and haven't yet
                    modified it 
                #>
                ($unifiedGroup.$nameOfIdentifier),

                <#### string pattern: #>
                ## "(?i)^(?<prefix>(?:$([regex]::Escape($manglingPrefix)))*)(?<unmangledValue>.*)`$"
                ## "(?i)^(?<prefix>(?:$([regex]::Escape($manglingPrefix)))?)(?<unmangledValue>.*)`$"
                <#  It might make sense to detect arbitrarily many occurences of
                    the mangling prefix rather than only zero or one occurence
                    (asterisk vs. question mark in the "prefix" matching group
                    in the regex).  If  we detect arbitrarily many occurences,
                    then we can say that a value is mangled if and only if it
                    starts with the mangling prefix.

                    In  practice, it would probably suffice to detect only zero
                    or one occurences of the mangling prefix at the beginning of
                    the string (because what are the odds we'd ever have two
                    occurences by chance...).  However, I like detecting
                    arbitrarily many occurences of the mangling string because
                    it makes the logic cleaner to think about, and because I can
                    imagine things going haywire with the mangling process
                    (getting interrupted and having to restart, perhaps) such
                    that we accidentally insert two occurences of the mangling
                    prefix.  Detecting arbitrarily many occurences of the
                    mangling prefix will help correct such accidents on
                    subsequent runs.  Of course, it also means that we can never
                    legitimately have an (unmangled) identifier value thaat
                    starts with the mangling prefix.  But this is not a huge
                    loss, because the mangling prefix is, by design,  so weird
                    and obscure that you wouold never want to have a legitimate
                    identifier value that started with the mangling prefix.
                #>
                "(?i)^(?<prefix>(?:$([regex]::Escape($manglingPrefix)))*)(?<unmangledValue>.*)`$"
            )

            $unmangledValue  = $($match.Groups['unmangledValue'].Value)
            
            $unmangledIdentity[$nameOfIdentifier] = "$($unmangledValue)"
            $mangledIdentity[$nameOfIdentifier]   = "$($manglingPrefix)$($unmangledValue)"
        }

        $desiredIdentity   = $($manglingDesired  ?   $mangledIdentity :  $unmangledIdentity)
        $undesiredIdentity = $($manglingDesired  ? $unmangledIdentity :    $mangledIdentity)


        Set-UnifiedGroup -Identity $unifiedGroup.GUID  @desiredIdentity
        Set-UnifiedGroup -Identity $unifiedGroup.GUID  -EmailAddresses @{remove=@($undesiredIdentity.PrimarySmtpAddress)}
        ##$identitiesWeWantToBeUnresolvable += $undesiredIdentity

        foreach($value in $desiredIdentity.Values){
            $desiredIdentityToGuidMap[$value] = $unifiedGroup.GUID
        }
        foreach($value in $undesiredIdentity.Values){
            $desiredIdentityToGuidMap[$value] = $null
        }
    }

    $maximumAllowedWaitDuration = $(new-timespan -minutes 3)
    $holdOffDuration            = $(new-timespan -seconds 8)
    $extraWaitDuration          = $(new-timespan -seconds 5)
    $waitStartTime              = $(get-date)
    ##  write-information "waiting up to $($maximumAllowedWaitDuration) for there to be no unifiedGroup having identity '$($permanentPrimarySmtpAddress)'."
    while(
        ((get-date) -lt ($waitStartTime + $maximumAllowedWaitDuration))
    ){
        ##  $resolvableIdentifierValues = @(
        ##      @(
        ##          $identitiesWeWantToBeUnresolvable |
        ##          % {$_.Values} |
        ##          ? {$_} |
        ##          ?{
        ##              @(
        ##                  @(
        ##                      $(get-unifiedgroup -identity $_ -erroraction silentlycontinue)
        ##                      $(get-recipient -identity $_ -erroraction silentlycontinue)
        ##                  ) |? {$_}
        ##              )
        ##          }
        ##      )
        ##  )

        $actualIdentityToGuidMap = @{}
        $failingKeys = @()
        write-information "$(get-date -format o): evaluating resolvability of the identifiers."
        foreach($key in $desiredIdentityToGuidMap.Keys){
            $actualIdentityToGuidMap[$key] = $(
                $(
                    $(get-unifiedgroup -identity $key -erroraction silentlycontinue) ?? 
                    $(get-recipient -identity $key -erroraction silentlycontinue)
                ).GUID
            )
            if($desiredIdentityToGuidMap[$key] -ne $actualIdentityToGuidMap[$key]){
                $failingKeys += $key
            }
        }

        

        if(-not $failingKeys){
            write-information "$(get-date -format o): all identifiers, mangled and unmangled, have the desired resolvability.  Hooray."
            break
        }
        write-information (-join @(
            "$(get-date -format o): Unfortunately, the following $($failingKeys.Count) identifiers do not "
            "have the desired resolvability: "
            "$( $failingKeys  | sort | join-string -separator ", " )"
        ))
        write-information (-join @(
            "$(get-date -format o): waiting "
            ## "(until $(get-date ($waitStartTime + $maximumAllowedWaitDuration) -format o )) "
            "up to $($maximumAllowedWaitDuration) "
            "for the desired resolvability to obtain."
        ))
        start-sleep -duration $holdOffDuration

        <#  MAYBE TODO: throw an error (or at least a more attention-grabbing
            warning message) any of the $identitiesWeWantToBeUnresolvable are still
            resolvable after $maximumAllowedWaitDuration is up. 
        #>
        <#  MAYBE TODO [DONE]: check that all expected new identifiers resolve
            correctly to the expected group. 
        #>
    }
    start-sleep -duration $extraWaitDuration


}

Set-Alias Install-TransportRules  Install-TransportRule
function Install-TransportRule {
    <# 
        .DESCRIPTION
        Takes a sequence of $transportRuleSpecs.  A transportRuleSpec is a
        hasahtable that contains a partial set of arguments for
        New-TransportRule, omitting only Name, Priority, Enabled, and Mode.   A
        transportRuleSpec is the pure business of a transport rule -- the
        condition and the action -- and none of the metadata.

        Takes a rootPathOfTransportRules which is a path-style (i.e.
        slash-delimited) prefix for the names of transport rules.   We will
        regard every transport rule whose name is a subpath of
        rootPathOfTransportRules to be our business.  We will  delete any suich
        existing transport rules and create zero or more new transport rules
        whose names are in this rootPathOfTransportRules.

        MAYBE TODO: look at the existing transport rules and the to-be-installed
        transport rules and figure out the minimal set of groups that need to be
        mangled in order to allow the desired change to the transport rules to
        succeed. Then, only mangle/unmangle those groups.  This would reduce the
        wait time.
    #>

    [CmdletBinding()]
    Param(
        [string] $rootPath,

        [System.Collections.Generic.List[Hashtable]] $transportRuleSpecs = @(),

        [switch] $groupNameMangling = $false
    )
    if(-not $rootPath){$rootPath = "/$(new-guid)"}

    ##  $uniquePrefixForTransportRules    = "$(new-guid)"
    ##  $rootPath =  (@(
    ##      ""
    ##      $uniquePrefixForTransportRules
    ##  ) -join "/").ToLower()

    .{#  delete our existing transport rules 
        &{# delete our existing transport rules
            write-host "deleting our existing transport rules if any"
            $ourExistingTransportRules = @(
                Get-TransportRule -ResultSize "Unlimited"  |
                ? {
                    $_.Name  -match 
                    (-join @(
                        "(?i)^"
                        [regex]::Escape($rootPath)
                        "(`$|/).*"
                    ))
                }
            )
    
            write-information "deleting $($ourExistingTransportRules.Count) existing transport rules"


            $ourExistingTransportRules | 
            %{
                write-information "removing existing transport rule '$($_.Name)'."
                Remove-TransportRule -Confirm:$false -Identity $_
            }

            write-information "finished deleting our existing transport rules"
        }
    
    }  
    
    write-information  "creating $($transportRuleSpecs.Count) transport rules"
    if($transportRuleSpecs  -and  ($groupNameMangling)){
        write-information "mangling group names"
        Set-GroupNameMangling -manglingDesired:$true
    }
    $transportRuleIndex = 0
    foreach($transportRuleSpec in $transportRuleSpecs){
        @(
            @{
                #  ====== parameters that are neither condition nor action: ====== 
                Name = (@($rootPath;$transportRuleIndex) -join "/" )
                Priority              = $transportRuleIndex
                Enabled               = $True
                ## Comments              = ""
                Mode                  = "Enforce"
            } 
            $transportRuleSpec
            $commonCondition
        )|Merge-HashTables  |
        % {
            write-information "creating the transport rule '$($_['Name'])'"
            New-TransportRule @_
        } | out-null
        $transportRuleIndex += 1
    }
    if(
        ## $transportRuleSpecs  -and 
        <#  We are intentionally unmangling here even if transportRuleSpecs is
            empty. This helps ensure that running Install-TransportRules with
            noGroupMangling:$false will always (attempt to) leave groups
            unmangled.   This could help recover from  accidentally-leftover
            mangling in some situations.  the only downsideis the
            agonizingly-long time (on the order of 20 seconds per group) it can
            take to mangle (or unmangle) all the groups.
        #>

        <# Never mind -- I can't stand  the wait: #>
        $transportRuleSpecs  -and 

        ($groupNameMangling)
    ){

        write-information "unmangling group names"
        Set-GroupNameMangling -manglingDesired:$false
    }
    write-information  "finished creating transport rules"
}

function  New-UserFriendlyPassword {
    <# depends on the MlkPwgen powershell module (https://github.com/mkropat/MlkPwgen) #>
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [int] $Length = 29
    )

    $passwordPredicate = {-not ($_ -match "(?-i)^.*[01IiLlOo()^].*`$")}
    $complexPrefix = (-join @(
        New-Password -Length 1 -Upper -Predicate $passwordPredicate
        New-Password -Length 1 -Digits -Predicate $passwordPredicate
        '@'
    ))

    return (
        -join @(
            $complexPrefix

            New-PronounceablePassword -Predicate   $passwordPredicate -Length ($Length - $complexPrefix.Length) |
            % {$_.ToLower()}
        )
    )
}


function Convert-ToBase64EncodedCliXml {
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory=$true)]
        [Object] $inputObject
    )

    [System.Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes((
            $(
                switch('strategy2'){
                    strategy1 {
                        $(
                            $pathOfTemporaryClixmlFile = (join-path $env:temp "$(new-guid).xml")
                            Export-CliXml -Path $pathOfTemporaryClixmlFile -InputObject $inputObject | out-null
                            gc -raw $pathOfTemporaryClixmlFile 
                        )
                    }
                    strategy2 {
                        ConvertTo-CliXml -Depth 30 -InputObject $inputObject
                    }
                }
            )
        ))
    )
}

function Convert-FromBase64EncodedCliXml {
    [CmdletBinding()]
    [OutputType([Object])]
    Param(
        [Parameter(Mandatory=$true)]
        [String] $base64EncodedCliXml
    )
    $cliXml = (
        [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String($base64EncodedCliXml)
        )
    )

    switch('strategy2'){
        strategy1 {
            $pathOfTemporaryClixmlFile = (join-path $env:temp "$(new-guid).xml")
            Set-Content -Path $pathOfTemporaryClixmlFile -Value $cliXml
            $(Import-Clixml -Path $pathOfTemporaryClixmlFile)
        }
        strategy2 {
            ConvertFrom-CliXml -InputObject $cliXml
        }
    }
}

function Get-AllMigrationUserStatistics {
    return @(
        Get-MigrationUser -ResultSize:unlimited |
        sort Identity |
        %{Get-MigrationUserStatistics -IncludeReport -IncludeSkippedItems -IncludeCopilotReport -Identity $_}
    )
}

function reportOnLastMatchingMessageTrace([scriptblock] $predicate){
    $lookaheadDuration = (New-Timespan -seconds 200)
    
    
    $messageTraces =  @(
        Get-MessageTrace -StartDate (Get-Date).AddHours(-48) -EndDate (Get-Date).AddMinutes(60) 
    )

    $messageTraceIdOfInterest = $(
        $messageTraces | 
        ? { & $predicate $_ } |
        sort Received | 
        select -last 1 |
        select -expand MessageTraceId
    )
    if(-not $messageTraceIdOfInterest){
        write-output  "we found no message traces of interest"
        return
    }


    $messageTracesOfInterest = @(
        $messageTraces |
        ? {($_.MessageTraceId -eq  $messageTraceIdOfInterest)} 
    )

    
    $timeOfFirstNotice = $(
        $messageTracesOfInterest |
        select -expand StartDate |
        sort |
        select -first 1
    )

    $possiblyRelatedMessageTraces = @(
        $messageTraces |
        ? {
            (-not ($_.MessageTraceId -eq  $messageTraceIdOfInterest ))  -and
            (
                ($_.Received -gt $timeOfFirstNotice) -and
                ($_.Received -lt ($timeOfFirstNotice.Add($lookaheadDuration)))
            )
        } 
    )


    $senderAddresses =  @(
        $messageTracesOfInterest |
        select -expand SenderAddress |
        select -unique | 
        sort
    )

    $recipientAddresses =  @(
        $messageTracesOfInterest |
        select -expand RecipientAddress |
        select -unique | 
        sort
    )

    "messageTraceIdOfInterest: $($messageTraceIdOfInterest)"
    "senderAddresses: $($senderAddresses)"
    "recipientAddresses: $($recipientAddresses)"

    function getFormattedDateTime([system.datetime] $utcDateTime){
        ##"$(([datetimeoffset] ([datetime]::SpecifyKind($utcDateTime,'Utc'))).ToLocalTime())"
        "{0:o}"  -f ([datetimeoffset] ([datetime]::SpecifyKind($utcDateTime,'Utc'))).ToLocalTime()
    }

    $selectedPropertiesOfMessageTrace  =  @(

        'MessageTraceId'
        'SenderAddress'
        'RecipientAddress'
        ##  'Index'
        @{n='Received'; e={getFormattedDateTime $_.Received}}
        ## @{n='StartDate'; e={getFormattedDateTime $_.StartDate}}
        ## @{n='EndDate'; e={getFormattedDateTime $_.EndDate}}
        'MessageId'

        'Status'

        'Subject'
    )

    @(
        $messageTracesOfInterest
        $possiblyRelatedMessageTraces
    ) |
    sort Received |
    select -property $selectedPropertiesOfMessageTrace |
    ft -auto





    foreach($messageTrace in @($messageTracesOfInterest | sort  Received)){
        "="*80
        "messageTrace: "
        ##$messageTrace | select *  -Exclude PSComputerName,RunspaceId,PSShowComputerName,Index,StartDate,EndDate | fl
        
        $messageTrace |
        select -property $selectedPropertiesOfMessageTrace  |
        fl

        "messageTraceDetails: "
        Get-MessageTraceDetail -MessageTraceId  $messageTrace.MessageTraceId -RecipientAddress $messageTrace.RecipientAddress | ## sort Date |
        select @(
            ##'Date'
            @{n='Date'; e={getFormattedDateTime $_.Date}}
            'Event'
            'Action'
            @{
                n="Sequence`nNumber"
                e={([xml]  $_.Data).root.MEP |? {$_.Name -eq  'SequenceNumber'} |%  {$_.Long} }
            }
            @{
                n="Rcpt`nCount"
                e={([xml]  $_.Data).root.MEP |? {$_.Name -eq  'RcptCount'} |%  {$_.Integer} }
            }
            @{
                n='SourceContext'
                e={([xml]  $_.Data).root.MEP |? {$_.Name -eq  'SourceContext'} |%  {$_.String} }
            }
            'Detail'
            
        ) |
        ft -auto
    }
}

function Get-InternetConnectedIpAddress {
    <#  Gets all ip addresses assigned to a network adapter on this computer that
        appear to be usable for Internet traffic (according to the results of
        Get-NEtConnectionProfile)
    #>
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    param(

    )

    get-netconnectionprofile |
    % {
        ## 'Internet' -in @($_.IPv4Connectivity;$_.IPv6Connectivity) 
        if($_.IPv4Connectivity -eq 'Internet'){get-netipaddress -InterfaceIndex $_.InterfaceIndex -AddressFamily:IPv4 }
        if($_.IPv6Connectivity -eq 'Internet'){get-netipaddress -InterfaceIndex $_.InterfaceIndex -AddressFamily:IPv6 }
    } |
    ? {$_.AddressState -eq "Preferred"} |
    ? { -not [System.Net.IPAddress]::Parse($_.ToString()).IsIPv6LinkLocal} |
    ? { -not [System.Net.IPAddress]::Parse($_.ToString()).IsIPv6SiteLocal} |
    sort
}

function getPartsOfPathOfMailboxFolder([string] $absolutePathOfMailboxFolder){
    <#  For example, pathParts of ":\Inbox\automated_crap\crashplan_automated_crap" is
        @('Inbox'; 'automated_crap'; 'crashplan_automated_crap')
    #>
    $parts = [String[]] @(
        $absolutePathOfThisPart = $absolutePathOfMailboxFolder
        while(-not (
            ($absolutePathOfThisPart -eq '')  -or
            ($absolutePathOfThisPart -eq '\')  -or
            ($absolutePathOfThisPart -eq '/')  -or
            ($absolutePathOfThisPart -match  "^[^\\\/:]*:(\\|\/|)`$") 
        )){
            ##$thisPart = split-path -leaf $absolutePathOfThisPart
            $thisPart = $absolutePathOfThisPart |% {[System.IO.Path]::TrimEndingDirectorySeparator($_)} |% {[System.IO.Path]::GetFileName( $_)}|% {[System.IO.Path]::TrimEndingDirectorySeparator($_)} 
            ##write-information "pushing: '$($thisPart)'"

            $thisPart
            ##$absolutePathOfThisPart  =  split-path -parent $absolutePathOfThisPart
            $absolutePathOfThisPart  = $absolutePathOfThisPart  |% {[System.IO.Path]::TrimEndingDirectorySeparator($_)} |% {[System.IO.Path]::GetDirectoryName( $_)}|% {[System.IO.Path]::TrimEndingDirectorySeparator($_)} 

        }
    )

    [array]::Reverse($parts)

    return $parts
}

function getOrCreateMailboxFolder([string] $absolutePathOfMailboxFolder){
    <# get a mailobx folder, creating it if it does not already exist #>

    $folder  = Get-MailboxFolder -Identity ":\"
    foreach($part in (getPartsOfPathOfMailboxFolder $absolutePathOfMailboxFolder)){
        $folder = $(
            ##(Get-MailboxFolder -Identity (join-path $folder.Identity $part)) ??
            (Get-MailboxFolder -Identity ([System.IO.Path]::Join($folder.Identity,$part))  -erroraction SilentlyContinue ) ??
            (
                New-MailboxFolder -Parent $folder.Identity -Name $part
            )
        )
    }
    return $folder
}
