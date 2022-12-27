#!pwsh
# [System.Reflection.Assembly]::Load("System.IdentityModel.Tokens.Jwt")
# [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
# [System.Reflection.Assembly]::LoadFrom("C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\System.IdentityModel.Tokens.Jwt.dll")
# [System.Reflection.Assembly]::LoadFrom("C:\Users\Admin\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.1.0\netCore\System.IdentityModel.Tokens.Jwt.dll")
# $ErrorActionPreference = "Break"

# try {
#     # Get-Item "C:\772fbe3753d54c15a35c8d8ee9d2f477" -ErrorAction Stop 2> $null
#     Get-Item "C:\772fbe3753d54c15a35c8d8ee9d2f477" -ErrorAction Stop
# } catch {
#     Write-Host "we are catching the error: $_"
# } finally {
#     # $ErrorActionPreference = "Break"
# }
# Write-Host "`$ErrorActionPreference  is $ErrorActionPreference "


Remove-Module neil-utility1 -ErrorAction SilentlyContinue
Import-Module neil-utility1

# [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll.setaside"))
# Import-Module (join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/Microsoft.IdentityModel.Logging.dll")
# Import-Module (join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/Microsoft.IdentityModel.Tokens.dll")
# [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/Microsoft.IdentityModel.Logging.dll"))
# [System.Reflection.Assembly]::LoadFrom((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/Microsoft.IdentityModel.Tokens.dll"))
# Disconnect-MgGraph 2> $null
# connectToOffice365 -bitwardenItemIdOfTheConfiguration "autoscaninc.com microsoftGraphManagement"
# connectToOffice365 -primaryDomainName "autoscaninc.com"

# doUglyHackToFixDependencyHellFor_System_IdentityModel_Tokens_Jwt
# Import-Module ExchangeOnlineManagement
# Disconnect-ExchangeOnline -confirm:0 
forceExchangeModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt

$primaryDomainName = "autoscaninc.com"
# $primaryDomainName = "lobergroofing.com"

$doInitialSetup = $true

if($doInitialSetup){
    # for the initial setup, microsoft.grpah version 1.19 cannot succesfully use
    # version 6.21.0.0 of the System.IdentityModel.Tokens.Jwt assembly that
    # ExchangeOnlineMAnagementModule uses. so, for initial setup, we have to
    # ensure that Microsfot.Graph's preferred version of this assembly is
    # loaded. But then, for normal operation, we need to have
    # ExchangeOnlineManagement's version of the assemlby loaded, because
    # ExchangeOnlineManagement module will not work with Graph's preferred
    # version of the assembly.  They don't call it dll hell for nothing.
    forceGraphModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt
    $( bw sync )

    # &{
    #     getBitwardenItem "$($primaryDomainName.Trim().ToLower()) companyParameters"  -ErrorAction SilentlyContinue 2> $null;
    #     getBitwardenItem "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement"  -ErrorAction SilentlyContinue 2> $null;
    # } | where-object {$_} | foreach-object { bw delete item $_['id'] -ErrorAction SilentlyContinue }
    # try { bw delete item (getBitwardenItem "$($primaryDomainName.Trim().ToLower()) companyParameters" )['id'] } catch {}
    # try { bw delete item (getBitwardenItem "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" )['id'] } catch {}

    $existingBitwardenItems = @(
        $(
            "$($primaryDomainName.Trim().ToLower()) companyParameters" 
            "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
        ) |  % { 
            bw --nointeraction --raw list items --search $_ | ConvertFrom-Json -AsHashtable
        } 
    )
    
    
    $existingBitwardenItems| % {
        & {
            $private:ErrorActionPreference = "SilentlyContinue"
            write-host "errorActionPreference is $ErrorActionPreference"
            Write-Host "deleting existing bitwarden item `"$($_['name'])`" (id=$($_['id']))"
            bw delete item $_['id']
        } $_
    }
    write-host "errorActionPreference is $ErrorActionPreference"
    connectToOffice365 -tenantIdHint $primaryDomainName -makeNewConfiguration
} else {
    forceExchangeModuleToLoadItsVersionOf_System_IdentityModel_Tokens_Jwt
    connectToOffice365 -primaryDomainName $primaryDomainName
}


Write-Host "ready"

return


grep -E -e "System.IdentityModel.Tokens.Jwt" -inHr  'C:\work\msgraph-sdk-powershell'/*.cs  | cut -c -150 | grep ".cs"

#%%
[System.AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object {$_.FullName -match "^System.IdentityModel.Tokens.Jwt\b.*`$" } |
    Sort-Object -Property FullName |
    Select FullName, Location

#%%    
$x | fl
$x | get-member
$x.GetModules()
$x.ManifestModule | fl
#%%

$Error

[Microsoft.IdentityModel.Tokens]


#%%
$x = [System.Reflection.Assembly]::LoadFile((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll"))
$y = [System.Reflection.Assembly]::LoadFile((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
$z = [System.Reflection.Assembly]::LoadFile((join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Microsoft.Graph.Authentication.dll"))

$xx = [System.Reflection.Assembly]::Load($x.GetName())
$xx = [System.Reflection.Assembly]::Load($x.FullName)
cd (Split-Path $x.Location)
$xx = [System.Reflection.Assembly]::Load($x.Location)
$yy = [System.Reflection.Assembly]::Load($y.GetName())
$zz = [System.Reflection.Assembly]::Load($z.GetName())

$alc2 = new-object "System.Runtime.Loader.AssemblyLoadContext" "alc2",$True
$xxx = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyName($x.GetName())
$xxx = $alc2.LoadFromAssemblyName($x.GetName())
$xxx = $alc2.LoadFromAssemblyName($y.GetName())

$xxx = $alc2.LoadFromAssemblyPath($x.Location)
$yyy = $alc2.LoadFromAssemblyPath($y.Location)
$zzz = $alc2.LoadFromAssemblyPath($z.Location)
$a = $alc2.LoadFromAssemblyPath([System.Reflection.Assembly].Module.Assembly.Location)
$a = 

$alc2.Assemblies | select FullName, Location

[System.Reflection.Assembly].Module.FullyQualifiedName

Import-Module ExchangeOnlineManagement

$x | fl
$y | fl
$y.GetName() | fl

$x.FullName.GetType()
# $xx = [System.Reflection.Assembly]::Load($x.FullName)

@($x.GetReferencedAssemblies())[0].GetType().FullName
@($x.GetReferencedAssemblies())[0] | get-member
$z | fl
$z.GetName() | fl
#%%
Import-Module Microsoft.Graph.Authentication
[Microsoft.Graph.PowerShell.Authentication.Utilities.DependencyAssemblyResolver] | fl
$z.GetReferencedAssemblies() | fl
[System.IdentityModel.Tokens.Jwt.JwtConstants].Module
$x.GetModules()[0].GetTypes().FullName

[System.Runtime.Loader.AssemblyLoadContext]::Default.Assemblies

[System.Runtime.Loader.AssemblyLoadContext]::Default | fl

[System.AppContext]::BaseDirectory
[System.AppContext]::TargetFrameworkName

[System.AppDomain]::CurrentDomain.BaseDirectory
[System.AppDomain]::CurrentDomain.DynamicDirectory
[System.AppDomain]::CurrentDomain.FriendlyName
[System.AppDomain]::CurrentDomain.RelativeSearchPath
[System.AppDomain]::CurrentDomain.ReflectionOnlyGetAssemblies()
[System.AppDomain]::CurrentDomain.SetupInformation | fl

#%%

explorer "/select,$(join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")"
explorer "/select,$(join-path (Get-InstalledModule "Microsoft.Graph.Authentication").InstalledLocation "Dependencies/System.IdentityModel.Tokens.Jwt.dll")"

#%%

bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) companyParameters"  | 
    ConvertFrom-Json -AsHashtable
#%%

$x = @(
    bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) companyParameters"  | 
        ConvertFrom-Json -AsHashtable
)
$x.GetType().FullNAme
$x[0].GetType().FullNAme
$x.Length
#%%

$x = (
    bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) companyParameters"  | 
        ConvertFrom-Json -AsHashtable
)
$x.GetType().FullNAme
$x.Length
# (["$($x.GetType().FullName)"] $x).Length
(,([System.Management.Automation.OrderedHashtable] $x)).Length

#%%
$x = @(
    
    # $(
    #     # bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) companyParameters" 
    #     # bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
    #     ""
    #     "[null,null]"
    #     "[3,4]"
    #     "[66]"
    # ) | ConvertFrom-Json -AsHashtable

    $(
        # bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) companyParameters" 
        # bw --nointeraction --raw list items --search "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
        "[]"
        "[3,4]"
        "[66]"
    ) |  % {$_ | ConvertFrom-Json -AsHashtable}

    $(
        "$($primaryDomainName.Trim().ToLower()) companyParameters" 
        "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
    ) |  % {bw --nointeraction --raw list items --search $_ | ConvertFrom-Json -AsHashtable}

   ,  @( "[44,55]" | ConvertFrom-Json -AsHashtable)

    5
    6
    7
    $(
        1
        2
    )
    $(
        1
        2
    )
)
$x.GetType().FullName
$x[0].GetType().FullName
$x.Length
$x

#%%
$x = @(
    $(
        "$($primaryDomainName.Trim().ToLower()) companyParameters" 
        "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
    ) |  % { 
        bw --nointeraction --raw list items --search $_ | ConvertFrom-Json -AsHashtable
    }
)
$x.GetType().FullName
$x[0].GetType().FullName
$x.Length
# $x
#%%

    $(
        "$($primaryDomainName.Trim().ToLower()) companyParameters" 
        "$($primaryDomainName.Trim().ToLower()) microsoftGraphManagement" 
    ) |  % { 
        bw --nointeraction --raw list items --search $_ | ConvertFrom-Json -AsHashtable
    } | % {
         bw delete item $_['id'] -ErrorAction SilentlyContinue 
    }



#%%
@(
    "" 
    "[null,null]"
    # "[3,4]"
    # "[66]"
) | % {$_ | ConvertFrom-Json -AsHashtable}
#%%
@(
    "" 
    "[null,null]"
    "[3,4]"
    # "[66]"
) | ConvertFrom-Json -AsHashtable
#%%
@(
    "" 
    "[null,null]"
    "[3,4]"
    # "[66]"
) | % {$_ | ConvertFrom-Json -AsHashtable}
#%%

$x = @(
    "" 
    "[null,null]"
    "[3,4]"
    # "[66]"
) 
$x | ConvertFrom-Json -AsHashtable

# %%
$y = [System.Reflection.Assembly]::LoadFile((join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll"))
$y | fl
$y | get-member
$y.GetModules()
$y.GetName() | fl



#%%
$x = $y.GetReferencedAssemblies() | % {
    (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyName($_)
}
$x
#%%
$pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file =  (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")

$s = @{

    rootAssembly = (
        # [System.Reflection.Assembly]::LoadFile($pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file)


        (
            new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True
        ).LoadFromAssemblyPath($pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file)
    )

    filter = { 
        Test-SubPath -ChildPath $_.Location -ParentPath  (
                Split-Path $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file -Parent
            )
    }

    pathHints = @(
        Split-Path $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file -Parent
    )


}; $x = getReferencedAssembliesRecursivelyForReflection @s 


$x.Length
$x | Sort-Object -Property Location | Select FullName, Location

#%%

# Test-SubPath -ChildPath 'C:\NonExistentFolder\NonExistentFile.txt' -ParentPath 'C:\NonexistentFolder'

[System.Runtime.Loader.AssemblyLoadContext]::Default.GetType().FullName
(new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).GetType().FullName

(new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).GetType() | fl
(new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).GetType().AssemblyQualifiedName
(new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).GetType().GetType().FullName
[System.Runtime.Loader.AssemblyLoadContext]::Default.GetType() | fl
[System.Runtime.Loader.AssemblyLoadContext]::Default| get-member

[System.AppContext]::GetData("APP_PATHS")
[System.AppContext]::GetData("APP_CONTEXT_DEPS_FILES")
[System.AppContext]::GetData("TRUSTED_PLATFORM_ASSEMBLIES") -split ";"

Import-Module (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")
Import-Module (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll")

#%% 
@(
    [System.Runtime.Loader.AssemblyLoadContext]::Default.GetType().FullName

    [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext( 
        [System.Reflection.Assembly]::LoadFile(
            (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")
        )
    ).GetType().FullName

    [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext( 
        (new-object "System.Runtime.Loader.AssemblyLoadContext" "asdfgasgafhg",$True).LoadFromAssemblyPath(
            (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")
        )
    ).GetType().FullName
)
##>>>   System.Runtime.Loader.DefaultAssemblyLoadContext
##>>>   System.Runtime.Loader.IndividualAssemblyLoadContext
##>>>   System.Runtime.Loader.AssemblyLoadContext

#%%
$pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file =  (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")
$x = [System.Reflection.Assembly]::LoadFile(
        $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file
    )

$alc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($x)
Write-Output "initially: "
$alc.Assemblies
$alc.LoadFromAssemblyPath(
    (join-path (split-path $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file -Parent) "Microsoft.IdentityModel.Logging.dll")
)
Write-Output "then: "
$alc.Assemblies

#%%
$(
    $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file =  (join-path (Get-InstalledModule "ExchangeOnlineManagement").InstalledLocation "netCore/System.IdentityModel.Tokens.Jwt.dll")
    $x = [System.Reflection.Assembly]::LoadFile(
            $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file
        )

    
    Write-Output "`ncheckpoint 1: "
    $alc.Assemblies

    $y = [System.Reflection.Assembly]::LoadFile(
        (join-path (split-path $pathOfExchange_System_IdentityModel_Tokens_Jwt_dll_file -Parent) "Microsoft.IdentityModel.Logging.dll")
    )

    [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($x) -eq [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($y)

    $alc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($x)

    Write-Output "`ncheckpoint 2: "
    $alc.Assemblies

    $alc.LoadFromAssemblyPath(
        $y.Location
    ) 1> $null

    Write-Output "`ncheckpoint 3:"
    $alc.Assemblies | Select FullName, Location
)

#%%
$alc.Name

& {

}

#%%
function foo1 {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # [String] $arg1,
        # [String] $arg2
        [Parameter(Position=0, ValueFromRemainingArguments)]
         $remaining
    )

    @(
        "args ($(@($remaining).Count)):"
        for($i=0; $i -lt @($remaining).Count; $i++){
            "    arg$($i) ($(if($null -eq @($remaining)[$i]){"(null)"} else { @($remaining)[$i].GetType().FullName})): $(@($remaining)[$i])"
        }

    ) -join "`n"
}

function splat {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory, 
            ValueFromPipeline
        )] 
        [String]
        $nameOfFunction,

        # [Parameter(ValueFromRemainingArguments)]
        # $remaining

        
        # [Parameter()]
        # [HashTable]
        # $hashTable = @{},

                
        [Parameter()]
        [Array]
        $array = @()

    )

    Write-Host "nameOfFunction: $nameOfFunction"
    # Write-Host "remaining: ($($remaining.GetType().FullName)) $($remaining)"
    # Write-Host "hashTable: ($($hashTable.GetType().FullName)) $($hashTable)"
    Write-Host "array: ($($array.GetType().FullName)) $($array)"
    
    # & $nameOfFunction $remaining

    # & $nameOfFunction $remaining
    
    # [Hashtable] $x = ([Hashtable] @($remaining)[0])
    # & $nameOfFunction @x

    # $x = $($remaining)

    # & $nameOfFunction @x
    # & $nameOfFunction @hashTable @array

    # & $nameOfFunction @array

    $s = $($array)
    & $nameOfFunction @s

}

function splat2 {
    # [CmdletBinding()]
    
    process {
        if($args.Count -eq 0){
            $s = @()
        } else {
            $s = @($args)[0]
        }
        Write-Host "`$_ ($($_.GetType().FullName)): $($_)"

        & $_ @s
    }

}

#%%

{foo1} | splat @{
    arg1 = "a"
    arg2 = "b"
}
#%%

splat "foo1" @{
    arg1 = "a"
    arg2 = "b"
}

splat "foo1" @(22)
splat "foo1" 22

#%%

$u =     @{
    black = "bad"
    white = "good"
}

foo1 @u
foo1 @$("u")
foo1 "u"
foo1 "@u"

foo1(22,33,44)
foo1 (,@(22,33,44))

foo1 @{
    black = "bad"
    white = "good"
}

#%%
@(&{
    black = "bad"
    white = "good"
})

#%%

$t = @(
    33,
    @{
        black = "bad"
        white = "good"
    }
)



#%%

"foo1" | splat2     @{
    black = "bad"
    white = "good"
}

"foo1" | splat2  @(33; 44; 55;)

{foo1} | splat2  @(33; 44; 55;)

#%%

foo1

$s = @{
    arg1 = "a"
    arg2 = 44
}
foo1 @s
foo1 @ s
foo1 (& "@s")
foo1 @ "s"

foo1 | splat @{
    arg1 = "a"
    arg2 = "b"
}

@s
#%%
foo1 @@{
    arg1 = "a"
    arg2 = "b"
}