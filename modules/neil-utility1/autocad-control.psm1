#!pwsh
<#
    commands for interacting with AutoCAD's COM automation interface.

    As an example of a few ideas about how to use this, see
    [https://gitlab.com/neiljackson1984/2020-08-13_219004_shaffer/-/raw/34d945d87f3c0c37408b5ddf39d569376283f79f/shaffer_process_notes.ps1].

    
#>

&{  # load several useful AutoCAD assemblies (dll files) into memory,
    # mainly so that we can look up enum values and use intellisense.
    #
    # I am not sure it's a great idea to be doing this automatically upon
    # loading this module.
    #
    # Especially, if I am importing this module implicityl all the time, it is
    # heavy-handed to have these assemblies loaded into memory, when, in many
    # cases, I am not doing anything at all with AutoCAD.  I am not sure the
    # best answer to this.
    #
    #
    # especially because the below logic relies on the main AutoCAD executable
    # file, named "acad.exe", to be available on the path, in order to find the
    # paths of the dlls, and acad.exe might not be accessible on the path.
    gci -recurse -file (split-path (get-command acad).Path -parent) -include @(
        "AcDbMgd.dll"
        "AcMgd.dll"
        "AcCoreMgd.dll"
        "Autodesk.AutoCAD.Interop.Common.dll"
        "Autodesk.AutoCAD.Interop.dll"
    ) | 
    select -expand fullname |
    % { [System.Reflection.Assembly]::LoadFrom($_) } |
    out-null
}


Set-Alias awaitQuiescence awaitAutocadQuiescence
Set-Alias awaitQuiescense awaitAutocadQuiescence
Set-Alias awaitAutocadQuiescense awaitAutocadQuiescence
function awaitAutocadQuiescence($acad){
    while(
        -not $(
            try{
                $acad.GetAcadState().IsQuiescent
            } catch {
                write-information "encountered exception while awaiting quiescence: $($_)."
                $false
            }
        )
    ){
        write-information "awaiting quiescence"; Start-Sleep -Seconds 2
    }
}

function tryToCloseDrawing1($acad){
    try{
        awaitQuiescence($acad)
        write-information "`$acad.Documents.Count: $($acad.Documents.Count)"
        $acad.Documents['Drawing1.dwg'] |% {$_.Close()}
        write-information "`$acad.Documents.Count: $($acad.Documents.Count)"
        
    } catch {
        write-information "encountered an error trying to close Drawing1.dwg: $($_)"
    } finally {
        awaitQuiescence($acad)
    }
}

set-alias getDocument Get-AutocadDocument
function Get-AutocadDocument([Object] $acad, [String] $pathOfDwgFile){
    # this is just about like $acad.Documents.Open(), except
    # that we check if the file is already opened and return the already-opened 
    # document if it is.
    $existingDocumentCandidates = @(
        $acad.Documents | ?{
            try{
                (resolve-path $_.FullName).Path -eq (resolve-path $pathOfDwgFile).Path
            } catch {

            }
        }
    )

    if($existingDocumentCandidates.Count -eq 1){
        write-information "using already open document: $($pathOfDwgFile)"
        return $existingDocumentCandidates[0]
    } else {
        write-information "opening: $($pathOfDwgFile)"
        $document = $acad.Documents.Open("$($pathOfDwgFile)")
        awaitQuiescence($acad)
        return $document
    }
}

set-alias getAcad Get-AutocadComObject
set-alias getAutocadComObject Get-AutocadComObject
function Get-AutocadComObject{

    [CmdletBinding()]
    param(
        [string] $product
    )

    <#
        try to get existing acad com object.  
        In the case where there is already an existing object, we'll ignore the
        $product argument and blindly assume that we are already in the desired
        mode.
        https://renenyffenegger.ch/notes/Microsoft/dot-net/namespaces-classes/System/Runtime/InteropServices/Marshal/GetActiveObject

        It probably makes sense to maintain the "Existing"  acad object in a
        module-scoped variable, and return that if it exists and is valid.
    #>
    
    add-type -typeDefinition (
        @(
            'using System;                                                        '
            'using System.Runtime.InteropServices;                                '
            '                                                                     '
            'namespace TQ84 {                                                     '
            '                                                                     '
            '   public class COM {                                                '
            '                                                                     '
            '     [DllImport("oleaut32.dll", PreserveSig=false)]                  '
            '      static extern void GetActiveObject(                            '
            '                                            ref Guid   rclsid,       '
            '                                                IntPtr pvReserved,   '
            '        [MarshalAs(UnmanagedType.IUnknown)] out Object ppunk         '
            '      );                                                             '
            '                                                                     '
            '     [DllImport("ole32.dll")]                                        '
            '      static extern int CLSIDFromProgID(                             '
            '         [MarshalAs(UnmanagedType.LPWStr)]      string lpszProgID,   '
            '                                            out Guid   pclsid        '
            '      );                                                             '
            '                                                                     '
            '      public static object getActiveObject(string progId) {          '
            '         Guid clsid;                                                 '
            '         CLSIDFromProgID(progId, out clsid);                         '
            '                                                                     '
            '         object obj;                                                 '
            '         GetActiveObject(ref clsid, IntPtr.Zero, out obj);           '
            '                                                                     '
            '         return obj;                                                 '
            '      }                                                              '
            '   }                                                                 '
            '}                                                                    '
        ) -join "`n"
    )
    try{
        $acad = [TQ84.COM]::getActiveObject('AutoCAD.Application')  
    } catch {
        $acad = $null
    }
            
    if($acad){
        write-verbose "using existing acad."
    } else {
        write-verbose "creating new acad."
        
        
        taskkill /t /f /im acad.exe 2>$null | out-null
        taskkill /t /f /im accoreconsole.exe 2>$null | out-null
        # accoreconsole.exe

        # set the LastLaunchedProduct registry value in order to force the
        # NEw-Object call below to launch acad in our desired product mode (e.g.
        # PLNT3D for plant 3d).
        Get-ChildItem -Path "registry::HKEY_CURRENT_USER\Software\Autodesk\Autocad" |
            ? {$_.PSChildName -match '(?-i)^R\d+(\.\d+)?$'} |  
            % {
                @{
                    Path    = $_.PSPath 
                    Name    = "LastLaunchedProduct" 
                    Value   = $product # "PLNT3D" 
                    Type    = ([Microsoft.Win32.RegistryValueKind]::String)
                } |% {Set-ItemProperty @_}
            } |
            Out-Null
        # it's overkill to do this for all autocad versions, but it gets the job done.

        # we had started AutoCAD with the /product PLANT3D (spelling?) option once before, so 
        # the below call to New-Object was causing acad to open in plant3d mode (which is a good thing for this project.)

        # https://devblogs.microsoft.com/powershell/getobject/

        $acad = New-Object -ComObject "AutoCAD.Application"; awaitQuiescence($acad)
        # $acad = [System.Runtime.Interopservices.Marshal]::GetActiveObject("AutoCAD.Application")

        #%%
        # $acad.Visible = $false;         awaitQuiescence($acad)
        # .Visible is a read-only propertyt.


    }

    return $acad
}

function getXRecordData($xRecord){
    [OutputType([Object])]
    $xRecordDataTypeRef = ([ref] (New-Object "Object"))
    $xRecordDataValueRef = ([ref] (New-Object "Object"))
    $xRecord.GetXRecordData($xRecordDataTypeRef, $xRecordDataValueRef) | Out-Null
    # return @(
    #         $xRecordDataTypeRef.Value
    #         $xRecordDataValueRef.Value
    #     )
    return $xRecordDataValueRef.Value
}

function getXData($acadEntity, [String] $appName=""){
    [OutputType([Object[]])]
    $xDataTypeRef = ([ref] (New-Object "Object"))
    $xDataValueRef = ([ref] (New-Object "Object"))
    $acadEntity.GetXData($appName, $xDataTypeRef, $xDataValueRef ) | Out-Null

    return [Object[]] $xDataValueRef.Value
}

function getXDataAsHashTable($acadEntity){
    # return a hashtable in which the keys are the names of the registered applications and the values are the corresponding array of 
    # xdata values.  Omit keys for whcih there is no xdata.

    $xDataHashTable = @{}

    foreach( $appName in ( [String[]] @($acadEntity.Document.RegisteredApplications |% {$_.Name})) ){
        $xDataArray = getXData -acadEntity $acadEntity -appName $appName
        if($xDataArray.Count -gt 0){
            $xDataHashTable[$appName] = $xDataArray
        }
    }

    return $xDataHashTable
}

Set-Alias setSelection Set-AutocadSelection
function Set-AutocadSelection([Object] $document, [Object[]] $entities){
    <# 
        example usage:
        # select some stuff:
        
        # using handles:
        setSelection -document $document -entities @(
            $document.HandleToObject("15218")
            $document.HandleToObject("15969")
        )

        # clear the selection (i.e. deselect everything.)
        setSelection -document $document -entities @()
    #>
    
    
    # with only the COM interface, I think this might be the
    # best we can do (clunky though it is) as a method to 
    # programmatically select entities.
    



    #we assume all the $entities are in the same document, namely $document.
    # this is a bit clunky.  We are including $document as an argument 
    # in order to handle the case where we want to clear the selection set.
    # (i.e. have nothing selected).
    $document.SendCommand(@(
            @(
                "("
                    "(lambda ( / selectionSet )"
                        # wrapping in a lambda just to keep the "selectionSet" variable private.
                        "(setq selectionSet (ssadd))"
                        $entities |% {
                            "(ssadd (handent `"$($_.Handle)`") selectionSet)"
                        }
                        "(sssetfirst nil selectionSet)"
                        "(princ)"
                    ")"
                ")"

            ) -join " "
            ""
        ) -join "`n"
    ) 
    
    # we might consider verifying that the specified entities are really in the
    # document before sending the command to acad.
}

function Install-AutocadElevatedComRegistration {
    <#  This fixes a problem that I encountered 2025-04-02-1657, likely due to
        my having recently enabled User Account Control in Windows, wherein,
        upon running Get-AutocadComObject from an elevated shell, I would get
        the error "New-Object: Retrieving the COM class factory for component
        with CLSID {00000000-0000-0000-0000-000000000000} failed due to the
        following error: 80040154 Class not registered (0x80040154
        (REGDB_E_CLASSNOTREG)).".  This problem was unique to an elevated shell
        -- it diod not happen in a non-elevated shell.

        This function copies the relevant AutoCAD-related COM registration
        registry data from the HKEY_CURRENT_USER hive (or actually from
        HKEY_CLASSES_ROOT, which seems to be a composite of
        HKEY_CURRENT_USER\SOFTWARE\Classes and
        HKEY_LOCAL_MACHINE\SOFTWARE\Classes, defaulting to the former in case of
        conflicting entries.) explicitly to the HKEY_LOCAL_MACHINE .   The
        vagueries of COM registration and User Account Control are above my
        paygrade, and I have no doubt that this is opening up some attack vector
        that I couldn't fathom, but at least it seems to solve my immediate
        problem.

        Run this function as a one-time fix in case you encounter the
        aforementioned error when running Get-AutocadComObject from an elevated
        shell.
    #>

    ##$sourceRoot  = "HKEY_CURRENT_USER\SOFTWARE\Classes"
    $sourceRoot  = "HKEY_CLASSES_ROOT"
    $destinationRoot  = "HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
    
    ## $humanReadableNamedSourceKeys = @(gci "registry::$($sourceRoot)" |? {$_.PSChildName -match "(?-i)^Outlook\.Application(\.\d+)?`$"})
    $humanReadableNamedSourceKeys = @(gci "registry::$($sourceRoot)" |? {$_.PSChildName -match "(?-i)^AutoCAD\.Application(\.\d+)?`$"})
    $classIds = @(
        $humanReadableNamedSourceKeys |
        % {Get-ItemPropertyValue -Path (join-path $_.PSPath "CLSID") -Name "(default)"} | 
        select -unique | 
        ? {$_}  |
        sort
    )
    $guidNamedSourceKeys = @(
        $classIds |
        % {gi "registry::$($sourceRoot)\CLSID\$($_)"}  | 
        ? {$_}
    )
    $sourceKeys = @(
        $humanReadableNamedSourceKeys
        $guidNamedSourceKeys
    )

    foreach($sourceKey in $sourceKeys){
        write-information "now working on '$($sourceKey.Name)'"
        $pathOfTemporaryRegFile1 = (join-path $env:temp "$(new-guid).reg")
        $pathOfTemporaryRegFile2 = (join-path $env:temp "$(new-guid).reg")
        reg export $sourceKey.Name $pathOfTemporaryRegFile1 
        (gc -raw $pathOfTemporaryRegFile1) -replace ([regex]::escape($sourceRoot)),$destinationRoot >  $pathOfTemporaryRegFile2

        ## gc $pathOfTemporaryRegFile2
        reg import $pathOfTemporaryRegFile2
    }
    
}