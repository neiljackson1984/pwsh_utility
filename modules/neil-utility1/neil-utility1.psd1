
# see [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests?view=powershell-7.3]
# see [https://learn.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-module-manifest?view=powershell-7.3]
# see [https://stackoverflow.com/questions/55668072/how-to-cause-install-module-to-also-install-any-required-modules]
@{
    ModuleVersion="0.0.1"
    Author = "Neil Jackson<neil@rattnow.com>"
    Description = "useful utilities and dependencies"
    GUID = '1e59d151-70ae-4cdc-9df3-83f6b7703ac1'
    NestedModules=@(
        # no good way to do wildcards here, unfortunately
    
        "ipv6-control.psm1"
        "Set-Owner.psm1"
        "utility.psm1"
        "email_forwarding_and_access_report.psm1"
        "new-user.psm1"
        "connect_to_office_365.psm1"
        "autodesk_identity.psm1"
        "autodesk_identity.psm1"
        "domain_controller_session.psm1"
        "autodesk_popup_slapdown.psm1"
        "dump-attachments.psm1"
        "autocad-control.psm1"
    )


    # RequiredModules=@(
        
    #     @{
    #         # [https://github.com/christaylorcodes/ConnectWiseControlAPI]
    #         ModuleName = 'ConnectWiseControlAPI'
    #         GUID = 'f94fa996-0f01-4c5c-9cd9-3227728ebacb'
    #         ModuleVersion = '0.3.5.0'
    #     }

    # )



    # # ExternalModuleDependencies = @('ConnectWiseControlAPI')
    #  PrivateData = @{
    #      ExternalModuleDependencies = @('ConnectWiseControlAPI')
    #      PSData = @{
    #          ExternalModuleDependencies = @('ConnectWiseControlAPI')
    #      } 
    #  } 
    ###  
    ###  # damnit -- it looks like cross-repository dependencies are not well
    ###  # supported by the Powershell package management architecture.
    ###  #
    ###  # I don't know what the best workaround here is -- vendoring?  seems
    ###  # heavy-handed and hard to maintain.
    
}
