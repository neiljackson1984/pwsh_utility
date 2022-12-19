@rem this batch file will invoke the connectToOffice365 powershell cmdlet, and pass 
@rem to that cmdlet an argument specifying a configuration file path in the same folder as this batch file.

@echo off
set directoryOfThisScript=%~dp0

pwsh -NoLogo -NoExit -Command "Import-Module """neil-utility1"""; connectToOffice365 -pathOfTheConfigurationFile """%directoryOfThisScript%config.json"""