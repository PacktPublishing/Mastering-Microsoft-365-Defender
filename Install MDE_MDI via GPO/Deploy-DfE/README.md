# Deploy MdE



## Prerequisite files

### Download-Prerequisites.ps1

Run the script, files will be downloaded to the script directory and placed in folders according to the Onboarding script.

Or add **-Path** and download files to somewhere else.

The Script will also extract the MMAgent to the MMAgent folder.

## WindowsDefenderATPOnboardingScript and md4ws.msi
Download tenant specific GPO onboarding package WindowsDefenderATPOnboardingPackage.zip and md4ws.msi from Tenant DfE portal and add to root of the script folder
https://security.microsoft.com
Make note of workspace ID and Key from Windows 7 and Server 2008 R2 onboarding page.

## CreateTsXDfEGPOandLogs.ps1
Run script and verify Log and SetupPath are correct (read from settings.csv, set manually when running script or set with parameters).
Parameters are: -TargetDir -LogDir -WorkspaceID -WorkspaceKey -Force -LinkGPO and can me used individually or together
For example: .\CreateTsXDfEGPOandLogs.ps1 -TargetDir "\\AD\NETLOGON\MDE" -LogDir "C:\MDELogs" -WorkspaceID XXXXX -WorkspaceKey XXXXX -Force
Default TargetDir is \\DomainNetbios\NETLOGON\Apps\MDE and default LogDir is C:\ScriptLogs\MDE. WorkspaceID and WorkspaceKey must always be set for -Force to work!
Script sets permissions, updates settings.csv, creates GPOs, creates directories and shares (if applicable) but does not link GPO unless -LinkGPO is set
