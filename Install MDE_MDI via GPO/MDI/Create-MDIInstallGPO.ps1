<#
.SYNOPSIS
Creates and links a GPO with a scheduled task that runs the Microsoft Defender for Identity installer

.DESCRIPTION
Creates and links a GPO with a scheduled task that runs the Microsoft Defender for Identity installer

Ensure that the disclaimer is read and understood before execution!
.PARAMETER ScriptPath
Path to the folder where the script is located (\\domain.tld\netlogon\apps\mdi)
.PARAMETER GPOInstallName
The name for the install GPO to create, default "MDI - DCAgentInstall"
.EXAMPLE
.\Create-MDIInstallGPO.ps1 -ScriptPath "\\domain.tld\netlogon\apps\mdi"
.EXAMPLE
.\Create-MDIInstallGPO.ps1 -ScriptPath "\\domain.tld\netlogon\apps\mdi" -GPOInstallName "Domain Controller - MDI Install"
.NOTES
Author: Truesec Cyber Security Incident Response Team
Website: https://truesec.com/
Created: 2023-01-09

VERSION
1.0 - Initial release

DISCLAIMER
Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
#>
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,
    HelpMessage='Enter path only to centrally stored Install-MDIAgent.ps1',
    Position=0)]
    [string]$ScriptPath,
    [string]$GPOInstallName = 'Domain Controller - MDI Install'
)
# Set variables
$DomainInfo = Get-ADDomain
$DomainDCOU = $DomainInfo.DomainControllersContainer
$DomainNB = $DomainInfo.NetBIOSName
$PDC = $DomainInfo.PDCEmulator

if (!($ScriptPath)) {
  $ScriptPath = Read-Host "Path to centrally stored version of Install-MicrosoftDefenderforIdentity.ps1. (Example: \\$DomainNB\NETLOGON\Apps\MDI)"
}
$ScriptPath = $ScriptPath.TrimEnd('\')

# Extract MDIGPOs zip
$WorkPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
if ((Get-ChildItem -Path $WorkPath\ExtractedGPO -Recurse).Count -lt 5) {
  Try {
    Expand-Archive $WorkPath\MDIGPOs.zip -DestinationPath "$WorkPath\ExtractedGPO" -Force -ErrorAction Stop
  }
  Catch {
    Add-Type -Assembly "System.IO.Compression.Filesystem"
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$WorkPath\MDIGPOs.zip", "$WorkPath\ExtractedGPO")
  }
}

#Get or Create GPO.s
Try {
  $InstallGPO = Get-GPO -Name $GPOInstallName -ErrorAction Stop -Server $PDC
}
Catch {
  Try {
    $InstallGPO = New-GPO -Name $GPOInstallName -ErrorAction Stop -Server $PDC
  }
  Catch {
    Throw "Unable to create $GPOInstallName GPO. Error: $($_.Exception.Message)"
  }
}

# Install GPO - Replace path and Import settings
$TaskPath = Get-ChildItem -Path "$WorkPath\ExtractedGPO\MDI - DCAgentInstall" -Recurse -Filter ScheduledTasks.xml
$Task = Get-Content $TaskPath.FullName
$Task = $Task.Replace("\\domain\share", "$ScriptPath")
$Task | Set-Content $TaskPath.FullName
Write-Verbose "Wrote new path $ScriptPath to $($TaskPath.FullName)"
Try {
  Import-GPO -Path "$WorkPath\ExtractedGPO\MDI - DCAgentInstall" -BackupGpoName "MDI - DCAgentInstall" -TargetName $InstallGPO.DisplayName -ErrorAction Stop -Server $PDC
  Write-Verbose "Imported settings from GPOBackup to $($InstallGPO.DisplayName)"
}
Catch {
  Write-Error "Unable to import Install GPO"
  Throw
}

# Link GPO
$DCGPLinks = (Get-GPInheritance -Target $DomainDCOU).GpoLinks
if ($DCGPLinks.DisplayName -notcontains $InstallGPO.Displayname) {
  Try {
    New-GPLink -Id $InstallGPO.Id -Target $DomainDCOU -LinkEnabled Yes -Enforced No -ErrorAction Stop -Server $PDC
  }
  Catch {
    Write-Error "Could not link Install GPO to Domain Controllers OU. Error: $($_.Exception.Message)" -Verbose
  }
}

# Remove extracted GPOs
Try {
  Remove-Item "$WorkPath\ExtractedGPO" -Force -Recurse -ErrorAction Stop
}
Catch {
  write-warning "Failed to delete folder: $WorkPath\ExtractedGPO"
}
