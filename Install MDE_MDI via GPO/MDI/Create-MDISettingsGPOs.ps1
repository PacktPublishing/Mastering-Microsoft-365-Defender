<#
.SYNOPSIS
This script adds Microsoft recommended configuration for Microsoft Defender for Identity

.DESCRIPTION
This script adds Microsoft recommended configuration for Microsoft Defender for Identity
SAM-R permissions for the MDI Account in the entire domain.
Auditing settings for Domain Controllers
Optional: Auditing configuration for entire Active Directory

Ensure that the disclaimer is read and understood before execution!

.PARAMETER MDIAccount
Username only of the MDI service account.

.PARAMETER GPOAuditingName
The name for the settings GPO to create, default "MDI - Auditing"

.PARAMETER GPOSAMRName
The name for the settings GPO to create, default "MDI - Allow SAM-R"

.EXAMPLE
.Create-MDISettingsGPOs.ps1 -MDIAccount "gMSA-dfi"
.EXAMPLE
.\Create-MDISettingsGPOs.ps1 -MDIAccount "gMSA-dfi" -GPOAuditingName "Domain Controller - MDI Auditing" -GPOSAMRName "Domain - MDI SAMR"
.NOTES
Author: Truesec Cyber Security Incident Response Team
Website: https://truesec.com/
Created: 2023-01-04

VERSION 1.0
1.0 - Initial release

DISCLAIMER
Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
#>
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,
    HelpMessage='Enter username only for MDI ServiceAccount',
    Position=0)]
    [string]$MDIAccount,
    [string]$GPOAuditingName = 'Domain Controller - MDI Auditing',
    [string]$GPOSAMRName = 'Domain - MDI SAMR'
)

# Set variables
$DomainInfo = Get-ADDomain
$DomainDN = $DomainInfo.DistinguishedName
$DomainDCOU = $DomainInfo.DomainControllersContainer
$PDC = $DomainInfo.PDCEmulator
$DomainNB = $DomainInfo.NetBIOSName
$DomainFQDN = $DomainInfo.DnsRoot
$DeletedDN = $DomainInfo.DeletedObjectsContainer

$i = 0
Do {
  if ($MDIAccount -and $i -eq 0) {
    $MDIAccount = $MDIAccount -replace [regex]::Escape("$DomainNB\"),''
    $MDIAccount = $MDIAccount.TrimEnd('$')
    $MDIAccount = $MDIAccount -replace [regex]::Escape("@$DomainFQDN"),''
  }
  else {
    $MDIAccount = Read-Host -Prompt 'ServiceAccount needed for SAM-R delegation (need to already exist) Example:gMSA-dfi'
  }
  Try {
    $AccountSID = (Get-ADServiceAccount -Identity $MDIAccount -ErrorAction Stop).SID.Value
    $gMSA = $true
  }
  Catch {
    Try {
      $AccountSID = (Get-ADUser -Identity $MDIAccount -ErrorAction Stop).SID.Value
      $gMSA = $false
    }
    Catch {
      $i++
      Write-Warning "$MDIAccount not found in Active Directory. Please try again! Attempt $i out of 3!"
    }
  }
}
Until ($AccountSID -or $i -eq 3)

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
  $AuditGPO = Get-GPO -Name $GPOAuditingName -ErrorAction Stop -Server $PDC
}
Catch {
  Try {
    $AuditGPO = New-GPO -Name $GPOAuditingName -ErrorAction Stop -Server $PDC
  }
  Catch {
    Throw "Unable to create $GPOAuditingName. Error: $($_.Exception.Message)"
  }
}
Try {
  $SAMRGPO = Get-GPO -Name $GPOSAMRName -ErrorAction Stop -Server $PDC
}
Catch {
  Try {
    $SAMRGPO = New-GPO -Name $GPOSAMRName -ErrorAction Stop -Server $PDC
  }
  Catch {
    Throw "Unable to create $GPOSAMRName. Error: $($_.Exception.Message)"
  }
}

# Auditing GPO Import settings
Try {
  Import-GPO -Path "$WorkPath\ExtractedGPO\MDI - Auditing" -BackupGpoName "MDI - Auditing" -TargetName $AuditGPO.DisplayName -ErrorAction Stop -Server $PDC
  Write-Verbose "Imported settings from GPOBackup to $($AuditGPO.DisplayName)"
}
Catch {
  Write-Error "Unable to import Auditing GPO"
  Throw
}

# SAM-R GPO Update user SID and Import settings
if ($AccountSID) {
  $SecEditPath = Get-ChildItem -Path "$WorkPath\ExtractedGPO\MDI - Allow SAM-R" -Recurse -Filter GptTmpl.inf
  $File = Get-Content $SecEditPath.FullName
  $File = $File.Replace("S-1-5-21-144253782-3019883942-3058657682-6602", "$AccountSID")
  $File | Set-Content $SecEditPath.FullName
  Write-Verbose "Wrote new SID $AccountSID to $($SecEditPath.FullName)"
}
else {
  Write-Warning "Unable to find user $MDIAccount. Update GPO $($SAMRGPO.DisplayName) manually!" -Verbose
}

Try {
  Import-GPO -Path "$WorkPath\ExtractedGPO\MDI - Allow SAM-R" -BackupGpoName "MDI - Allow SAM-R" -TargetName $SAMRGPO.DisplayName -ErrorAction Stop -Server $PDC
  Write-Verbose "Imported settings from GPOBackup to $($SAMRGPO.DisplayName)"
}
Catch {
  Write-Error "Unable to import SAM-R GPO"
  Throw
}

# Deny ENTERPRISE DOMAIN CONTROLLERS group from applying SAM-R policy
$i = 0
Do {
  $GPOACL = Get-Acl -Path AD:"CN={$($SAMRGPO.Id.Guid)},CN=Policies,CN=System,$DomainDN" -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 3
  $i++
}
Until ($GPOACL -or $i -eq 40)
if ($i -lt 40) {
  $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.SecurityIdentifier]"S-1-5-9", "ExtendedRight", "Deny", [Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939")
  $GPOACL.AddAccessRule($Rule)
  Try {
    Set-Acl -Path AD:"CN={$($SAMRGPO.Id.Guid)},CN=Policies,CN=System,$DomainDN" -AclObject $GPOACL -ErrorAction Stop
  }
  Catch {
    Write-Error "Could not Deny ENTEPRISE DOMAIN CONTROLLERS from $($SAMRGPO.DisplayName) GPO. Fix manually!" -Verbose
  }
}
else {
  Write-Error "Could not Deny ENTEPRISE DOMAIN CONTROLLERS from $($SAMRGPO.DisplayName) GPO. Fix manually!" -Verbose
}

# Link GPO.s
$DomainGPLinks = (Get-GPInheritance -Target $DomainDN).GpoLinks
if ($DomainGPLinks.DisplayName -notcontains $SAMRGPO.Displayname) {
  Try {
    New-GPLink -Id $SAMRGPO.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes -ErrorAction Stop -Server $PDC
  }
  Catch {
    Write-Error "Could not link $($SAMRGPO.DisplayName) GPO to domain. Error: $($_.Exception.Message)" -Verbose
  }
}

$DCGPLinks = (Get-GPInheritance -Target $DomainDCOU).GpoLinks
if ($DCGPLinks.DisplayName -notcontains $AuditGPO.Displayname) {
  Try {
    New-GPLink -Id $AuditGPO.Id -Target $DomainDCOU -LinkEnabled Yes -Enforced No -ErrorAction Stop -Server $PDC
  }
  Catch {
    Write-Error "Could not link $($AuditGPO.DisplayName) GPO to Domain Controllers OU. Error: $($_.Exception.Message)" -Verbose
  }
}

# Set MDI Account permissions for Deleted Objects
if ($gMSA) {
  $MDIAccount = "$($MDIAccount)$"
}
$MDIAccountNB = "$DomainNB\$MDIAccount"

$RecycleBinEnabled = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' -ErrorAction SilentlyContinue).EnabledScopes
if ($AccountSID) {
  if ($RecycleBinEnabled) {
    Start-Process -FilePath "$env:SystemRoot\system32\dsacls.exe" -ArgumentList """$DeletedDN"" /TakeOwnership" -NoNewWindow -Wait
    Start-Process -FilePath "$env:SystemRoot\system32\dsacls.exe" -ArgumentList """$DeletedDN"" /G ""$MDIAccountNB"":LCRP" -NoNewWindow -Wait
  }
  else {
    Write-Warning "Deleted objects container not found! Enable recycle bin and set permissions manually!" -Verbose
  }
}
else {
  Write-Warning "$MDIAccountNB not found! Set Recycle bin permissions manually!" -Verbose
}

# Set Active Directory auditing rules
$SetACL = Read-Host "Set MDI auditing rules on $DomainDN (y/n)"
if ($SetACL -eq 'y') {
  $i = 0
  Do {
    $DomainACL = Get-Acl -Audit -Path AD:$DomainDN -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $i++
  }
  Until ($DomainACL -or $i -eq 40)
  if ($i -lt 40) {
    $User = [Security.Principal.SecurityIdentifier]'S-1-1-0' # Everyone
    $ObjectTypes = @('bf967aba-0de6-11d0-a285-00aa003049e2', #User objects
                     'bf967a86-0de6-11d0-a285-00aa003049e2', #Computer objects
                     'bf967a9c-0de6-11d0-a285-00aa003049e2', #Group objects
                     '7b8b558a-93a5-4af7-adca-c017e67f1057', #msDS-GroupManagedServiceAccount objects
                     'ce206244-5827-4a86-ba1c-1c0c386c1b64') #msDS-ManagedServiceAccount objects
    foreach ($ObjectType in $ObjectTypes) {
      $Rule = New-Object DirectoryServices.ActiveDirectoryAuditRule $User, 'CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, ExtendedRight, Delete, WriteDacl, WriteOwner', 'Success', '00000000-0000-0000-0000-000000000000', 'Descendents', $ObjectType
      $DomainACL.AddAuditRule($Rule)
    }
    Set-Acl -Path AD:$DomainDN -AclObject $DomainACL
  }
  else {
    Write-Error "Could not set auditing permission on $DomainDN. Set manually!" -Verbose
  }
}
else {
  Write-Warning 'Set auditing SACL manually according to : https://learn.microsoft.com/en-us/defender-for-identity/configure-windows-event-collection#configure-object-auditing' -Verbose
}

# Remove extracted GPOs
try {
    Remove-Item "$WorkPath\ExtractedGPO" -Force -Recurse -ErrorAction Stop
}
catch {
    write-warning "Failed to delete folder: $WorkPath\ExtractedGPO"
}
