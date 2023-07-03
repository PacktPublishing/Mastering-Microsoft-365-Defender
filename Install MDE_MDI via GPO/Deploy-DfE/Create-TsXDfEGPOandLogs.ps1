<#
Filestructure needed:
\
\dotNET\            .NET 4.8 offline installer (https://go.microsoft.com/fwlink/?linkid=2088631)
\KBs\               Required updates for previous OS versions
\log\               Logfiles directory
\MMAgent\           Microsoft Monitoring agent x64. Download and extract content. (https://go.microsoft.com/fwlink/?LinkId=828603)
\MMAgent\x86\       Microsoft Monitoring agent x86. Download and extract content. (https://go.microsoft.com/fwlink/?LinkId=828604)
\Scripts\           Download and put Windows 10 GPO Onboarding script from Defender for Endpoint portal here.
\md4ws.msi          Download and put preview install package from Defender for Endpoint portal here.

Permissions: Domain Controllers and Domain Computers - Read and Execute (logfile write permissions are set when created by script)
Settings file need to exist in same directory as the running script.
Leave SetupPath and LogPath empty to use \\DomainNB\NETLOGON\Apps\MDE as SetupPath and C:\ScriptLogs\MDE as LogPath
#>
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory,GroupPolicy
[CmdletBinding()]
Param (
  [string]$TargetDir,
  [string]$LogDir,
  [string]$WorkspaceID,
  [string]$WorkspaceKey,
  [switch]$Force,
  [switch]$LinkGPO
)

# Get environment information
$hostname = hostname
$ADDomain = Get-ADDomain
$DomainNB = $ADDomain.NetBIOSName
$DomainDN = $ADDomain.DistinguishedName
$DomainSID = $ADDomain.DomainSid.Value
$DomainComputersGroup = Get-ADGroup -Filter "SID -eq '$DomainSID-515'"
$DomainControllersGroup = Get-ADGroup -Filter "SID -eq '$DomainSID-516'"
$RunningPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$BuiltinAdminGroup = ((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount])).Value

# Read parameter file
if (Test-Path -LiteralPath "$RunningPath\settings.csv" -ErrorAction SilentlyContinue) {
  $Settings = Import-Csv -Path "$RunningPath\settings.csv" -Delimiter ','
}
else {
  Write-Warning 'Cannot read the settings file. Exiting...'
  exit
}

# Verify that DfE_GPO.zip exists
if (!(Test-Path -Path "$RunningPath\DfE_GPO.zip" -ErrorAction SilentlyContinue)) {
  Write-Warning 'Cannot find DfE_GPO.zip file. Exiting...'
  exit
}

# If parameters not set use values from settings file. Ask user if WorkspaceID and/or WorkspaceKey is not set
if (!($TargetDir)) {
  [string]$SetupPath = ($Settings | Where-Object {$_.Parameter -eq 'SetupPath'}).Value
  if ($SetupPath -notlike "*\*") {
    [string]$SetupPath = "\\$DomainNB\NETLOGON\Apps\MDE"
  }
  $SetupPath = $SetupPath.TrimEnd('\')
}
else {
  $SetupPath = $TargetDir.TrimEnd('\')
}
if (!($LogDir)) {
  [string]$LogPath = ($Settings | Where-Object {$_.Parameter -eq 'LogPath'}).Value
  if ($LogPath -notlike "*\*") {
    [string]$LogPath = "C:\ScriptLogs\MDE"
  }
  $LogPath = $LogPath.TrimEnd('\')
}
else {
  $LogPath = $LogDir.TrimEnd('\')
}
if (!($WorkspaceID)) {
  [string]$WorkspaceID = ($Settings | Where-Object {$_.Parameter -eq 'WorkspaceID'}).Value
  if ($WorkspaceID -eq 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx') {
    $NewWorkspaceID = Read-Host 'Please enter tenant WorkspaceID'
    $Settings | ForEach-Object { if ($_.Parameter -eq 'WorkspaceID') { $_.Value = $NewWorkspaceID } }
    $WorkspaceID = $NewWorkspaceID
  }
}
if (!($WorkspaceKey)) {
  [string]$WorkspaceKey = ($Settings | Where-Object {$_.Parameter -eq 'WorkspaceKey'}).Value
  if ($WorkspaceKey -eq 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==') {
    $NewWorkspaceKey = Read-Host 'Please enter tenant WorkspaceKey'
    $Settings | ForEach-Object { if ($_.Parameter -eq 'WorkspaceKey') { $_.Value = $NewWorkspaceKey } }
    $WorkspaceKey = $NewWorkspaceKey
  }
}

# Verify paths with user unless force is set
if ($Force) {
  $VerifyPaths = 'y'
}
else {
  $CurrentFGColor = $host.ui.RawUI.ForegroundColor
  $host.ui.RawUI.ForegroundColor = 'Green'
  Write-Output "NOTE!`nUNC-paths will be used as is! Share and file permissions needs to be set manually!`nIf local paths are specified the script will create shares and set both share and file permissions."
  $host.ui.RawUI.ForegroundColor = $CurrentFGColor
    
  Do {
    $VerifyPaths = Read-Host "`nPaths that will be used in deployment:`nSetupPath:$SetupPath`nLogPath:$LogPath`n`nIs this correct(y/n)"
  }
  Until ($VerifyPaths.Length -eq 1)

  # If user chose "n" then ask for new path and verify new paths
  if ($VerifyPaths -eq 'n' ) {
    Do {
      $NewSetupPath = Read-Host "`n(Entering a local path will create folder and share. Entering a UNC path will use already configured share)`nEnter path to script directory or hit enter to use $SetupPath"
      if ($NewSetupPath -ne '') {
        $SetupPath = $NewSetupPath
      }
      $LogPath = Read-Host "`n(Entering a local path will create folder and share. Entering a UNC path will use already configured share)`nEnter path to log directory or hit enter to use $SetupPath\log"
      if ($LogPath -eq '') {
        $LogPath = "$SetupPath\log"
      }
    }
    Until ($SetupPath -like '*\*' -and $LogPath -like '*\*')
    
    Write-Output "`nPaths that will be used in deployment (based on manually entered path):`nSetupPath:$SetupPath`nLogPath:$LogPath`n"
    $VerifyPaths = 'y'
  }
}

if ($VerifyPaths -eq 'y') {

  # If local path create folder if not exist and share if does not exist. Use SMB Share if entered.
  if ($SetupPath -notlike '\\*') {
    if (Test-Path $SetupPath -ErrorAction SilentlyContinue) {
      $Directory = Get-Item -Path $SetupPath
    }
    else {
      Try {
        $Directory = New-Item -Path $SetupPath -ItemType Directory -ErrorAction Stop
        Write-Verbose "Created directory $SetupPath"
      }
      Catch {
        Write-Error $_
        Throw
      }
    }

    # Create SMB share if it doesn't exist
    $SetupPathShare = Get-SmbShare -Name $Directory.Name -ErrorAction SilentlyContinue
    if (!($SetupPathShare)) {
      $SetupPathShare = New-SmbShare -Name $Directory.Name -Path $Directory.FullName -ChangeAccess "$DomainNB\$($DomainComputersGroup.Name)","$DomainNB\$($DomainControllersGroup.Name)" -FullAccess $BuiltinAdminGroup -FolderEnumerationMode AccessBased
    }
    elseif ($SetupPathShare.Path -ne $Directory.FullName) {
      $SetupPathShare = New-SmbShare -Name "MDE_$($Directory.Name)" -Path $Directory.FullName -ChangeAccess "$DomainNB\$($DomainComputersGroup.Name)","$DomainNB\$($DomainControllersGroup.Name)" -FullAccess $BuiltinAdminGroup -FolderEnumerationMode AccessBased
    }
    $SetupPath = "\\$hostname\$($SetupPathShare.Name)"
  }
  if ($SetupPath -like '*NETLOGON*') {
    $NetlogonShare = Get-SmbShare -Name NETLOGON -ErrorAction SilentlyContinue
    if ($NetlogonShare) {
      $NetlogonPathOnly = $SetupPath -replace '^[^NETLOGON]+NETLOGON', ''
      $NetlogonPath = "$($NetlogonShare.Path)$NetlogonPathOnly"
      if (!(Test-Path $NetlogonPath)) {
        New-Item -Path $NetlogonPath -ItemType Directory -ErrorAction SilentlyContinue
      }
    }
    else {
      Write-Warning "Default share permissions does not allow write to $DomainNB\NETLOGON. Setup files needs to be copied manually!"
    }
    $SetupNetlogon = $true
  }
  else {
    $SetupNetlogon = $false
  }
  
  if ($LogPath -notlike '\\*') {
    if (Test-Path $LogPath -ErrorAction SilentlyContinue) {
      $Directory = Get-Item -Path $LogPath
    }
    else {
      Try {
        $Directory = New-Item -Path $LogPath -ItemType Directory -ErrorAction Stop
        Write-Verbose "Created directory $LogPath"
      }
      Catch {
        Write-Error $_
        Throw
      }
    }
    
    if ($LogPath -ne "$SetupPath\log" -or (!(Get-SmbShare -Name 'ScriptLogs'))) {
      # Create SMB share if it doesn't exist
      $LogPathShare = Get-SmbShare -Name $Directory.Name -ErrorAction SilentlyContinue
      if (!($LogPathShare)) {
        $LogPathShare = New-SmbShare -Name $Directory.Name -Path $Directory.FullName -ChangeAccess "$DomainNB\$($DomainComputersGroup.Name)","$DomainNB\$($DomainControllersGroup.Name)" -FullAccess $BuiltinAdminGroup -FolderEnumerationMode AccessBased
      }
      elseif ($LogPathShare.Path -ne $Directory.FullName) {
        $LogPathShare = New-SmbShare -Name "MDE_$($Directory.Name)" -Path $Directory.FullName -ChangeAccess "$DomainNB\$($DomainComputersGroup.Name)","$DomainNB\$($DomainControllersGroup.Name)" -FullAccess $BuiltinAdminGroup -FolderEnumerationMode AccessBased
      }
      $LogPath = "\\$hostname\$($LogPathShare.Name)"
    }
    elseif (Get-SmbShare -Name 'ScriptLogs') {
      $LogPath = "\\$hostname\ScriptLogs\MDE"
    }
    else {
      $LogPath = "$SetupPath\log"
    }
  }
  if (!(Test-Path "$LogPath\Status" -ErrorAction SilentlyContinue)) {
    New-Item -Path $LogPath -Name Status -ItemType Directory -ErrorAction Stop
  }
  if ($LogPath -like '*NETLOGON*') {
    Write-Error "Default share permissions does not allow write to $DomainNB\NETLOGON. Log files should be hosted on their own share!"
    $LogNetlogon = $true
  }

  
  # Set base directory file permissions
  if ($SetupNetlogon -eq $true -and $NetlogonShare) {
    & icacls $SetupPath /inheritance:d | Out-Null
    & icacls $SetupPath /remove:g "*S-1-5-32-545" /remove:g "*S-1-3-0" | Out-Null
    & icacls $SetupPath /grant:r "$DomainNB\$($DomainComputersGroup.Name):(OI)(CI)RX" /grant:r "$DomainNB\$($DomainControllersGroup.Name):(OI)(CI)RX" | Out-Null
  }
  elseif ($SetupNetlogon -eq $false) {  
    & icacls $SetupPath /inheritance:d | Out-Null
    & icacls $SetupPath /remove:g "*S-1-5-32-545" /remove:g "*S-1-3-0" | Out-Null
    & icacls $SetupPath /grant:r "$DomainNB\$($DomainComputersGroup.Name):(OI)(CI)RX" /grant:r "$DomainNB\$($DomainControllersGroup.Name):(OI)(CI)RX" | Out-Null
  }

  # Set status log directory directory permissions
  if ($LogNetlogon -ne $true) {
    & icacls $LogPath /inheritance:d | Out-Null
    & icacls $LogPath /remove:g "*S-1-5-32-545" /remove:g "*S-1-3-0" | Out-Null
    & icacls $LogPath /grant:r "*S-1-5-32-545:(OI)(CI)RX" /grant:r "$DomainNB\$($DomainComputersGroup.Name):(OI)(IO)RX" /grant:r "$DomainNB\$($DomainControllersGroup.Name):(OI)(IO)RX" | Out-Null
    & icacls "$LogPath\Status" /inheritance:d | Out-Null
    & icacls "$LogPath\Status" /grant:r "*S-1-3-0:(OI)(IO)M" | Out-Null
    & icacls "$LogPath\Status" /grant:r "$DomainNB\$($DomainComputersGroup.Name):M" /grant:r "$DomainNB\$($DomainControllersGroup.Name):M" | Out-Null
  }

  # Test if Scripts folder exists in running path otherwise create an empty folder. Move WindowsDefenderATPOnboardingScript.cmd if exists
  if (!(Test-Path -Path "$RunningPath\Scripts" -ErrorAction SilentlyContinue)) {
    Try {
      New-Item "$RunningPath\Scripts" -ItemType Directory -ErrorAction Stop | Out-Null
    }
    Catch {
      Write-Warning "Could not create $RunningPath\Scripts. Create path manually!"
    }
  }
  if (Test-Path -LiteralPath "$RunningPath\WindowsDefenderATPOnboardingScript.cmd" -ErrorAction SilentlyContinue) {
    Move-Item -LiteralPath "$RunningPath\WindowsDefenderATPOnboardingScript.cmd" -Destination "$RunningPath\Scripts" -Force -ErrorAction SilentlyContinue
  }
  elseif (Test-Path -LiteralPath "$RunningPath\WindowsDefenderATPOnboardingPackage.zip" -ErrorAction SilentlyContinue) {
    Expand-Archive -LiteralPath $RunningPath\WindowsDefenderATPOnboardingPackage.zip -DestinationPath $RunningPath\Scripts -Force -ErrorAction Stop
    Remove-Item -LiteralPath $RunningPath\Scripts\OptionalParamsPolicy -Recurse -Force -ErrorAction SilentlyContinue
  }
  else {
    if (!(Test-Path -LiteralPath "$RunningPath\Scripts\WindowsDefenderATPOnboardingScript.cmd" -ErrorAction SilentlyContinue) -and !(Test-Path -LiteralPath "$SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd" -ErrorAction SilentlyContinue )) {
      Write-Warning "WindowsDefenderATPOnboardingScript.cmd not found! File needs to be copied manually to ""$SetupPath\Scripts"""
    }
  }

  # Create logfiles and set permissions
  if (!(Test-Path -Path "$LogPath\successlog.txt" -ErrorAction SilentlyContinue)) {
    Try {
      Set-Content -Path "$LogPath\successlog.txt" -Value 'ComputerName, Status, OperatingSystem, TimeStamp' -ErrorAction Stop
      & icacls "$LogPath\successlog.txt" /grant "$DomainNB\$($DomainComputersGroup.Name):(RX,W)" /grant "$DomainNB\$($DomainControllersGroup.Name):(RX,W)" | Out-Null
    }
    Catch {
      Write-Error 'Could not create SuccessLog. Create file and set permissions manually!'
    }
  }
  if (!(Test-Path -Path "$LogPath\errorlog.txt" -ErrorAction SilentlyContinue)) {
    Try {
      Set-Content -Path "$LogPath\errorlog.txt" -Value 'ComputerName, Status, OperatingSystem, TimeStamp' -ErrorAction Stop
      & icacls "$LogPath\errorlog.txt" /grant "$DomainNB\$($DomainComputersGroup.Name):(RX,W)" /grant "$DomainNB\$($DomainControllersGroup.Name):(RX,W)" | Out-Null
    }
    Catch {
      Write-Error 'Could not create ErrorLog. Create file and set permissions manually!'
    }
  }

  # Unblock .Net 4.8 executeable if possible
  if ($PSVersionTable.PSVersion.Major -ge 3) {
    Unblock-File -Path $SetupPath\dotNET\ndp48-x86-x64-allos-enu.exe -ErrorAction SilentlyContinue
    Unblock-File -Path $RunningPath\dotNET\ndp48-x86-x64-allos-enu.exe -ErrorAction SilentlyContinue
  }

  # Get or Create GPO.s
  Try {
    $DfeGPO = Get-GPO -Name 'Admin - Onboard Defender for Endpoints' -ErrorAction Stop
  }
  Catch {
    Try {
      $DfeGPO = New-GPO -Name 'Admin - Onboard Defender for Endpoints' -ErrorAction Stop
    }
    Catch {
      Throw "Unable to create Onboard GPO. Error: $($_.Exception.Message)"
    }
  }
  Try {
    $ForcePassiveGPO = Get-GPO -Name 'Admin - Force Defender Passive Mode for Servers' -ErrorAction Stop
  }
  Catch {
    Try {
      $ForcePassiveGPO = New-GPO -Name 'Admin - Force Defender Passive Mode for Servers' -ErrorAction Stop
    }
    Catch {
      Throw "Unable to create Force Defender GPO. Error: $($_.Exception.Message)"
    }
  }

  # Extract GPO export zip-file. Update scriptpath in GPO export then import GPO 
  Try {
    Expand-Archive -LiteralPath $RunningPath\DfE_GPO.zip -DestinationPath $RunningPath\ExportedOnboardGPO -Force -ErrorAction Stop
    Expand-Archive -LiteralPath $RunningPath\ForcePassive_GPO.zip -DestinationPath $RunningPath\ExportedForcePassiveGPO -Force -ErrorAction Stop
  }
  Catch {
    Add-Type -Assembly "System.IO.Compression.Filesystem"
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$RunningPath\DfE_GPO.zip","$RunningPath\ExportedOnboardGPO")
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$RunningPath\ForcePassive_GPO.zip","$RunningPath\ExportedForcePassiveGPO")
  }
  $File = Get-ChildItem -Path $RunningPath\ExportedOnboardGPO -Recurse -Filter ScheduledTasks.xml
  [XML]$XML = Get-Content -Path $File.FullName
  Write-Output "Task arguments will be set to: $($XML.ScheduledTasks.TaskV2.Properties.Task.Actions.Exec.Arguments -replace '"\\\\domain.name\\NETLOGON\\Onboard-WindowsDefenderEndpoints\\Onboard-DefenderATP.ps1"', "$SetupPath\Onboard-TsXDfE.ps1")"
  $XML.ScheduledTasks.TaskV2.Properties.Task.Actions.Exec.Arguments = $XML.ScheduledTasks.TaskV2.Properties.Task.Actions.Exec.Arguments -replace '"\\\\domain.name\\NETLOGON\\Onboard-WindowsDefenderEndpoints\\Onboard-DefenderATP.ps1"', """$SetupPath\Onboard-TsXDfE.ps1"""
  $XML.Save($File.FullName)
  Try {
    Import-GPO -Path $RunningPath\ExportedOnboardGPO -BackupGpoName $DfeGPO.DisplayName -TargetName $DfeGPO.DisplayName -ErrorAction Stop | Out-Null
    Import-GPO -Path $RunningPath\ExportedForcePassiveGPO -BackupGpoName $ForcePassiveGPO.DisplayName -TargetName $ForcePassiveGPO.DisplayName -ErrorAction Stop | Out-Null
  }
  Catch {
    Write-Error "Unable to import GPO. Error: $($_.Exception.Message)" -Verbose
  }
  Start-Sleep -Seconds 3
  Remove-Item -Path "$RunningPath\ExportedOnboardGPO" -Recurse -Force
  Remove-Item -Path "$RunningPath\ExportedForcePassiveGPO" -Recurse -Force

  # Link GPO to domain root and enforce if user answers "y"
  $DomainGPLinks = (Get-GPInheritance -Target $DomainDN).GpoLinks
  if ($DomainGPLinks.DisplayName -notcontains $DfeGPO.Displayname) {
    if (!($Force -or $LinkGPO)) {
      $GPOLink = Read-Host "Link and enforce ""$($DfeGPO.DisplayName)"" to $DomainDN ? (y/n)"
    }
    if ($GPOLink -eq 'y' -or $LinkGPO) {
      Try {
        New-GPLink -Id $DfeGPO.Id -Target $DomainDN -LinkEnabled Yes -Enforced Yes -ErrorAction Stop
      }
      Catch {
        Write-Error "Could not link Onboard GPO to domain. Error: $($_.Exception.Message)" -Verbose
      }
    }
    else {
      Write-Warning "GPO:""$($DfeGPO.DisplayName)"" needs to be linked manually!"
    }
  }
  Write-Warning "GPO:""$($ForcePassiveGPO.DisplayName)"" needs to be linked manually if customer is running 3rd party antivirus!"
  
  # Write new settings.csv with current values
  Write-Output "Writing settings to $RunningPath\settings.csv ..."
  $Settings | ForEach-Object { if ($_.Parameter -eq 'SetupPath') { $_.Value = $SetupPath } }
  $Settings | ForEach-Object { if ($_.Parameter -eq 'Logpath') { $_.Value = $LogPath } }
  $Settings | ForEach-Object { if ($_.Parameter -eq 'WorkspaceID') { $_.Value = $WorkspaceID } }
  $Settings | ForEach-Object { if ($_.Parameter -eq 'WorkspaceKey') { $_.Value = $WorkspaceKey } }
  $Settings | Export-Csv -Path "$RunningPath\settings.csv" -Delimiter ',' -NoTypeInformation  
  
  # Set copy destination to local netlogon path or SetupPath
  if ($SetupNetlogon -eq $false) {
    $DestinationPath = $SetupPath
  }
  elseif ($NetlogonShare) {
    $DestinationPath = $NetlogonPath
  }
    
  # Prompt if force not set to copy content to SetupPath
  if ((Get-ChildItem -Path $SetupPath -Recurse).Count -lt 10 -and $DestinationPath) {
    if ($Force) {
      $CopyContent = 'y'
    }
    else {
      $CopyContent = Read-Host "Copy files and folders from $RunningPath to $DestinationPath (y/n)"
    }
    if ($CopyContent -eq 'y') {
      Try {
        Write-Output 'Copying files...'
        Get-ChildItem -Path $RunningPath -Exclude ForcePassive_GPO.zip, DfE_GPO.zip, Create-TsXDfEGPOandLogs.ps1, Download-Prerequisites.ps1, README.md, WindowsDefenderATPOnboardingPackage.zip  | Copy-Item -Destination $DestinationPath -Recurse -Force
      }
      Catch {
        Write-Warning "Some files might have failed to copy. Please check $SetupPath !"
      }
    }
  }

  # Always try and copy current settings.csv and WindowsATPOnboardingScript to destination
  if ($DestinationPath) {
    Copy-Item -Path $RunningPath\settings.csv -Destination $SetupPath -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath "$RunningPath\Scripts\WindowsDefenderATPOnboardingScript.cmd" -ErrorAction SilentlyContinue) {
      Copy-Item -Path "$RunningPath\Scripts\WindowsDefenderATPOnboardingScript.cmd" -Destination "$SetupPath\Scripts" -Force -ErrorAction SilentlyContinue
    }
  }
  
  Write-Output "`nPrepare completed!"
  Exit
}

if ($VerifyPaths -ne 'y' -and $VerifyPaths -ne 'n') {
  Write-Warning 'You did not answer "y" or "n". Please try again!'
}
