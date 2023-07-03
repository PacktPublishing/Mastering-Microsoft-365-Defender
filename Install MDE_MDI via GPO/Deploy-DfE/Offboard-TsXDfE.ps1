<#
Instructions:
 Download Windows 10 GPO Offboardingscript from https://securitycenter.microsoft.com
 Copy to Scripts folder and rename file to WindowsDefenderATPOffboardingScript.cmd
 Run Offboard-DefenderATP.ps1 script from same folder as settings.csv
#>
#Requires -RunAsAdministrator

#Read parameter file
if (Test-Path -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\settings.csv" -ErrorAction SilentlyContinue) {
  $Settings = Import-Csv -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\settings.csv" -Delimiter ','
}
else {
  Write-Warning 'Cannot read the settings file. Exiting...'
  exit
}

#Setting parameters:
[string]$SetupPath = ($Settings | Where-Object {$_.Parameter -eq 'SetupPath'}).Value
if ($SetupPath -notlike "*\*") {
  [string]$SetupPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
}
$SetupPath = $SetupPath.TrimEnd('\')
[string]$WorkspaceID = ($Settings | Where-Object {$_.Parameter -eq 'WorkspaceID'}).Value


#Get OS information.
$OS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, BuildNumber, OSArchitecture

#If OS is Windows 10 or Server 2019 and higher run offboarding script
if ($OS.Caption -like '*Windows 10*' -or [int32]$OS.Buildnumber -ge 17763) {
  if (!(Test-Path -Path $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd)) {
    Throw "Unable to find Offboarding script at $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd"
  }
  if ((Get-Item -Path $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd).Length -le 0) {
    Throw "$SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd file size is 0. Please copy correct file."
  }
  & $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd
}

# If OS other than Windows 10 or 2019 and higher run offboarding if new agent installed and remove Workspace with tenant workspaceId if configured.
else {
  if ((Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like 'Microsoft Defender for Endpoint'").Name -eq 'Microsoft Defender for Endpoint') {
    if (!(Test-Path -Path $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd)) {
      Throw "Unable to find Offboarding script at $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd"
    }
    if ((Get-Item -Path $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd).Length -le 0) {
      Throw "$SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd file size is 0. Please copy correct file."
    }
    & $SetupPath\Scripts\WindowsDefenderATPOffboardingScript.cmd
  }
  
  if (Get-Service -Name HealthService -ErrorAction SilentlyContinue) {
    
    #Check if workspace is configured .
    $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
    $Configured = $ManagementAgentConfig.GetCloudWorkspaces() | Where-Object {$_.workSpaceId -eq $WorkspaceID}

    If ($Configured) {

      #Remove Onboarding status in registry
      Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' | Where-Object PSChildName -eq 'Status' | Remove-Item -Force

      #Remove workspace on existing Log Analytics Agent.
      $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction Stop
      $ManagementAgentConfig.RemoveCloudWorkspace($WorkspaceID)
      $ManagementAgentConfig.ReloadConfiguration()
    }
  }
}
