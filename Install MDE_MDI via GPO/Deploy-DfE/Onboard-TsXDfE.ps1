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

Permissions: Domain Controllers and Domain Computers - Read and Execute (logfile write permissions are set when created by Create-DfEGPOandLogs.ps1 script)
Settings file need to exist in same directory as the running script. Leave SetupPath and LogPath empty to use running path.

Force installing MMAgent instead of new agent by creating the registry entry HKLM\Software\TSX\ForceMMA on supported OS.s.
#>
[CmdletBinding()]
Param ()

function Get-ComputerRebootStatus {
  If ((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing').PSChildName -contains 'RebootPending' -or (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').PSChildName -contains 'RebootRequired') {
    return $true
  }
  else {
    return $false
  }
}

function Test-DefenderServiceStatus {
  $DefenderService = Get-Service -Name windefend
  if ($DefenderService.Status -ne 'Running') {
    Try {
      Get-Service -Name windefend | Start-Service -Confirm:$false -ErrorAction Stop
      if ($DefenderService.StartType -ne 'Automatic') {
        Get-Service -Name windefend | Set-Service -StartupType Automatic -ErrorAction Stop
      }
      Do {
        $DefenderService = Get-Service -Name windefend -ErrorAction Stop
        if ($DefenderService.Status -eq 'Stopped') {
          return $false
          break
        }
        Start-Sleep -Seconds 2
      }
      Until ($DefenderService.Status -eq 'Running')
      return $true
    }
    Catch {
       return $false
    }
  }
  else {
    return $true
  }
}

function Write-SuccessInformation {
  Param (
    [Parameter(Mandatory=$True,Position=0)]
    $Message
  )
  $CurrentFGColor = $host.ui.RawUI.ForegroundColor
  $host.ui.RawUI.ForegroundColor = 'DarkGreen'
  Write-Output $Message
  $host.ui.RawUI.ForegroundColor = $CurrentFGColor
}

function Write-RebootInformation {
  Param (
    [Parameter(Mandatory=$True,Position=0)]
    $Message
  )
  $CurrentFGColor = $host.ui.RawUI.ForegroundColor
  $host.ui.RawUI.ForegroundColor = 'DarkYellow'
  Write-Output $Message
  $host.ui.RawUI.ForegroundColor = $CurrentFGColor
}

function Write-ErrorInformation {
  Param (
    [Parameter(Mandatory=$True,Position=0)]
    $Message
  )
  $CurrentFGColor = $host.ui.RawUI.ForegroundColor
  $host.ui.RawUI.ForegroundColor = 'Red'
  Write-Output $Message
  $host.ui.RawUI.ForegroundColor = $CurrentFGColor
}

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
[string]$LogPath = ($Settings | Where-Object {$_.Parameter -eq 'LogPath'}).Value
if ($LogPath -notlike "*\*") {
  [string]$LogPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\log"
}
$LogPath = $LogPath.TrimEnd('\')
[string]$WorkspaceID = ($Settings | Where-Object {$_.Parameter -eq 'WorkspaceID'}).Value
[string]$WorkspaceKey = ($Settings | Where-Object {$_.Parameter -eq 'WorkspaceKey'}).Value
[string]$DfePreview = ($Settings | Where-Object {$_.Parameter -eq 'PreviewDfEforServers'}).Value
[string]$RebootIfNeeded = ($Settings | Where-Object {$_.Parameter -eq 'RebootIfNeeded'}).Value
[string]$UninstallOldSCOM = ($Settings | Where-Object {$_.Parameter -eq 'UninstallOldSCOM'}).Value

#Create EventLog source if it does not exist.
if (!([System.Diagnostics.EventLog]::SourceExists('TSxOnboardDfE'))) {
  Try {
    New-EventLog -LogName Application -Source TSxOnboardDfE -ErrorAction Stop
  }
  Catch {
    Throw 'Unable to create eventlog source for logging'
  }
}

#Get OS information.
$ComputerName = ($env:ComputerName).ToUpper()
$OS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, BuildNumber, OSArchitecture


#If OS is Server 2012 (without R2) or lower than Windows7 SP1 write to errorlog.
if ($OS.BuildNumber -eq 9200 -or [int32]$OS.BuildNumber -lt 7601 -or $null -eq $OS.BuildNumber) {
  if (Test-Path "$LogPath\errorlog.txt") {
    $ComputerinErrorLog = Get-Content "$LogPath\errorlog.txt" | Where-Object {$_.Contains($ComputerName)}
  }
  if (!($ComputerinErrorLog)) {
    Try {
      Add-Content -Path "$LogPath\errorlog.txt" -Value "$ComputerName, OSNotSupported, $($OS.Caption)($($OS.BuildNumber)), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))" -ErrorAction Stop
    }
    Catch {
      Write-Warning 'Unable to write to logfile. Check path and permissions.'
      Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Warning -EventId 401 -Message "Windows Defender for Endpoint onboarding script was unable to write to the logfile. Please check Errorlog file permissions on file "$LogPath\errorlog.txt""
    }
    Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 801 -Message "Windows Defender for Endpoint is not supported on $($OS.Caption)"
  }
  $Status = 'NotSupported'
}


#If OS is Windows 10, Windows Server 2019 or higher onboard OS with script
elseif ($OS.Caption -like '*Windows 10*' -or [int32]$OS.Buildnumber -ge 17763) {

  #Install Windows Defender on servers if not installed
  if ($OS.Caption -like '*Server*') {
    if ((Get-WindowsFeature -Name Windows-Defender).InstallState -ne 'Installed') {
      $result = Install-WindowsFeature -Name Windows-Defender -IncludeAllSubFeature
      $ComputerRebootNeeded = Get-ComputerRebootStatus
      if ($ComputerRebootNeeded -or $result.RestartNeeded -eq 'Yes') {
        $Status = 'SuccessRebootNeeded'
        $Result = 'RebootNeeded_DefenderInstalled'
        $InstallResults += "InstalledWindowsDefender`n"
      }
    }
  }

  #Verify that reboot has occured after patch installation
  $LatestRebootNeededEventTime = (Get-EventLog -LogName Application -Source TSxOnboardDfE -ErrorAction SilentlyContinue | Sort-Object TimeWritten -Descending | Where-Object EventID -eq 102 | Select-Object -First 1).TimeWritten
  if ($LatestRebootNeededEventTime) {
    $LatestRebootEventTime = (Get-EventLog -LogName System -Source EventLog -ErrorAction SilentlyContinue | Sort-Object TimeWritten -Descending | Where-Object EventID -eq 6005 | Select-Object -First 1).TimeWritten
    if ($LatestRebootEventTime -lt $LatestRebootNeededEventTime) {
      $ComputerRebootNeeded = $true
      $Status = 'SuccessRebootNeeded'
      if ($null -eq $Result) {
        $Result = 'RebootNeeded'
      }
    }
  }

  #Check onboarded status and onboard computer if not onboarded already.
  if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status').OnboardingState -ne $true -and $ComputerRebootNeeded -ne $true) {

    #Check if onboarding file exists and is not 0 bytes
    if (!(Test-Path -Path $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd)) {
      Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read onboarding script file : $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
      Throw "Unable to find Onboarding script at $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
    }
    if ((Get-Item -Path $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd).Length -le 0) {
      Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script size is 0 : $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
      Throw "$SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd file size is 0. Please copy correct file."
    }

    if ($OS.Caption -like '*Server*') {
      #Verify Defender Service status
      if ($(Test-DefenderServiceStatus) -ne $true) {
        $Result = 'FailedDefenderService'
        $Status = 'Failed'
        $InstallResults += "Windows Defender Service could not be started.`n"
      }
    }

    #Try and update the Antivirus signatures
    Try {
      if ((Test-NetConnection).PingSucceeded -eq $true) {
        Update-MpSignature -ErrorAction Stop
        Start-Sleep -Seconds 10
      }
    }
    Catch {}

    #Run onboarding script and verify installation status in Event Viewer
    Try {
      $InstallDate = (Get-Date).AddSeconds(-10)
      & $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd
      $i = 0
      Do {
        $InstallEvent = (Get-EventLog -LogName Application -Source WDATPOnboarding -After $InstallDate -Newest 1)
        Start-Sleep -Seconds 2
        $i++
      }
      Until ($InstallEvent.Count -ge 1 -or $i -ge 150)
      if ($InstallEvent.Message -like 'Successfully*') {
        $Result = 'Onboarded'
        $Status = 'Success'
        $InstallResults += "Onboarded computer to DfE`n"
      }
      else {
        $Result = 'FailedOnboarding'
        $Status = 'Failed'
        $InstallResults += "Unable to verify install. Message: $($InstallEvent.Message)`n"
      }
    }
    Catch {
      Write-Error "Could not run onboarding script. Error: $($_.Exception.Message)"
      $ExceptionMessage = $_.Exception
      $Result = 'FailedOnboarding'
      $Status = 'Failed'
      $InstallResults += "Failed to onboard computer to DfE`n"
    }
  }
}


#If OS is not Windows 10, Server 2019 or higher install, upgrade and/or configure workspace.
else {

  #Check registry key for forcing MMAgent install.
  $ForceMMARegistry = Get-ItemProperty -Path HKLM:\SOFTWARE\TSX -Name ForceMMA -ErrorAction SilentlyContinue
  if ($ForceMMARegistry) {
    $DfePreview = 'false'
  }

  #Install required updates on Windows 7 or Windows Server 2008 R2.
  if ($OS.Caption -like '*Windows 7*' -or $OS.Caption -like '*Windows Server 2008 R2*') {

    #Install the February 2018 monthly update rollup.
    $KB4074598 = Get-HotFix -Id KB4074598 -ErrorAction SilentlyContinue
    if (!($KB4074598)) {
      if ($OS.OSArchitecture -like '*64*') {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\windows6.1-kb4074598-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB4074598`n"
        }
        Catch {
          Write-Warning "Could not install KB4074598. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB4074598`n"
        }
      }
      else {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\windows6.1-kb4074598-x86.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB4074598`n"
        }
        Catch {
          Write-Warning "Could not install KB4074598. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB4074598`n"
        }
      }
    }

    #Update for customer experience and diagnostic telemetry.
    $KB3080149 = Get-HotFix -Id KB3080149 -ErrorAction SilentlyContinue
    if (!($KB3080149)) {
      if ($OS.OSArchitecture -like '*64*') {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows6.1-KB3080149-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB3080149`n"
        }
        Catch {
          Write-Warning "Could not install KB3080149. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB3080149`n"
        }
      }
      else {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows6.1-KB3080149-x86.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB3080149`n"
        }
        Catch {
          Write-Warning "Could not install KB3080149. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB3080149`n"
        }
      }
    }
  }

  #Install required updates on Windows 8.1 or Windows Server 2012 R2.
  if ($OS.Caption -like '*Windows 8.1*' -or $OS.Caption -like '*Windows Server 2012 R2*') {

    #Update for customer experience and diagnostic telemetry.
    $KB3080149 = Get-HotFix -Id KB3080149 -ErrorAction SilentlyContinue
    if (!($KB3080149)) {
      if ($OS.OSArchitecture -like '*64*') {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows8.1-KB3080149-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB3080149`n"
        }
        Catch {
          Write-Warning "Could not install KB3080149. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB3080149`n"
        }
      }
      else {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows8.1-KB3080149-x86.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB3080149`n"
        }
        Catch {
          Write-Warning "Could not install KB3080149. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB3080149`n"
        }
      }
    }

    #Update for Universal C Runtime in Windows.
    $KB2999226 = Get-HotFix -Id KB2999226 -ErrorAction SilentlyContinue
    if (!($KB2999226)) {
      if ($OS.OSArchitecture -like '*64*') {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows8.1-KB2999226-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB2999226`n"
        }
        Catch {
          Write-Warning "Could not install KB2999226. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB2999226`n"
        }
      }
      else {
        Try {
          Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows8.1-KB2999226-x86.msu"" /quiet /norestart" -Wait -ErrorAction Stop
          $InstallResults += "Installed KB2999226`n"
        }
        Catch {
          Write-Warning "Could not install KB2999226. Error: $($_.Exception.Message)"
          $InstallResults += "Failed to install KB2999226`n"
        }
      }
    }
  }

  #Check if .Net 4.5 or newer is installed
  if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -ge 378389) {

    #Add TLS1.2 registry settings for .Net
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force

    #Run MMAgent install and onboard if DfePreview not set or operatingsystem is not supported for DfEPreview
    if ($DfePreview -eq 'false' -or $OS.Caption -like "*Windows 8*" -or $OS.Caption -like "*Windows 7*" -or $OS.Caption -like "*Windows Server 2008*") {

      #Uninstall SCOM 2012 or SCOM 2007 Agent if installed and UninstallOldSCOM set to true in settings or else log error and exit
      $scom2012 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5155DCF6-A1B5-4882-A670-60BF9FCFD688}'
      $scom2007 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{25097770-2B1F-49F6-AB9D-1C708B96262A}'
      if (Test-Path -LiteralPath $scom2012 -or Test-Path -LiteralPath $scom2007) {
        if ($UninstallOldSCOM -eq 'true') {
          if (Test-Path -LiteralPath $scom2012) {
            Try {
              Start-Process -FilePath 'C:\Windows\system32\msiexec.exe' -ArgumentList '/qn /X {5155DCF6-A1B5-4882-A670-60BF9FCFD688}' -Wait -ErrorAction Stop
              $InstallResults += "Successfully uninstalled SCOM 2012 Agent`n"
            }
            Catch {
              $InstallResults += "Failed to uninstall SCOM 2012 Agent`n"
              $Result = 'FailedSCOM2012AgentUninstall'
              $Status = 'Failed'
            }
          }
          if (Test-Path -LiteralPath $scom2007) {
            Try {
              Start-Process -FilePath 'C:\Windows\system32\msiexec.exe' -ArgumentList '/qn /X {25097770-2B1F-49F6-AB9D-1C708B96262A}' -Wait -ErrorAction Stop
              $InstallResults += "Successfully uninstalled SCOM 2007 Agent`n"
            }
            Catch {
              $InstallResults += "Failed to uninstall SCOM 2007 Agent`n"
              $Result = 'FailedSCOM2007AgentUninstall'
              $Status = 'Failed'
            }
          }
        }
        else {
          $InstallResults += "Old SCOM Agent blocks install of new MMAgent!`n"
          $Result = 'FailedOldMMAgent'
          $Status = 'Failed'
          Add-Content -Path "$LogPath\errorlog.txt" -Value "$ComputerName, $Result, $($OS.Caption)($($OS.BuildNumber)), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))" -ErrorAction Stop
          Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 800 -Message "Windows Defender for Endpoint onboarding script failed to onboard computer $ComputerName.`n`nSteps taken:`n$InstallResults`n`nException:`n$ExceptionMessage"
          Throw 'Old SCOM Agent blocks install of new MMAgent. Set UninstallOldSCOM to true in settings.csv to force uninstall!'
        }
      }
        
      #Check for installed MMAgent.
      if (Get-Service -Name HealthService -ErrorAction SilentlyContinue) {

        #Check if Log Analytics agent version installed is same as or higher then provided if not upgrade.
        if (!(Test-Path -Path $SetupPath\MMAgent\Setup.exe -ErrorAction SilentlyContinue)) {
          Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read MMAgent Setup file : $SetupPath\MMAgent\Setup.exe"
          Throw "Unable to find MMAgent setup at $SetupPath\MMAgent\Setup.exe"
        }
        [Version]$SetupMMAgentVersion = (Get-Item $SetupPath\MMAgent\Setup.exe).VersionInfo.ProductVersion
        [Version]$MMACurrentVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\' -Name AgentVersion).AgentVersion
        if ($MMACurrentVersion -lt $SetupMMAgentVersion) {

          #Upgrade Log Analytics agent 64 or 32-bit.
          if ($OS.OSArchitecture -like "*64*") {
            Try {
              Start-Process -FilePath $SetupPath\MMAgent\setup.exe -ArgumentList '/qn AcceptEndUserLicenseAgreement=1' -NoNewWindow -Wait -ErrorAction Stop
              $Result = 'UpgradedAgent64'
              $Status = 'Success'
              $InstallResults += "Upgraded MMAgent 64-bit from $MMACurrentVersion to $SetupMMAgentVersion`n"
            }
            Catch {
              $ExceptionMessage = $_.Exception
              $Result = 'FailedUpgradeAgent64'
              $Status = 'Failed'
              $InstallResults += "Failed to upgrade MMAgent 64-bit ($MMACurrentVersion)`n"
            }
          }
          else {
            if (!(Test-Path -Path $SetupPath\MMAgent\x86\Setup.exe -ErrorAction SilentlyContinue)) {
              Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read MMAgent Setup file : $SetupPath\MMAgent\x86\Setup.exe"
              Throw "Unable to find MMAgent setup at $SetupPath\MMAgent\x86\Setup.exe"
            }
            Try {
              Start-Process -FilePath $SetupPath\MMAgent\x86\setup.exe -ArgumentList '/qn AcceptEndUserLicenseAgreement=1' -NoNewWindow -Wait -ErrorAction Stop
              $Result = 'UpgradedAgent32'
              $Status = 'Success'
              $InstallResults += "Upgraded MMAgent 32-bit from $MMACurrentVersion to $SetupMMAgentVersion`n"
            }
            Catch {
              $ExceptionMessage = $_.Exception
              $Result = 'FailedUpgradeAgent32'
              $Status = 'Failed'
              $InstallResults += "Failed to upgrade MMAgent 32-bit ($MMACurrentVersion)`n"
            }
          }
        Start-Sleep -Seconds 15
        }

        #Check if workspace is already configured otherwise add workspace.
        $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
        $Configured = $ManagementAgentConfig.GetCloudWorkspaces() | Where-Object {$_.workSpaceId -eq $WorkspaceID}
        if (!($Configured)) {
          Try {

            #Configure workspace on existing Log Analytics Agent.
            $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction Stop
            $ManagementAgentConfig.AddCloudWorkspace($WorkspaceID, $WorkspaceKey)
            $ManagementAgentConfig.ReloadConfiguration()
            if (!($Result)) {
              $Result = 'AddedWorkSpaceToAgent'
            }
            $Status = 'Success'
            $InstallResults += "Added workspace to MMAgent`n"
          }
          Catch {
            $ExceptionMessage = $_.Exception
            $Result = 'FailedWorkspaceAdd'
            $Status = 'Failed'
            $InstallResults += "Failed to add workspace to MMAgent`n"
          }

          #Check if computer needs a reboot
          $ComputerRebootNeeded = Get-ComputerRebootStatus
        }
      }
      else {

        #Install Log Analytics Agent 64 or 32-bit.
        if ($OS.OSArchitecture -like '*64*') {
          if (!(Test-Path -Path $SetupPath\MMAgent\Setup.exe)) {
            Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read MMAgent Setup file : $SetupPath\MMAgent\Setup.exe"
            Throw "Unable to find MMAgent setup at $SetupPath\MMAgent\Setup.exe"
          }
          Try {
            Start-Process -FilePath $SetupPath\MMAgent\setup.exe -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$WorkspaceID OPINSIGHTS_WORKSPACE_KEY=$WorkspaceKey AcceptEndUserLicenseAgreement=1" -NoNewWindow -Wait -ErrorAction Stop
            $Result = 'InstalledAgent64'
            $Status = 'Success'
            $InstallResults += "Installed MMAgent 64-bit`n"
          }
          Catch {
            Write-Error "Could not install MMAgent. Error: $($_.Exception.Message)"
            $ExceptionMessage = $_.Exception
            $Result = 'FailedInstallAgent64'
            $Status = 'Failed'
            $InstallResults += "Failed to install MMAgent 64-bit`n"
          }
        }
        else {
          if (!(Test-Path -Path $SetupPath\MMAgent\x86\Setup.exe)) {
            Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read MMAgent Setup file : $SetupPath\MMAgent\x86\Setup.exe"
            Throw "Unable to find MMAgent setup at $SetupPath\MMAgent\x86\Setup.exe"
          }
          Try {
            Start-Process -FilePath $SetupPath\MMAgent\x86\setup.exe -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$WorkspaceID OPINSIGHTS_WORKSPACE_KEY=$WorkspaceKey AcceptEndUserLicenseAgreement=1" -NoNewWindow -Wait -ErrorAction Stop
            $Result = 'InstalledAgent32'
            $Status = 'Success'
            $InstallResults += "Installed MMAgent 32-bit`n"
          }
          Catch {
            Write-Error "Could not install MMAgent. Error: $($_.Exception.Message)"
            $ExceptionMessage = $_.Exception
            $Result = 'FailedInstallAgent32'
            $Status = 'Failed'
            $InstallResults += "Failed to install MMAgent 32-bit`n"
          }
        }

        #Check if computer needs a reboot
        $ComputerRebootNeeded = Get-ComputerRebootStatus
      }
    }

    #If DfePreview is set to true install new agent and prereqs on Windows Server 2012 R2 and Windows Server 2016
    if ($OS.Caption -like '*Windows Server 2012 R2*' -or $OS.Caption -like '*Windows Server 2016*' -and $DfePreview -eq 'true') {

      #If Monitoring agent is installed and workspace configured remove DfE workspace from Monitoring agent
      if (Get-Service -Name HealthService -ErrorAction SilentlyContinue) {
        $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
        $Configured = $ManagementAgentConfig.GetCloudWorkspaces() | Where-Object {$_.workSpaceId -eq $WorkspaceID}
        if ($Configured) {

          #Remove Onboarding status in registry
          Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' | Where-Object PSChildName -eq 'Status' | Remove-Item -Force

          #Remove workspace on existing Log Analytics Agent.
          $ManagementAgentConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction Stop
          $ManagementAgentConfig.RemoveCloudWorkspace($WorkspaceID)
          $ManagementAgentConfig.ReloadConfiguration()

          $InstallResults += "RemovedWorkspaceFromMMAgent`n"
        }
      }

      # Verify Defender feature installation on Windows Server 2016
      if ($OS.Caption -like '*Windows Server 2016*') {

        #Install Windows Defender if not installed
        if ((Get-WindowsFeature -Name Windows-Defender).InstallState -ne 'Installed') {
          $result = Install-WindowsFeature -Name Windows-Defender-Features -IncludeAllSubFeature -IncludeManagementTools
          $ComputerRebootNeeded = Get-ComputerRebootStatus
          if ($ComputerRebootNeeded -or $result.RestartNeeded -eq 'Yes') {
            $Status = 'RebootNeeded'
            $Result = 'RebootNeeded_DefenderInstalled'
            $InstallResults += "InstalledWindowsDefender`n"
          }
        }
      }

      #Check onboarded status and onboard computer if not onboarded already.
      if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue).OnboardingState -ne $true) {

        #Install required updates on Windows Server 2016
        if ($OS.Caption -like '*Windows Server 2016*') {

          #Verify Defender Service status
          if ($(Test-DefenderServiceStatus) -ne $true) {
            $Result = 'FailedDefenderService'
            $Status = 'Failed'
            $InstallResults += "Windows Defender Service could not be started.`n"
          }

          #Try and update the Antivirus signatures
          Try {
            if ((Test-NetConnection).PingSucceeded -eq $true) {
              Update-MpSignature -ErrorAction Stop
              Start-Sleep -Seconds 10
            }
          }
          Catch {}

          #2021-09 Servicing Stack Update for Windows Server 2016 for x64-based Systems
          $KB5005698 = Get-HotFix -Id KB5005698 -ErrorAction SilentlyContinue
          if (!($KB5005698)) {
            Try {
              Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows10.0-KB5005698-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
              $InstallResults += "Installed KB5005698`n"
            }
            Catch {
              Write-Warning "Could not install KB5005698. Error: $($_.Exception.Message)"
              $InstallResults += "Failed to install KB5005698`n"
            }
          }

          #2018-10 Cumulative Update for Windows Server 2016 for x64-based Systems
          $KB4462928 = Get-HotFix -Id KB4462928 -ErrorAction SilentlyContinue
          if (!($KB4462928)) {
            Try {
              Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows10.0-kb4462928-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
              $ComputerRebootNeeded = Get-ComputerRebootStatus
              if ($ComputerRebootNeeded) {
                $Status = 'SuccessRebootNeeded'
                if ($null -eq $Result) {
                  $Result = 'RebootNeeded_KB4462928'
                }
                $InstallResults += "Installed KB4462928. Reboot needed`n"
              }
              else {
                $Status = 'Success'
                $InstallResults += "Installed KB4462928`n"
              }
            }
            Catch {
              Write-Warning "Could not install KB4462928. Error: $($_.Exception.Message)"
              $InstallResults += "Failed to install KB4462928`n"
            }
          }

          #Platform Update for Windows Defender
          if ($Result -ne 'RebootNeeded_DefenderInstalled' -and $Result -ne 'RebootNeeded_KB4462928') {
            if ((Get-MpComputerStatus).AMProductVersion -lt '4.18.2301.6') {
              Start-Process -FilePath "$SetupPath\KBs\updateplatform-x64.exe" -Wait -ErrorAction Stop
              Start-Sleep -Seconds 30
              if ((Get-MpComputerStatus).AMProductVersion -ge '4.18.2301.6') {
                $InstallResults += "Installed updated Windows Defender engine`n"
              }
              else {
                $InstallResults += "Could not verify updated Windows Defender engine`n"
              }
            }
          }
        }

        #Install required updates on Windows Server 2012 R2
        if ($OS.Caption -like '*Windows Server 2012 R2*') {

          #2018-10 Preview of Monthly Quality Rollup for Windows Server 2012 R2 for x64-based Systems (Computer will bluescreen when running onboarding script if this update is not installed)
          $KB4462921 = Get-HotFix -Id KB4462921 -ErrorAction SilentlyContinue
          if (!($KB4462921)) {
            Try {
              Start-Process -FilePath 'wusa.exe' -ArgumentList """$SetupPath\KBs\Windows8.1-kb4462921-x64.msu"" /quiet /norestart" -Wait -ErrorAction Stop
              $ComputerRebootNeeded = Get-ComputerRebootStatus
              if ($ComputerRebootNeeded) {
                $Status = 'SuccessRebootNeeded'
                $Result = 'RebootNeeded_KB4462921'
                $InstallResults += "Installed KB4462921. Reboot needed`n"
              }
              else {
                $Status = 'Success'
                $InstallResults += "Installed KB4462921`n"
              }
            }
            Catch {
              Write-Warning "Could not install KB4462921. Error: $($_.Exception.Message)"
              $Status = 'Failed'
              $Result = 'FailedKB4462921'
              $InstallResults += "Failed to install KB4462921`n"
            }
          }
        }

        #Uninstall SCEP if installed
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Security Client'
        if (Test-Path -LiteralPath $path) {
            $displayName = (Get-ItemProperty -LiteralPath:$path -Name:'DisplayName').DisplayName
            $SCEPUninstallString = (Get-ItemProperty -Path $path -Name 'UninstallString').UninstallString
            $SCEPUninstallString = $SCEPUninstallString.replace('"','')
            $SCEPUninstallPath = ($SCEPUninstallString -split 'Setup.exe ')[0]
            $SCEPUninstallArgs = ($SCEPUninstallString -split 'Setup.exe ')[1]
            Try {
              Start-Process -FilePath "$($SCEPUninstallPath)Setup.exe" -ArgumentList "$SCEPUninstallArgs /s" -Wait -ErrorAction Stop
              $InstallResults += "Successfully uninstalled $displayname`n"
            }
            Catch {
              $InstallResults += "Failed uninstall $displayname`n"
            }
        }

        #Install the Microsoft Defender for Endpoint agent if it's not installed already
        if ((Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like 'Microsoft Defender for Endpoint'").Name -ne 'Microsoft Defender for Endpoint') {
          if (Test-Path -Path "$SetupPath\md4ws.msi") {
            Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $SetupPath\md4ws.msi /quiet" -NoNewWindow -Wait -ErrorAction Stop
            Start-Sleep -Seconds 15
            $ComputerRebootNeeded = Get-ComputerRebootStatus
          }
          else {
            $ExceptionMessage = "$SetupPath\md4ws.msi not found! Verify it exists!"
            Write-Error "Error running $SetupPath\mds4ws.msi. File not found!"
            $Status = 'Failed'
            $Result = 'md4wsFileMissing'
          }
          if ((Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like 'Microsoft Defender for Endpoint'").Name -eq 'Microsoft Defender for Endpoint') {
            $Status = 'Success'
            $Result = 'InstalledDfeAgent'
            $InstallResults += "Installed DfeAgent`n"
          }
          else {
            if ($ComputerRebootNeeded) {
              $Status = 'SuccessRebootNeeded'
              $Result = 'RebootNeededInstallDfeAgent'
            }
            else {
              $Status = 'Failed'
              $InstallResults += "Failed to install DfeAgent`n"
              $Result = 'FailedInstallDfeAgent'
            }
            
          }
        }
        else {
          #Verify Defender Service status
          if ($(Test-DefenderServiceStatus) -ne $true) {
            $Result = 'FailedDefenderService'
            $Status = 'Failed'
            $InstallResults += "Windows Defender Service could not be started.`n"
          }
        }

        #Verify that reboot has occured after patch installation
        $LatestRebootNeededEventTime = (Get-EventLog -LogName Application -Source TSxOnboardDfE -ErrorAction SilentlyContinue | Sort-Object TimeWritten -Descending | Where-Object EventID -eq 102 | Select-Object -First 1).TimeWritten
        if ($LatestRebootNeededEventTime) {
          $LatestRebootEventTime = (Get-EventLog -LogName System -Source EventLog -ErrorAction SilentlyContinue | Sort-Object TimeWritten -Descending | Where-Object EventID -eq 6005 | Select-Object -First 1).TimeWritten
          if ($LatestRebootEventTime -lt $LatestRebootNeededEventTime) {
            $ComputerRebootNeeded = $true
            $Status = 'SuccessRebootNeeded'
            if ($null -eq $Result) {
              $Result = 'RebootNeeded'
            }
          }
        }

        #If computer reboot is not needed then run Onboarding script
        if ($ComputerRebootNeeded -ne $true -and $Status -ne 'Failed') {
          if (!(Test-Path -Path $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd)) {
            Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script could not read onboarding script file : $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
            Throw "Unable to find Onboarding script at $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
          }
          if ((Get-Item -Path $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd).Length -eq 0) {
            Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 802 -Message "Windows Defender for Endpoint onboarding script size is 0 : $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd"
            Throw "$SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd file size is 0. Please copy correct file."
          }

          #Run onboarding script and verify installation status in Event Viewer
          Try {
            $InstallDate = (Get-Date).AddSeconds(-10)
            & $SetupPath\Scripts\WindowsDefenderATPOnboardingScript.cmd
            $i = 0
            Do {
              $InstallEvent = Get-EventLog -LogName Application -Source WDATPOnboarding -After $InstallDate -Newest 1
              Start-Sleep -Seconds 2
              $i++
            }
            Until ($InstallEvent.Count -ge 1 -or $i -ge 150)
            if ($InstallEvent.Message -like 'Successfully*') {
              $Result = 'Onboarded'
              $Status = 'Success'
              $InstallResults += "Onboarded computer to DfE`n"
            }
            else {
              $Result = 'FailedOnboarding'
              $Status = 'Failed'
              $InstallResults += "Unable to verify install. Message: $($InstallEvent.Message)`n"
            }
          }
          Catch {
            Write-Error "Could not run onboarding script. Error: $($_.Exception.Message)"
            $ExceptionMessage = $_.Exception
            $Result = 'FailedOnboarding'
            $Status = 'Failed'
            $InstallResults += "Failed to onboard computer to DfE`n"
          }
        }
      }
    }
  }
  else {

    #Install .Net 4.8 if .Net 4.5 or higher is not installed.
    Try {
      Start-Process -FilePath $SetupPath\dotNET\ndp48-x86-x64-allos-enu.exe -ArgumentList '/q /norestart' -Wait -ErrorAction Stop
      $Result = 'dotNet45Missing'
      $Status = 'Success'
      $InstallResults += "Installed .Net Framework 4.8`n"
    }
    Catch {
      Write-Error "Could not install .Net 4.8. Error: $($_.Exception.Message)"
      $ExceptionMessage = $_.Exception
      $Result = 'FaileddotNet48Install'
      $Status = 'Failed'
      $InstallResults += "Failed to install .Net Framework 4.8`n"
    }

    #Check if computer needs a reboot
    $ComputerRebootNeeded = Get-ComputerRebootStatus
  }
}


#If ComputerRebootNeeded and Status success update Status
If ($ComputerRebootNeeded -and $Status -eq 'Success') {
  $Status = 'SuccessRebootNeeded'
  $Result = 'RebootNeeded'
}

#Log to success or errorlog
if ($Status -like 'Success') {
  Try {
    Add-Content -Path "$LogPath\successlog.txt" -Value "$ComputerName, $Result, $($OS.Caption)($($OS.BuildNumber)), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))" -ErrorAction Stop
  }
  Catch {
    Write-Warning 'Unable to write to logfile. Check permissions.'
    Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Warning -EventId 401 -Message "Windows Defender for Endpoint onboarding script was unable to write to the logfile. Please check Successlog file permissions on file ""$LogPath\successlog.txt"""
  }
  Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Information -EventId 100 -Message "Windows Defender for Endpoint onboarding script successfully onboarded computer $ComputerName.`n`nSteps taken:`n$InstallResults"
  Write-SuccessInformation -Message "Windows Defender for Endpoint onboarding script successfully onboarded computer $ComputerName.`n`nSteps taken:`n$InstallResults"
}

if ($Status -eq 'Failed') {
  Try {
    Add-Content -Path "$LogPath\errorlog.txt" -Value "$ComputerName, $Result, $($OS.Caption)($($OS.BuildNumber)), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))" -ErrorAction Stop
  }
  Catch {
    Write-Warning 'Unable to write to logfile. Check permissions.'
    Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Warning -EventId 401 -Message "Windows Defender for Endpoint onboarding script was unable to write to the logfile. Please check Errorlog file permissions on file ""$LogPath\errorlog.txt"""
  }
  Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Error -EventId 800 -Message "Windows Defender for Endpoint onboarding script failed to onboard computer $ComputerName.`n`nSteps taken:`n$InstallResults`n`nException:`n$ExceptionMessage"
  Write-ErrorInformation -Message "Windows Defender for Endpoint onboarding script failed to onboard computer $ComputerName.`n`nSteps taken:`n$InstallResults`n`nException:`n$ExceptionMessage"
}

if ($null -eq $Status) {
  Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Information -EventId 101 -Message "Windows Defender for Endpoint onboarding script ran on computer $ComputerName but computer is already onboarded."
  Write-SuccessInformation -Message "Windows Defender for Endpoint onboarding script ran on computer $ComputerName but computer is already onboarded."
  if (Test-Path "$LogPath\Status") {
    if (!(Test-Path "$LogPath\Status\$ComputerName*")) {
      Set-Content -Path "$LogPath\Status\$($ComputerName)_$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HHmm')).txt" -Value 'Computer is already onboarded!' -ErrorAction SilentlyContinue
    }
  }
}

if ($Status -like 'SuccessRebootNeeded') {
  if (Test-Path "$LogPath\successlog.txt") {
    $ComputerinSuccessLog = Get-Content "$LogPath\successlog.txt" | Where-Object {$_.Contains("$ComputerName, RebootNeeded")}
  }
  if (!($ComputerinSuccessLog)) {
    Try {
      Add-Content -Path "$LogPath\successlog.txt" -Value "$ComputerName, $Result, $($OS.Caption)($($OS.BuildNumber)), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))" -ErrorAction Stop
    }
    Catch {
      Write-Warning 'Unable to write to logfile. Check permissions.'
      Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Warning -EventId 401 -Message "Windows Defender for Endpoint onboarding script was unable to write to the logfile. Please check Successlog file permissions on file ""$LogPath\successlog.txt"""
    }
  }
  Write-EventLog -LogName Application -Source TSxOnboardDfE -EntryType Information -EventId 102 -Message "Windows Defender for Endpoint onboarding script successfully ran on computer $ComputerName but a reboot is required before onboarding can complete.`n`nSteps taken:`n$InstallResults"
  Write-RebootInformation -Message "Windows Defender for Endpoint onboarding script successfully ran on computer $ComputerName but a reboot is required before onboarding can complete.`n`nSteps taken:`n$InstallResults"
}

#Reboot computer if needed and RebootIfNeeded value is set to true
if ($RebootIfNeeded -eq 'true' -and $Status -eq 'SuccessRebootNeeded') {
  Restart-Computer  -Force
}
