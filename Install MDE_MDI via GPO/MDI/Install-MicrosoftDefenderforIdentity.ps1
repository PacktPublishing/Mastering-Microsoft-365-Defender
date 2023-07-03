<#
.VERSION 1.0
1.0 - Init version

.DESCRIPTION
Install and register Microsoft Defender for Identity Agent with a Scheduled Task


.NOTES
Author: Truesec Cyber Security Incident Response Team
Website: https://truesec.com/
>> Created: 2023-01-09


.DISCLAIMER
Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.

#>

[CmdletBinding()]
Param(
    $Config
)

Function Invoke-Exe{
    [CmdletBinding(SupportsShouldProcess=$true)]

    param(
        [parameter(mandatory=$false,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Executable,

        [parameter(mandatory=$false,position=1)]
        [string]
        $Arguments
    )

    if($Arguments -eq "")
    {
        Write-Verbose "Running $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru"
        $ReturnFromEXE = Start-Process -FilePath $Executable -NoNewWindow -Wait -Passthru
    }else{
        Write-Verbose "Running $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru"
        $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru
    }
    Write-Verbose "Returncode is $($ReturnFromEXE.ExitCode)"
    Return $ReturnFromEXE.ExitCode
}
Function Get-OSVersion{
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    Switch -Regex ($OS.Version)
    {
    "6.1"
        {
        If($OS.ProductType -eq 1)
            {$OSv = "Windows 7 SP1"}
                Else
            {$OSv = "Windows Server 2008 R2"}
        }
    "6.2"
        {If($OS.ProductType -eq 1)
            {$OSv = "Windows 8"}
                Else
            {$OSv = "Windows Server 2012"}
        }
    "6.3"
        {If($OS.ProductType -eq 1)
            {$OSv = "Windows 8.1"}
                Else
            {$OSv = "Windows Server 2012 R2"}
        }
    "10."
        {If($OS.ProductType -eq 1)
            {$OSv = "Windows 10"}
                Else
            {$OSv = "Windows Server 2016"}
        }
    DEFAULT {$OSv = "Unknown"}
    }
    Return $OSV
}
Function Import-SMSTSENV{
    try
    {
        $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
        Write-Output "$ScriptName - tsenv is $tsenv "
        $MDTIntegration = "YES"
        
        #$tsenv.GetVariables() | % { Write-Output "$ScriptName - $_ = $($tsenv.Value($_))" }
    }
    catch
    {
        Write-Output "$ScriptName - Unable to load Microsoft.SMS.TSEnvironment"
        Write-Output "$ScriptName - Running in standalonemode"
        $MDTIntegration = "NO"
    }
    Finally
    {
    if ($MDTIntegration -eq "YES"){
        $Logpath = $tsenv.Value("LogPath")
        $LogFile = $Logpath + "\" + "$ScriptName.txt"

    }
    Else{
        $Logpath = $env:TEMP
        $LogFile = $Logpath + "\" + "$ScriptName.txt"
    }
    }
}
Function Start-Logging{
    start-transcript -path $LogFile -Force
}
Function Stop-Logging{
    Stop-Transcript
}
Function Test-TSXDomainController {
  if((Get-Service | Where-Object Name -EQ KDC).Count -ge 1){
    $true
  }
  else{
    $false
  }
}

# Set Vars
$SCRIPTDIR = Split-Path -parent $MyInvocation.MyCommand.Path
$SCRIPTNAME = Split-Path -leaf $MyInvocation.MyCommand.Path
$SOURCEROOT = "$SCRIPTDIR\Source"
$LANG = (Get-Culture).Name
$ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE

#Try to Import SMSTSEnv
. Import-SMSTSENV

#Start Transcript Logging
. Start-Logging

#Detect current OS Version
$OSVersion = Get-OSVersion

#Output base info
Write-Host ""
Write-Host "$ScriptName - ScriptDir: $ScriptDir"
Write-Host "$ScriptName - SourceRoot: $SOURCEROOT"
Write-Host "$ScriptName - ScriptName: $ScriptName"
Write-Host "$ScriptName - OS Name: $OSVersion"
Write-Host "$ScriptName - OS Architecture: $ARCHITECTURE"
Write-Host "$ScriptName - Current Culture: $LANG"
Write-Host "$ScriptName - Integration with MDT(LTI/ZTI): $MDTIntegration"
Write-Host "$ScriptName - Log: $LogFile"


$Key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=='

if ($Key -eq 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==') {
    Throw 'Customer specific access key not added to script.'
}

$InstallerFile = Get-ChildItem -Path $SOURCEROOT -Filter "Azure ATP Sensor Setup.exe"
$EXE = $InstallerFile.FullName
$Arguments = "/quiet NetFrameworkCommandLineArguments='/q' AccessKey=$Key"

if (Test-TSXDomainController) {
    if (!(Get-Service -Name 'AATPSensor' -ErrorAction SilentlyContinue)) {
        Write-Output "$ScriptName - Invoke-Exe -Executable $Exe -Arguments $Arguments"
        Invoke-Exe -Executable $Exe -Arguments $Arguments
    }
}

#Stop Logging
. Stop-Logging