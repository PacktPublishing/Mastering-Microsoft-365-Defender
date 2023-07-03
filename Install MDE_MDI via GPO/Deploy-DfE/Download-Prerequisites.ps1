<#
.DESCRIPTION
  Download needed updates for Defender for Endpoint
  If -Path is not set, updates will be saved to same directory as the script.
.EXAMPLE
  PS C:\> C:\Temp\Download-Prerequisites.ps1
  Download Patches to
      C:\Temp\dotNET
      C:\Temp\KBs
      C:\Temp\MMAgent

#>


[CmdletBinding()]
param (
  [Parameter(Mandatory = $false)]
  [string]
  $Path = $PSScriptRoot
)

# List of files to be downloaded
$PatchURL = @{
  # Updates
  "KBs\Windows6.1-KB3080149-x64.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows6.1-kb3080149-x64_f25965cefd63a0188b1b6f4aad476a6bd28b68ce.msu"
  "KBs\windows6.1-kb3080149-x86.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows6.1-kb3080149-x86_3d35229a4f48ada7b2a0ef048dd424bc2eae63ca.msu"
  "KBs\windows6.1-kb4074598-x64.msu"   = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/02/windows6.1-kb4074598-x64_87a0c86bfb4c01d9c32d2cd3717b73c1b83cb798.msu"
  "KBs\windows6.1-kb4074598-x86.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/02/windows6.1-kb4074598-x86_0d2b75cacdc29b6fc557c426a62922fe277a2063.msu"
  "KBs\Windows8.1-KB2999226-x64.msu"   = "https://download.microsoft.com/download/9/6/F/96FD0525-3DDF-423D-8845-5F92F4A6883E/Windows8.1-KB2999226-x64.msu"
  "KBs\Windows8.1-KB2999226-x86.msu"   = "https://download.microsoft.com/download/E/4/6/E4694323-8290-4A08-82DB-81F2EB9452C2/Windows8.1-KB2999226-x86.msu"
  "KBs\Windows8.1-KB3080149-x64.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows8.1-kb3080149-x64_4254355747ba7cf6974bcfe27c4c34a042e3b07e.msu"
  "KBs\Windows8.1-KB3080149-x86.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows8.1-kb3080149-x86_cde14a122cd474335c4327afeb109be06377750f.msu"
  "KBs\windows8.1-kb4462921-x64.msu"   = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2018/10/windows8.1-kb4462921-x64_ac21d4ad649316b496483d21ddd89721cf0814d9.msu"
  "KBs\windows10.0-kb4462928-x64.msu"  = "http://download.windowsupdate.com/c/msdownload/update/software/updt/2018/10/windows10.0-kb4462928-x64_c3c3bd7c809ed0a53afab205ccbc229556f384c7.msu"
  "KBs\windows10.0-kb5005698-x64.msu"  = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2021/09/windows10.0-kb5005698-x64_ff882b0a9dccc0c3f52673ba3ecf4a2a3b2386ca.msu"
  "KBs\updateplatform-x64.exe"         = "http://download.windowsupdate.com/c/msdownload/update/software/defu/2023/01/updateplatform_cca39b7c461f636e4d94fa20ac9ee842ae7a9caf.exe"
  
  # Dotnet 4.8 Offline installer
  "dotNET\ndp48-x86-x64-allos-enu.exe" = "https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe"
  # MMA Agent
  "MMASetupx64.exe"                    = "https://go.microsoft.com/fwlink/?LinkId=828603"
  "MMASetupx86.exe"                    = "https://go.microsoft.com/fwlink/?LinkId=828604"

}

# Load webclient
$WebClient = New-Object System.Net.WebClient


# Create Folders to downlaod files to
New-Item -ItemType Directory -Path $Path -Name KBs -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Path -Name dotNET -ErrorAction SilentlyContinue

Write-Host "Downloading files to $Path"

# Loop url's and download the files
$PatchURL.GetEnumerator() | ForEach-Object {

  # Set filename and url to a variable
  $url = $_.Value
  $FileName = $_.Name

  # Download the file
  try {
    Write-Host "Downloading to: $Path\$FileName"
    $WebClient.DownloadFile($url, "$Path\$FileName")
    Write-Host "Done" -ForegroundColor Green

  }
  catch {
    Write-Warning "Could not download $Filename - $($_)"

  }

}

Write-Host "Unblock MMAgent setup and extract to MMAgent folder.."
Unblock-File $Path\MMASetupx64.exe
Unblock-File $Path\MMASetupx86.exe

# Extract MMAgent
Start-Process $Path\MMASetupx64.exe -ArgumentList "/C /T:""$Path\MMAgent"" /Q" -Wait
Start-Process $Path\MMASetupx86.exe -ArgumentList "/C /T:""$Path\MMAgent\x86"" /Q" -Wait

Remove-Item $Path\MMASetupx64.exe -Confirm:$false -Force
Remove-Item $Path\MMASetupx86.exe -Confirm:$false -Force

Write-Warning "The new MdE Agent (md4ws.msi) is not downloaded"

