#!/usr/local/bin/powershell
#Requires -Version 3 -Module PSLogger

<#
    .SYNOPSIS
    The Sperry 'autopilot' module includes functions to automate changes related to working in a specific office network environment, vs working elsewhere, or remotely
    .DESCRIPTION
    Customizes the user's operating environment and launches specified applications, to operate in a workplace persona
    The module includes functions such as ProfileSync, CheckProcess, and utilizes the Write-Log function from the PSLogger Module.
    .NOTES
    NAME     : Sperry.ps1
    LANGUAGE : Windows PowerShell
    AUTHOR   : Bryan Dady
    DATE     : 11/2/2015

#>
#========================================
[CmdletBinding(SupportsShouldProcess)]
param ()

# Enforce coding rules in expressions, scripts, and script blocks based on latest available rules; un-comment for dev, re-comment for release

# Define PSUpdateDate variable and populate from persistent state settings file
New-Variable -Name PSHelpUpdatedDate -Description 'Date/time stamp of the last Update-Help run' -Scope Global -Force
Write-Output -InputObject 'Importing shared saved state info from Microsoft.PowerShell_state.json to custom object: $PSState'
try {
    $Global:PSState = (Get-Content -Path $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json -ErrorAction Ignore) -join "`n" | ConvertFrom-Json
}
catch {
    Write-Warning -Message "Unable to load PowerShell saved state info from $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json to custom object: `$PSState"
}   

if ((Get-WmiObject -Class Win32_OperatingSystem -Property Caption).Caption -like '*Windows Server*')
{
  [bool]$onServer = $true
}
else
{
  [bool]$onServer = $false
}

# Functions
#========================================
# FYI this same function is also globally defined in ProfilePal module
Function global:Test-LocalAdmin {
  Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

Function Import-Settings {
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  
  $Script:SettingsFileName = 'Sperry.json'
  # Enhancement : support -Force parameter
  if (Get-Variable -Name Settings -Scope Global -ErrorAction Ignore)
  {
    Remove-Variable -Name Settings -Scope Global
  }
  
  Write-Debug -Message "`$Global:Settings = (Get-Content -Path $(join-path -Path $(Split-Path -Path $((Get-PSCallStack).ScriptName | Sort-Object -Unique) -Parent) -ChildPath $Script:SettingsFileName)) -join ""``n"" | ConvertFrom-Json"
  try {
    $Global:Settings = (Get-Content -Path $(join-path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath $Script:SettingsFileName)) -join "`n" | ConvertFrom-Json
    Write-Verbose -Message 'Settings imported. Run Show-Settings to see details.' 
  }
  catch {
    write-warning -Message 'Critical Error loading settings from from sperry.json'
  }
}

Write-Verbose -Message 'Import Sperry configs'
Import-Settings

Function Show-Settings {
  <#
      .SYNOPSIS
      Shows current contents of module's custom settings data structure 

      .DESCRIPTION
      In order to show settings, the settings must first be retrieved from the json file.
      If the Settings variable is not yet populated, then Import-Settings funciton is invoked first 

      .EXAMPLE
      Show-Settings
      
      json_description : User customization for PowerShell Sperry module.
      version          : 0.1.6
      updated          : 11-21-2016
      XenApp           : {@{Name=Assyst; QLaunch=GBCI02XA:Assyst}, @{Name=cmd; QLaunch=GBCI02XA:Command Line}, @{Name=Excel;
      QLaunch=GBCI02XA:Microsoft Excel 2010}, @{Name=Firefox; QLaunch=GBCI02XA:FireFox}...}
      KnownProcess     : {@{Name=Brave; Path=$env:LOCALAPPDATA\brave\Update.exe}, @{Name=CodeInsider;
      Path=${env:ProgramFiles(x86)}\Microsoft VS Code Insiders\bin\code-insiders.cmd}, @{Name=GitHub;
      Path=$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GitHub, Inc\GitHub.appref-ms},
      @{Name=iexplore; Path=$env:ProgramFiles\Internet Explorer\iexplore.exe}...}
      UNCPath          : {@{DriveName=H; FullPath=\\hcdata\homes$\gbci\$env:USERNAME}, @{DriveName=I;
      FullPath=\\hcdata\homes$\gbci\$env:USERNAME`2}, @{DriveName=R; FullPath=\\hcdata\apps},
      @{DriveName=S; FullPath=\\hcdata\gbci\shared\it}...}
      Workplace        : @{Office=System.Object[]; Remote=System.Object[]}
      Network          : @{SSID=Halcyon}
      configurations   : {@{name=PowerShell; type=PowerShell; program=Sperry.psm1}}

  #>
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  
  if (-not (Get-Variable -Name Settings -Scope Global -ErrorAction Ignore))
  {
    Write-Verbose -Message 'Import Sperry configs'
    Import-Settings
  }
  
  Write-Output -InputObject "`n # Showing `$Global:Settings, as imported from $Script:SettingsFileName #"
  Write-Output -InputObject $Global:Settings
}

function Mount-Path {
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp

  # $AllDrives = 1 (true) means map all drives; 0 (false) means only map H: and S:
  Write-Log -Message 'Mapping Network Drives' -Function $MyInvocation.MyCommand.Name -Verbose
  if (Test-LocalAdmin) { Write-Log -Message 'Mapping drives with a different account, may result in them NOT appearing properly in Explorer' -Function $MyInvocation.MyCommand.Name }

  # Read in UNC path / drive letter mappings from sperry.json : Sperry.uncPaths
  # loop through all defined drive mappings
  $Global:Settings.UNCPath | ForEach-Object {
    $DriveName = $ExecutionContext.InvokeCommand.ExpandString($PSItem.DriveName)
    $PathRoot   = $ExecutionContext.InvokeCommand.ExpandString($PSItem.FullPath)

    if (Test-Path -Path ('{0}:\' -f $DriveName)) {
      Write-Warning -Message ('Drive letter {0} already in use.' -f $DriveName)
    }
    elseif (-not (Test-Path -Path $PathRoot)) {
      Write-Warning -Message ('Path {0} was not found; unable to map to drive letter {1}' -f $PathRoot, $DriveName)            
    }
    else
    {
      Write-Log -Message ('New-PSDrive {0}: {1}' -f $DriveName, $PathRoot) -Function 'Mount-Path'
      Write-Debug -Message (' New-PSDrive -Persist -Name {0} -Root {1} -PSProvider FileSystem -scope Global' -f $DriveName, $PathRoot)
      New-PSDrive -Name $DriveName -Root $PathRoot -PSProvider FileSystem -Persist -scope Global -ErrorAction:SilentlyContinue
      Start-Sleep -Milliseconds 500
    }
  }
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

# Define Get-PSFSDrive function -- specifies invoking Get-PSDrive, for -PSProvider FileSystem 
function Get-PSFSDrive {
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Write-Log -Message 'Enumerating mapped network drives' -Function $MyInvocation.MyCommand.Name
  get-psdrive -PSProvider FileSystem 
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

# Define Dismount-Path function
function Dismount-Path {
  [CmdletBinding(SupportsShouldProcess)]
  param (
  )
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name
  get-psdrive -PSProvider FileSystem | ForEach-Object {
    if ($PSItem.DisplayRoot -like '\\*') {
      Write-Log -Message ('Remove-PSDrive {0}: {1}' -f $PSItem.Name, $PSItem.DisplayRoot) -Function $MyInvocation.MyCommand.Name
      Remove-PSDrive -Name $PSItem
    }
  }
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

function Connect-WiFi {
  <#
      .SYNOPSIS
      Connect to a named WiFi network
      .DESCRIPTION
      Checks 1st that Sophos Firewall is stopped, identifies available wireless network adapters and then connects them to a named network (SSID) using the netsh.exe wlan connect command syntax
      .EXAMPLE
      Connect-WiFi 'Starbucks'
      
      Attempts to connect the wireless network adapter(s) to SSID 'Starbucks'

      Starbucks - shows the WiFi SSID connected to
      True - indicates the netsh command returned successful

      .EXAMPLE
      Connect-WiFi
      Attempts to connect the wireless network adapter to the default SSID
      The function contains a default SSID variable, for convenience
  #>
  [CmdletBinding(SupportsShouldProcess)]
  [OutputType([string])]
  param (
    [Parameter(
        Mandatory,
        Position=0,
        HelpMessage='Specify name of wireless (WiFi) network SSID to connect to'
    )]
    [Alias('NetworkName','NetworkID','WiFi')]
    [String]
    $SSID
    ,
    [Parameter(
        Position=1
    )]
    [Alias('AdapterName')]
    [string]
    $ConnectionID = 'Wireless'
    ,
    [Parameter(
        Position=2
    )]
    [Alias('sleep','pause','delay')]
    [ValidateRange(1,60)]
    [int]
    $WaitTime = 10
  )

  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Set-ServiceGroup -Name 'Sophos Client Firewall*' -Status Stopped

#  ForEach-Object -InputObject @(Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)) {
    Write-Log -Message ("Connecting {0} to {1}" -f $PSItem.NetConnectionID, $SSID) -Function $MyInvocation.MyCommand.Name
#    if ($PSItem.Availability -ne 3) {
    if ((Get-NetConnStatus -ConnectionID $ConnectionID | Select-Object -Property Availability) -ne 3)
    {
      if (Test-LocalAdmin) {
        if (($PSItem.enable()).ReturnValue -eq 0) {
          Write-Log -Message 'Adapter Enabled' -Function $MyInvocation.MyCommand.Name
        } else {
          throw ("A fatal error was encountered trying to enable Network Adapter {0} (Device {1})" -f $PSItem.Name,$PSItem.DeviceID)
        }
      } else {
        Write-Log -Message 'Attempting to invoke new powershell sessions with RunAs (elevated permissions) to enable adapter via' -Function $MyInvocation.MyCommand.Name
        Open-AdminConsole -Command {ForEach-Object -InputObject @(Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)) { ($PSItem.enable()).ReturnValue }}
        if ($return -eq 0)
        {
          Write-Log -Message 'Adapter Enabled' -Function $MyInvocation.MyCommand.Name
        }
        else
        {
          Write-Log -Message ("A fatal error was encountered trying to enable Network Adapter {0} (Device {1})" -f $PSItem.Name,$PSItem.DeviceID) -Verbose
        }
      }
      Start-Sleep -Seconds 1
    }

    Write-Log -Message "netsh.exe wlan connect $SSID" -Function $MyInvocation.MyCommand.Name
    $results = Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan connect "$SSID"}
    Write-Log -Message $results -Function $MyInvocation.MyCommand.Name
    Start-Sleep -Seconds $WaitTime
#  }
  return $results

  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp

}

function Disconnect-WiFi {
  <#
      .SYNOPSIS
      Disconnect from any/all WiFi networks
      .DESCRIPTION
      Designed as a complement to Connect-WiFi, this disconnect function automates disconnecting from wifi, e.g. for when setting into Office workplace
      .EXAMPLE
      .> Disconnect-WiFi

      True - indicates the netsh command returned successful
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name

  if($PSCmdlet.ShouldProcess( 'Disconnected wlan', "Disconnect wlan`?", 'Disconnecting wlan' ))
  {
    $results = Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan disconnect}
    return $results
  }
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

function Get-WiFi {
  <#
      .SYNOPSIS
      List Availability WiFi networks
      .DESCRIPTION
      Designed as a complement to Connect-WiFi, this function pulls available wifi network SIDs into this PowerShell context
      .EXAMPLE
      .\> Get-WiFi
  #>
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Write-Log -Message 'netsh.exe wlan show networks' -Function $MyInvocation.MyCommand.Name -Verbose
  Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan show networks}
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

function Get-IPAddress {
<#
    .SYNOPSIS
    Returns Adapter description, IP Address, and basic DHCP info.
    .DESCRIPTION
    Uses Get-WmiObject -Class Win32_NetworkAdapterConfiguration queries, for IP enabled network adapters, this function returns the IP Addresses (IPv4 and IPv6, if available), default gateway, DNS server list, and adapter description and index.
    .EXAMPLE
    PS C:\> Get-IPAddress
    Get-IPAddress
    Logging to $env:USERPROFILE\Documents\WindowsPowerShell\log\Get-IPAddress_20150430.log

    SiteName           : Unrecognized
    AdapterHost        : ComputerName
    Gateway            : {192.168.1.11}
    IPAddress          : {192.168.1.106}
    DNSServers         : {192.168.0.1, 208.67.220.220, 208.67.222.222}
    AdapterDescription : Intel(R) Wireless-N 7260
    .EXAMPLE
    PS C:\> Get-IPAddress.IPAddress
    # Returns only the IP Address(es) of DHCP enabled adapters, as a string
    10.10.101.123
    .NOTES
    NAME        :  Get-IPAddress
    VERSION     :  1.0.1
    LAST UPDATED:  5/1/2015
    AUTHOR      :  Bryan Dady
    .INPUTS
    None
    .OUTPUTS
    Write-Log
#>
  New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private
  Get-WmiObject -Class Win32_NetworkAdapterConfiguration  -Filter 'IpEnabled = True AND DhcpEnabled = True' |
  ForEach-Object -Process {
    #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
    $Private:properties = [ordered]@{
      'AdapterHost'        =$PSItem.PSComputerName
      'AdapterDescription' =$PSItem.Description
      'IPAddress'          =$PSItem.IPAddress
      'Gateway'            =$PSItem.DefaultIPGateway
      'DNSServers'         =$PSItem.DNSServerSearchOrder
    }
    $Private:RetObject = New-Object -TypeName PSObject -Property $properties

    return $RetObject # $OutputObj
  } # end of foreach
} # end function Get-IPAddress

function Redo-DHCP {
  <#
      .SYNOPSIS
      Release / Renew DHCP lease for all DHCP enabled IP-based network adapters
      .EXAMPLE
      PS C:\> Redo-DHCP
      Functionally equivalent to: ipconfig /release - wait - ipconfig /renew
      .NOTES
      NAME        :  Redo-DHCP
      VERSION     :  1.0.0
      LAST UPDATED:  4/30/2015
      .LINK
      https://gallery.technet.microsoft.com/scriptcenter/Renew-IP-Adresses-Using-365f6bfa
  #>
  $Private:ethernet = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true}

  foreach ($Private:adapter in $Private:ethernet) {
    Write-Debug -Message 'Releasing IP Address'
    Start-Sleep -Seconds 2
    $Private:adapter.ReleaseDHCPLease() | out-Null
    Write-Debug -Message 'Renewing IP Address'
    $Private:adapter.RenewDHCPLease() | out-Null
    Write-Log -Message ('IP address is {0} with Subnet {1}' -f $adapter.IPAddress, $adapter.IPSubnet) -Function $MyInvocation.MyCommand.Name
  }
  return Get-IPAddress
}

function Set-UAC {
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  # Check current UAC level via registry
  # We want ConsentPromptBehaviorAdmin = 5
  # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
  if (((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin) -ne 5)
  { # prompt for UAC update
    Write-Log -Message 'Opening User Account Control Settings dialog ...' -Function $MyInvocation.MyCommand.Name
    & $env:SystemDrive\Windows\System32\UserAccountControlSettings.exe
  }
  Start-Sleep -Seconds 5

  # Wait for UAC to be complete before proceeding
  Test-ProcessState -ProcessName 'UserAccountControlSettings' -Wait

  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

function Set-Workplace {
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(
        Mandatory,
        Position=0,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage='Specify workplace zone, or context, as defined in Sperry.json.'
    )]
    [String]
    [alias('mode','scope')]
    [ValidateScript({$PSItem -in $Global:Settings.Workplace.Name})]
    $Zone
  )
  $loggingTag = $MyInvocation.MyCommand.Name
  Show-Progress -msgAction Start -msgSource $MyInvocation.MyCommand.Name

  # Always simplify UAC prompt level, so we run this before {switching ($zone)}
  Write-Log -Message 'Checking UserAccountControl level' -Function $loggingTag
  Set-UAC

  Write-Log -Message "Loading settings for Workplace $zone as defined in $SettingsFileName." -Function $loggingTag -Verbose
  $MySettings = $Global:Settings.Workplace | Where-Object -FilterScript {$PSItem.Name -eq $zone}

  if ($MySettings.function_before) {
    $MySettings.function_before | ForEach-Object -Process {
      Write-Debug -Message "Function $($PSItem.Name) - Message: $($PSItem.Message)"
      Write-Log -Message "$($PSItem.Message)" -Function $loggingTag
      Invoke-Expression -Command $PSItem.Name
      Start-Sleep -Milliseconds 777
    }
  } else {
    Write-Log '$MySettings.function_before was not found.' -Function $loggingTag
  }

  if ($MySettings.ServiceGroup) {
    $MySettings.ServiceGroup | ForEach-Object -Process {
      Write-Log -Message ('{0}' -f $PSItem.Message) -Function $loggingTag
      Set-ServiceGroup -Name $PSItem.Name -Status $PSItem.Status
      Start-Sleep -Milliseconds 777
    }
  } else {
    Write-Log '$MySettings.ServiceGroup was not found.' -Function $loggingTag
  }

  if ($MySettings.ProcessState) {
    $MySettings.ProcessState | ForEach-Object -Process {
      Write-Log -Message ('{0}' -f $PSItem.Message) -Function $loggingTag
      Set-ProcessState -Name $PSItem.Name -Action $PSItem.Action
      Start-Sleep -Milliseconds 777
    }
  } else {
    Write-Log '$MySettings.ProcessState was not found.' -Function $loggingTag
  }

  # Update IE home page
  Write-Log -Message 'Setting Internet Explorer start page to $($MySettings.IEHomePage)' -Function $loggingTag
  Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $MySettings.IEHomePage -force -ErrorAction Ignore
  Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $MySettings.IEHomePage -force -ErrorAction Ignore

  # Set preferred / defined default browser
  Write-Log -Message "Setting URL Progid to $($MySettings.BrowserProgid)" -Function $loggingTag
  Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value $MySettings.BrowserProgid
  Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value $MySettings.BrowserProgid

  $MySettings.function_after | ForEach-Object -Process {
    Write-Log -Message "$($PSItem.Message)" -Function $PSItem.Name
    Invoke-Expression -Command $PSItem.Name
    Start-Sleep -Milliseconds 777
  }

  Write-Output -InputObject 'If you''d like to (re)open all Desktop Documents, run Show-DesktopDocuments'

  Show-Progress -msgAction Stop -msgSource $loggingTag  # Log end time stamp

  return ('Ready for {0} work' -f $zone)
}

Function Open-Browser
{
  [CmdletBinding()]
  param (
    [Parameter(
        Mandatory,
        Position=0,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage='URL to open in default web browser.'
    )]
    [ValidatePattern({^https?:\/\/?.+\.\w{2,6}})]
    [String]
    [alias('address','site')]
    $URL
  )

  Write-Verbose -Message "Start-Process -FilePath $URL"
  Start-Process -FilePath $URL
}

Function Show-DesktopDocuments
{
  Write-Log -Message 'Opening all Desktop Documents' -Function $MyInvocation.MyCommand.Name
  # Open all desktop PDF files
  Get-ChildItem -Path $env:USERPROFILE\Desktop\*.pdf | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 400}
  # Open all desktop Word doc files
  Get-ChildItem -Path $env:USERPROFILE\Desktop\*.doc* | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 800}
}
