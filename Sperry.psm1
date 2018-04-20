#!/usr/local/bin/pwsh
#Requires -Version 3 -Module PSLogger

<#
    .SYNOPSIS
    The Sperry 'autopilot' module includes functions to automate changes related to working in a specific office network environment, vs working elsewhere, or remotely
    .DESCRIPTION
    Customizes the user's operating environment and launches specified applications, to operate in a workplace persona
    The module includes functions such as ProfileSync, CheckProcess, and utilizes the Write-Log function from the PSLogger Module.
    .NOTES
    NAME     : Sperry.psm1
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

Set-Variable -Name MySettings -Description 'Sperry Settings' -Option AllScope

Write-Output -InputObject 'Importing shared saved state info from Microsoft.PowerShell_state.json to custom object: $PSState'
try {
    $Global:PSState = (Get-Content -Path $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json -ErrorAction Ignore) -join "`n" | ConvertFrom-Json
}
catch {
    Write-Warning -Message "Unable to load PowerShell saved state info from $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json to custom object: `$PSState"
}   

if ((Get-WmiObject -Class Win32_OperatingSystem -Property Caption).Caption -like '*Windows Server*') {
  [bool]$onServer = $true
} else {
  [bool]$onServer = $false
}

# Functions
#========================================
# FYI this same function is also globally defined in ProfilePal module
function Test-LocalAdmin {
    <#
        .SYNOPSIS
            Test if the current user of the current host (e.g. Console) have Admin permissions; returns simple boolean result
        .DESCRIPTION
            Updated to take advantage of the automatic variable $IsAdmin added in v4.0
    #>
    if ((Get-Variable -Name IsAdmin -ErrorAction Ignore) -eq $true) {
    Return $IsAdmin
  } else {
    Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')
  }
} # end function Test-LocalAdmin

function Import-Settings {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SettingsFileName = 'Sperry.json'
    )
  
    # Enhancement : support -Force parameter
    if (Get-Variable -Name MySettings -Scope Global -ErrorAction Ignore) {
        Remove-Variable -Name MySettings -Scope Global
    }
    Write-Debug -Message ('$JSONPath = Join-Path -Path $(Split-Path -Path {0} -Parent) -ChildPath {1}' -f $PSCommandPath, $SettingsFileName)
    $JSONPath = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath $SettingsFileName
    Write-Verbose -Message ('$MySettings = (Get-Content -Path {0}) -join "`n" | ConvertFrom-Json' -f $JSONPath)
    $MySettings = (Get-Content -Path $JSONPath) -join "`n" | ConvertFrom-Json

    if ($MySettings.About) {
        Write-Verbose -Message 'Settings imported. Run Show-Settings to see details.'
        $MySettings | Select-Object -ExpandProperty About
    } else {
        Write-Warning -Message ('Critical Error loading settings from {0}' -f $JSONPath)
    }
    <#
        .SYNOPSIS
        Import (Initialize) module settings from a specified JSON file

        .DESCRIPTION

        .EXAMPLE
        PS .\>Import-Settings -SettingsFileName sperry-template.json

        name        : Sperry PowerShell Module
        type        : PowerShell
        program     : Sperry.psm1
        description : User customization for PowerShell Sperry module
        version     : 1.0.0
        updated     : 11-1-2017
        notes       : consolidated information to new 'about' category

    #>
} # end function Import-Settings

Write-Verbose -Message 'Import Sperry configs'
Import-Settings

function Show-Settings {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SettingsFileName = 'Sperry.json'
    )

    if (-not (Get-Variable -Name MySettings -ErrorAction Ignore)) {
        Write-Verbose -Message ('Import Sperry config as defined in {0}' -f $SettingsFileName)
        Import-Settings -SettingsFileName $SettingsFileName
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message ' # Showing $MySettings, for Sperry module #'
    return $MySettings

    <#
        .SYNOPSIS
        Shows current contents of module's custom settings data structure 

        .DESCRIPTION
        In order to show settings, the settings must first be retrieved from the json file.
        If the Settings variable is not yet populated, then Import-Settings funciton is invoked first 

        .EXAMPLE
        Show-Settings | select -ExpandProperty About
        
        name        : Sperry PowerShell Module
        type        : PowerShell
        program     : Sperry.psm1
        description : User customization for PowerShell Sperry module
        version     : 0.1.11
        updated     : 11-28-2017
        notes       : consolidated information to new 'about' category

        .EXAMPLE
        Show-Settings

        About        : {@{name=Sperry PowerShell Module; type=PowerShell; program=Sperry.psm1; description=User customization for PowerShell Sperry module; version=1.0.0; updated=11-1-2017; notes=consolidated information to new 'about' category}}
        KnownProcess : {@{Name=Chrome; Path=${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe}, @{Name=Code; Path=$env:ProgramFiles\Microsoft VS Code\code.exe}, @{Name=CodeInsider; Path=$env:ProgramFiles\Microsoft VS Code Insiders\bin\code-insiders.cmd}, @{Name=GitHub; Path=$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GitHub, Inc\GitHub.appref-ms}...}
        UNCPath      : {@{DriveName=H; FullPath=\\SMB-FQDN\ShareRoot$\$env:USERNAME}}
        Workplace    : {@{Name=Remote; function_before=System.Object[]; ServiceGroup=System.Object[]; IEHomePage=https://personal.BrowserHomePage.url; BrowserProgid=ChromeHTML; ProcessState=System.Object[]; function_after=System.Object[]}, @{Name=Office; function_before=System.Object[]; ServiceGroup=System.Object[]; IEHomePage=https://corporate.BrowserHomePage.url; BrowserProgid=IE.HTTPS; function_after=System.Object[]}}
    #>
} # end function Show-Settings

function Mount-Path {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp

    if (-not $MySettings.UNCPath) {
        Import-Settings
    }
    # $AllDrives = 1 (true) means map all drives; 0 (false) means only map H: and S:
    Write-Log -Message 'Mapping Network Drives' -Function $MyInvocation.MyCommand.Name
    if (Test-LocalAdmin) { Write-Log -Message 'Mapping drives with a different account, may result in them NOT appearing properly in Explorer' -Function $MyInvocation.MyCommand.Name }

    # Read in UNC path / drive letter mappings from sperry.json : Sperry.uncPaths
    # loop through all defined drive mappings
    $MySettings.UNCPath | ForEach-Object {
        Write-Debug -Message ('$PSItem.DriveName: {0}' -f $PSItem.DriveName)
        Write-Debug -Message ('$PSItem.FullPath: {0}' -f $PSItem.FullPath)
        $DriveName = $ExecutionContext.InvokeCommand.ExpandString($PSItem.DriveName)
        $PathRoot  = $ExecutionContext.InvokeCommand.ExpandString($PSItem.FullPath)
        Write-Verbose -Message ('$DriveName: {0}' -f $DriveName)
        Write-Verbose -Message ('$PathRoot: {0}' -f $PathRoot)
        
        if (Test-Path -Path ('{0}:\' -f $DriveName)) {
            # Write-Warning -Message ('Drive letter {0} already in use.' -f $DriveName)
            Write-Log -Message ('Drive letter {0} already in use' -f $DriveName) -Function 'Mount-Path'
        } elseif (-not (Test-Path -Path $PathRoot)) {
            # Write-Warning -Message ('Path {0} was not found; unable to map to drive letter {1}' -f $PathRoot, $DriveName)            
            Write-Log -Message ('Path {0} was not found; unable to map to drive letter {1}' -f $PathRoot, $DriveName) -Function 'Mount-Path'
        } else {
            Write-Log -Message ('New-PSDrive {0}: {1}' -f $DriveName, $PathRoot) -Function 'Mount-Path'
            Write-Debug -Message (' New-PSDrive -Persist -Name {0} -Root {1} -PSProvider FileSystem -scope Global' -f $DriveName, $PathRoot)
            New-PSDrive -Name $DriveName -Root $PathRoot -PSProvider FileSystem -Persist -scope Global -ErrorAction:SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Mount-Path

# Define Get-PSFSDrive function -- specifies invoking Get-PSDrive, for -PSProvider FileSystem 
function Get-PSFSDrive {
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Enumerating mapped network drives' -Function $MyInvocation.MyCommand.Name
    Get-PSDrive -PSProvider FileSystem
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Get-PSFSDrive

# Define Dismount-Path function
function Dismount-Path {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        if ($PSItem.DisplayRoot -like '\\*') {
            Write-Log -Message ('Remove-PSDrive {0}: {1}' -f $PSItem.Name, $PSItem.DisplayRoot) -Function $MyInvocation.MyCommand.Name
            Remove-PSDrive -Name $PSItem
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Dismount-Path

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
    Write-Log -Message 'netsh.exe wlan show networks' -Function $MyInvocation.MyCommand.Name
    Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan show networks}
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Get-WiFi

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

  # Check and conditionally open UAC window, before invoking repeated elevated commands
  Write-Log -Message 'Checking UserAccountControl level' -Function $MyInvocation.MyCommand.Name
  Open-UAC
  
  Set-ServiceGroup -Name '*Firewall*' -Status Stopped

    Write-Log -Message ('Connecting {0} to {1}' -f $ConnectionID, $SSID) -Function $MyInvocation.MyCommand.Name

    if ((Get-NetConnStatus -ConnectionID $ConnectionID | Select-Object -Property Availability) -ne 3) {
      if (Test-LocalAdmin) {
        if (($PSItem.enable()).ReturnValue -eq 0) {
          Write-Log -Message 'Adapter Enabled' -Function $MyInvocation.MyCommand.Name
        } else {
          throw ('A fatal error was encountered trying to enable Network Adapter {0} (Device {1})' -f $PSItem.Name,$PSItem.DeviceID)
        }
      } else {
        Write-Log -Message 'Attempting to invoke new powershell sessions with RunAs (elevated permissions) to enable adapter via' -Function $MyInvocation.MyCommand.Name
        Open-AdminConsole -Command {ForEach-Object -InputObject @(Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)) { ($PSItem.enable()).ReturnValue }}
        if ($return -eq 0) {
          Write-Log -Message 'Adapter Enabled' -Function $MyInvocation.MyCommand.Name
        } else {
          Write-Log -Message ('A fatal error was encountered trying to enable Network Adapter {0} (Device {1})' -f $PSItem.Name,$PSItem.DeviceID)
        }
      }
      Start-Sleep -Seconds 1
    }

    Write-Log -Message ('netsh.exe wlan connect {0}' -f $SSID) -Function $MyInvocation.MyCommand.Name
    $results = Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan connect "$SSID"}
    Write-Log -Message $results -Function $MyInvocation.MyCommand.Name
    Start-Sleep -Seconds $WaitTime

    return $results

  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp

} # end function Connect-WiFi

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

  if($PSCmdlet.ShouldProcess( 'Disconnected wlan', "Disconnect wlan`?", 'Disconnecting wlan' )) {
    $results = Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan disconnect}
    return $results
  }
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Disconnect-WiFi

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
      VERSION     :  1.0.2
      LAST UPDATED:  7/7/2017
      AUTHOR      :  Bryan Dady
      .INPUTS
      None
      .OUTPUTS
      Write-Log
  #>
  New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private
  Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IpEnabled = True' |
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

    return $Private:RetObject # $OutputObj
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
        $null = $Private:adapter.ReleaseDHCPLease()
        Write-Debug -Message 'Renewing IP Address'
        $null = $Private:adapter.RenewDHCPLease()
        Write-Log -Message ('IP address is {0} with Subnet {1}' -f $adapter.IPAddress, $adapter.IPSubnet) -Function $MyInvocation.MyCommand.Name
    }
    return Get-IPAddress
} # end function Redo-DHCP

function Open-UAC {
    <#
        .SYNOPSIS
        Open Windows User Account Control Settings application window.

        .DESCRIPTION
        Detects if current UAC setting is other than this functions expected Default setting (such as Always Notify or lesser than Default options), by inspecting the ConsentPromptBehaviorAdmin value in the local Windows registry.
        If ConsentPromptBehaviorAdmin is other than the expected/Default value, the UserAccountControlSettings.exe is invoked.
    #>
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    # Check current UAC level via registry
    # We want ConsentPromptBehaviorAdmin = 5
    # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
    $ConsentPromptBehaviorAdmin = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin
    if ($ConsentPromptBehaviorAdmin -eq 5) {
        # prompt for UAC update
        Write-Verbose -Message ('User Account Control set to an approved level: {0}' -f $ConsentPromptBehaviorAdmin)
    } elseif ($ConsentPromptBehaviorAdmin -eq 0) {
        Write-Verbose -Message ('User Account Control set to an approved level: {0}' -f $ConsentPromptBehaviorAdmin)
    } else {
        Write-Log -Message 'Opening User Account Control Settings dialog ...' -Function $MyInvocation.MyCommand.Name
        & $env:SystemDrive\Windows\System32\UserAccountControlSettings.exe
    }
    Start-Sleep -Seconds 5

    # Wait for UAC to be complete before proceeding
    Test-ProcessState -ProcessName 'UserAccountControlSettings' -Wait

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Open-UAC

function Open-Browser {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='URL to open in default web browser.'
        )]
        [ValidatePattern({\S+\.\w{2,6}})]
        [String]
        [alias('address','site')]
        $URL
    )

    Write-Verbose -Message ('Start-Process -FilePath {0}' -f $URL)
    if (-not ($URL -match '^http?:\/\/?.+\.\w{2,6}}')) {
        Write-Verbose -Message 'Prepending ambiguous $URL with https://'
        $URL = 'https://' + $URL
    }

    Start-Process -FilePath $URL
} # end function Open-Browser

function Show-DesktopDocuments {
    Write-Log -Message 'Opening all Desktop Documents' -Function $MyInvocation.MyCommand.Name
    # Open all desktop PDF files
    Get-ChildItem -Path $env:USERPROFILE\Desktop\*.pdf | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 400}
    # Open all desktop Word doc files
    Get-ChildItem -Path $env:USERPROFILE\Desktop\*.doc* | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 800}
} # end function Show-DesktopDocuments

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
    [ValidateScript({$PSItem -in $MySettings.Workplace.Name})]
    $Zone
  )

  Show-Progress -msgAction Start -msgSource $MyInvocation.MyCommand.Name

  # Always simplify UAC prompt level, so we run this before {switching ($zone)}
  Write-Log -Message 'Checking UserAccountControl level' -Function $MyInvocation.MyCommand.Name
  Open-UAC

  Write-Log -Message ('Loading settings for Workplace {0} as defined in {1}.' -f $zone, $SettingsFileName) -Function $MyInvocation.MyCommand.Name
  $ZoneSettings = $MySettings.Workplace | Where-Object -FilterScript {$PSItem.Name -eq $zone}

  if (-not ($ZoneSettings.function_before)) {
    Write-Log -Message '$ZoneSettings.function_before was not found.' -Function $MyInvocation.MyCommand.Name
  } else {
    $ZoneSettings.function_before | ForEach-Object -Process {
      Write-Debug -Message ('Function {0} - Message: {1}' -f $PSItem.Name, $PSItem.Message)
      Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
      Invoke-Expression -Command $PSItem.Name
      Start-Sleep -Milliseconds 777
    }
  }

  if (-not ($ZoneSettings.ServiceGroup)) {
    Write-Log -Message '$ZoneSettings.ServiceGroup was not found.' -Function $MyInvocation.MyCommand.Name
  } else {
    $ZoneSettings.ServiceGroup | ForEach-Object -Process {
      Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
      Set-ServiceGroup -Name $PSItem.Name -Status $PSItem.Status
      Start-Sleep -Milliseconds 777
    }
  }

  if (-not ($ZoneSettings.ProcessState)) {
    Write-Log -Message '$ZoneSettings.ProcessState was not found.' -Function $MyInvocation.MyCommand.Name
  } else {
    $ZoneSettings.ProcessState | ForEach-Object -Process {
      Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
      Set-ProcessState -Name $PSItem.Name -Action $PSItem.Action
      Start-Sleep -Milliseconds 777
    }
  }

  # Update IE home page
  Write-Log -Message 'Setting Internet Explorer start page to $($ZoneSettings.IEHomePage)' -Function $MyInvocation.MyCommand.Name
  Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $ZoneSettings.IEHomePage -force -ErrorAction Ignore
  Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $ZoneSettings.IEHomePage -force -ErrorAction Ignore

    # Set preferred / defined default browser
    Write-Log -Message 'Updating default browser via registry edit' -Function $MyInvocation.MyCommand.Name
    Write-Log -Message ('Setting URL Progid to {0}' -f $ZoneSettings.BrowserProgid) -Function $MyInvocation.MyCommand.Name
    @('http','https') | ForEach {
        $Private:URL = ('HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{0}\UserChoice' -f $PSItem)
        # In case the reg key does not yet exist, we must first create it, as New-ItemProperty can not make a new reg key item prior to setting a property of the item
        if (-not (Test-Path -Path $Private:URL)) {
            Write-Log -Message ('Creating registry key items for {0} URL Associations' -f $PSItem) -Function $MyInvocation.MyCommand.Name
            New-Item -Path $Private:URL -Force
        }
        Set-ItemProperty -Path $Private:URL -Name Progid -Value $ZoneSettings.BrowserProgid -Force
    }
  <#
    Write-Log -Message 'Updating default browser via registry edit' -Function $MyInvocation.MyCommand.Name
    # In case the reg key does not yet exist, we must first create it, as New-ItemProperty can not make a new reg key item prior to setting a property of the item
    if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice)) {
        Write-Log -Message 'Creating registry key items for http URL Associations' -Function $MyInvocation.MyCommand.Name
        New-Item -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Force
    }

    if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice)) {
        Write-Log -Message 'Creating registry key items for https URL Associations' -Function $MyInvocation.MyCommand.Name
        New-Item -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Force
    }
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value $MySettings.BrowserProgid -Force
  #>


  $ZoneSettings.function_after | ForEach-Object -Process {
    Write-Log -Message ('{0}' -f $PSItem.Message) -Function $PSItem.Name
    Invoke-Expression -Command $PSItem.Name
    Start-Sleep -Milliseconds 777
  }

  if (-not ($ZoneSettings.Printer)) {
    Write-Log -Message '$ZoneSettings.Printer preference was not found.' -Function $MyInvocation.MyCommand.Name
  } else {
    $ZoneSettings.Printer | ForEach-Object -Process {
      Write-Log -Message ('Setting default printer: {0}' -f $ZoneSettings.Printer) -Function $MyInvocation.MyCommand.Name
      Set-Printer -printerShareName $ZoneSettings.Printer
      Start-Sleep -Milliseconds 333
    }
  }

  Write-Output -InputObject 'If you''d like to (re)open all Desktop Documents, run Show-DesktopDocuments'

  Show-Progress -msgAction Stop -msgSource $MyInvocation.MyCommand.Name  # Log end time stamp

  return ('Ready for {0} work' -f $zone)
} # end function Set-Workplace
