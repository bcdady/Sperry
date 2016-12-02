#!/usr/local/bin/powershell
#Requires -Version 3
# Set-StrictMode -Version Latest # enforces coding rules in expressions, scripts, and script blocks based on latest available rules
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
# Define / instantiate some basic references for later use
#$Script:myName = $MyInvocation.MyCommand.Name
#$Script:myPath = split-path -Path $MyInvocation.MyCommand.Path -Parent -Resolve

# Define PSUpdateDate variable and populate from persistent state settings file
New-Variable -Name PSHelpUpdatedDate -Description 'Date/time stamp of the last Update-Help run' -Scope Global -Force
Write-Output -InputObject 'Importing shared saved state info from Microsoft.PowerShell_state.json to custom object: $PSState'
try {
    $Global:PSState = (Get-Content -Path $env:ProgramFiles\WindowsPowerShell\Microsoft.PowerShell_state.json) -join "`n" | ConvertFrom-Json
}
catch {
    Write-Warning -Message "Critical Error loading PowerShell saved state info from $env:ProgramFiles\WindowsPowerShell\Microsoft.PowerShell_state.json to custom object: `$PSState"
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
    Write-Debug -Message "`$Global:Settings = (Get-Content -Path $(join-path -Path $(Split-Path -Path $((Get-PSCallStack).ScriptName | Sort-Object -Unique) -Parent) -ChildPath 'Sperry.json')) -join ""``n"" | ConvertFrom-Json"
    try {
        $Global:Settings = (Get-Content -Path $(join-path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath 'Sperry.json')) -join "`n" | ConvertFrom-Json
        Write-Verbose -Message 'Settings imported. Run Show-Settings to see details.' 
    }
    catch {
        write-warning 'Critical Error loading settings from from sperry.json'
    }
}

Write-Output -InputObject 'Import $Sperry configs'
Import-Settings

Function Show-Settings {
    param ()
    Write-Output -InputObject $Global:Settings
}

function Set-DriveMaps {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp

    # $AllDrives = 1 (true) means map all drives; 0 (false) means only map H: and S:
    Write-Log -Message 'Mapping Network Drives' -Function $MyInvocation.MyCommand.Name -Verbose
    if (Test-LocalAdmin) { Write-Log -Message 'Mapping drives with a different account, may result in them NOT appearing properly in Explorer' -Function $MyInvocation.MyCommand.Name; }

    # Read in UNC path / drive letter mappings from sperry.json : Sperry.uncPaths
    # loop through all defined drive mappings
    $Global:Settings.UNCPath | ForEach-Object {
        $DriveName = $ExecutionContext.InvokeCommand.ExpandString($PSItem.DriveName)
        $UNCroot   = $ExecutionContext.InvokeCommand.ExpandString($PSItem.FullPath)
        if ( (-not (Test-Path "$DriveName`:\") -and (Test-Path $UNCroot))) {
            Write-Log -Message "New-PSDrive $DriveName`: $UNCroot" -Function 'Set-DriveMaps'
            Write-Debug -Message " New-PSDrive -Persist -Name $DriveName -Root $UNCroot -PSProvider FileSystem -scope Global"
            New-PSDrive -Name $DriveName -Root $UNCroot -PSProvider FileSystem -Persist -scope Global # -ErrorAction:SilentlyContinue
            Start-Sleep -m 500
        }
        else
        {
            Write-Warning -Message "Drive letter $DriveName already in use, or path $UNCroot was not found."
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

# Define Get-DriveMaps function
function Get-DriveMaps {
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Enumerating mapped network drives' -Function $MyInvocation.MyCommand.Name
    get-psdrive -PSProvider FileSystem 
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
}

# Define Remove-DriveMaps function
function Remove-DriveMaps {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name
    get-psdrive -PSProvider FileSystem | ForEach-Object {
        if (${_}.DisplayRoot -like '\\*') {
            Write-Log -Message "Remove-PSDrive $(${_}.Name): $(${_}.DisplayRoot)" -Function $MyInvocation.MyCommand.Name
            remove-psdrive ${_};
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
        Connect-WiFi 'Starbucks'; - Attempts to connect the wireless network adapter(s) to SSID 'Starbucks'

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
            Position=0
        )]
        [Alias('NetworkName','NetworkID','WiFiName','WiFiID')]
        [String]
        $SSID,

        [Parameter(
            Position=1
        )]
        [Alias('sleep','pause','delay')]
        [ValidateRange(1,60)]
        [int16]
        $WaitTime = 10
    )

    $NetConnectionStatus = @{
        0 = 'Disconnected'
        1 = 'Connecting'
        2 = 'Connected'
        3 = 'Disconnecting'
        4 = 'Hardware Not Present'
        5 = 'Hardware Disabled'
        6 = 'Hardware Malfunction'
        7 = 'Media Disconnected'
        8 = 'Authenticating'
        9 = 'Authentication Succeeded'
        10 = 'Authentication Failed'
        11 = 'Invalid Address'
        12 = 'Credentials Required'
    }

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp;
    Set-ServiceGroup -Name 'Sophos Client Firewall*' -Status Stopped
    ForEach-Object -InputObject @(Get-WmiObject Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND Name LIKE '%ireless%'") {
        Write-Log -Message "Connecting $($PSItem.NetConnectionID) to $SSID" -Function $($MyInvocation.MyCommand).Name
        if ($PSItem.Availability -ne 3) {
            if (test-localadmin) {
                if (($PSItem.enable()).ReturnValue -eq 0) {
                    Write-Log -Message 'Adapter Enabled' -Function $($MyInvocation.MyCommand).Name
                } else {
                    throw "A fatal error was encountered trying to enable Network Adapter $($PSItem.Name) (Device $($PSItem.DeviceID))"
                }
            } else {
                Write-Log -Message 'Attempting to invoke new powershell sessions with RunAs (elevated permissions) to enable adapter via' -Function $MyInvocation.MyCommand.Name
#                $ScriptBlock = { 
 #                   ForEach-Object -InputObject @(Get-WmiObject Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND Name LIKE '%ireless%'") { ($PSItem.enable()).ReturnValue } }
                $return = Open-AdminConsole -Command {ForEach-Object -InputObject @(Get-WmiObject Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND Name LIKE '%ireless%'") { ($PSItem.enable()).ReturnValue }}
                # $return = Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-NoProfile -NonInteractive -Command $ScriptBlock" -Verb RunAs -WindowStyle Normal
                if ($return -eq 0)
                {
                    Write-Log -Message 'Adapter enabled' -Function $MyInvocation.MyCommand.Name
                }
                else
                {
                    throw "A fatal error was encountered trying to enable Network Adapter $($PSItem.Name) (Device $($PSItem.DeviceID))"
                }
            }
            Start-Sleep -Seconds 1
        }
        Write-Log -Message "netsh.exe wlan connect $SSID" -Function $($MyInvocation.MyCommand).Name
        $results = Invoke-Command -ScriptBlock {netsh.exe wlan connect "$SSID"}
        Write-Log -Message $results -Function $MyInvocation.MyCommand.Name
        Start-Sleep -Seconds $WaitTime
    }
    return $SSID, $?

    Show-Progress -msgAction 'Stop' -msgSource $($MyInvocation.MyCommand).Name # Log end time stamp

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

    if($PSCmdlet.ShouldProcess( "Disconnected wlan", "Disconnect wlan`?", "Disconnecting wlan" ))
    {
        Invoke-Command -ScriptBlock {netsh.exe wlan disconnect}
        return $?
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
    $avail_SID = netsh.exe wlan show networks
    Write-Debug -Message $avail_SID -Debug
    return $?
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
      $Private:RetObject = New-Object -TypeName PSObject -Prop $properties

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

    foreach ($Private:adapter in $ethernet) {
        Write-Debug -Message 'Releasing IP Address'
        Start-Sleep -Seconds 2
        $adapter.ReleaseDHCPLease() | out-Null
        Write-Debug -Message 'Renewing IP Address'
        $adapter.RenewDHCPLease() | out-Null
        Write-Log -Message 'The New Ip Address is '$adapter.IPAddress' with Subnet '$adapter.IPSubnet'' -Function $MyInvocation.MyCommand.Name
    }
    return Get-IPAddress
}

function Start-CitrixReceiver {

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp

    if (Test-LocalAdmin) {
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue
        Start-Service -Name RadeSvc -ErrorAction:SilentlyContinue # Citrix Streaming Service
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue # Citrix System Monitoring Agent
    } else {
        if ( -not (Get-Process -Name Receiver))
        {
            Write-Log -Message 'Need to elevate privileges for proper completion ... requesting admin credentials.' -Function $MyInvocation.MyCommand.Name
            Start-Sleep -Milliseconds 333
            # Before we launch an elevated process, check (via function) that UAC is conveniently set
            Set-UAC
            Open-AdminConsole -Command {Start-CitrixReceiver} 
        }
        else
        {
            Write-Log -Message 'Confirmed Citrix Receiver is running.' -Function $MyInvocation.MyCommand.Name
        }
    }

    # Confirm Citrix XenApp shortcuts are available, and then launch frequently used apps
    if (test-path -Path "$env:USERPROFILE\Desktop\Assyst.lnk" -PathType Leaf) {
        Write-Output -InputObject 'Starting cmd'
        Start-XenApp -Qlaunch 'cmd'
        Write-Output -InputObject 'Pausing for Receiver to start up ...'
        Start-Sleep -Seconds 60
<#        Write-Output -InputObject 'Starting OneNote'
        Start-XenApp -Qlaunch 'OneNote'
        Write-Output -InputObject 'Starting Outlook'
        Start-XenApp -Qlaunch 'Microsoft Outlook 2010'
        Start-Sleep -Seconds 2
        Write-Output -InputObject 'Skype for Business'
        Start-XenApp -Qlaunch 'Skype for Business'
        Start-Sleep -Seconds 2

        Write-Output -InputObject 'Starting ITSC'
        & "$env:USERPROFILE\Desktop\IT Service Center.lnk"
        Start-Sleep -Seconds 1
        Write-Output -InputObject 'Starting H Drive'
        & "$env:USERPROFILE\Desktop\H Drive.lnk"
        Start-Sleep -Seconds 1
#>
        Write-Output -InputObject 'Starting Firefox (XenApp)'
        xa_firefox

<#        Write-Output -InputObject 'Opening Nessus Security Center'
        & 'H:\Favorites\Links\GBCI IT\Nessus SecurityCenter.url'
        Write-Output -InputObject 'Opening GoToMeeting'
        & 'H:\Favorites\Links\GBCI IT\GoToMeeting.url'

        <# Optional RFE : Open more browser 'favorites':
        e.g
            H:\Favorites\Links\Login - Splunk.url
            Exchange Admin Center.url
            vSphere Web Client.url
            WSUS - Report Manager.url
            Nessus SecurityCenter.url
        #>
    } else {
        Write-Log -Message 'Unable to locate XenApp shortcuts. Please check network connectivity to workplace resources and try again.' -Function $MyInvocation.MyCommand.Name
    }

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
    return $true # (Get-Process -Name Receiver).Description
}

function Set-UAC {
    Show-Progress -msgAction 'Start' $MyInvocation.MyCommand.Name # Log start time stamp
    # Check current UAC level via registry
    # We want ConsentPromptBehaviorAdmin = 5
    # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
    if (((get-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin) -ne 5)
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
            HelpMessage='Specify workplace zone, or context. Accepts Work or Home.'
        )]
        [String]
        [alias('mode','scope')]
        [ValidateSet('Office', 'Remote')]
        $Zone
    )
    Show-Progress -msgAction Start -msgSource $MyInvocation.MyCommand.Name

    # Always simplify UAC prompt level, so we run this before {switching ($zone)}
    Write-Log -Message 'Checking UserAccountControl level' -Function $MyInvocation.MyCommand.Name
    Set-UAC

    switch ($zone) {
        'Office' {
            Write-Log -Message 'Update network adapter state' -Function $MyInvocation.MyCommand.Name
            Set-NetConnStatus

            Write-Log -Message 'Confirm workplace firewall is functional' -Function $MyInvocation.MyCommand.Name
            Set-ServiceGroup -Name 'Sophos Client Firewall*' -Status Running

            Write-Log -Message 'Map all defined network drives' -Function $MyInvocation.MyCommand.Name
            Set-DriveMaps
            #Get-DriveMaps

            # Update IE home page to intranet Infrastructure page
            $IEHomePage = 'https://intranet2/pg_view.aspx?PageID=1294'
            Write-Log -Message 'Setting Intranet-Infrastrucure as Internet Explorer start page.' -Function $MyInvocation.MyCommand.Name
            Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $IEHomePage -force -ErrorAction:SilentlyContinue
            Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $IEHomePage -force -ErrorAction:SilentlyContinue

            Write-Log -Message 'Start Citrix Receiver' -Function $MyInvocation.MyCommand.Name
            Start-CitrixReceiver

            # Set IE as local default browser; since there's challenges with Firefox's enhanced security and employer's network monitoring
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value IE.HTTP
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value IE.HTTPS
        }
        'Remote' {
            # Make sure stuff I always want running is 'still' running
            # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
            # In the following block it's referred to as 'taskmgr', because the procexp option was used to replace native taskmgr (Win7)

            Write-Log -Message 'Modify FW Profile' -Function $MyInvocation.MyCommand.Name
            Get-ServiceGroup -Name 'Sophos Client Firewall*' -Status Stopped

            Write-Log -Message 'Dismount mapped network drives' -Function $MyInvocation.MyCommand.Name
            Remove-DriveMaps
            Get-DriveMaps

            Write-Log -Message 'Clear CAG cookies from IE' -Function $MyInvocation.MyCommand.Name
            Clear-IECookie 'cag'

            Write-Log -Message 'Connect to WiFi' -Function $MyInvocation.MyCommand.Name
            Set-NetConnStatus -Enable
            # Connect-WiFi -SSID 'Halcyon' -sleep 5

            # Update IE home page to skip intranet and go straight to CAG
            $IEHomePage = 'https://cag.glacierbancorp.com/'
            Write-Log -Message 'Setting CAG as Internet Explorer start page.' -Function $MyInvocation.MyCommand.Name
            Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $IEHomePage -force -ErrorAction:SilentlyContinue
            Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $IEHomePage -force -ErrorAction:SilentlyContinue

            # Set Firefox as local default browser
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value BraveHTML #FirefoxURL
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value BraveHTML #FirefoxURL

            & "$env:ProgramFiles\Internet Explorer\iexplore.exe" $IEHomePage
        }
        Default {}
    }

    # Then we resume instructions we always process

    # Open default web browser and VS Code (Insiders/beta release)
    Write-Log -Message 'Start Brave Browser' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState -ProcessName Brave -Action Start
    
    Write-Log -Message 'Start vscode (insider)' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState -ProcessName CodeInsider -Action Start
    <#
    Write-Log -Message 'Start PortableApps menu' -Function $MyInvocation.MyCommand.Name
    # Start other stuff; nice to haves
    & "$env:SystemDrive\SWTOOLS\Start.exe" # Start PortableApps menu
    #>

    <#
    Write-Log -Message 'Open Process Explorer, minimized' -Function $MyInvocation.MyCommand.Name
    # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
    if (!(Get-Process procexp -ErrorAction:SilentlyContinue)) {
        Set-ProcessState taskmgr Start
    }

    Write-Log -Message 'Open Firefox' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState -ProcessName Firefox -Action Start

    Write-Log -Message 'Running puretext' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState puretext Start
    #>
    
    # Reminders:
    # # # RFE : add time-out to the following prompt ??? as a background job?
    $elect = read-host 'Open Desktop documents? [Y/N]'
    Start-Sleep -Seconds 1
    switch ($elect)
    {
        Y {
            Write-Log -Message 'Opening all Desktop Documents' -Function $MyInvocation.MyCommand.Name
            # Open all desktop PDF files
            Get-ChildItem $env:USERPROFILE\Desktop\*.pdf | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 400}
            # Open all desktop Word doc files
            Get-ChildItem $env:USERPROFILE\Desktop\*.doc* | ForEach-Object { & $_ ; Start-Sleep -Milliseconds 800}
        }
        N { }
        default {
            "Sorry $elect is not a valid selection"
            $elect = read-host 'Open Desktop documents? [Y/N]'
        #    escape $elect
        }
    }

    Show-Progress -msgAction Stop -msgSource $MyInvocation.MyCommand.Name  # Log end time stamp

    return "Ready for $zone work"
}