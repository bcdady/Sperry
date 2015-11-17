#Requires -Version 3.0 -Modules PSLogger
Set-StrictMode -Version Latest; # enforces coding rules in expressions, scripts, and script blocks based on latest available rules
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

# Functions
#========================================
Function global:Test-LocalAdmin() {
    Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

function Set-DriveMaps {
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [alias('mode','scope')]
        [Switch]
        $AllDrives
    )
    
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp

    # $AllDrives = 1 (true) means map all drives; 0 (false) means only map H: and S:
    write-log -Message 'Mapping Network Drives' -Function $MyInvocation.MyCommand.Name
    if (Test-LocalAdmin) { Write-Log -Message 'Mapping drives with a different account, may result in them NOT appearing properly in Explorer' -Function $MyInvocation.MyCommand.Name -verbose; }

    # Define all drive letter = UNC path pairs here; we can control which-ones-to-map later
    $Private:uncPaths = @{	
        'H' = "\\gbci02sanct3\homes$\gbci\$env:USERNAME"
        'I' = "\\gbci02sanct3\homes$\gbci\$env:USERNAME"+'2'
        'R' = '\\gbci02sanct1\apps'
        'S' = '\\gbci02sanct3\gbci\shared\it'
        'X' = '\\gbci02sanct3\GBCI\Shared'
        'V' = '\\glacierbancorp.local\SysVol\glacierbancorp.local\scripts'
    }

    if ($AllDrives) {
        # loop through all defined drive mappings
        $uncPaths.Keys | ForEach-Object {
            if (!(Test-Path ${_}:)) {
                write-log -Message "New-PSDrive ${_}: "$uncPaths.${_} -Function $MyInvocation.MyCommand.Name
                New-PSDrive -Persist -Name ${_} -Root $uncPaths.${_} -PSProvider FileSystem -scope Global -ErrorAction:SilentlyContinue
            }
            Start-Sleep -m 500
        }
    } else {
        if (!(Test-Path H:)) {
            write-log -Message "New-PSDrive H: $($uncPaths.H)" -Function $MyInvocation.MyCommand.Name
            New-PSDrive -Persist -Name H -Root "$($uncPaths.H)" -PSProvider FileSystem -scope Global
        }

        if (!(Test-Path S:)) {
            Write-Log -Message "New-PSDrive S: $($uncPaths.S)" -Function $MyInvocation.MyCommand.Name
            New-PSDrive -Persist -Name S -Root "$($uncPaths.S)" -PSProvider FileSystem -scope Global
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp
}

# Define Remove-DriveMaps function
function Remove-DriveMaps {
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp
    Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name
    get-psdrive -PSProvider FileSystem | ForEach-Object {
        if (${_}.DisplayRoot -like '\\*') {
            Write-Log -Message "Remove-PSDrive $(${_}.Name): $(${_}.DisplayRoot)" -Function $MyInvocation.MyCommand.Name -Verbose;
            remove-psdrive ${_};
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp
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
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('NetworkName','NetworkID','WiFiName','WiFiID')]
        [String[]]
        $SSID = 'Halcyon',

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('sleep','pause','delay')]
        [ValidateRange(1,60)]
        [int16]
        $WaitTime = 10
    )

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp;
    Write-Log -Message 'Check that SophosFW is stopped' -Function $MyInvocation.MyCommand.Name;
    if (Get-SophosFW('Running')) { Set-SophosFW -ServiceAction Stop}

    Write-Log -Message 'Enumerate WiFi adapters (e.g. Intel(R) Wireless-N 7260)' -Function $MyInvocation.MyCommand.Name

    $Private:wireless_adapters = @(Get-WmiObject Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND Name LIKE '%ireless%'") # | Select-Object -Property Name,NetConnectionID,NetConnectionStatus,NetEnabled) # CimInstance
    ForEach-Object -InputObject $wireless_adapters {
        Write-Log -Message "Connecting $($PSItem.NetConnectionID) to $SSID" -Function $MyInvocation.MyCommand.Name
        if ($PSItem.NetEnabled -ne $true) {
            write-log -Message 'Enabling Adapter' -Function $MyInvocation.MyCommand.Name
            $PSItem.enable()
            Start-Sleep -Seconds 1
        }
        Write-Log -Message "netsh.exe wlan connect $SSID" -Function $MyInvocation.MyCommand.Name
        Invoke-Command -ScriptBlock {netsh.exe wlan connect "$SSID"}
        Start-Sleep -Seconds $WaitTime
    }
    return $SSID, $?

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp

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
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp
    Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name
    Invoke-Command -ScriptBlock {netsh.exe wlan disconnect}
    <# http://www.powertheshell.com/reference/wmireference/root/cimv2/Win32_NetworkAdapter/

        $NetConnectionStatus_ReturnValue = 
        @{
        0='Disconnected'
        1='Connecting'
        2='Connected'
        3='Disconnecting'
        4='Hardware Not Present'
        5='Hardware Disabled'
        6='Hardware Malfunction'
        7='Media Disconnected'
        8='Authenticating'
        9='Authentication Succeeded'
        10='Authentication Failed'
        11='Invalid Address'
        12='Credentials Required'
        ..='Other'
    #>
    
    return $?
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp
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
    ForEach-Object {
        #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
        $Private:properties = @{
            'AdapterDescription'=$PSItem.Description
            'IPAddress'=$PSItem.IPAddress
            'Gateway'=$PSItem.DefaultIPGateway
            'DNSServers'=$PSItem.DNSServerSearchOrder
            'AdapterHost'=$PSItem.PSComputerName
        }
        $Private:RetObject = New-Object –TypeName PSObject –Prop $properties

        return $RetObject; # $OutputObj
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
        Start-Sleep -Seconds 2; 
        $adapter.ReleaseDHCPLease() | out-Null 
        Write-Debug -Message 'Renewing IP Address'
        $adapter.RenewDHCPLease() | out-Null  
        Write-Log -Message 'The New Ip Address is '$adapter.IPAddress' with Subnet '$adapter.IPSubnet'' -Function $MyInvocation.MyCommand.Name
    }
    return Get-IPAddress
}

function Start-CitrixReceiver {

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp

    if (Test-LocalAdmin) {
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue
        Start-Service -Name RadeSvc -ErrorAction:SilentlyContinue; # Citrix Streaming Service
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue; # Citrix System Monitoring Agent
    } else {
        if (!(Get-Process -Name Receiver)) {

        Write-Log -Message 'Need to elevate privileges for proper completion ... requesting admin credentials.' -Function $MyInvocation.MyCommand.Name -verbose
        Start-Sleep -Milliseconds 333
        # Before we launch an elevated process, check (via function) that UAC is conveniently set
        Set-UAC

        start-process -FilePath powershell.exe -ArgumentList '-Command {Start-CitrixReceiver}' -verb RunAs -Wait

        } else {
            Write-Log -Message 'Confirmed Citrix Receiver is running.' -Function $MyInvocation.MyCommand.Name
        }
    }

    # Confirm Citrix XenApp shortcuts are available, and then launch frequently used apps
    if (test-path "$env:USERPROFILE\Desktop\Assyst.lnk") {
        Start-XenApp -Qlaunch 'Skype for Business'
        Start-Sleep -Seconds 10
        & "$env:USERPROFILE\Desktop\Microsoft OneNote 2010.lnk"
        Start-Sleep -Seconds 45
        # Start-XenApp -Qlaunch 'Outlook Web Access'
#        & "$env:USERPROFILE\Desktop\Office Communicator.lnk"
        & "$env:USERPROFILE\Desktop\IT Service Center.lnk"; Start-Sleep -Seconds 2
        & "$env:USERPROFILE\Desktop\Microsoft Outlook 2010.lnk"; Start-Sleep -Seconds 2
        & "$env:USERPROFILE\Desktop\S Drive.lnk"

        <# Optional RFE : Open more browser 'favorites':
        e.g
        H:\Favorites\Links\Login - Splunk.url

            H:\Favorites\Links\assyst (test).url
            H:\Favorites\Links\Assyst.url
            Exchange Admin Center.url
            Kbox.url
            H:\Favorites\Links\Login - Splunk.url
            MBAM BitLocker Key Recovery.url
            OnCommand Balance.url
            Veeam Backup Enterprise Manager.url
            vSphere Web Client.url
            WSUS - Report Manager.url
            Nessus SecurityCenter.url
            AppSense Self-Service.url
            Secure Mailbox - Login.url
            H:\Favorites\Links\Outlook Web App - Calendar.url
            Citrix Director.url
            H:\Favorites\Links\Outlook Web App - mail.url
        #>
    } else {
        Write-Log -Message 'Unable to locate XenApp shortcuts. Please check network connectivity to workplace resources and try again.' -Function $MyInvocation.MyCommand.Name -verbose
    }

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp
    return (Get-Process -Name Receiver)
}

function Set-UAC {
    Show-Progress -msgAction 'Start' $MyInvocation.MyCommand.Name; # Log start time stamp
    # Check current UAC level via registry
    # We want ConsentPromptBehaviorAdmin = 5
    # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
    if (((get-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin) -ne 5)
    { # prompt for UAC update
		Write-Log -Message 'Opening User Account Control Settings dialog ...' -Function $MyInvocation.MyCommand.Name -verbose
		& $env:SystemDrive\Windows\System32\UserAccountControlSettings.exe
    }
    Start-Sleep -Seconds 5

    # Wait for UAC to be complete before proceeding
    Test-ProcessState -ProcessName 'UserAccountControlSettings' -Wait
    
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp
}

function Set-Workplace {
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true,
        HelpMessage='Specify workplace zone, or context. Accepts Work or Home.')]
        [String[]]
        [alias('mode','scope')]
        [ValidateSet('Office', 'Remote')]
        $zone
    )
    Show-Progress -msgAction Start -msgSource $MyInvocation.MyCommand.Name; 
    switch ($zone) {
        'Office' {
            Write-Log -Message 'Disconnecting WiFi' -Function $MyInvocation.MyCommand.Name -Verbose
            Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name
            Invoke-Command -ScriptBlock {netsh.exe wlan disconnect}; # disconnect any WiFi

            Write-Log -Message 'Checking UserAccountControl level' -Function $MyInvocation.MyCommand.Name
            Set-UAC

            Write-Log -Message 'Confirm workplace firewall is functional' -Function $MyInvocation.MyCommand.Name -Verbose
            Set-SophosFW -ServiceStatus Running

            Write-Log -Message 'Map all defined network drives' -Function $MyInvocation.MyCommand.Name -Verbose
            Set-DriveMaps -AllDrives

            Write-Log -Message 'Start Citrix Receiver' -Function $MyInvocation.MyCommand.Name -Verbose
            Start-CitrixReceiver
            # Sync files
            Write-Log -Message 'Running Profile-Sync' -Function $MyInvocation.MyCommand.Name -verbose
            Sync-Profiles; # available from . .\Scripts\SyncProfiles.ps1, which is loaded in user profile script
            Write-Log -Message 'Done with Profile-Sync' -Function $MyInvocation.MyCommand.Name

            # Check default printer name, and re-set if necessary
            # ** RFE enhance to ask for printer name, select from list based on current IP
            # Get-Printer -Network
            if ($env:ComputerName -ne 'GC91IT78') {
                # set default printer based on IP address ranges for common IT locations
                switch (get-IPaddress) {
                    '10.10.*' { }
                    '10.20.*' { }
                    '10.100.*' { }
                } 
                # XenApp Session
                Write-Log -Message 'Set Default network printer to GBCI92_IT252' -Function $MyInvocation.MyCommand.Name
                if ((Get-Printer -Default).Name -ne 'GBCI92_IT252') {
                    Set-Printer -printerShareName GBCI91_IT252
                }
            }

            # Set IE as local default browser; since there's challenges with Firefox's enhanced security and employer's network monitoring
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value IE.HTTP
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value IE.HTTPS
        }
        'Remote' {
            # Make sure stuff I always want running is 'still' running
            # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
            # In the following block it's referred to as 'taskmgr', because the procexp option was used to replace native taskmgr (Win7)

            Set-UAC
    	    
            Write-Log -Message 'Stop FW Services' -Function $MyInvocation.MyCommand.Name
            Set-SophosFW -ServiceStatus Stopped

            Write-Log -Message 'Dismount mapped network drives' -Function $MyInvocation.MyCommand.Name
            Remove-DriveMaps

            Write-Log -Message 'Clear CAG cookies from IE' -Function $MyInvocation.MyCommand.Name
            Clear-IECookies 'cag'

            Write-Log -Message 'Connect to default WiFi network' -Function $MyInvocation.MyCommand.Name
            Connect-WiFi -SSID 'Halcyon' -sleep 5

            # Update IE home page to skip intranet and go straight to CAG
            Write-Log -Message 'Setting CAG as Internet Explorer start page.' -Function $MyInvocation.MyCommand.Name
            Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value 'https://cag.glacierbancorp.com/' -force -ErrorAction:SilentlyContinue 
            Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value 'https://cag.glacierbancorp.com/' -force -ErrorAction:SilentlyContinue

            # Set Firefox as local default browser
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value FirefoxURL
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value FirefoxURL

            & "$env:ProgramFiles\Internet Explorer\iexplore.exe" 'https://cag.glacierbancorp.com'
        }
        Default {}
    }

    Write-Log -Message 'Start PortableApps menu' -Function $MyInvocation.MyCommand.Name
    # Start other stuff; nice to haves
    & "$env:SystemDrive\SWTOOLS\Start.exe"; # Start PortableApps menu

    Write-Log -Message 'Open Process Explorer, minimized' -Function $MyInvocation.MyCommand.Name
    # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
    if (!(Get-Process procexp -ErrorAction:SilentlyContinue)) {
        Set-ProcessState taskmgr Start
    }

    Write-Log -Message 'Open Firefox' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState -ProcessName Firefox -Action Start 

    Write-Log -Message 'Running puretext' -Function $MyInvocation.MyCommand.Name
    Set-ProcessState puretext Start
	
    # Reminders: 
	$elect = read-host "Open Desktop documents? [Y/N]" 
	switch ($elect)  { 
        Y {
			Write-Log -Message 'Opening all Desktop Documents' -Function $MyInvocation.MyCommand.Name
			# Open all desktop PDF files
			Get-ChildItem $env:USERPROFILE\Desktop\*.pdf | foreach { & $_ }
			# Open all desktop Word doc files
			Get-ChildItem $env:USERPROFILE\Desktop\*.doc* | foreach { & $_ }
		} 
        N { } 
        default {"Sorry $elect is not a valid selection"; Start-Sleep -seconds 1; $elect = read-host "Open Desktop documents? [Y/N]"; escape $elect} 
    } 

    Show-Progress -msgAction Stop -msgSource $MyInvocation.MyCommand.Name;  # Log end time stamp

    return "Ready for $zone work"
}

Export-ModuleMember -function * -alias *
