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
        DATE     : 04/09/2015
#>
#========================================

[cmdletbinding()]

# Define / instantiate some basic references for later use
$myName = $MyInvocation.MyCommand.Name;
$myPath = split-path $MyInvocation.MyCommand.Path;

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
    $uncPaths = @{	
        'H' = "\\gbci02sanct3\homes$\gbci\$env:USERNAME";
        'I' = "\\gbci02sanct3\homes$\gbci\$env:USERNAME"+'2';
        'R' = '\\gbci02sanct1\apps';
        'S' = '\\gbci02sanct3\gbci\shared\it';
        'X' = '\\gbci02sanct3\GBCI\Shared';
        'V' = '\\glacierbancorp.local\SysVol\glacierbancorp.local\scripts';
    }

    if ($AllDrives) {
        # loop through all defined drive mappings
        $uncPaths.Keys | ForEach-Object {
            if (!(Test-Path ${_}:)) {
                write-log -Message "New-PSDrive ${_}: "$uncPaths.${_} -Function $MyInvocation.MyCommand.Name;
                New-PSDrive -Persist -Name ${_} -Root $uncPaths.${_} -PSProvider FileSystem -scope Global -ErrorAction:SilentlyContinue;
            }
            Start-Sleep -m 500;
        }
    } else {
        if (!(Test-Path H:)) {
            write-log -Message "New-PSDrive H: $($uncPaths.H)" -Function $MyInvocation.MyCommand.Name;
            New-PSDrive -Persist -Name H -Root "$($uncPaths.H)" -PSProvider FileSystem -scope Global; # -ErrorAction:SilentlyContinue;
        }

        if (!(Test-Path S:)) {
            Write-Log -Message "New-PSDrive S: $($uncPaths.S)" -Function $MyInvocation.MyCommand.Name;
            New-PSDrive -Persist -Name S -Root "$($uncPaths.S)" -PSProvider FileSystem -scope Global; # -ErrorAction:SilentlyContinue;
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp; #  'SetDriveMaps'; # Log end time stamp
}

# Define Remove-DriveMaps function
function Remove-DriveMaps {
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp;
    Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name;
    get-psdrive -PSProvider FileSystem | ForEach-Object {
        if (${_}.DisplayRoot -like '\\*') {
            # $driveData = 'Remove-PSDrive ',${_}.Name,': ',${_}.DisplayRoot; #  -verbose"; # debugging
            # $logLine =  $driveData -join ' ';
            # write-log $logLine;
            Write-Log -Message "Remove-PSDrive $(${_}.Name): $(${_}.DisplayRoot)" -Function $MyInvocation.MyCommand.Name -Verbose;
            remove-psdrive ${_};
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp;
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
        [Parameter(Mandatory=$false, Position=0)]
        [String[]]
        $SSID = 'Halcyon'
    )

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp; #  'Connect-WiFi'; # Log start time stamp
    Write-Log -Message 'Check that SophosFW is stopped' -Function $MyInvocation.MyCommand.Name;
    if (Get-SophosFW('Running')) { Set-SophosFW -ServiceAction Stop}

    Write-Log -Message 'enumerate wifi adapters (e.g. Intel(R) Wireless-N 7260)' -Function $MyInvocation.MyCommand.Name;
    $wireless_adapters = @(Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND Name LIKE '%ireless%'" | Select-Object -Property Name,NetConnectionID,NetConnectionStatus)
    ForEach-Object -InputObject $wireless_adapters {
        Write-Log -Message "Connecting $PSItem.NetConnectionID to $SSID" -Function $MyInvocation.MyCommand.Name;
        Write-Log -Message "netsh.exe wlan connect $SSID" -Function $MyInvocation.MyCommand.Name;
        Invoke-Command -ScriptBlock {netsh.exe wlan connect "$SSID"};
        Start-Sleep -Seconds 10;
    }
    return $SSID, $?

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp; #  'Connect-WiFi'; # Log end time stamp

}

function Disconnect-WiFi {
<#
    .SYNOPSIS
        Disconnect from any/all wi-fi networks
    .DESCRIPTION
        Designed as a complement to Connect-WiFi, this disconnect function automates disconnecting from wifi, e.g. for when setting into Office workplace
    .EXAMPLE
        .> Disonnect-WiFi

        True - indicates the netsh command returned successful
#>
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp; #  'Disconnect-WiFi'; # Log start time stamp
    Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name;
    Invoke-Command -ScriptBlock {netsh.exe wlan disconnect}; # > $null}
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
    
    return $?;
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp; #  'Disconnect-WiFi'; # Log end time stamp
}

function Get-IPAddress {
<#
    .SYNOPSIS
        Returns a custom object with properties related to location on a corporate network, and basic DHCP info.
    .DESCRIPTION
        Using Get-CIM... queries, this function returns info about the IP Address, the physical site/location that address is related to, default gateway, DNS server list, and adapter name.
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
        VERSION     :  1.0.0
        LAST UPDATED:  5/1/2015
        AUTHOR      :  Bryan Dady
    .INPUTS
        None
    .OUTPUTS
        Write-Log
#>
    New-Variable -Name outputobj -Description 'Object to be returned by this function'
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration  -Filter 'IpEnabled = True AND DhcpEnabled = True' | 
    foreach {
        switch ($PSItem.IPAddress) {
            '10.10.'  {$SiteName = 'Helena'}
            '10.20.'  {$SiteName = 'Missoula'}
            '10.100.' {$SiteName = 'Missoula'}
            Default   {$SiteName = 'Unrecognized' }
        } # end switch

        if ($SiteName -eq 'Unrecognized') {
            Write-Log -Message 'Connected to unrecognized network' -Function $MyInvocation.MyCommand.Name -Verbose
        } else {
            Write-Log -Message "Connected to GBCI - $SiteName" -Function $MyInvocation.MyCommand.Name
        } # end if $SiteName

        #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
        $properties = @{
            'AdapterDescription'=$PSItem.Description;
            'IPAddress'=$PSItem.IPAddress;
            'SiteName'=$SiteName;
            'Gateway'=$PSItem.DefaultIPGateway;
            'DNSServers'=$PSItem.DNSServerSearchOrder;
            'AdapterHost'=$PSItem.PSComputerName;
        }
        $object = New-Object –TypeName PSObject –Prop $properties

        # Add this resulting object to the array object to be returned by this function
        $outputobj += $object
    }
    return $outputobj;

    break;

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
    $ethernet = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true}  
 
    foreach ($adapter in $ethernet) { 
        Write-Debug -Message 'Releasing IP Address';
        Start-Sleep -Seconds 2; 
        $adapter.ReleaseDHCPLease() | out-Null 
        Write-Debug -Message 'Renewing IP Address';
        $adapter.RenewDHCPLease() | out-Null  
        Write-Log -Message 'The New Ip Address is '$adapter.IPAddress' with Subnet '$adapter.IPSubnet'' -Function $MyInvocation.MyCommand.Name -Debug
    }
}

function Start-CitrixReceiver {

    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name; # Log start time stamp;

    if (Test-LocalAdmin) {
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue;
        Start-Service -Name RadeSvc -ErrorAction:SilentlyContinue; # Citrix Streaming Service
        Start-Service -Name RSCorSvc -ErrorAction:SilentlyContinue; # Citrix System Monitoring Agent
    } else {
        Write-Log -Message 'Need to elevate privileges for proper completion ... requesting admin credentials.' -Function $MyInvocation.MyCommand.Name -verbose;
        # Before we launch an elevated process, check (via function) that UAC is conveniently set
        Set-UAC;

        start-process -FilePath powershell.exe -ArgumentList '-Command {Start-CitrixReceiver}' -verb RunAs -Wait; # -ErrorAction:SilentlyContinue;

    }
    # Confirm Citrix XenApp shortcuts are available, and then launch
    if (test-path "$env:USERPROFILE\Desktop\Outlook Web Access.lnk") {
        & "$env:USERPROFILE\Desktop\Office Communicator.lnk";  Start-Sleep -s 30;
        & "$env:USERPROFILE\Desktop\IT Service Center.lnk"; Start-Sleep -s 1;
        & "$env:USERPROFILE\Desktop\RDP Client.lnk"; Start-Sleep -s 1;
        & "$env:USERPROFILE\Desktop\Microsoft OneNote 2010.lnk"; Start-Sleep -s 1;
        & "$env:USERPROFILE\Desktop\Microsoft Outlook 2010.lnk"; Start-Sleep -s 1;
        & "$env:USERPROFILE\Desktop\H Drive.lnk";
    } else {
        Write-Log -Message 'Unable to locate XenApp shortcuts. Please check network connectivity to workplace resources and try again.' -Function $MyInvocation.MyCommand.Name -verbose;
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name; # Log end time stamp; #  'StartCitrixReceiver'; # Log end time stamp

}

function Set-UAC {
    Show-Progress -msgAction 'Start' $MyInvocation.MyCommand.Name; # Log start time stamp
    # Check current UAC level via registry
    # We want ConsentPromptBehaviorAdmin = 5
    # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
    if (((get-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin) -ne 5)
    { # prompt for UAC update
        & $env:SystemDrive\Windows\System32\UserAccountControlSettings.exe;
    }
    Start-Sleep -Seconds 5;
    
    # Wait for UAC to be complete before proceeding
    Set-ProcessState -ProcessName 'UserAccountControlSettings' -Action Test
    
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
            Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name;
            Invoke-Command -ScriptBlock {netsh.exe wlan disconnect}; # disconnect any wi-fi

            Set-UAC;

            Write-Log -Message 'Start FW Services' -Function $MyInvocation.MyCommand.Name;
            Set-SophosFW -ServiceAction Start;

            Write-Log -Message 'Map network drives' -Function $MyInvocation.MyCommand.Name;
            Set-DriveMaps;

            Write-Log -Message 'Start Citrix Receiver' -Function $MyInvocation.MyCommand.Name;
            Start-CitrixReceiver;
            # Sync files Write-Log -Message 'Running Profile-Sync' -Function $MyInvocation.MyCommand.Name -verbose;
            # ** replace with direct access to the function via inclusion of the ps1 file in this Sperry module
            # *** First the Profile-Sync function(s) need to be cleaned up and modularized
            # Write-Log -Message 'Done with Profile-Sync' -Function $MyInvocation.MyCommand.Name;

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
                Write-Log -Message 'Set Default network printer to GBCI91_IT252' -Function $MyInvocation.MyCommand.Name;
                if ((Get-Printer -Default).Name -ne 'GBCI91_IT252') {
                    Set-Printer -printerShareName GBCI91_IT252
                }
            }

            # Set IE as local default browser; since there's challenges with Firefox's enhanced security and employer's networwork monitoring
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value IE.HTTP
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value IE.HTTPS
        }
        'Remote' {
            # Make sure stuff I always want running is 'still' running
            # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
            # In the following block it's referred to as 'taskmgr', because the procexp option was used to replace native taskmgr (Win7)

            Set-UAC;
    	    
            Write-Log -Message 'Stop FW Services' -Function $MyInvocation.MyCommand.Name;
            Set-SophosFW -ServiceAction Stop;

            Write-Log -Message 'Dismount mapped network drives' -Function $MyInvocation.MyCommand.Name;
            Remove-DriveMaps;

            Write-Log -Message 'Clear CAG cookies from IE' -Function $MyInvocation.MyCommand.Name;
            Clear-IECookies 'cag';

            Write-Log -Message 'Connect to default Wi-Fi network' -Function $MyInvocation.MyCommand.Name;
            Connect-WiFi;

            # Update IE home page to skip intranet and go straight to CAG
            Write-Log -Message 'Setting CAG as Internet Explorer start page.' -Function $MyInvocation.MyCommand.Name;
            Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value 'https://cag.glacierbancorp.com/' -force -ErrorAction:SilentlyContinue 
            Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value 'https://cag.glacierbancorp.com/' -force -ErrorAction:SilentlyContinue

            # Set Firefox as local default browser
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Name Progid -Value FirefoxURL
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value FirefoxURL

            & "$env:ProgramFiles\Internet Explorer\iexplore.exe" 'https://cag.glacierbancorp.com'
            #	Write-Log -Message 'Running Evernote' -Function $MyInvocation.MyCommand.Name;
            #	start-process powershell.exe "$PSScriptRoot\checkProcess.ps1 evernote Start";
        }
        Default {}
    }

    Write-Log -Message 'Start PortableApps menu' -Function $MyInvocation.MyCommand.Name;
    # Start other stuff; nice to haves
    & "$env:SystemDrive\SWTOOLS\Start.exe"; # Start PortableApps menu

    Write-Log -Message 'Open Process Explorer, minimized' -Function $MyInvocation.MyCommand.Name;
    # for SysInternals ProcExp, check if it's already running, because re-launching it, doesn't stay minimized
    if (Get-Process procexp -ErrorAction:SilentlyContinue) {
        # Write-Host " FYI: Process Explorer is already running.";
    } else {
        Set-ProcessState taskmgr Start; # -verb open -windowstyle Minimized;
    }

    Write-Log -Message 'Open Firefox' -Function $MyInvocation.MyCommand.Name;
    Set-ProcessState -ProcessName Firefox -Action Start 

    #	Write-Log -Message 'Running puretext' -Function $MyInvocation.MyCommand.Name;
    #	start-process powershell.exe -command {"$PSScriptRoot\checkProcess.ps1 puretext Start"};
    #	start-process powershell.exe -command {"$PSScriptRoot\checkProcess.ps1 chrome Start"};
	
    <#	# Reminders: 
            # Open all desktop PDF files
            Write-Log -Message 'Opening all Desktop Documents' -Function $MyInvocation.MyCommand.Name;
            Get-ChildItem $env:USERPROFILE\Desktop\*.pdf | foreach { & $_ }
            # Open all desktop Word doc files
            Get-ChildItem $env:USERPROFILE\Desktop\*.doc* | foreach { & $_ }
    #>
    Show-Progress -msgAction Stop -msgSource $MyInvocation.MyCommand.Name;  # Log end time stamp
}

Export-ModuleMember -function Set-Workplace, Connect-WiFi, Set-DriveMaps, Remove-DriveMaps, Start-CitrixReceiver, Get-IECookies, Clear-IECookies, Get-IPAddress, Get-Printer, Set-Printer, Get-SophosFW, Set-SophosFW, Set-ProcessState, Start-XenApp, Start-Robosync, Sync-HomeShares -alias *
