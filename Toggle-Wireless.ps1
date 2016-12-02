#requires -Version 3
<#
    .SYNOPSIS
        This script will toggle the wireless adapter on or off based on batterystatus
    .DESCRIPTION
        This script will query Win32_Battery and will evaluate the value of the
        BatteryStatus property to determine what to do. There are 11 possible values
        a value of 2 states the system has access to AC, so I use this as the
        value to check.

        If BatteryStatus is 2, the script will disable the wireless adapter that has
        the matching ConnectionID. Any other value then the script will enable the
        same wireless adapter.

        For a complete list of values please see the related links section.
    .PARAMETER ConnectionID
        This is a string that represents how the network card is named when you view
        it from the Network and Sharing applet in Windows. This is stored as the
        NetConnectionID in WMI.

        This value must match how the network card is displayed otherwise the script
        will fail. For information on changing the name of your network adapter
        please see the related links section.

    .PARAMETER Enable
        Force enable named network adapter

    .PARAMETER ListAvailable
        Enumerate all local network adapters by name

    .EXAMPLE
        .\Toggle-Wireless.ps1 -ConnectionID 'Wifi'

        Description
        -----------
        This example shows the basic syntax of the command. If there is an adapter
        with a NetConnectionID of Wifi, then based on the value of BatteryStatus
        the adapter will either be enabled or disabled.
    .NOTES
        Partially base on Toggle-Wireless.ps1 by jspatton (06/27/2012 08:54:56)

        Updated 11/22/2016 Enhance NetConnStatus to skip enabling wifi if Ethernet has address
        Updated 11/23/2016 Improve SupportsShouldProcess / whatif / confirm behavior
    .LINK
        https://code.google.com/p/mod-posh/wiki/Production/Toggle-Wireless.ps1
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa394074(v=vs.85).aspx
        http://technet.microsoft.com/en-us/library/dd163571
#>

Write-Verbose -Message 'Declaring function Set-NetConnStatus'
function Set-NetConnStatus {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    Param (
        [string]
        [Parameter(
            Position=0,
            HelpMessage='Specify the name network adapter (NetConnectionID) to control'
        )]
        $ConnectionID = 'Wireless',

        [switch]
        $Enable,

        [switch]
        $ListAvailable,

        [Switch]
        $Force
    )

    $RejectAll = $false;
    $ConfirmAll = $false;

#    Begin
#    {
        Write-Output -InputObject ''
        Write-Verbose -Message "$(Get-Date): Starting $($MyInvocation.MyCommand.Name)"

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

        # Set default value for variable
        $IsAdmin = $false

        if ($ListAvailable)
        {
            Write-Output -InputObject ''
            Write-Output -InputObject 'Listing available Network Connections by ID:'
            Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
            Write-Output -InputObject ''
        }
        else
        {
# replaced with test-admin
#           $IsAdmin = ([security.principal.windowsprincipal][security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')

            Write-Output -InputObject ''
            Write-Output -InputObject "Getting details for Network Connection '$ConnectionID'"

            $NetAdapter    = Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'"
            $NetAdapterName = $NetAdapter.Name
            $CurStatText = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

            try
            {
                $IPAddress     = (Get-IPAddress).IPAddress
                $IPAdapterName = (Get-IPAddress).AdapterDescription
            }
            catch
            {
                Write-Debug -Message 'Failed to retrieve an IP address (via Get-IPaddress function)'
                $IPAddress     = $null
                $IPAdapterName = $null
            }
            Write-Verbose -Message "Network Adapter $IPAdapterName is connected to IP Address is $IPAddress"
            # force enable
            if ($Enable)
            {
                $AdapterState = 'Enabled'
            }
            # Determine end state the NetworkAdapter (as identified by $ConnectionID) should be in
            elseif (((Get-WmiObject -Class Win32_Battery -Property BatteryStatus).BatteryStatus -eq 2))
            {
                if ($IPAddress)
                {
                    Write-Verbose -Message 'Computer is plugged in (charging)'
                    if ($IPAdapterName -eq $NetAdapterName)
                    {
                        Write-Verbose -Message "Confirmed IP Address is associated with the specified adapter. No changes will be initiated."
                    }
                    else
                    {
                        Write-Verbose -Message "IP Address is associated with a different adapter. $NetAdapterName should be Disabled."                        
                        $AdapterState = 'Disabled'
                    }
                }
                else
                {
                    # enable if no ip address
                    Write-Verbose -Message "Computer is plugged in (charging), but has no IP Address. $NetAdapterName should be Enabled."
                    $AdapterState = 'Enabled'
                }                
            }
            else
            {
                Write-Verbose -Message "Computer does NOT seem to be plugged in (charging)."
                if ($IPAddress)
                {
                    Write-Verbose -Message "Computer has IP Address $IPAddress. No changes will be initiated."
                }
                else
                # status quo
                {
                    Write-Verbose -Message 'Computer has no IP Address. $NetAdapterName will be Enabled.'
                    $AdapterState = 'Enabled'
                }
            }
        }
#    }

    # Make it so
#    Process
#    {
        if (-not $ListAvailable)
        {
            if (-not $NetAdapter)
            {
                Write-Error -Message "Unable to find a Network Connection named '$($ConnectionID)'"
            }
            else
            {
                Write-Verbose -Message "Network Connection '$ConnectionID' is $CurStatText"
                if (($AdapterState -eq 'Disabled') -and $($NetAdapter.NetEnabled))
                {
                    Write-Verbose -Message "Setting Network Connection $($NetAdapter.Name) to $AdapterState"
                    if($PSCmdlet.ShouldProcess( "Disabling adapter $ConnectionID", "Disable adapter $ConnectionID`?", "Disabling adapter $ConnectionID" ))
                    {
                        # Now we should make a change, so check if we have permission
                        if (-not (Test-LocalAdmin))
                        {
                            Write-Output -InputObject 'Changing network adapter settings requires elevated permissions. Attempting to re-run this function with admin RunAs.'
                            try
                            {
                                Set-UAC
                            }
                            catch
                            {
                                Write-Warning 'Failed to invoke Set-UAC function.'
                            }

                            Write-Verbose -Message 'Elevating via Open-AdminConsole'
                            Open-AdminConsole -Command Set-NetConnStatus
                        }
                        else
                        {
                            $Return = $NetAdapter.Disable()
                            if ($Return.ReturnValue -ne 0)
                            {
                                Write-Verbose -Message "Unable to disable wireless, the adapter returned: $($Return.ReturnValue)"
                            }
                            else
                            {
                                Write-Verbose -Message "Wireless adapter disabled: $($Return.ReturnValue)"
                            }
                        }
                    }
                }
                elseif (($AdapterState -eq 'Enabled') -and -not $($NetAdapter.NetEnabled))
                {
                    Write-Verbose -Message "Setting network adapter: $($NetAdapter.Name) to $AdapterState"
                    if($PSCmdlet.ShouldProcess( "Enabling adapter $ConnectionID", "Enable adapter $ConnectionID`?", "Enabling adapter $ConnectionID" ))
                    {
                        # Now we should make a change, so check if we have permission
                        if (-not (Test-LocalAdmin))
                        {
                            try
                            {
                                Set-UAC
                            }
                            catch
                            {
                                Write-Warning 'Failed to invoke Set-UAC function.'
                            }

                            Write-Verbose -Message 'Elevating via Open-AdminConsole'
                            Open-AdminConsole -Command Set-NetConnStatus
                        }
                        else
                        {
                            $Return = $NetAdapter.Enable()
                            if ($Return.ReturnValue -ne 0)
                            {
                                Write-Warning -Message "Unable to enable wireless, the adapter returned: $($Return.ReturnValue)"
                            }
                            else
                            {
                                Write-Output -InputObject "Wireless adapter enabled: $($Return.ReturnValue)"
                            }
                        }
                    }
                }
                else
                {
                    Write-Verbose -Message "Wireless adapter will be left as $AdapterState, $CurStatText" -Verbose
                }

                # Double-check that WiFi was changed or otherwise is now in desired state
                Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'" | Select-Object -Property @{LABEL='Adapter/Device Name';EXPRESSION={$_.Name}},@{LABEL='Network Connection Name';EXPRESSION={$_.NetConnectionID}},@{LABEL='Status';EXPRESSION={$($NetConnectionStatus.[int]($_.NetConnectionStatus))}},@{LABEL='Enabled';EXPRESSION={$_.NetEnabled}}
            }
        }
#    }
#    End
#    {
        Write-Output -InputObject ''
        Write-Verbose -Message "$(Get-Date): Ending $($MyInvocation.MyCommand.Name)"
#    }
}

Write-Verbose -Message 'Declaring function Get-NetConnStatus'
function Get-NetConnStatus {
    [CmdletBinding()]
    Param
    (
        [string]
        [Parameter(
            Position=0,
            HelpMessage='Specify the network adapter name (NetConnectionID) to check/get status of. Use -ListAvailable to enumerate available NetConnectionID / Names'
        )]
        $ConnectionID = 'Wireless',

        [switch]
        $ListAvailable
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

    Write-Output -InputObject ''
    Write-Verbose -Message "$(Get-Date): Starting $($MyInvocation.MyCommand.Name)"

    if ($ListAvailable)
    {
        Write-Verbose -Message 'Listing available Network Connections by Name'
        Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
    }
    else
    {
        Write-Verbose -Message "Getting details for Network Connection $ConnectionID"

        $NetAdapter    = Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'"
        $NetAdapterName = $NetAdapter.Name
        $CurStatText = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

        if (-not $NetAdapter)
        {
            Write-Error "Unable to find a Network Connection named $($ConnectionID)"
        }
        else
        {
            Write-Verbose -Message "Network Connection '$ConnectionID' is $CurStatText"
        }

        # Double-check that WiFi was changed or otherwise is now in desired state
        Write-Output -InputObject ''
        Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'" | Select-Object -Property @{LABEL='Adapter/Device Name';EXPRESSION={$_.Name}},@{LABEL='Network Connection Name';EXPRESSION={$_.NetConnectionID}},@{LABEL='Status';EXPRESSION={$($NetConnectionStatus.[int]($_.NetConnectionStatus))}},@{LABEL='Enabled';EXPRESSION={$_.NetEnabled}}
    }
    Write-Output -InputObject ''
    Write-Verbose -Message "$(Get-Date): Ending $($MyInvocation.MyCommand.Name)"
}