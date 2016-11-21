#requires -Version 2
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
    .EXAMPLE
        .\Toggle-Wireless.ps1 -ConnectionID 'Wifi'

        Description
        -----------
        This example shows the basic syntax of the command. If there is an adapter
        with a NetConnectionID of Wifi, then based on the value of BatteryStatus
        the adapter will either be enabled or disabled.
    .NOTES
        ScriptName : Toggle-Wireless.ps1
        Created By : jspatton
        Date Coded : 06/27/2012 08:54:56
        ScriptName is used to register events for this script

        ErrorCodes
        100 = Success
        101 = Error
        102 = Warning
        104 = Information

        This script needs to run from an administrative shell.
    .LINK
        https://code.google.com/p/mod-posh/wiki/Production/Toggle-Wireless.ps1
    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa394074(v=vs.85).aspx
    .LINK
        http://technet.microsoft.com/en-us/library/dd163571
#>

# $MyInvocation debugging
$MyPath = Resolve-Path -Path $MyInvocation.MyCommand.Path

function Set-NetConnStatus {
    [CmdletBinding()]
    Param (
        [string]
        [Parameter(
            Position=0,
            HelpMessage='Specify the name (SSID) of the WiFi network to connect to.'
        )]
        $ConnectionID = 'Wireless',

        [switch]
        $Enable,

        [switch]
        $ListAvailable
    )

#    Begin
#    {
        Write-Output -InputObject ''
        Write-Output -InputObject "$(Get-Date): Starting $($MyInvocation.MyCommand.Name)"

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
            Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property NetConnectionID | Sort-Object -Unique -Property NetConnectionID
            Write-Output -InputObject ''
        }
        else
        {
            # replace with test-admin ?
            $IsAdmin = ([security.principal.windowsprincipal][security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')

            # Dotsource in the functions you need.
            Write-Output -InputObject ''
            Write-Output -InputObject "Getting details for wireless adapter $ConnectionID"
            $Wifi    = Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'"

            $CurStatCode = [int]($Wifi.NetConnectionStatus)
            $CurStatText = $($NetConnectionStatus.[int]($Wifi.NetConnectionStatus))

            # Determine end state the NetworkAdapter (as identified by $ConnectionID) should be in
            if ($Enable)
            {
                $AdapterState = 'Enabled'
            }
            elseif ((Get-WmiObject -Class Win32_Battery -Property BatteryStatus).BatteryStatus -eq 2)
            {
                # Write-Output -InputObject 'The system has access to AC so no battery is being discharged. However, the battery is not necessarily charging.'
                Write-Output -InputObject 'Computer seems to be plugged in to power, and so should also have wired ethernet, so WiFi will be disabled.'
                $AdapterState = 'Disabled'
            }
            else
            {
                Write-Output -InputObject 'Computer does NOT seem to be plugged in to power. WiFi will be enabled.'
                $AdapterState = 'Enabled'
            }
        }
#    }

    # Make it so
#    Process
#    {
        if (-not $ListAvailable)
        {
            if (-not $Wifi)
            {
                Write-Error -Message "Unable to find a wireless adapter named $($ConnectionID)"
            }
            else
            {
                Write-Output -InputObject "NIC Adapter: $ConnectionID is $CurStatText"

                if (-not $IsAdmin)
                {
                    try
                    {
                        Set-UAC
                    }
                    catch
                    {
                        Write-Warning 'Failed to invoke Set-UAC functions.'
                    }

                    Write-Output -InputObject 'Elevating via Open-AdminConsole -NoProfile'
                    $load_script = ". $MyPath" # ; Set-NetConnStatus; start-sleep -Seconds 5}"
                    # Write-Output -InputObject "DEBUG: Open-AdminConsole -NoProfile -Command {& $load_script; Set-NetConnStatus; start-sleep -Seconds 5}"
                    Open-AdminConsole -NoProfile -Command "{ start-transcript; set-psdebug -Trace 2; Set-NetConnStatus; start-sleep -Seconds 1; set-psdebug -off; stop-transcript}"
                }
                else
                {
                    Write-Output -InputObject "Updating configuration / state of Network Adapter: $($Wifi.Name) to $AdapterState"

                    if ($AdapterState -eq 'Disabled')
                    {
                        $Return = $Wifi.Disable()
                        if ($Return.ReturnValue -ne 0)
                        {
                            Write-Output -InputObject "Unable to disable wireless, the adapter returned: $($Return.ReturnValue)"
                        }
                        else
                        {
                            Write-Output -InputObject "Wireless adapter disabled: $($Return.ReturnValue)"
                        }
                    }
                    elseif ($AdapterState -eq 'Enabled')
                    {
                        $Return = $Wifi.Enable()
                        if ($Return.ReturnValue -ne 0)
                        {
                            Write-Warning -Message "Unable to enable wireless, the adapter returned: $($Return.ReturnValue)"
                        }
                        else
                        {
                            Write-Output -InputObject "Wireless adapter enabled: $($Return.ReturnValue)"
                        }
                    }
                    else
                    {
                        Write-Output -InputObject "Wireless adapter will be left as $AdapterState, $CurStatText)"
                    }
                }

                # Double-check that WiFi was changed or otherwise is now in desired state
                Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'" | Select-Object -Property @{LABEL='Adapter/Device Name';EXPRESSION={$_.Name}},@{LABEL='Network Connection Name';EXPRESSION={$_.NetConnectionID}},@{LABEL='Status';EXPRESSION={$($NetConnectionStatus.[int]($_.NetConnectionStatus))}},@{LABEL='Enabled';EXPRESSION={$_.NetEnabled}} | format-table -autosize
            }
        }
#    }
#    End
#    {
        Write-Output -InputObject ''
        Write-Output -InputObject "$(Get-Date): Ending $($MyInvocation.MyCommand.Name)"
#    }
}

# | Select-Object -Property Name,NetConnectionID,$($NetConnectionStatus.[int]($Wifi.NetConnectionStatus)),NetEnabled
# @{LABEL='Adapter/Device Name';EXPRESSION={$_.Name}},@{LABEL='Network Connection Name';EXPRESSION={$_.NetConnectionID}},@{LABEL='Status';EXPRESSION={$($NetConnectionStatus.[int]($_.NetConnectionStatus))}},@{LABEL='Enabled';EXPRESSION={$_.NetEnabled}}

function Get-NetConnStatus {
    [CmdletBinding()]
    Param
    (
        [string]
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false, HelpMessage='Message')]
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
    Write-Output -InputObject "$(Get-Date): Starting $($MyInvocation.MyCommand.Name)"

    if ($ListAvailable)
    {
        Write-Output -InputObject ''
        Write-Output -InputObject 'Listing available Network Connections by ID:'
        Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property NetConnectionID | Sort-Object -Unique -Property NetConnectionID
        Write-Output -InputObject ''
    }
    else
    {
        Write-Output -InputObject ''
        Write-Output -InputObject "Getting details for wireless adapter $ConnectionID"
        if (-not (Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'"))
        {
            Write-Error "Unable to find a wireless adapter named $($ConnectionID)"
        }
        else
        {
            Write-Output -InputObject "NIC Adapter: $ConnectionID is $($NetConnectionStatus.[int]($Wifi.NetConnectionStatus))"
        }

        # Double-check that WiFi was changed or otherwise is now in desired state
        Write-Output -InputObject ''
        Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetConnectionID = '$($ConnectionID)'" | Select-Object -Property @{LABEL='Adapter/Device Name';EXPRESSION={$_.Name}},@{LABEL='Network Connection Name';EXPRESSION={$_.NetConnectionID}},@{LABEL='Status';EXPRESSION={$($NetConnectionStatus.[int]($_.NetConnectionStatus))}},@{LABEL='Enabled';EXPRESSION={$_.NetEnabled}} | format-table -autosize
    }
    Write-Output -InputObject ''
    Write-Output -InputObject "$(Get-Date): Ending $($MyInvocation.MyCommand.Name)"
}