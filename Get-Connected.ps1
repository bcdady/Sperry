#requires -Version 3

[CmdletBinding()]
Param ()

Write-Verbose -Message 'Declaring function Get-WiFi'
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

Write-Verbose -Message 'Declaring function Connect-WiFi'
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
      Open-AdminConsole -Command {ForEach-Object -InputObject @(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)) { ($PSItem.enable()).ReturnValue }}
      if ($return -eq 0) {
        Write-Log -Message 'Adapter Enabled' -Function $MyInvocation.MyCommand.Name
      } else {
        Write-Log -Message ('A fatal error was encountered trying to enable Network Adapter {0} (Device {1})' -f $PSItem.Name,$PSItem.DeviceID) -Verbose
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

Write-Verbose -Message 'Declaring function Disconnect-WiFi'
function Disconnect-WiFi {
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
  Write-Log -Message 'netsh.exe wlan disconnect' -Function $MyInvocation.MyCommand.Name

  if($PSCmdlet.ShouldProcess( 'Disconnected wlan', "Disconnect wlan`?", 'Disconnecting wlan' )) {
    $results = Invoke-Command -ScriptBlock {& "$env:windir\system32\netsh.exe" wlan disconnect}
    return $results
  }
  Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
  <#
    .SYNOPSIS
      Disconnect from any/all WiFi networks
    .DESCRIPTION
      Designed as a complement to Connect-WiFi, this disconnect function automates disconnecting from wifi, e.g. for when setting into Office workplace
    .EXAMPLE
      .\>_ Disconnect-WiFi

      True - indicates the netsh command returned successful
  #>
} # end function Disconnect-WiFi

Write-Verbose -Message 'Declaring function Get-IPAddress'
function Get-IPAddress {
  [CmdletBinding(SupportsShouldProcess)]
  param ()
  New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private
  Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IpEnabled = True' |
  ForEach-Object -Process {
    #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
    $Private:properties = [ordered]@{
      'AdapterHost'        = $PSItem.PSComputerName
      'AdapterDescription' = $PSItem.Description
      'IPAddress'          = $PSItem.IPAddress
      'Gateway'            = $PSItem.DefaultIPGateway
      'DNSServers'         = $PSItem.DNSServerSearchOrder
    }
    $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties

    return $Private:RetObject # $OutputObj
  } # end of foreach
  <#
      .SYNOPSIS
      Returns Adapter description, IP Address, and basic DHCP info.
      .DESCRIPTION
      Uses Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration queries, for IP enabled network adapters, this function returns the IP Addresses (IPv4 and IPv6, if available), default gateway, DNS server list, and adapter description and index.
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
} # end function Get-IPAddress

function Redo-DHCP {
  $Private:Ethernet = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true}

  foreach ($Private:Adapter in $Private:Ethernet) {
      Write-Verbose -Message 'Releasing IP Address'
      $null = $Private:Adapter.ReleaseDHCPLease()
      Start-Sleep -Seconds 1
      Write-Verbose -Message 'Renewing IP Address'
      $null = $Private:Adapter.RenewDHCPLease()
      Write-Verbose -Message ('IP address is {0} with Subnet {1}' -f $adapter.IPAddress, $adapter.IPSubnet)
  }
  return Get-IPAddress
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
} # end function Redo-DHCP

Write-Verbose -Message 'Declaring function Set-NetConnStatus'
function Set-NetConnStatus {
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
  Param (
    [string]
    [Parameter(Position=0)]
    $ConnectionID = 'Wireless',
    [switch]
    $Enable,
    [switch]
    $ListAvailable,
    [Switch]
    $Force
  )

  # Set default value for variables
  $AdapterState = 'Disabled'

  Write-Output -InputObject ''
  Write-Verbose -Message ('{0}: Starting {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)

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

    if ($ListAvailable) {
        Write-Output -InputObject ''
        Write-Output -InputObject 'Listing available Network Connections by ID:'
        Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
        Write-Output -InputObject ''
      } else {
        if (-not $Global:onServer) {
          Write-Output -InputObject ''
          Write-Output -InputObject ("Getting details for Network Connection '{0}'" -f $ConnectionID)

          $NetAdapter     = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f ($ConnectionID))
          $NetAdapterName = $NetAdapter.Name
          $CurStatText    = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

          try {
            $IPAddress     = (Get-IPAddress).IPAddress
            $IPAdapterName = (Get-IPAddress).AdapterDescription
          }
          catch {
            Write-Debug -Message 'Failed to retrieve an IP address (via Get-IPAddress function)'
            $IPAddress     = $null
            $IPAdapterName = $null
          }
          Write-Verbose -Message ('Network Adapter {0} is connected to IP Address is {1}' -f $IPAdapterName, $IPAddress)
          # force enable
          if ($Enable) {
            $AdapterState = 'Enabled'
          }
          # Determine end state the NetworkAdapter (as identified by $ConnectionID) should be in
          elseif (((Get-CimInstance -ClassName Win32_Battery -Property BatteryStatus).BatteryStatus -eq 2)) {
            if ($IPAddress) {
              Write-Verbose -Message 'Computer is plugged in (charging)'
              if ($IPAdapterName -eq $NetAdapterName) {
                Write-Verbose -Message 'Confirmed IP Address is associated with the specified adapter. No changes will be initiated.'
              } else {
                Write-Verbose -Message ('IP Address is associated with a different adapter. {0} should be Disabled.' -f $NetAdapterName)
                $AdapterState = 'Disabled'
              }
            } else {
              # enable if no ip address
              Write-Verbose -Message ('Computer is plugged in (charging), but has no IP Address. {0} should be Enabled.' -f $NetAdapterName)
              $AdapterState = 'Enabled'
            }
          } else {
            Write-Verbose -Message "Computer does NOT seem to be plugged in (charging)."
            if ($IPAddress)
            {
              Write-Verbose -Message ('Computer has IP Address {0}. No changes will be initiated.' -f $IPAddress)
            }
            else
            # status quo
            {
              Write-Verbose -Message 'Computer has no IP Address. $NetAdapterName will be Enabled.'
              $AdapterState = 'Enabled'
            }
          }
        }
      }

      # Make it so
      if ((-not $ListAvailable) -and (-not $Global:onServer)) {
        if (-not $NetAdapter) {
          Write-Error -Message ("Unable to find a Network Connection named '{0}'" -f ($ConnectionID))
        } else
        {
          Write-Verbose -Message ("Network Connection '{0}' is {1}" -f $ConnectionID, $CurStatText)
          Write-Debug -Message ("{0} is {1} ; {2} is {3}" -f '$AdapterState', $AdapterState, '$NetAdapter.NetEnabled', ($NetAdapter.NetEnabled))
          if (($AdapterState -eq 'Disabled') -and $($NetAdapter.NetEnabled)) {
            Write-Verbose -Message ('Setting Network Connection {0} to {1}' -f $NetAdapter.Name, $AdapterState)
            if($PSCmdlet.ShouldProcess( ('Disabling adapter {0}' -f $ConnectionID), ('Disable adapter {0}`?' -f $ConnectionID), ('Disabling adapter {0}' -f $ConnectionID) )) {
              # Now we should make a change, so check if we have permission
              if (-not (Test-LocalAdmin)) {
                Write-Output -InputObject 'Changing network adapter settings requires elevated permissions. Attempting to re-run this function with admin RunAs.'
                try {
                  Set-UAC
                }
                catch {
                  Write-Warning -Message 'Failed to invoke Set-UAC function.'
                }

                Write-Verbose -Message 'Elevating via Open-AdminConsole'
                Open-AdminConsole -Command {Set-NetConnStatus}
              } else {
                $Return = $NetAdapter.Disable()
                if ($Return.ReturnValue -ne 0) {
                  Write-Verbose -Message ('Unable to disable wireless, the adapter returned: {0}' -f $Return.ReturnValue)
                } else {
                  Write-Verbose -Message ('Wireless adapter disabled: {0}' -f $Return.ReturnValue)
                }
              }
            }
          }
          elseif (($AdapterState -eq 'Enabled') -and -not $($NetAdapter.NetEnabled)) {
            Write-Verbose -Message ('Setting network adapter: {0} to {1}' -f $NetAdapter.Name, $AdapterState)
            if($PSCmdlet.ShouldProcess( ('Enabling adapter {0}' -f $ConnectionID), ('Enable adapter {0}`?' -f $ConnectionID), ('Enabling adapter {0}' -f $ConnectionID) )) {
              # Now we should make a change, so check if we have permission
              if (-not (Test-LocalAdmin)) {
                try {
                  Set-UAC
                }
                catch {
                  Write-Warning -Message 'Failed to invoke Set-UAC function.'
                }

                Write-Verbose -Message 'Elevating via Open-AdminConsole'
                Open-AdminConsole -Command {Set-NetConnStatus}
              } else {
                $Return = $NetAdapter.Enable()
                if ($Return.ReturnValue -ne 0) {
                  Write-Warning -Message ('Unable to enable wireless, the adapter returned: {0}' -f $Return.ReturnValue)
                } else {
                  Write-Output -InputObject ('Wireless adapter enabled: {0}' -f $Return.ReturnValue)
                }
              }
            }
          } else {
            Write-Verbose -Message ('Wireless adapter will be left as {0}, {1}' -f $AdapterState, $CurStatText) -Verbose
          }

          # Double-check that WiFi was changed or otherwise is now in desired state
          Get-CimInstance -ClassName Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID) | Select-Object -Property @{LABEL='Adapter/Device Name'; EXPRESSION={$PSItem.Name}},@{LABEL='Network Connection Name'; EXPRESSION={$PSItem.NetConnectionID}},@{LABEL='Status'; EXPRESSION={$($NetConnectionStatus.[int]($PSItem.NetConnectionStatus))}},@{LABEL='Enabled'; EXPRESSION={$PSItem.NetEnabled}}
        }
      }

  Write-Output -InputObject ''
  Write-Verbose -Message ('{0}: Ending {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)
  <#
      .SYNOPSIS
      This script will toggle the wireless adapter on or off based on BatteryStatus
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
      Set-NetConnStatus -ConnectionID 'Wifi'

      Description
      -----------
      This example shows the basic syntax of the command. If there is an adapter
      with a NetConnectionID of Wifi, then based on the value of BatteryStatus
      the adapter will either be enabled or disabled.
      .NOTES
      Partially based on Toggle-Wireless.ps1 by JSPatton (06/27/2012 08:54:56)

      Updated 11/22/2016 Enhance NetConnStatus to skip enabling wifi if Ethernet has address
      Updated 11/23/2016 Improve SupportsShouldProcess / WhatIf / Confirm behavior
      .LINK
      https://code.google.com/p/mod-posh/wiki/Production/Toggle-Wireless.ps1
      http://msdn.microsoft.com/en-us/library/windows/desktop/aa394074(v=vs.85).aspx
      http://technet.microsoft.com/en-us/library/dd163571
  #>
}

Write-Verbose -Message 'Declaring function Get-NetConnStatus'
function Get-NetConnStatus {
  [CmdletBinding()]
  Param(
    [Parameter(Position=0)]
    [string]
    $ConnectionID,
    [Parameter(Position=1)]
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
    Write-Verbose -Message ('{0}: Starting {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)

    if (-not $ConnectionID) {
        Write-Output -InputObject 'No ConnectionID specified; enumerating physical network adapters'
        $ListAvailable = $true
    }

    if ($ListAvailable) {
        Write-Verbose -Message 'Listing available Physical Network Adapters / Connections by Name'
        Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
    } else {
        Write-Verbose -Message ('Getting details for Network Connection {0}' -f $ConnectionID)

        $NetAdapter  = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)
        $CurStatText = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

        if (-not $NetAdapter) {
            Write-Error -Message ('Unable to find a Network Connection named {0}' -f ($ConnectionID))
        } else {
            Write-Verbose -Message ("Network Connection '{0}' is {1}" -f $ConnectionID, $CurStatText)
        }

        # Double-check that WiFi was changed or otherwise is now in desired state
        Write-Output -InputObject ''
        $outputObject = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID) -Property *
        Write-Output -InputObject $outputObject | Select-Object -Property @{LABEL='Adapter/Device Name'; EXPRESSION={$PSItem.Name}},@{LABEL='Network Connection Name'; EXPRESSION={$PSItem.NetConnectionID}},@{LABEL='Status'; EXPRESSION={$($NetConnectionStatus.[int]($PSItem.NetConnectionStatus))}},@{LABEL='Enabled'; EXPRESSION={$PSItem.NetEnabled}}

        # return full object
        return $outputObject
    }
    Write-Output -InputObject ''
    Write-Verbose -Message ('{0}: Ending {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)
}