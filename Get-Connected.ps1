#requires -Version 3

[CmdletBinding(SupportsShouldProcess)]
Param ()

Write-Verbose -Message 'Declaring function Set-NetConnStatus'
function Set-NetConnStatus {
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
  Param (
    [string]
    [Parameter(Position=0)]
    $ConnectionID = 'Wireless'
    ,
    [switch]
    $Enable
    ,
    [switch]
    $ListAvailable
    ,
    [Switch]
    $Force
  )

  # Set default value for variables
  $IsAdmin      = $false
  $AdapterState = 'Disabled'
  $RejectAll    = $false
  $ConfirmAll   = $false

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

    if ($ListAvailable)
    {
      Write-Output -InputObject ''
      Write-Output -InputObject 'Listing available Network Connections by ID:'
      Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
      Write-Output -InputObject ''
    }
    else
    {
      Write-Output -InputObject ''
      Write-Output -InputObject ("Getting details for Network Connection '{0}'" -f $ConnectionID)

      $NetAdapter     = Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f ($ConnectionID))
      $NetAdapterName = $NetAdapter.Name
      $CurStatText    = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

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
      Write-Verbose -Message ('Network Adapter {0} is connected to IP Address is {1}' -f $IPAdapterName, $IPAddress)
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
            Write-Verbose -Message 'Confirmed IP Address is associated with the specified adapter. No changes will be initiated.'
          }
          else
          {
            Write-Verbose -Message ('IP Address is associated with a different adapter. {0} should be Disabled.' -f $NetAdapterName)                        
            $AdapterState = 'Disabled'
          }
        }
        else
        {
          # enable if no ip address
          Write-Verbose -Message ('Computer is plugged in (charging), but has no IP Address. {0} should be Enabled.' -f $NetAdapterName)
          $AdapterState = 'Enabled'
        }                
      }
      else
      {
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

  # Make it so
  if (-not $ListAvailable)
  {
    if (-not $NetAdapter)
    {
      Write-Error -Message ("Unable to find a Network Connection named '{0}'" -f ($ConnectionID))
    }
    else
    {
      Write-Verbose -Message ("Network Connection '{0}' is {1}" -f $ConnectionID, $CurStatText)
      Write-Debug -Message ("{0} is {1} ; {2} is {3}" -f '$AdapterState', $AdapterState, '$NetAdapter.NetEnabled', ($NetAdapter.NetEnabled))
      if (($AdapterState -eq 'Disabled') -and $($NetAdapter.NetEnabled))
      {
        Write-Verbose -Message ('Setting Network Connection {0} to {1}' -f $NetAdapter.Name, $AdapterState)
        if($PSCmdlet.ShouldProcess( ('Disabling adapter {0}' -f $ConnectionID), ('Disable adapter {0}`?' -f $ConnectionID), ('Disabling adapter {0}' -f $ConnectionID) ))
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
              Write-Warning -Message 'Failed to invoke Set-UAC function.'
            }

            Write-Verbose -Message 'Elevating via Open-AdminConsole'
            Open-AdminConsole -Command {Set-NetConnStatus}
          }
          else
          {
            $Return = $NetAdapter.Disable()
            if ($Return.ReturnValue -ne 0)
            {
              Write-Verbose -Message ('Unable to disable wireless, the adapter returned: {0}' -f $Return.ReturnValue)
            }
            else
            {
              Write-Verbose -Message ('Wireless adapter disabled: {0}' -f $Return.ReturnValue)
            }
          }
        }
      }
      elseif (($AdapterState -eq 'Enabled') -and -not $($NetAdapter.NetEnabled))
      {
        Write-Verbose -Message ('Setting network adapter: {0} to {1}' -f $NetAdapter.Name, $AdapterState)
        if($PSCmdlet.ShouldProcess( ('Enabling adapter {0}' -f $ConnectionID), ('Enable adapter {0}`?' -f $ConnectionID), ('Enabling adapter {0}' -f $ConnectionID) ))
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
              Write-Warning -Message 'Failed to invoke Set-UAC function.'
            }

            Write-Verbose -Message 'Elevating via Open-AdminConsole'
            Open-AdminConsole -Command {Set-NetConnStatus}
          }
          else
          {
            $Return = $NetAdapter.Enable()
            if ($Return.ReturnValue -ne 0)
            {
              Write-Warning -Message ('Unable to enable wireless, the adapter returned: {0}' -f $Return.ReturnValue)
            }
            else
            {
              Write-Output -InputObject ('Wireless adapter enabled: {0}' -f $Return.ReturnValue)
            }
          }
        }
      }
      else
      {
        Write-Verbose -Message ('Wireless adapter will be left as {0}, {1}' -f $AdapterState, $CurStatText) -Verbose
      }

      # Double-check that WiFi was changed or otherwise is now in desired state
      Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID) | Select-Object -Property @{LABEL='Adapter/Device Name'; EXPRESSION={$PSItem.Name}},@{LABEL='Network Connection Name'; EXPRESSION={$PSItem.NetConnectionID}},@{LABEL='Status'; EXPRESSION={$($NetConnectionStatus.[int]($PSItem.NetConnectionStatus))}},@{LABEL='Enabled'; EXPRESSION={$PSItem.NetEnabled}}
    }
  }
      
  Write-Output -InputObject ''
  Write-Verbose -Message ('{0}: Ending {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)
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
      Set-NetConnStatus -ConnectionID 'Wifi'

      Description
      -----------
      This example shows the basic syntax of the command. If there is an adapter
      with a NetConnectionID of Wifi, then based on the value of BatteryStatus
      the adapter will either be enabled or disabled.
      .NOTES
      Partially based on Toggle-Wireless.ps1 by jspatton (06/27/2012 08:54:56)

      Updated 11/22/2016 Enhance NetConnStatus to skip enabling wifi if Ethernet has address
      Updated 11/23/2016 Improve SupportsShouldProcess / whatif / confirm behavior
      .LINK
      https://code.google.com/p/mod-posh/wiki/Production/Toggle-Wireless.ps1
      http://msdn.microsoft.com/en-us/library/windows/desktop/aa394074(v=vs.85).aspx
      http://technet.microsoft.com/en-us/library/dd163571
  #>
  }

Write-Verbose -Message 'Declaring function Get-NetConnStatus'
function Get-NetConnStatus {
  [CmdletBinding(SupportsShouldProcess)]
  Param
  (
    [Parameter(
        Position=0
    )]
    [string]
    $ConnectionID = 'Wireless'
    ,
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

    if ($ListAvailable)
    {
        Write-Verbose -Message 'Listing available Network Connections by Name'
        Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object -Property Name,NetConnectionID | Sort-Object -Unique -Property NetConnectionID
    }
    else
    {
        Write-Verbose -Message ('Getting details for Network Connection {0}' -f $ConnectionID)

        $NetAdapter    = Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID)
        $NetAdapterName = $NetAdapter.Name
        $CurStatText = $($NetConnectionStatus.[int]($NetAdapter.NetConnectionStatus))

        if (-not $NetAdapter)
        {
            Write-Error -Message ('Unable to find a Network Connection named {0}' -f ($ConnectionID))
        }
        else
        {
            Write-Verbose -Message ("Network Connection '{0}' is {1}" -f $ConnectionID, $CurStatText)
        }

        # Double-check that WiFi was changed or otherwise is now in desired state
        Write-Output -InputObject ''
        $outputObject = Get-WmiObject -Class Win32_NetworkAdapter -Filter ("PhysicalAdapter=True AND NetConnectionID = '{0}'" -f $ConnectionID) -Property *
        Write-Output -InputObject $outputObject | Select-Object -Property @{LABEL='Adapter/Device Name'; EXPRESSION={$PSItem.Name}},@{LABEL='Network Connection Name'; EXPRESSION={$PSItem.NetConnectionID}},@{LABEL='Status'; EXPRESSION={$($NetConnectionStatus.[int]($PSItem.NetConnectionStatus))}},@{LABEL='Enabled'; EXPRESSION={$PSItem.NetEnabled}}

        # return full object 
        return $outputObject
    }
    Write-Output -InputObject ''
    Write-Verbose -Message ('{0}: Ending {1}' -f (Get-Date), $MyInvocation.MyCommand.Name)
}