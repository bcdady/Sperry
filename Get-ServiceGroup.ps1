#Requires -Version 3.0

#   [Get|Set]-ServiceGroup.ps1 belongs to the Sperry 'autopilot' module, which includes functions
#   to automate getting into and out of work mode.
#   Component of Sperry module; requires functions from other module files.

[CmdletBinding(SupportsShouldProcess)]
param ()
Set-StrictMode -Version latest

Write-Verbose -Message "Declaring function Get-ServiceGroup"
function Get-ServiceGroup {
    [cmdletbinding(SupportsShouldProcess)]
    <#
      .SYNOPSIS
        Get-ServiceGroup function belongs to the Sperry 'autopilot' module, which includes functions to automate getting into and out of work mode.
      .DESCRIPTION
        Interacts with collections of Windows Services, and adds a boolean (true/false) StatusMatch property, indicating whether all Services in the ServiceGroup match the specied status 
        Complements Set-ServiceGroup function, which eases bulk control of services with a similar name
        As a component of the Sperry module, expects/requires functions from other module files, such as Write-Log function.
      .EXAMPLE
        PS C:\> Get-ServiceGroup -Name Sophos -Status Stopped
        Enumerate current state of all services with a name matching Sophos* (as an aggregate of all related Windows services)

        Name        Status      ServiceCount    StatusMatch
        ----        ------      ------------    -----------
        Sophos      Stopped     6               False

      .EXAMPLE
        PS C:\> Get-ServiceGroup -Name Bluetooth
        Gets the current status of all Bluetooth services and compares to (function default status) Running

        Name        Status      ServiceCount    StatusMatch
        ----        ------      ------------    -----------
        Bluetooth   Running     3               True

      .NOTES
        NAME        :  Get-ServiceGroup.ps1
        VERSION     :  2.2.1
        LAST UPDATED:  11/27/2016
        AUTHOR      :  Bryan Dady
      .LINK
        Sperry.psm1 
      .INPUTS
        None
      .OUTPUTS
        Write-Log
    #>
    # Calculates the cumulative status of all services matching the Name parameter
    Param(
        [Parameter(
            Position = 0,
            Mandatory,
            HelpMessage = 'Specify service name to match. Accepts partial names.'
        )]
        [String]
        [alias('Name')]
        [ValidateNotNullOrEmpty()]
        $ServiceName,
        [Parameter(Position = 1)]
        [String]
        [alias('ServiceStatus','State')]
        [ValidateSet('Running', 'Stopped')]
        $Status = 'Running'
    )
    [bool]$StatusMatch = $false
    # reset variables
    $Services = @()
    $ServiceCount = 0
    $StatusCount = 0

    Show-Progress -Mode 'Start' -Action ServiceGroup
    # Log start timestamp
    # 1st: Let's check if the services are running, via accompanying Get-ServiceGroup function
    Write-Log -Message ('Getting services with Name matching {0}' -f $ServiceName) -Function ServiceGroup
    $Services = @(Get-Service -Name $ServiceName) 
    $ServiceCount = $Services.Count
    Write-Log -Message ('Service Count: {0}' -f $ServiceCount) -Function ServiceGroup
    Write-Log -Message ('Checking count of {0} services with status of {1}' -f $ServiceName, $Status) -Function ServiceGroup
    $StatusCount = @($Services | Where-Object -FilterScript { $PSItem.Status -eq $Status }).Count
    Write-Log -Message ('Service Count matching Status: {0}' -f $ServiceCount) -Function ServiceGroup
#    Write-Verbose -Message ('Service Count matching Status: {0}' -f $ServiceCount)

    # if the count of actual running doesn't match the all services count, then our answer is false
    if ($StatusCount -eq $ServiceCount) {
        $StatusMatch = $true
    } else {
        $StatusMatch = $false
    }
    Write-Debug -Message "Get-ServiceGroup $Status = $StatusMatch"

    # Define properties of custom object to be returned
    $Private:properties = [Ordered]@{
        'Name'         = $ServiceName
        'Status'       = $Status
        'ServiceCount' = $ServiceCount
        'StatusMatch'  = $StatusMatch
    }
    $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties

    Show-Progress -Mode Stop -Action ServiceGroup
    # Log stop time-stamp

    return $Private:RetObject
}

Write-Verbose -Message "Declaring function Set-ServiceGroup"
function Set-ServiceGroup {
  [cmdletbinding(SupportsShouldProcess)]
  <#
      .SYNOPSIS
        Set-ServiceGroup function belongs to the Sperry 'autopilot' module, which includes functions to automate getting into and out of work mode.
      .DESCRIPTION
        Interacts with collections of Windows Services, and adds a boolean (true/false) StatusMatch property, indicating whether all Services in the ServiceGroup match the specied status 
        Invokes Get-ServiceGroup to return the latest status of the service group
        As a component of the Sperry module, expects/requires functions from other module files, such as Write-Log function.
      .EXAMPLE
        PS C:\> Set-ServiceGroup -Name Sophos -Status Stopped
        Enumerate current state of all services with a name matching Sophos* (as an aggregate of all related Windows services)

        Name        Status      ServiceCount    StatusMatch
        ----        ------      ------------    -----------
        Sophos      Stopped     6               False

      .EXAMPLE
        PS C:\> Set-ServiceGroup -Name Bluetooth
        Sets the current status of all Bluetooth services to (function default status of) Running

        Name        Status      ServiceCount    StatusMatch
        ----        ------      ------------    -----------
        Bluetooth   Running     3               True

      .NOTES
        NAME        :  Set-ServiceGroup.ps1
        VERSION     :  2.2.1
        LAST UPDATED:  11/27/2016
        AUTHOR      :  Bryan Dady
      .LINK
        Sperry.psm1 
      .INPUTS
        None
      .OUTPUTS
        Write-Log
  #>
    # Calculates the cumulative status of all services matching the Name parameter
    Param(
        [Parameter(
			Position = 0,
            Mandatory,
            HelpMessage = 'Specify service name to match. Accepts partial names.'
        )]
        [String]
        [alias('Name')]
        [ValidateNotNullOrEmpty()]
        $ServiceName,
        [Parameter(Position = 1)]
        [String]
        [alias('ServiceStatus','State')]
        [ValidateSet('Running', 'Stopped')]
        $Status = 'Running'
    )

    [bool]$StatusMatch = $null

    Show-Progress -Mode Start -Action ServiceGroup
    # Log start time-stamp
    $StatusMatch = $((Get-ServiceGroup -ServiceName $ServiceName -Status $Status | Select-Object -Property Name, StatusMatch).StatusMatch)

    if ($StatusMatch) {
        Write-Log -Message "$ServiceName services confirmed $Status" -Function ServiceGroup
    } else {
        Write-Log -Message "$ServiceName services were NOT confirmed $Status" -Function ServiceGroup
        # Need to change status of all services in the group 
        if (Test-LocalAdmin) {
            # We have elevated permissions; proceed with controlling services
            switch ($Status) {
                'Running' {
                    Write-Log -Message 'Confirmed elevated privileges; Starting $ServiceName services' -Function ServiceGroup
                    Start-Service -Name $ServiceName -PassThru | Format-Table -AutoSize -Property Name,Status
                    Start-Sleep -Seconds 1
                }
                'Stopped' {
                    Write-Log -Message 'Confirmed elevated privileges; Stopping $ServiceName services' -Function ServiceGroup
                    Stop-Service -Name $ServiceName -PassThru | Format-Table -AutoSize -Property Name,Status
                    Start-Sleep -Seconds 1
                }
            }        
        } else {
            # Before we attempt to elevate permissions, check current services state 
            Write-Debug -Message "StatusMatch: $StatusMatch"

            Write-Log -Message 'Need elevated privileges to proceed ... attempting Start-Service using admin privileges.' -Function ServiceGroup -Verbose
            # Check and conditionally open UAC window, before invoking repeated elevated commands
            Write-Log -Message 'Checking UserAccountControl level' -Function ServiceGroup
            Open-UAC

            $CommandString = "Set-ServiceGroup -ServiceName {0} -Status {1} -Verbose" -f "'$ServiceName'",$Status
            Write-Debug -Message "Open-AdminConsole -Command $CommandString"
            Open-AdminConsole -Command $CommandString -Verbose
            Start-Sleep -Seconds 6
        }

        # Get ServiceGroup and show output
        Get-ServiceGroup -ServiceName $ServiceName -Status $Status
    }
    # Log stop time-stamp
    Show-Progress -Mode Stop -Action ServiceGroup
}
