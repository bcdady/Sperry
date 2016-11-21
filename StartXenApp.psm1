#Requires -Version 2

function Start-XenApp
{
<#
    .SYNOPSIS
        Extension of Sperry module, to simplify invoking Citrix Receiver PNAgent.exe
    .DESCRIPTION
        Sets pnagent path string, assigns frequently used arguments to function parameters, including aliases to known /Qlaunch arguments
    .PARAMETER Qlaunch
        The Qlaunch parameter references a shortcut name, to be referenced against the known XenApp apps to launch, and then passes to pnagent to be launched by Citrix
    .PARAMETER Reconnect
        Requests that PNAgent attempt to reconnect to any existing Citrix XenApp session for the current user
    .PARAMETER Terminatewait
        Attempts to close all applications in the current user's Citrix XenApp session, and logoff from that session
    .PARAMETER ListAvailable
        Enumerates available XenApp shortcuts that can be passed to -QLaunch

    .EXAMPLE
        PS C:\> Start-XenApp -Qlaunch rdp
        Remote Desktop (or mstsc.exe) client, using the rdp alias, which is defined in the $XenApps hashtable
    .EXAMPLE
        PS C:\> Start-XenApp -open excel
        Open Excel, using the -open alias for the -Qlaunch parameter
    .EXAMPLE
        PS C:\> Start-XenApp -ListAvailable
        Enumerate available XenApp shortcuts to launch
    .NOTES
        NAME        :  Start-XenApp
        VERSION     :  1.3
        LAST UPDATED:  4/9/2015
        AUTHOR      :  Bryan Dady
#>
    [CmdletBinding(DefaultParameterSetName = 'Launch')]
    #    [OutputType([int])]
    Param (
        # PNArgs specifies whether PNAgent.exe should attempt to reconnect an existing session, Qlaunch a new app, or other supported behavior
        [Parameter(
            Position = 0,
            ParameterSetName = 'Mode'
		)]
        [Alias('args','XenApp','launch','start','open')]
        [String]
        $Qlaunch = '-ListAvailable',

        [Parameter(
            Position = 3,
            ParameterSetName = 'Launch'
		)]
        [ValidateNotNullOrEmpty()]
        [Alias('connect')]
        [switch]
        $Reconnect,

        [Parameter(
            Position = 1,
            ParameterSetName = 'Mode'
		)]
        [ValidateNotNullOrEmpty()]
        [Alias('end', 'close', 'halt', 'exit', 'stop')]
        [switch]
        $Terminatewait,

        [Parameter(
            Position = 2,
            ParameterSetName = 'Mode'
		)]
        [ValidateNotNullOrEmpty()]
        [Alias('list', 'show', 'enumerate')]
        [switch]
        $ListAvailable

    )

    # Set pnagent path string
    $Global:pnagent = "${env:ProgramFiles(x86)}\Citrix\ICA Client\pnagent.exe"
    Show-Progress -msgAction Start -msgSource $PSCmdlet.MyInvocation.MyCommand.Name

    # Load up $Setting.XenApp from sperry.json into Script scope $XenApps hashtable
    $Script:XenApps = @{}

    if ([bool]$($Settings.XenApp))
    {
        $Settings.XenApp | ForEach-Object {
            Write-Debug -Message "$($PSItem.Name) = $($ExecutionContext.InvokeCommand.ExpandString($PSItem.Qlaunch))"
            $script:XenApps.Add("$($PSItem.Name)",$ExecutionContext.InvokeCommand.ExpandString($PSItem.Qlaunch))
        }
    }
    else
    {
        throw "Unable to load global settings from `$Settings object. Perhaps there was an error loading from sperry.json."
    }

    if ($PSBoundParameters.ContainsKey('Qlaunch'))
    {
        if ($XenApps.Keys -contains $Qlaunch)
        {
            $Private:Arguments = '/CitrixShortcut: (1)', "/QLaunch ""$($XenApps.$Qlaunch)"""
        }
        else
        {
            # if a shortcut key is not defined in $XenApps, pass the full 'string' e.g. GBCI02XA:Internet Explorer
            $Private:Arguments = '/CitrixShortcut: (1)', '/QLaunch', """GBCI02XA:$Qlaunch"""
            # possible RFE: enhance string whitespace handling of $Qlaunch
        }
        # /Terminate Closes out PNAgent and any open sessions
        # /terminatewait  Closes out PNAgent and any open sessions; Logs off
        # /Configurl  /param:URL  (useful if you haven't set up the client as part of the install)
        # /displaychangeserver
        # /displayoptions
        # /logoff
        # /refresh
        # /disconnect
        # /reconnect
        # /reconnectwithparam
        # /qlaunch  (syntax example pnagent.exe /Qlaunch "Farm1:Calc")

        # As long as we have non-0 arguments, run it using Start-Process and arguments list
        if ($Private:Arguments -ne $NULL)
        {
            Write-Log -Message "Starting $($Arguments.Replace('/CitrixShortcut: (1) /QLaunch ',''))" -Function $PSCmdlet.MyInvocation.MyCommand.Name -Verbose
            # $pnagent
            Start-Process $pnagent -ArgumentList "$Private:Arguments" -Verbose
        }
        else
        {
            Write-Log -Message "Unrecognized XenApp shortcut: $XenApp`nPlease try again with one of the following:" -Function $PSCmdlet.MyInvocation.MyCommand.Name
            $XenApps.Keys
            break
        }
    }
    elseif ($PSBoundParameters.ContainsKey('Reconnect'))
    {
        Write-Log -Message 'Start pnagent.exe /reconnect' -Function $PSCmdlet.MyInvocation.MyCommand.Name
        Start-Process $pnagent -ArgumentList '/reconnect'
    }
    elseif ($PSBoundParameters.ContainsKey('Terminatewait'))
    {
        Write-Log -Message 'Start pnagent.exe /terminatewait' -Function $PSCmdlet.MyInvocation.MyCommand.Name
        Start-Process $pnagent -ArgumentList '/terminatewait'
    }
    elseif ($PSBoundParameters.ContainsKey('ListAvailable'))
    {
        Write-Log -Message '`nEnumerating all available `$XenApps Keys' -Function $PSCmdlet.MyInvocation.MyCommand.Name
        $XenApps |
        Sort-Object -Property Name |
        Format-Table -AutoSize
    }

    Show-Progress -msgAction Stop -msgSource $PSCmdlet.MyInvocation.MyCommand.Name
}
