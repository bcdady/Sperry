#Requires -Version 2 -Modules PSLogger, Sperry

# Predefine XenApp Qlaunch arguments for running Citrix [pnagent] applications
# By Predefining at the script scope, we can evaluate parameters using ValidateScript against this hashtable
$Script:XenApps = @{
    assyst       = 'GBCI02XA:Assyst'
    communicator = 'GBCI02XA:Office Communicator'
    cmd          = 'GBCI02XA:Command Line'
    ocs          = 'GBCI02XA:Office Communicator'
    excel        = 'GBCI02XA:Microsoft Excel 2010'
    h_drive      = 'GBCI02XA:H Drive'
    IE           = 'GBCI02XA:Internet Explorer'
    IE_11        = 'GBCI02XA:Internet Explorer 11'
    itsc         = 'GBCI02XA:IT Service Center'
    mstsc        = 'GBCI02XA:RDP Client'
    onenote      = 'GBCI02XA:Microsoft OneNote 2010'
    outlook      = 'GBCI02XA:Microsoft Outlook 2010'
    powerpoint   = 'GBCI02XA:Microsoft Powerpoint 2010'
    rdp          = 'GBCI02XA:RDP Client'
    s_drive      = 'GBCI02XA:S Drive'
    word         = 'GBCI02XA:Microsoft Word 2010'
    visio        = 'GBCI02XA:Microsoft Visio 2013'
}

# Get Microsoft Office specific shortcuts into their own hashtable
$RDS_OfficeShortcuts = $shortcuts.Keys | ForEach-Object -Process { if ($($shortcuts.$PSItem) -like '*office*') {@{$PSItem = $($shortcuts.$PSItem)}}}

# Upgrade to get-shortcuts:
# Create new alias function name from parsed string between last \ and .lnk, replace/remove Microsoft and all spaces
<#
outicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook 2010.lnk
accicons.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Access 2010.lnk
cagicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Office 2010 Tools\Microsoft Clip Organizer.lnk
inficon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft InfoPath Designer 2010.lnk
joticon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote 2010.lnk
lyncicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\Office 2013 Tools\Skype for Business Recording Manager.lnk
misc.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Office 2010 Tools\Digital Certificate for VBA Projects.lnk
msouc.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\Office 2013 Tools\Office 2013 Upload Center.lnk
oisicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Office 2010 Tools\Microsoft Office Picture Manager.lnk
pj11icon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Project 2010.lnk
pptico.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint 2010.lnk
ppvwicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office PowerPoint Viewer 2007.lnk
pubs.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher 2010.lnk
visicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Visio 2010.lnk
wordicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word 2010.lnk
wrdvicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office Word Viewer 2003.lnk
xlicons.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel 2010.lnk
xlvwicon.exe :: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office Excel Viewer.lnk

$shortcuts.'outicon.exe'
joticon.exe # OneNote
lyncicon.exe
oisicon.exe # Office Picture Manager
pj11icon.exe # Project
pptico.exe # PowerPoint
visicon.exe # Visio
$shortcuts.'wordicon.exe' # Word
xlicons.exe # Excel

$shortcuts.'iexplore.exe'
$shortcuts.'jhaintvports.exe'
$shortcuts.'msinfo32.exe'
$shortcuts.'SnippingTool.exe'
$shortcuts.'ADTool.exe'
$shortcuts.'LnchPrcExp.exe'
$shortcuts.'LnchPrcMon.exe'
$shortcuts.'SynServiceMonitor.exe'
$shortcuts.'Citrix Quick Launch.exe'

$shortcuts.'PrintDetective.exe'
$shortcuts.'InternetShortcut.exe'
#>

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
        # PNArgs specifies whether PNAgent.exe should attempt to reconnect an existing session, Qlanch a new app, or other supported behavior
        [Parameter(Mandatory = $false, 
                ValueFromPipeline = $false,
                ValueFromPipelineByPropertyName = $false, 
                ValueFromRemainingArguments = $false, 
                Position = 0,
        ParameterSetName = 'Mode')]
        [ValidateScript({
                    $PSItem -in $XenApps.Keys
                }
        )]
        [Alias('args','XenApp','launch','start','open')]
        [String] 
        $Qlaunch = '-ListAvailable',

        [Parameter(Mandatory = $false, 
                Position = 3,
        ParameterSetName = 'Launch')]
        [ValidateNotNullOrEmpty()]
        [Alias('connect')]
        [switch] 
        $Reconnect,

        [Parameter(Mandatory = $false, 
                Position = 1,
        ParameterSetName = 'Mode')]
        [ValidateNotNullOrEmpty()]
        [Alias('end', 'close', 'halt', 'exit', 'stop')]
        [switch] 
        $Terminatewait,

        [Parameter(Mandatory = $false, 
                Position = 2,
        ParameterSetName = 'Mode')]
        [ValidateNotNullOrEmpty()]
        [Alias('list', 'show', 'enumerate')]
        [switch] 
        $ListAvailable

    )

    # Set pnagent path string
    $Global:pnagent = "${env:ProgramFiles(x86)}\Citrix\ICA Client\pnagent.exe"

    Show-Progress -msgAction Start -msgSource $PSCmdlet.MyInvocation.MyCommand.Name

    if ($PSBoundParameters.ContainsKey('Qlaunch')) 
    {
        if ($XenApps.Keys -contains $Qlaunch) 
        {
            $Private:Arguments = '/CitrixShortcut: (1)', "/QLaunch ""$($XenApps.$Qlaunch)"""
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
            Write-Log -Message "Start pnagent.exe $Private:Arguments)" -Function $PSCmdlet.MyInvocation.MyCommand.Name
            # $pnagent
            Start-Process $pnagent -ArgumentList $Private:Arguments
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

Export-ModuleMember -Function *