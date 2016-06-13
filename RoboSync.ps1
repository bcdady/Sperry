#Requires -Version 3

# ======= HEADER ========================
#$Script:myPath = Split-Path -Path $MyInvocation.MyCommand.Path
#$Script:myName = $MyInvocation.MyCommand.Name
$Script:myWPS  = Join-Path -Path "$([Environment]::GetFolderPath('MyDocuments'))" -ChildPath 'WindowsPowerShell'

[Cmdletbinding(SupportsShouldProcess = $true)]
$Script:loggingPreference = 'Continue'

# $Script:loggingPath = "$myWPS\log"
# $Script:logFileDateString = Get-Date -UFormat '%Y%m%d'

[bool]$Script:PurgeTarget = $false 

# Use regular expression make a .log file that matches this scripts name; makes logging portable

#$MyInvocation.MyCommand.Name -match "(.*)\.\w{2,3}?$" *>$NULL
#$Script:myLogName = $Matches.1

# $Script:loggingFilePreference = $(Join-Path -Path $(Join-Path -Path "$([Environment]::GetFolderPath('MyDocuments'))" -ChildPath 'WindowsPowerShell\log') -ChildPath $($MyInvocation.MyCommand.Name -replace '.ps1',$("-$(Get-Date -UFormat '%Y%m%d').log")))

$Script:loggingFilePreference = $(Join-Path -Path $myWPS -ChildPath $('log'+$MyInvocation.MyCommand.Name -replace '.ps1',$("-$(Get-Date -UFormat '%Y%m%d').log")))

Write-Output -InputObject "loggingFilePreference is $loggingFilePreference"

# '\\path\Robosync.ps1' -replace '.ps1',$("-$(Get-Date -UFormat '%Y%m%d').log")

# Use regular expression on launch path to determine if this script is in dev mode (in a folder named 'working') or not; makes logging more portable
if ($testMode) 
{
    $Script:loggingFilePreference = Join-Path -Path $Script:loggingPath -ChildPath "$myLogName-test-$logFileDateString.log"
}

<#
        Robocopy.exe example: robocopy.exe source destination [options]
        Our preferred options: 
        /S   :: copy Subdirectories, but not empty ones.
        /PURGE :: delete dest files/dirs that no longer exist in source.
        /R:n :: number of Retries on failed copies: default 1 million.
        /W:n :: Wait time between retries: default is 30 seconds.
        /L   :: List only - don't copy, timestamp or delete any files.	
        /LOG+:file :: output status to LOG file (append to existing log).
        /TEE :: output to console window, as well as the log file.
        /NJH :: No Job Header.
        /NJS :: No Job Summary.
        /MAX:n :: MAXimum file size - exclude files bigger than n bytes.
        /MIN:n :: MINimum file size - exclude files smaller than n bytes.
        /MAXLAD:n :: MAXimum Last Access Date - exclude files unused since n.
        /XF file [file]... :: eXclude Files matching given names/paths/wildcards.
        /XD dirs [dirs]... :: eXclude Directories matching given names/paths.
        e.g. /XD: `$RECYCLE.BIN
#>
# ======= SETUP =========================
# robocopy specific log filename strings; initialized once, reused within Robosync function :
# instantiate array of names of months
$Script:monthNames = (New-Object -TypeName system.globalization.datetimeformatinfo).MonthNames
# Get the name of the current month by looking up get-date results in $monthNames (zero-based) array
[string]$Script:thisMonth = $monthNames[((Get-Date).Month-1)]
$Script:logFileDateString = Get-Date -UFormat '%Y%m%d'
$Script:logFileName = "robocopy_$logFileDateString.log"
$Script:robocopyOptions = "/S /R:1 /W:1 /NJH /NS /NC /NP /LOG+:$loggingFilePreference /TEE /XF `~`$* desktop.ini *.log Win8RP-Pro-Boot.zip /XD OneNote log `$RECYCLE.BIN Assyst-CUG CUG DAI ""Win8 ADK"" ""My Demos"" Reference GitHub .git .hg EIT KRosling SnagIt Synergy TFEM NO-SYNC $env:USERPROFILE\Documents\Scripts\archive\ $env:USERPROFILE\Documents\Scripts\borrowed\ $env:USERPROFILE\Documents\Scripts\FastTrack\ $env:USERPROFILE\Documents\Scripts\MyScripts\ $myWPS\For-TechNet-Gallery\ $(Resolve-Path -Path $myWPS\Modules\ISESteroids*) ""$myWPS\PowerShell.org eBooks"" $myWPS\Snippets $myWPS\workbench"

# ======= ROBOSYNC FUNCTION =============
function Start-Robosync  
{
<#
    .SYNOPSIS
        Robocopy command and control function synchronize folders, for example, between local and network directories
    .DESCRIPTION
        Can be used to synchronized documents, etc. between a user's local (laptop) and network share based Home Directory. Also works for replicating or backing up a script repository. By defining many preset parameters for robocopy.exe, as well as exposing some parameter, this function makes it easier to synchronize several different network-based (NAS) and/or 'local' directories.
    .EXAMPLE
        PS C:\> Start-Robosync -source """H:\My Documents""" -Destination "$env:userprofile\Documents"
        Synchronizes all files from mapped network drive H:\My Documents folder, to local, variable-based user's profile Documents directory, including recursive sub-directories.
        *** Note *** : Note the triple-quotes around the source value, because it has a space in the value string, and we need to carefully wrap it up before passing to robocopy.exe
    .NOTES
        NAME        :  Start-Robosync
        VERSION     :  1.4.5
        LAST UPDATED:  11/16/2015
    .LINK
        Sperry.psm1 
        Write-Log.psm1 
        Show-Progress.ps1 
#>
    [Cmdletbinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true,
            Position=0,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Specify path to source directory, can be UNC.'
        )]
        [alias('from')]
        [String[]]
        [ValidateScript({Test-Path -Path $PSItem -PathType Container})]
        $Source,

        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify path to destination directory, can be UNC.'
        )]
        [String[]]
        [alias('target','to')]
        [ValidateScript({Test-Path -Path $PSItem -PathType Container -IsValid})]
        $Destination
    )
    Show-Progress -msgAction Start -msgSource RoboSync


    if ($Destination -imatch 'C:\\Users\\') 
    {
        #unless cleanRemote, presume we're robo-syncing recently changed files from remote shares to local, so don't sync back anything that hasn't been touched in the past 90 days
        $Script:robocopyOptions = $robocopyOptions, '/MAXLAD:90' -join ' '
        if ($PurgeTarget) 
        {
            $Script:robocopyOptions = $robocopyOptions, '/PURGE' -join ' '
        }
    }
    if ($Destination -imatch 'Desktop') 
    {
        #Constrain desktop items to be copied to < 100 MB
        $Script:robocopyOptions = $robocopyOptions, '/MAX:1048576' -join ' '
    }

    if ($Destination -imatch 'Favorites') 
    {
        #Constrain desktop items to be copied to < 100 MB
        $Script:robocopyOptions = $robocopyOptions, '/MAX:1048576' -join ' '
    }

    # if -whatif was included, proceed with dry run
    if (!$PSCmdlet.ShouldProcess($Destination) ) 
    {
        # update log file name to specify test mode, and add /L switch to robocopy options to run in List Only mode 
        $Script:loggingPath = $loggingPath -replace '\\log\\', '\\log\\test\\' # 'log\testing' -Resolve;
        $Script:robocopyOptions = $robocopyOptions, '/L' -join ' '
        Write-Log -Message "# # # Robocopy $Source $Destination $robocopyOptions" -Function Robosync
        Start-Process -FilePath robocopy.exe -ArgumentList """$Source"" ""$Destination"" $robocopyOptions" -Wait -Verb open  -RedirectStandardError $loggingFilePreference
        [bool]$showLog = $?
    }
    else 
    {
        #Run the Robocopy
        Write-Log -Message "# # # Robocopy ""$Source"" ""$Destination"" $robocopyOptions" -Function Robosync
        Start-Process -FilePath robocopy.exe -ArgumentList """$Source"" ""$Destination"" $robocopyOptions" -Wait -Verb open  2> $loggingFilePreference 3> loggingFilePreference
        # 3>&2 didn't work
        [bool]$showLog = $?
    }
    Write-Log -Message "_`n" -Function Robosync

    # show results from the just-created Robosync log file
    if (($showLog) -and (Test-Path -Path $loggingFilePreference -PathType Leaf )) 
    {
        Write-Output -InputObject 'Preparing to display progress logged by Robocopy ...' -Verbose
        Start-Sleep -Seconds 6
        Get-Content -Path $loggingFilePreference -Tail 77
        # -Tail 77 controls that only the last n lines are shown
    } else 
    {
        Write-Log -Message "`$showLog: $showLog; LogFileName: $loggingFilePreference" -Debug
    }
    
    Show-Progress -msgAction Stop -msgSource RoboSync
}

trap [System.Exception] 
{
    Write-Log -Message 'Errors occurred. See log file for details.' -Function Robosync -Verbose
    #uh oh, we may not be connected to the network
    Write-Log -Message "Likely could not connect to home share (`$env:HOMESHARE )" -Function Robosync
    Write-Log -Message "ErrorLevel: $error[0]" -Function Robosync
    Read-Host -Prompt 'Please press any key to acknowledge.'
}

# ======= PROFILE PATH REFERENCE ================
# [HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders]
<# "AppSenseData" = \\gbci02sanct3\homes$\gbci\BDady\AppSenseData\Recent\Win7-2008
        AppData=[Roaming]
        Cache=[Local]
        Cookies=[Local]
        Desktop=[Local]
        Favorites=[Local]
        History=[Local]
        Local AppData=[Local]
        My Music=AppSenseData\Music
        My Pictures=AppSenseData\Pictures
        My Video=AppSenseData\Video
        NetHood=[Local]
        Personal=[Local]\Documents
        PrintHood=[Roaming]
        Programs=[Roaming]
        Recent=\AppSenseData\Recent\Win7-2008
        SendTo=[Roaming]
        Start Menu=[Roaming]
        Startup=[Roaming]
        Templates=[Roaming]
#>