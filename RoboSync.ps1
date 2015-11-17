#Requires -Version 3.0 -Modules PSLogger

# ======= HEADER ========================
$Script:myPath = split-path $MyInvocation.MyCommand.Path;
$Script:myName = $MyInvocation.MyCommand.Name;

# ======= SETUP =========================
[Cmdletbinding(SupportsShouldProcess=$true)]
$Script:loggingPreference='Continue';
$Script:loggingPath = Resolve-Path -Path $env:USERPROFILE\Documents\WindowsPowerShell\log
$Script:logFileDateString = get-date -UFormat '%Y%m%d';
[bool]$Script:PurgeTarget = $false; 

# Use regular expression make a .log file that matches this scripts name; makes logging portable
$MyInvocation.MyCommand.Name -match "(.*)\.\w{2,3}?$" *>$NULL; $Script:myLogName = $Matches.1;
$Script:loggingFilePreference = Join-Path -Path $loggingPath -ChildPath "$myLogName-$logFileDateString.log"

# Use regular expression on launch path to determine if this script is in dev mode (in a folder named 'working') or not; makes logging more portable
if ($testMode) { $Script:loggingFilePreference = Join-Path -Path $Script:loggingPath -ChildPath "$myLogName-test-$logFileDateString.log"; }

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

# robocopy specific log filename strings; initialized once, reused within Robosync function :
$Script:monthNames = (new-object system.globalization.datetimeformatinfo).MonthNames; # instantiate array of names of months
[string]$Script:thisMonth = $monthNames[((Get-Date).Month-1)]; # Get the name of the current month by looking up get-date results in $monthNames (zero-based) array
$Script:logFileDateString = get-date -UFormat '%Y%m%d';
$Script:logFileName = "robocopy_$logFileDateString.log";
$Script:robocopyOptions = "/S /R:1 /W:1 /NJH /NS /NC /NP /LOG+:$loggingPath\$logFileName /TEE /XF `~`$* desktop.ini *.log Win8RP-Pro-Boot.zip /XD OneNote log `$RECYCLE.BIN Assyst-CUG CUG DAI ""Win8 ADK"" ""My Demos"" Reference GitHub .git .hg EIT KRosling SnagIt Synergy TFEM NO-SYNC $env:USERPROFILE\Documents\Scripts\archive\ $env:USERPROFILE\Documents\Scripts\borrowed\ $env:USERPROFILE\Documents\Scripts\FastTrack\ $env:USERPROFILE\Documents\Scripts\MyScripts\ $env:USERPROFILE\Documents\WindowsPowerShell\For-TechNet-Gallery\ $(Resolve-Path -Path $env:USERPROFILE\Documents\WindowsPowerShell\Modules\ISESteroids*) ""$env:USERPROFILE\Documents\WindowsPowerShell\PowerShell.org eBooks"" $env:USERPROFILE\Documents\WindowsPowerShell\Scripts $env:USERPROFILE\Documents\WindowsPowerShell\Snippets $env:USERPROFILE\Documents\WindowsPowerShell\workbench";

# ======= ROBOSYNC FUNCTION =============
function Start-Robosync  {
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
VERSION     :  1.4.3
LAST UPDATED:  6/8/2015

.LINK
Sperry.psm1 
Write-Log.psm1 
Show-Progress.ps1 
.INPUTS
None
.OUTPUTS
None
#>
 [Cmdletbinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true, HelpMessage='Specify path to source directory, can be UNC.')]
        [alias('from')]
        [String[]]
        [ValidateScript({Test-Path -Path $_ -PathType Container -IsValid})]
        $Source,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true, HelpMessage='Specify path to destination directory, can be UNC.')]
        [String[]]
        [alias('target','to')]
        [ValidateScript({Test-Path -Path $_ -PathType Container -IsValid})]
        $Destination,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true, HelpMessage='Specify additional robocopy options')]
        [String[]]
        [alias('parameters','arguments')]
        $Options
    )
    Show-Progress -msgAction Start -msgSource RoboSync;

    if ($Destination -imatch 'C:\\Users\\') {
        #unless cleanRemote, presume we're robo-syncing recently changed files from remote shares to local, so don't sync back anything that hasn't been touched in the past 90 days
        $Script:robocopyOptions = $robocopyOptions, '/MAXLAD:90' -join ' ';
        if ($PurgeTarget) {
            $Script:robocopyOptions = $robocopyOptions, '/PURGE' -join ' ';
        }
    }
    if ($Destination -imatch 'Desktop') {
        #Constrain desktop items to be copied to < 100 MB
        $Script:robocopyOptions = $robocopyOptions, '/MAX:1048576' -join ' ';
    }

    if ($Destination -imatch 'Favorites') {
        #Constrain desktop items to be copied to < 100 MB
        $Script:robocopyOptions = $robocopyOptions, '/MAX:1048576' -join ' ';
    }

    if ($Options -ne $NULL) {
        #Append robocopy Options with values of $Options parameter
        Write-Debug "Appending robocopy Options with `$Options: $Options"
        $Script:robocopyOptions = $robocopyOptions, $Options -join ' ';
        Write-Debug "`$robocopyOptions = $robocopyOptions"
    }    

    # if -whatif was included, proceed with dry run
    if (!$PSCmdlet.ShouldProcess($Destination) ) {
        # update log file name to specify test mode, and add /L switch to robocopy options to run in List Only mode 
        $Script:loggingPath = $loggingPath -replace '\\log\\', '\\log\\test\\' # 'log\testing' -Resolve;
        $Script:robocopyOptions = $robocopyOptions, '/L' -join ' ';
        Write-Log -Message "# # # Robocopy $Source $Destination $robocopyOptions" -Function Robosync;
        Start-Process robocopy.exe """$Source"" ""$Destination"" $robocopyOptions" -wait -verb open  -RedirectStandardError $loggingPath\robocopy-errors.log        
        [bool]$showLog = $?

    } else {
        #Run the Robocopy
        Write-Log -Message "# # # Robocopy ""$Source"" ""$Destination"" $robocopyOptions" -Function Robosync;
        Start-Process robocopy.exe """$Source"" ""$Destination"" $robocopyOptions" -wait -verb open  2> $loggingPath\robocopy-errors.log 3> $loggingPath\robocopy-warnings.log; # 3>&2 didn't work
        [bool]$Script:showLog = $?
    }
    Write-Log -Message "_`n" -Function Robosync;

    # show results from the just-created Robosync log file
    if (($showLog) -and (Test-Path -Path $loggingPath\$logFileName -PathType Leaf )) {
        Write-Output -InputObject 'Preparing to display progress logged by Robocopy ...' -Verbose;
        Start-Sleep -Seconds 6;
        Get-Content -Path $loggingPath\$logFileName -Tail 77; # -Tail 77 controls that only the last n lines are shown
    } else {
        Write-Log -Message "`$showLog: $showLog; LogFileName: $loggingPath\$logFileName" -Debug;
    }
    
    Show-Progress -msgAction Stop -msgSource RoboSync    
    
}

trap [System.Exception] {
    Write-Log -Message 'Errors occurred. See log file for details.' -Function Robosync -verbose;
    #uh oh, we may not be connected to the network
    Write-Log -Message "Likely could not connect to home share (`$env:HOMESHARE )" -Function Robosync;
    Write-Log -Message "ErrorLevel: $error[0]" -Function Robosync;
    Read-Host -Prompt 'Please press any key to acknowledge.';
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