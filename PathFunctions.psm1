#requires -Version 2 -Modules CimCmdlets
<#
.SYNOPSIS
    PathFunctions Module contains functions that help make it easier to interact with PSDrive paths.
.DESCRIPTION
    PathFunctions.psm1 - Provides common functions for connecting to, enumerating, and disconnecting from predefined UNC paths
#>


function Mount-Path {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp

    if (-not $MySettings.UNCPath) {
        Import-Settings
    }
    # $AllDrives = 1 (true) means map all drives; 0 (false) means only map H: and S:
    Write-Log -Message 'Mapping Network Drives' -Function $MyInvocation.MyCommand.Name
    if (Test-LocalAdmin) { Write-Log -Message 'Mapping drives with a different account, may result in them NOT appearing properly in Explorer' -Function $MyInvocation.MyCommand.Name }

    # Read in UNC path / drive letter mappings from sperry.json : Sperry.uncPaths
    # loop through all defined drive mappings

    if (-not ($MySettings.UNCPath)) {
        Write-Log -Message '$MySettings.UNCPath was not found.' -Function $MyInvocation.MyCommand.Name
    } else {
        $MySettings.UNCPath | Sort-Object -Property Order | ForEach-Object -Process {
            Write-Debug -Message ('$PSItem.DriveName: {0}' -f $PSItem.DriveName)
            Write-Debug -Message ('$PSItem.FullPath: {0}' -f $PSItem.FullPath)
            $DriveName = $ExecutionContext.InvokeCommand.ExpandString($PSItem.DriveName)
            $PathRoot  = $ExecutionContext.InvokeCommand.ExpandString($PSItem.FullPath)
            Write-Verbose -Message ('$DriveName: {0}' -f $DriveName)
            Write-Verbose -Message ('$PathRoot: {0}' -f $PathRoot)

            $Private:OKMount = $false
            if (Test-Path -Path ('{0}:\' -f $DriveName)) {
                # Write-Warning -Message ('Drive letter {0} already in use.' -f $DriveName)
                Write-Log -Message ('Drive letter {0} already in use' -f $DriveName) -Function 'Mount-Path'
            } else {
                $Private:OKMount = $true
            }

            if (Test-Path -Path $PathRoot -ErrorAction:SilentlyContinue) {
                $Private:OKMount = $true
            } else {
                # Write-Warning -Message ('Path {0} was not found; unable to map to drive letter {1}' -f $PathRoot, $DriveName)
                Write-Log -Message ('Path {0} was not found; unable to map to drive letter {1}' -f $PathRoot, $DriveName) -Function 'Mount-Path' -Verbose
                $Private:OKMount = $false
            }

            if ($Private:OKMount) {
                Write-Log -Message ('New-PSDrive {0}: {1}' -f $DriveName, $PathRoot) -Function 'Mount-Path'
                Write-Debug -Message (' New-PSDrive -Persist -Name {0} -Root {1} -PSProvider FileSystem -scope Global' -f $DriveName, $PathRoot)
                New-PSDrive -Name $DriveName -Root $PathRoot -PSProvider FileSystem -Persist -Scope Global -ErrorAction:SilentlyContinue
                Start-Sleep -Milliseconds 150
            }
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Mount-Path

# Define Get-PSFSDrive function -- specifies invoking Get-PSDrive, for -PSProvider FileSystem
function Get-PSFSDrive {
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Enumerating mapped network drives' -Function $MyInvocation.MyCommand.Name
    Get-PSDrive -PSProvider FileSystem
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Get-PSFSDrive

# Define Dismount-Path function
function Dismount-Path {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    Write-Log -Message 'Removing mapped network drives' -Function $MyInvocation.MyCommand.Name
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        if ($PSItem.DisplayRoot -like '\\*') {
            Write-Log -Message ('Remove-PSDrive {0}: {1}' -f $PSItem.Name, $PSItem.DisplayRoot) -Function $MyInvocation.MyCommand.Name
            if ($PSItem.Name -like $pwd.Path[0]) {
                Set-Location
            }
            if ($PSItem.Name -like $HOME.Path[0]) {
                # Reset $HOME from a network path to a local path
                Set-Variable  -Name HOME -Value (Resolve-Path -Path $env:USERPROFILE) -Force
            }
            Remove-PSDrive -Name $PSItem
        }
    }
    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Dismount-Path
