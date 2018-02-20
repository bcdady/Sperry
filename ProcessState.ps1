#!/usr/local/bin/powershell
#Requires -Version 3 -Module PSLogger
<#
    .SYNOPSIS
        checkProcess.ps1 is designed to simplify process management for frequently used executables / applications.
        It can be used to find and check that a process is running, including waiting / pausing while that process is still running (e.g. waiting for a setup to complete before proceeding), or stop any running process.
        If the path to a process is defined within the script's $knownPaths table, it can also be used to specifically control the arguments and startup behavior of those programs.
    .DESCRIPTION
        checkProcess.ps1 is can be used to find and check that any process is running, including waiting / pausing while that process is still running (e.g. waiting for a setup to complete before proceeding), or stop a running process.
        If the path to a process is defined within the script's $knownPaths hash-table, it can also be used to specifically control the arguments and startup behavior of those programs.
    .PARAMETER processName
        Name of process to check for, start up, or stop
    .PARAMETER Start
        Run the script in Start mode, which includes looking up the processName parameter in the $knownPaths table, and then invoking accordingly
    .PARAMETER Stop
        Run the script in Stop mode, which starts a seek and destroy mission for the specified processName on the local OS
    .PARAMETER Test
        Run the script in Test mode, which checks for a running process matching the processName parameter, and can either return a boolean result representing whether or not the processName was found running, and it can optionally wait for the process to stop before returning.
    .EXAMPLE
        checkProcess.ps1 -processName notepad -start
    .Notes
        LANG: PowerShell
        NAME: checkProcess.ps1
        AUTHOR: Bryan Dady
        DATE: 11/25/09
        COMMENT: Shared script for controlling a common set of processes for various modes
        : History - 2014 Jun 25 : Added / updated Citrix knownPaths
        : History - 2015 Mar 20 : Moved Citrix knownPaths and related PNAgent.exe controll to StartXenApp.ps1, and incorporated both checkProcess.ps1 and StartXenApp.ps1 into the Sperry Module for PowerShell
        : History - 2016 Nov 13 : Replace knownpaths hashtable in this script with a reference to JSON objects defined in Sperry.json
    .Outputs
        Calls Write-Log.ps1 to write a progress log to the file system, as specified in the setup block of the script
#>

# Contains only filename.ext leaf; for full path and filename, use $PSCommandPath
[bool]$script:interrupt  = $false

# Setup necessary configs for PSLogger's Write-Log cmdlet
[cmdletbinding(SupportsShouldProcess)]
$loggingPreference = 'Continue'

# Functions
# =======================================
# checkProcess([Process Name], [Start|Stop])
function Set-ProcessState {
[cmdletbinding(SupportsShouldProcess)]
<#
    .SYNOPSIS
        A helper function for streamlining start-process and stop-process cmdlet interactions for predefined executable file paths and their arguments / parameters.
    .DESCRIPTION
        Using the ProcessName parameter, and the internally defined $knownPaths hash table, Set-ProcessState can be used to either Start or Stop a particular application / process, simply by specifying the -Action parameter
    .PARAMETER processName
        Name of process to check for, start up, or stop
    .PARAMETER Action
        Specify whether to start processName, or to Stop it.
    .PARAMETER ListAvailable
        Enumerate $knownPaths hash table
    .EXAMPLE
        Get-Process C:\> Set-ProcessState -ProcessName iexplore -Action Stop
        Stop all running instances of Internet Explorer
    .EXAMPLE
        Get-Process C:\> Set-ProcessState -ProcessName Firefox -Action Start
        Effectively equivalent to Start-Process Firefox browser, when the path to Firefox.exe is defined in your Sperry JSON file.
    .NOTES
        NAME        :  Set-ProcessState
        VERSION     :  2.1.2
        LAST UPDATED:  6/10/2015
        AUTHOR      :  Bryan Dady
    .LINK
        PSLogger
        Sperry
#>
    Param (
        [parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        [alias('Name')]
        $ProcessName,

        [parameter(Position = 1)]
        [ValidateSet('Start', 'Stop')]
        [String]
        [alias('Status')]
        $Action,

        [Parameter(Position = 2)]
        [switch]
        $ListAvailable
    )

    # begin {
    # =======================================
    # Start with empty process arguments / parameters
    $script:CPargs   = ''
    # Import hashtable (associative array) of known paths for executable files
    # IMPORTANT: key needs to match executable name for STOP and Wait modes to work
    # NOTE: start arguments are added later so that the same key can be used for starting and stopping processes

    Import-Settings
    $script:knownPaths = @{}
    try {
        $MySettings.KnownProcess | out-null
    }
    catch {
        throw $Error
    }
    
    $MySettings.KnownProcess | ForEach-Object {
        Write-Debug -Message "$($PSItem.Name) = $($ExecutionContext.InvokeCommand.ExpandString($PSItem.Path))"
        $script:knownPaths.Add("$($PSItem.Name)",$ExecutionContext.InvokeCommand.ExpandString($PSItem.Path))
    }

    # Predefine 'prompt-list' to control which processes invoke user approval and which ones terminate silently
    $script:askTerminate = @('receiver', 'outlook', 'iexplore', 'brave', 'code', 'chrome', 'firefox')

    if ($PSBoundParameters.ContainsKey('ListAvailable'))
    {
        Write-Log -Message "Enumerating all available `$XenApps Keys" -Function ProcessState
        $script:knownPaths | Sort-Object -Property Name # | Format-Table -AutoSize
    } else {
        $script:process = Get-Process -Name $ProcessName -ErrorAction:SilentlyContinue
    }

#    process {  

    switch ($Action) {
        'Start' {
            if (!($?)) {
                # unsuccessful getting $process aka NOT running
                if ($knownPaths.Keys -contains $ProcessName) {
                    # specify unique launch/start parameters
                    switch ($ProcessName) {
                        'receiver' {
                            $script:CPargs = '/startup'
                        }
                        'concentr' {
                            $script:CPargs = '/startup'
                        }
                        'evernote' {
                            $script:CPargs = '/minimized'
                        }
                        'taskmgr' {
                            $script:CPargs = '/t'
                        }
                        'Brave' {
                            $script:CPargs = '--processStart "Brave.exe"'
                        }
                        default {
                            # passing a 'space' should prevent Start-Process from freaking out about a null -ArgumentList, and hopefully not freak out the -FilePath exe
                            $script:CPargs = ' '
                        }
                    }

                    if ($PSCmdlet.ShouldProcess($ProcessName)) {
                        # launch process from known path, with specified argument(s)
                        if (($script:CPargs | Measure-Object -Character).Characters -gt 1) {
                            Write-Log -Message "Starting $ProcessName $($knownPaths[$ProcessName]) -ArgumentList $script:CPargs" -Function ProcessState
                            Write-Verbose -Message "Starting $ProcessName $($knownPaths[$ProcessName]) -ArgumentList $script:CPargs"
                            Start-Process -FilePath $($knownPaths[$($ProcessName)]) -ArgumentList $script:CPargs
                        } else {
                            Write-Log -Message "Starting $ProcessName $($knownPaths[$ProcessName])" -Function ProcessState
                            Write-Verbose -Message "Starting $ProcessName $($knownPaths[$ProcessName])"
                            Start-Process -FilePath $($knownPaths[$($ProcessName)]) 
                        }
                    } else {  
                        Write-Output -InputObject "What if: Performing the operation ""Start-Process"" on target ""$knownPaths[$ProcessName]"" with -ArgumentList ""$CPargs"" for key ($ProcessName)."
                    }  
                } else {
                    Write-Log -Message "Path to launch '$ProcessName' is undefined" -Function ProcessState  -Verbose
                }
            } # end if (!($?))
        } # end 'Start'
        'Stop' {
            if ($?) {
                # $process is running
                if ($askTerminate -contains $ProcessName) {
                    # processName is running, prompt to close
                    Write-Log -Message "$ProcessName is running."
                    $script:confirm = Read-Host -Prompt "`n # ACTION REQUIRED # `nClose $ProcessName, then type ok and click [Enter] to proceed.`n"
                    while ( -not ($script:interrupt )) {
                        if($script:confirm -ilike 'ok') {
                            $script:interrupt = $true
                        } else {
                            Write-Log -Message "Invalid response '$script:confirm'" -Function ProcessState  -Verbose
                            $script:confirm = Read-Host -Prompt "`n # ACTION REQUIRED # `nType ok and click [Enter] once $ProcessName is terminated."
                        }
                    }
                    Start-Sleep -Seconds 1
                    # wait one second to allow time for $process to stop
                    # Check if the process was stopped after we asked
                    $script:process = Get-Process -Name $ProcessName -ErrorAction:SilentlyContinue
                    while ($script:process) {
                        # Application/process is still running, prompt to terminate
                        Write-Log -Message "$ProcessName is still running." -Function ProcessState  -Verbose
                        $response = Read-Host -Prompt "Would you like to force terminate? `n[Y] Yes  [N] No  (default is 'null'):"
                        if($response -ilike 'Y') {
                            # Special handling for Citrix PNAgent
                            if (($ProcessName -eq 'receiver') -or ($ProcessName -eq 'pnamain')) {
                                if ($PSCmdlet.ShouldProcess($ProcessName)) {
                                    # If we try to stop Citrix Receiver; we first try to terminate these related processes / services in a graceful order
                                    Write-Log -Message 'Stopping Citrix Receiver (and related processes, services)' -Function ProcessState  -Verbose
                                    Start-Process -FilePath $knownPaths.pnagent -ArgumentList '/terminatewait' -RedirectStandardOutput .\pnagent-termwait.log -RedirectStandardError .\pnagent-twerr.log
                                    Start-Process -FilePath $knownPaths.concentr -ArgumentList '/terminate' -RedirectStandardOutput .\pnagent-term.log -RedirectStandardError .\pnagent-termerr.log
                                    # Citrix Streaming Helper Service
                                    Set-ProcessState -ProcessName redirector -Action Stop
                                    Set-ProcessState -ProcessName prefpanel -Action Stop
                                    Set-ProcessState -ProcessName nsepa -Action Stop # Citrix Access Gateway EPA Server
                                    Set-ProcessState -ProcessName concentr -Action Stop
                                    Set-ProcessState -ProcessName wfcrun32 -Action Stop
                                    # Citrix Connection Manager; child of ssonsvr.exe
                                    Set-ProcessState -ProcessName wfica32 -Action Stop
                                    #Set-ProcessState pnamain Stop; # Citrix
                                    Set-ProcessState -ProcessName receiver -Action Stop
                                } else {
                                    Write-Output -InputObject 'What if: Stopping Citrix Receiver and related processes, services).'
                                }
                            }
                            # if no Citrix Special handling is needed, then we stop the process
                            $script:process | ForEach-Object -Process {
                                Write-Log -Message "Stop-Process $($PSItem.ProcessName) (ID $($script:process.id))" -Function ProcessState
                                if ($PSCmdlet.ShouldProcess($ProcessName)) {
                                    Stop-Process -Id $script:process.id
                                } else {
                                    Write-Output -InputObject "What if: Performing the operation ""Stop-Process"" on target ""Name: $ProcessName, Id: $($process.id)""."
                                }
                            }
                        } elseif($response -ilike 'N') {
                            # manually override termination
                            break
                        } else {
                            Write-Log -Message "Invalid response '$response'." -Function ProcessState  -Path - verbose
                        }
                        # confirm process is terminated
                        $script:process = Get-Process -Name $ProcessName -ErrorAction:SilentlyContinue
                    }
                } else {
                    # kill the process
                    $script:process | ForEach-Object -Process {
                        Write-Log -Message "Stop-Process $($PSItem.ProcessName) (ID $($process.id))" -Function ProcessState
                        if ($PSCmdlet.ShouldProcess($ProcessName)) {
                            Stop-Process -Id $process.id
                        } else {
                            Write-Output -InputObject "What if: Performing the operation ""Stop-Process"" on target ""Name: $ProcessName, Id: $($process.id)""."
                        }
                    }
                }
            }
        }
    }
}

function Test-ProcessState {
  <#
      .SYNOPSIS
        A wrapper/helper function for get-process cmdlet interaction.
      .DESCRIPTION
        Using the ProcessName parameter, looks for a match in the results from get-process, and responds with some of the details/properties from get-process about the matching processes
      .PARAMETER processName
        Name of process to check for, start up, or stop
      .PARAMETER Wait
        An optional boolean property to specify whether to continue checking periodically if processName is still running
        This is intended to be useful for scenarios where next steps should be delayed until a named process has exited
      .PARAMETER WaitTime
        An optional integer property to specify amount of time (in milliseconds) to wait between recurring invocation of get-process
        The default value is 50 milliseconds
      .EXAMPLE
        PS .\> Test-ProcessState powershell | fl
       
        Path    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Name    : powershell
        Status  : Running
        WaitFor : False

        Path    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Name    : powershell
        Status  : Running
        WaitFor : False

        Check / confirms that one or more instances of powershell.exe are running, and shows some of their key stats via format-list (alias fl)

      .EXAMPLE
        PS .\> Test-ProcessState -ProcessName notepad -Wait

        Wait for all running instances of notepad to stop
        Since no processes of notepad were found in get-process results, there is no output
      .EXAMPLE
        PS .\> [bool](Test-ProcessState -ProcessName iexplore)

        True

        Returns a simple True/False answer to the question of whether or not any processes are running with a name matching *iexplore*

      .NOTES
        NAME        :  Test-ProcessState
        VERSION     :  2.1.2
        LAST UPDATED:  6/10/2015
        AUTHOR      :  Bryan Dady
      .LINK
        PSLogger
        Sperry
  #>
    # Setup Advanced Function Parameters
    [cmdletbinding()]
    Param (
        [parameter(
          Position = 0,
          Mandatory,
          HelpMessage='Specify the name of the process to check is running'
        )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,

        [Parameter(Position = 1)]
        [switch]
        $Wait,

        [Parameter(Position = 2)]
        [Alias('Delay')]
        [int16]
        $WaitTime = 50
    )

    if ($PSBoundParameters.ContainsKey('ListAvailable')) {
        Write-Log -Message "`nEvaluating predefined process paths" -Function ProcessState -Verbose
        foreach ($app in $knownPaths.Keys) {
            Write-Log -Message "$app = $($knownPaths.$app)" -Function ProcessState
            if (Test-Path -Path $knownPaths.$app -PathType Leaf) {
                Write-Log -Message "Confirmed $app target at path $($knownPaths.$app)" -Function ProcessState
            } else {
                Write-Log -Message "Unable to confirm $app target at path $($knownPaths.$app)" -Verbose -Function ProcessState
            }
        }
    } else {
        # Check if $ProcessName is running
        Write-Log -Message "Checking if $ProcessName is running" -Function ProcessState
        Start-Sleep -Milliseconds 500
        $script:process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if ($Wait) {
            #Setup variables for the following nested while loops
            [int16]$script:InnerCounter = 0 # Start from zero
            [int16]$script:OuterCounter = 0 # Start from zero
            while ($script:process) {
                # it appears to be running; let's wait for it
                Write-Log -Message "Found $ProcessName running. Wait parameter is True and delay duraction is $WaitTime milliseconds" -Function ProcessState

                $InnerCounter = 0 # re-start from zero
                # Let's increment up to 100 (%) progress while we wait
                [Int]$script:LoopCount = 100

                # Loop through write-progress as long as the counter is less than $WaitTime
                while ($InnerCounter -lt $LoopCount) {
                    write-progress -activity "Waiting for $ProcessName to end gracefully" -status "$InnerCounter% Complete:" -percentcomplete $InnerCounter
                    Start-Sleep -Milliseconds $waitTime
                    $InnerCounter++; # Increment inner loop
                }
                # The longer we wait ... the slower we loop
                if ($OuterCounter -ge 100) {
                    # As long as the per loop delay as less than 30 seconds (30000 ms), slow down the wait time on every other loop through
                    Write-Debug -Message "if ((($WaitTime*$LoopCount) -le 30000) -and ($OuterCounter%2 -eq 0))"

                    if ((($WaitTime*$LoopCount) -le 30000) -and ($OuterCounter%2 -eq 0)) {
                        # slow $waitTime by doubling it
                        $WaitTime = ($WaitTime * 2)
                        Write-Debug -Message "Increased `$waitTime to $WaitTime"
                    }
                }
                $OuterCounter++ # Increment outer loop
                Write-Log -Message "   still waiting for $ProcessName : ($WaitTime)" -Function ProcessState  -Verbose
                Write-Debug -Message "   still waiting for $ProcessName : [`$InnerCounter: $InnerCounter ; `$OuterCounter: $OuterCounter ; `$waitTime: $WaitTime ]"
                # check again
                $script:process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
            }
            Write-Progress -Activity "Waiting for $ProcessName" -Status '.' -Completed
        } else {
            if ($script:process) {
                # it appears to be running
                # Similar to: Get-Process -ProcessName *7z* | Select-Object -Property Name,Path | Format-Table -AutoSize
                $script:process | ForEach-Object -Process {
                    #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
                    $script:properties = @{
                        'Name'=$PSItem.Name
                        'Path'=$PSItem.Path
                        'Status'='Running'
                        'WaitFor'=$false
                    }
                    $script:RetObject = New-Object -TypeName PSObject -Prop $script:properties
                    return $script:RetObject
                } # end of foreach

                Write-Log -Message "Confirmed $ProcessName is running. Wait parameter is False." -Function ProcessState
            } else {
                Write-Log -Message "$ProcessName was NOT found running." -Function ProcessState
                return $false
            }
        }
    }
}
