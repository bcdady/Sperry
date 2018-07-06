#!/usr/local/bin/pwsh
#Requires -Version 3
#========================================
# NAME      : Get-ProcessByUser.ps1
# LANGUAGE  : Microsoft PowerShell
# AUTHOR    : Bryan Dady
# COMMENT   : Get-ProcessByUser applies the ability of WMI to correlate a process with it's user, WITHOUT the elevated permissions required by the PowerShell cmdlet Get-Process with it's -IncludeUserName parameter
# UPDATED   : 06/01/2018 - Improved script compatibility across Windows PowerShell (Desktop) and PowerShell Core, such as Is* variables and PSEdition support
#========================================
[CmdletBinding()]
param()
Set-StrictMode -Version latest

Write-Verbose -Message 'Defining function Get-ProcessByUser'
Function Get-ProcessByUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position=0)]
        [String]
        $ComputerName = '.',
        [Parameter(Position=1)]
        [Alias('User','Owner')]
        [String]
        $UserName = "$ENV:USERNAME",
        [Parameter(Position=2,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('ProcessName')]
        [String]
        $Name = '*'
    )

    # Pre-define variables
    $Private:Processes       = @()
    $Private:RetObject       = New-Object -TypeName PSObject
    $Private:RetCollection   = @{}
    [int]$Private:TotalCount = 0
    [int]$Private:ProgressCounter = 0

    # If the $ProcessName variable ends with .exe, remove it, as the Get-Process cmdlet excludes file extensions
    #$ProcessName = $ProcessName -replace '\.exe$',''
    # the 'Name' parameter us used by this function to match the parameterset of Get-Process, but then we translate that to the internal variable of $ProcessName, for clarity throughout the function
    Set-Variable -Name ProcessName -Value $Name -Description 'Process Name parameter' -Option Private

    # Handle WQL by replacing asterisk with wildcard percent character
    $Private:filterProcessName = $Private:ProcessName -replace '\*','%'
    # Handle WQL by replacing .exe with wildcard percent character
    #if (($Private:filterProcessName -NotMatch '\.exe$') -and ($Private:filterProcessName -NotMatch '%$')) {
    #    $Private:filterProcessName = "$Private:filterProcessName%"
    #}

    Write-Verbose -Message ('ComputerName is {0} ' -f $ComputerName)
    Write-Verbose -Message ('UserName is {0} ' -f $UserName)
    Write-Verbose -Message ('Process Name is {0} ' -f $ProcessName)
    Write-Verbose -Message ('(WMI filter) Process Name is {0} ' -f $Private:filterProcessName)

    # Check if $ComputerName parameter/variable is a well known alias 
    if ($ComputerName -ne '.' -and $ComputerName -ne 'localhost') {
        if ($ProcessName -eq '*') {
            Write-Verbose -Message ('Getting All Processes from Computer ''{0}'' and user {1}' -f $ComputerName, $UserName)
        } else {
            Write-Verbose -Message ('Getting Processes matching the name ''{0}'' from Computer ''{1}'' and user {2}' -f $ProcessName, $ComputerName, $UserName)
        }

        # Check if node named in $ComputerName parameter/variable is available via network
        if (Test-Connection -ComputerName $ComputerName -Quiet) {
            Write-Debug -Message ('$Processes = Get-WMIObject -ComputerName {0} -Class Win32_Process -Filter "ProcessID > 10 AND Name LIKE ''{1}''"' -f $ComputerName, $ProcessName)
            $Private:Processes = Get-WMIObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessID > 10 AND Name LIKE '$Private:filterProcessName'"
            Write-Debug -Message ('$Processes2 = Invoke-Command -ComputerName {0} -ScriptBlock {Get-Process -Name {1}}' -f $ComputerName, $ProcessName)
            #$Private:Processes2 = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-Process -Name $ProcessName}
        } else {
            Write-Error -Message ('Failed to confirm network availability of remote computer: {0}' -f $ComputerName)
            break
        }
    } else {
        # Help cmdlets behave well / as expected by not specifying -ComputerName 
        Write-Debug -Message ('$Processes = Get-WMIObject -Class Win32_Process -Filter "ProcessID > 10 AND Name LIKE ''{0}''"' -f $Private:filterProcessName)
        $Private:Processes = @(Get-WMIObject -Class Win32_Process -Filter "ProcessID > 10 AND Name LIKE '$Private:filterProcessName'")
        #Write-Debug -Message ('$Processes2 = Get-Process -Name "{0}"' -f $ProcessName)
        #$Private:Processes2 = @(Get-Process -Name "$ProcessName")
    }

    # Pre-define return object
    #$properties = @{}
    $Private:RetObject = New-Object -TypeName PSObject
    $Private:RetCollection = @()
    $Private:TotalCount = $Private:Processes.Count

    try {
        $null = Get-Variable -Name Processes -Scope Private -ValueOnly -ErrorAction SilentlyContinue
        Write-Debug -Message ('$Processes: {0} | Select-Object -First 10) ...' -f $Private:Processes.Name)
    }
    catch {
        Write-Warning -Message ('NO Processes found running matching filter: {0}' -f $ProcessName)
        Write-Debug -Message 'NO Matching Processes retrieved'
        throw 'NO Matching Processes'
    }

    ForEach ($Process in $Private:Processes) {
        if ($null -eq $Process.Name) {
            Write-Warning -Message 'No Process Name.'
            break
        } elseif ($null -eq $Process.ProcessID) {
            Write-Warning -Message 'No Process ID.'
            break
        }

        [int]$PercentComplete = $Private:ProgressCounter/$Private:TotalCount*100
        Write-Progress -Activity ('Collecting Process Info for {0}' -f $UserName) -Status "Progress:" -PercentComplete ($Private:ProgressCounter/$Private:TotalCount*100 -as [int]) -CurrentOperation $Process.Name
        $ProgressCounter++

        $Private:ProcessOwner = 'Unknown'

        if ($null -ne $Process.GetOwner().User) {
            $Private:ProcessOwner = $Process.GetOwner().User
            Write-Verbose -Message ('$ProcessOwner for {0} is ''{1}''' -f $Process.Name, $Private:ProcessOwner)
        }
         
        if ($Private:ProcessOwner -like "*$UserName*") {
            $AppendApp = $false
            # Check if $Process.Name exists in $RetCollection, and if so, append this ProcessID, instead of adding redundant object instance
            # "if ($($Process.Name) -in $($Private:RetCollection.Name)"
            # Write-Verbose -Message ('$Process.GetOwner().User: {0}' -f $Process.GetOwner().User)

            #try {
            #('$Private:RetCollection.Count -gt 0: {0}' -f ((Select-Object -InputObject $Private:RetCollection -Property Count -ErrorAction SilentlyContinue) -gt 0))
            #('$Process.Name -in $Private:RetCollection.Name: {0}' -f ($Process.Name -in (Select-Object -InputObject $Private:RetCollection -Property Name -ErrorAction SilentlyContinue)))
            
            # 'GetType:'
            # $Private:RetCollection.GetType()
            # $Private:RetCollection | Get-Member -ErrorAction SilentlyContinue

            if (($Private:RetCollection | Get-Member -ErrorAction SilentlyContinue) -and $Process.Name -in $Private:RetCollection.Name) {
                $AppendApp = $true
                Write-Verbose -Message ('Adding new PID to existing Process object: {0} (PID {1})' -f $Process.Name, $Process.ProcessID)
                
                # Get the object to be updated/appended in RetCollection
                $Private:ProcObject = $Private:RetCollection | Where-Object -FilterScript {$PSItem.Name -eq $Process.Name}

                # Get the rest of RetCollection, exclusive of the object to be updated, so the updated object can later be re-added, as a unique member of the collection  
                $Private:OldCollection = $Private:RetCollection | Where-Object -FilterScript {$PSItem.Name -ne $Process.Name}

                # Concatenate the new ProcessID and assign the new ProcessID array back to the same Process object
                $Private:PIDArray = $Private:ProcObject.ProcessID += $Process.ProcessID
                $Private:ProcObject.ProcessID = $Private:PIDArray

                # The 'new' / replacement RetCollection = OldCollection + updated ProcObject
                $Private:RetCollection = $Private:OldCollection
                $Private:RetCollection += $Private:ProcObject

            } else {
                #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
                if ($Process.Name -in $MyKnownApps) {
                    $Private:ThisProcessInfo = Get-Process -ID $Process.ProcessID
                    $Private:properties = [ordered]@{
                        'Name'        = $Process.Name
                        'Path'        = $Process.Path
                        'ProcessID'   = ,$Process.ProcessID
                        'Owner'       = $Private:ProcessOwner
                        'Description' = $Private:ThisProcessInfo.Description
                        'Version' = $Private:ThisProcessInfo.ProductVersion
                    }
                    # Instantiate custom object with these properties
                    $Private:RetObject = New-Object -TypeName PSObject -Property $properties

                    # Empty the variable prior to moving on
                    #Remove-Variable -Name properties -Scope Script -Force -ErrorAction SilentlyContinue  
                    Write-Debug -Message ('Adding object to RetCollection: {0}' -f $Private:RetObject)
                    # Append the current object instance to the collection of objects to be returned
                    $Private:RetCollection += $Private:RetObject
                } else {
                    Write-Verbose -Message ('Skipping background process: {0}' -f $Process.Name)
                }
            }

            # Empty the variable of any current object prior to moving on
            Remove-Variable -Name RetObject -Scope Script -Force -ErrorAction SilentlyContinue
        } else {
            Write-Debug -Message ('Process {0} belongs to {1}' -f $Process.Name, $Private:ProcessOwner)
        }
    }
    Write-Progress -Activity 'Get-ProcessInfo' -Completed
    return $Private:RetCollection | Sort-Object -Property Name,ProcessID

    <#
     .SYNOPSIS
        Gets the processes, for the current or specified user, that are running on the local computer or a remote computer.
     .DESCRIPTION
        The Get-Process cmdlet gets the processes on a local or remote computer.

        Without parameters, Get-ProcessByUser gets all of the processes on the local computer, for the current user.
        You can also specify a particular process by process name or process ID (PID) or pass a process object through the pipeline to
        Get-Process.

        By default, Get-Process returns a process object that includes the Name, Description, Owner (UserName), and ID (PID) 
        for each process.

     .EXAMPLE
        Get-ProcessByUser

        Getting * Processes from Computer . and current user

        Name             Description                     Owner          ProcessID
        ----             -----------                     -----          ---------
        taskhost.exe     Host Process for Windows T...   [username]     3740

    #>
}
