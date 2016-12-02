# https://powershell.org/forums/topic/retrieving-process-list-and-owner-name/
# how to use from another script/function:
# foreach ($app in $workApps) {Get-ProcessbyUser -name $app*}

Write-Verbose -Message 'Defining function Get-ProcessbyUser'
function Get-ProcessByUser {
<#
    .SYNOPSIS
        Gets the processes, for the current or specified user, that are running on the local computer or a remote computer.
    .DESCRIPTION
        The Get-Process cmdlet gets the processes on a local or remote computer.

        Without parameters, Get-ProcessbyUser gets all of the processes on the local computer, for the current user.
        You can also specify a particular process by process name or process ID (PID) or pass a process object through the pipeline to
        Get-Process.

        By default, Get-Process returns a process object that includes the Name, Description, Owner (UserName), and ID (PID) 
        for each process.

    .EXAMPLE
        Get-ProcessbyUser

        Getting * Processes from Computer . and current user

        Name             Description                     Owner          ProcessID
        ----             -----------                     -----          ---------
        taskhost.exe     Host Process for Windows T...   [username]     3740

#>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position=0)]
        [String]
        $ComputerName = '.',

        [Parameter(Position=1)]
        [Alias('User','Owner')]
        [String]
        $UserName = "$ENV:USERNAME",

        [Parameter(Position=2)]
        [Alias('Name')]
        [String]
        $ProcessName = '*'
    )

    # Handle WQL by replacing asterisk with percent
    $script:filterProcessName = $ProcessName -replace '\*','%' 

    Write-Debug -Message "Getting $ProcessName Processes from Computer $ComputerName and user $UserName"
    # Check if $ComputerName parameter/variable is a well known alias 
    if ($ComputerName -ne '.' -and $ComputerName -ne 'localhost')
    {
        # Check if node named in $ComputerName parameter/variable is available via network
        if (Test-Connection -ComputerName $ComputerName -Quiet)
        {
            Write-Debug -Message "`$Processes = Get-WMIObject -ComputerName $ComputerName -Class Win32_Process -Filter ""ProcessID > 10 AND Name LIKE '$filterProcessName'"""
            $script:Processes = Get-WMIObject -ComputerName $ComputerName Win32_Process -Filter "ProcessID > 10 AND Name LIKE '$filterProcessName'"
            Write-Debug -Message "`$Processes2 = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-Process -Name $ProcessName}"
            $script:Processes2 = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-Process}
        }
        else
        {
            Write-Error -Message "Failed to confirm network availability of remote computer: $ComputerName"
            break;
        }
    }
    else
    {
        # Help cmdlets behave well / as expected by not specifying -ComputerName 
        Write-Debug -Message "`$Processes = Get-WMIObject -Class Win32_Process -Filter ""ProcessID > 10 AND Name LIKE '$filterProcessName'"""
        $script:Processes = @(Get-WMIObject Win32_Process -Filter "ProcessID > 10 AND Name LIKE '$filterProcessName'")
        Write-Debug -Message "`$Processes2 = Get-Process -Name $ProcessName"
        $script:Processes2 = @(Get-Process)
    }

    # Pre-define return object
    #$properties = @{}
    $script:RetObject = New-Object -TypeName PSObject
    $Script:RetCollection = @()
    $script:ProgressCounter = 0

    Get-Variable -Name Processes -ErrorAction Stop
    
    Write-Debug -Message "`$Processes: $($Processes.Name | Select-Object -First 10) ..."
    ForEach ($Process in $Processes)
    {
        Write-Debug -Message "Write-Progress -Activity 'Get-ProcessInfo' -PercentComplete ($ProgressCounter/$($Processes.Count)) :: $($ProgressCounter/$($Processes.Count)) -CurrentOperation $($Process.Name)"
        Write-Progress -Activity 'Get-ProcessInfo' -PercentComplete $([int]($ProgressCounter/($Processes.Count))*100) -CurrentOperation $Process.Name
        $ProgressCounter++
        # $Process | get-member -membertype properties
        Write-Debug -Message "Get `$ProcessOwner for $($Process.Name)"
        $ErrorActionPreference = SilentlyContinue
        $script:ProcessOwner = $Process.getowner().User
        if ($null -eq $ProcessOwner)
        {
            $script:ProcessOwner = 'Unknown'    
        }
        $ErrorActionPreference = Stop
         
        if ($ProcessOwner -like "*$UserName*")
        {
            $AppendApp = $false
            # Check if $Process.Name exists in $RetCollection, and if so, append this ProcessID, instead of adding redundant object instance
            # "if ($($Process.Name) -in $($Script:RetCollection.Name)"
            try {
                if ($Process.Name -in $Script:RetCollection.Name)
                {
                    $AppendApp = $true
                }    
            }
            catch {
                Write-Verbose -Message "There was an unexpected exception comparing the current process name with the process collection"
            }
            if ($AppendApp)
            {
                Write-Debug -Message "Adding new PID to existing Process object: $($Process.Name) :: $($Process.ProcessID)"
                
                # Get the object to be updated from  RetCollection
                $script:procObject = $RetCollection | where {$PSItem.Name -eq $Process.Name}
                Write-Debug -Message "The matched process object from RetCollection is: $procObject"
                # Get the rest of RetCollection, exclusive of the object to be updated, so the updated object can later be added, as a unique member of the collection  
                Write-Debug -Message "`$script:OldCollection = `$script:RetCollection"
                $script:OldCollection = $script:RetCollection | where {$PSItem.Name -ne $Process.Name}
                Write-Debug -Message "This process object's previous ProcessID property is: $($procObject.ProcessID)"
#                $script:newProcessID = @()
#                $script:newProcessID = @($procObject.ProcessID,$Process.ProcessID)
                Write-Debug -Message "This process object's new ProcessID property will be: $($procObject.ProcessID),$($Process.ProcessID)"
                #$procObject.ProcessID = $updateObject.ProcessID
                # Update custom object with these properties
                $script:properties = [ordered]@{
                    'Name'        = $procObject.Name
                    'ProcessID'   = "$($procObject.ProcessID),$($Process.ProcessID)" 
                    'Owner'       = $procObject.Owner
                    'Description' = $procObject.Description
                }
                $script:RetObject = New-Object -TypeName PSObject -Property $properties
                Write-Debug -Message "`$script:RetObject $script:RetObject"
                # Empty the variable prior to moving on
                Write-Debug -Message "Remove-Variable -Name properties -Scope Script"
                Remove-Variable -Name properties -Scope Script -Force -ErrorAction Ignore
                # Replace the current object instance to the collection object
                Write-Debug -Message "Remove-Variable -Name RetCollection -Scope Script"
                Remove-Variable -Name RetCollection -Scope Script -Force -ErrorAction Ignore 
                Write-Debug -Message "`$script:RetCollection = `$script:OldCollection"
                $script:RetCollection = $script:OldCollection
                $script:RetCollection += $script:RetObject
                # Replace the current object instance to the collection object
                Remove-Variable -Name OldCollection -Scope Script -Force -ErrorAction Ignore
            }
            else
            {
                #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
                $script:properties = [ordered]@{
                    'Name'        = $Process.Name
                    'ProcessID'   = $Process.ProcessID
                    'Owner'       = $Process.getowner().User
                    'Description' = ($Processes2 | ? { $_.ID -eq $Process.ProcessID }).Description
                }
                # Instantiate custom object with these properties
                $script:RetObject = New-Object -TypeName PSObject -Property $properties

                # Empty the variable prior to moving on
                Remove-Variable -Name properties -Scope Script -Force -ErrorAction Ignore  
                Write-Debug -Message "Adding the following object to RetCollection: `n $($script:RetObject)"
                # Append the current object instance to the collection of objects to be returned
                $script:RetCollection += $script:RetObject
            }
            $ErrorActionPreference = 'Stop' 
            # Empty the variable of any current object prior to moving on
            Remove-Variable -Name RetObject -Scope Script -Force -ErrorAction Ignore
        }
        else
        {
            Write-Debug -Message "Process $($Process.Name) belongs to $ProcessOwner"
        }
    }
    Write-Progress -Activity 'Get-ProcessInfo' -Completed
    return $script:RetCollection | Sort-Object -Property Name,ProcessID
}
