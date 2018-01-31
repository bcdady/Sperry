#requires -Version 2 -Modules CimCmdlets
<#
.SYNOPSIS
    PrinterFunctions Module contains functions that help make it easier to interact with printer ports via WMI (for backward compatibility).
.DESCRIPTION
    PrinterFunctions.psm1 - Provides common functions for retrieving info and controlling printer settings
#>

# *** RFE : Enumerate domain / directory published printers, with their address, subnet and/or vlan.

# Define new global variable for default printer
New-Variable -Name DefaultPrinter -Description 'Default Printer' -Scope Global -ErrorAction Ignore

function Get-Printer {
  <#
    .Synopsis
      Get-Printer retrieves details of printer ports
    .DESCRIPTION
      Can enumerate default printer, local printers, and network printers
    .EXAMPLE
      Get-Printer -Default
    .EXAMPLE
      Get-Printer -Network
    .EXAMPLE
      Get-Printer -Local
  #>
    [CmdletBinding()]
    [OutputType([int])]
    Param (
        # List Default printer
        [switch]$Default,
        # Enumerate only local printers
        [switch]$Local,
        # Enumerate only network printers
        [switch]$Network
    )

    Show-Progress -msgAction Start -msgSource $PSCmdlet.MyInvocation.MyCommand.Name
    [string]$CIMfilter = ''

    if ($Default) {
        $CIMfilter = "Default='True'"
    } elseif ($Local) {
        $CIMfilter = "Local='True'"
    } elseif ($Network) {
        $CIMfilter = "Network='True'"
    } 
    # else  $CIMfilter remains $null, so returns all results
    if ($CIMfilter) {
        # Query CIM with -Filter
        $printerInfo = Get-CimInstance -ClassName Win32_Printer -Filter $CIMfilter | Select-Object -Property Name, ShareName, ServerName, CapabilityDescriptions, Default, Local, Network, DriverName
    } else {
        # Query CIM withOUT -Filter
        $printerInfo = Get-CimInstance -ClassName Win32_Printer | Select-Object -Property Name, ShareName, ServerName, CapabilityDescriptions, Default, Local, Network, DriverName
    }

    # If default parameter was specified, update default printer
    if ($Default) {
        $Global:DefaultPrinter = $printerInfo
    }
    
    Show-Progress -msgAction Stop -msgSource $PSCmdlet.MyInvocation.MyCommand.Name

    return $printerInfo
}

function Set-Printer {
    <#
        .SYNOPSIS
            Set your own default printer by specifying it's ShareName
        .DESCRIPTION
            Set-Printer uses WMI to set the Default printer, specified by it's short, simple ShareName property. To list all available printers by ShareName, see the Get-NetworkPrinters or Get-LocalPrinters cmdlets.
        .PARAMETER printerShareName
            Specify the desired printers ShareName property
        .EXAMPLE
            PS C:\>  Set-Printer GBCI91_IT252
            Set's the default printer to GBCI91_IT252
        .NOTES
            NAME        :  Set-Printer
            VERSION     :  1.1.1
            LAST UPDATED:  7/6/2017
            AUTHOR      :  Bryan Dady
    #>
    [CmdletBinding()]
    param (
        [String]
        [Alias('PrinterShareName','PrinterName')]
        $Name = ((Get-Printer | Select-Object -First 1 -Property Name).Name)
    )
    Write-Verbose "Preparing to set printer '$Name' as Default"

    # Try to Get-Printer
    Write-Verbose -Message "`$PrinterObject = (Get-Printer | Where-Object -FilterScript {`$PSItem.Name -like '*$Name*'})"
    $PrinterObject = (Get-Printer | Where-Object -FilterScript {$PSItem.Name -like "*$Name*"})
    Write-Verbose -Message "`$PrinterObject.ShareName is $($PrinterObject.ShareName)"

    if ($PrinterObject.ShareName) {
        # Specify .SetDefaultPrinter against ShareName
        $WMIFilter = "ShareName=""$Name"""
    } else {
        # Specify .SetDefaultPrinter against Printer 'Name'
        $WMIFilter = "Name=""$Name"""
    }
    
    # Use WMI to Set Default Printer // This must be WMI, as an otherwise matching CimInstance does not provide the .SetDefaultPrinter() method
    Write-Debug -Message "`$PrinterWMIObject = Get-WmiObject -Class win32_printer -Filter $WMIFilter"
    $PrinterWMIObject = Get-WmiObject -Class win32_printer -Filter $WMIFilter
    # return (Get-WmiObject -Class win32_printer -Filter "ShareName='$printerShareName'").SetDefaultPrinter() | Out-Null; $?

    try {
        return $PrinterWMIObject.SetDefaultPrinter() | Out-Null; $?
    }
    catch {
        Write-Warning -Message "Failed to get details of an available printer matching this filter: $WMIFilter"
        return $null
    }
}
