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

Write-Verbose -Message 'Declaring function Get-Printer'
function Get-Printer {
<#
	.Synopsis
	   Get-Printer retrieves details of printer ports
	.DESCRIPTION
	   Can enumerate default printer, local printers, and network printers
	.EXAMPLE
	   Get-Printer -Default

	.EXAMPLE
	   Get-Printer -Default
#>
    [CmdletBinding()]
    [OutputType([int])]
    Param (
        # List Default printer
        [switch]
        $Default,
        # Enumerate only local printers
        [switch]
        $Local,
        # Enumerate only network printers
        [switch]
        $Network
    )
    Show-Progress -msgAction Start -msgSource $PSCmdlet.MyInvocation.MyCommand.Name
    [string]$Script:CIMfilter

    if ($Default) {
        $Script:CIMfilter = "Default='True'"
    } elseif ($Local) {
        $Script:CIMfilter = "Local='True'"
    } elseif ($Network) {
        $Script:CIMfilter = "Network='True'"
    } 
    # else  $CIMfilter remains $null, so returns all results

    $Script:printerInfo = Get-CimInstance -ClassName Win32_Printer -Filter $CIMfilter | Select-Object -Property Name, ShareName, ServerName, CapabilityDescriptions, Default, Local, Network, DriverName

    # If default printer was retrieved, update 
    if ($Default) {
        $Global:DefaultPrinter = $printerInfo 
    }
    
    Show-Progress -msgAction Stop -msgSource $PSCmdlet.MyInvocation.MyCommand.Name

    return $printerInfo
}

Write-Verbose -Message 'Declaring Function Set-Printer'
function Set-Printer  {
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
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [String]
        $printerShareName
    )
    return (Get-WmiObject -Class win32_printer -Filter "ShareName='$printerShareName'").SetDefaultPrinter() | Out-Null; $?
}

#Export-ModuleMember -Function Get-Printer, Set-Printer -Variable DefaultPrinter