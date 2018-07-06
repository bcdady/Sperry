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

            Returns the current Default printer (Default = True)

            Name                   : Microsoft Print to PDF
            ShareName              :
            ServerName             :
            CapabilityDescriptions : {Copies, Color}
            Default                : True
            Local                  : True
            Network                : False
            DriverName             : Microsoft Print to PDF Driver
        .EXAMPLE
            Get-Printer -Network
        .EXAMPLE
            Get-Printer -Local
    #>
    [CmdletBinding()]
    [OutputType([int])]
    Param (
        # Default CIM/WMI filter
        # "PrintProcessor like '%win%'"
        [string]$Name,
        # List Default printer
        [switch]$Default,
        # Enumerate only local printers
        [switch]$Local,
        # Enumerate only network printers
        [switch]$Network
    )

    Show-Progress -msgAction Start -msgSource $PSCmdlet.MyInvocation.MyCommand.Name

    if ($Name) {
        # replace common wildcard asterisk character with CIM Filter percent character
        $Name = $Name -replace '\*','%'
        $CIMfilter = "Name like '$Name' OR ShareName like '$Name'"
        Write-Verbose -Message ('$CIMfilter = {0}' -f $CIMfilter)
        # Write-Verbose -Message ('$CIMfilter = "ShareName like ''{0}''" OR "Name like ''{0}''"' -f $Name)
    } else {
        $CIMfilter = 'PrinterStatus=3'
    }

    if ($Default) {
        $CIMfilter = "$CIMfilter AND Default='True'"
    }
    if ($Local) {
        $CIMfilter = "$CIMfilter AND Local='True'"
    }
    if ($Network) {
        $CIMfilter = "$CIMfilter AND Network='True'"
    } 
    
    #if ($CIMfilter) {
        # Query CIM with -Filter
        $printerInfo = Get-CimInstance -ClassName Win32_Printer -Filter $CIMfilter | Select-Object -Property Name, ShareName, ServerName, CapabilityDescriptions, Default, Local, Network, DriverName
    #} else {
    #    # Query CIM withOUT -Filter
    #    $printerInfo = Get-CimInstance -ClassName Win32_Printer | Select-Object -Property Name, ShareName, ServerName, CapabilityDescriptions, Default, Local, Network, DriverName
    #}

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
        #[Parameter(Position=0,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [String]
        [Alias('PrinterShareName','PrinterName')]
        $Name = (Get-Printer -Name *PDF* | Select-Object -First 1 -ExpandProperty Name)
    )
    Write-Verbose -Message ("Preparing to set printer '{0}' as Default" -f $Name)

    # Try to Get-Printer's ShareName
    Write-Verbose -Message '$PrinterObject = Get-Printer -Name *$Name* | Select-Object -First 1' #(Get-Printer | Where-Object -FilterScript {$PSItem.Name -like "$Name"})'
    $PrinterObject = Get-Printer -Name $Name | Select-Object -First 1 # | Where-Object -FilterScript {$PSItem.ShareName -like "$Name" -or $PSItem.Name -like "$Name"})
    Write-Verbose -Message ('$PrinterObject is: Name= ''{0}'' Driver= ''{1}''' -f $PrinterObject.Name, $PrinterObject.DriverName)

    if ($null -eq $PrinterObject) {
        Write-Verbose -Message '$PrinterObject is $null'
        $Name = $Name -replace '\*','%'
        $WMIFilter = "Name like '$Name'"
    } else {
        if ($PrinterObject.ShareName) {
            # Specify .SetDefaultPrinter against ShareName
            $WMIFilter = ("ShareName='{0}'" -f $PrinterObject.ShareName)
        } else {
            # Specify .SetDefaultPrinter against Printer 'Name'
            $WMIFilter = ("Name='{0}'" -f $PrinterObject.Name)
        }
    }
    Write-Verbose -Message ('"$WMIFilter = {0}"' -f $WMIFilter)
    
    # Use WMI to Set Default Printer // This must be WMI, as an otherwise matching CimInstance does not provide the .SetDefaultPrinter() method
    Write-Debug -Message ('$PrinterWMIObject = Get-WmiObject -Class win32_printer -Filter {0}' -f $WMIFilter)
    $PrinterWMIObject = Get-WmiObject -Class win32_printer -Filter $WMIFilter

    if ($null -eq $PrinterWMIObject) {
        Write-Warning -Message ('Failed to get details of an available printer matching this filter: {0}' -f $WMIFilter)
    } else {
        if (($PrinterWMIObject.GetType()).IsArray) {
            $PrinterWMIObject = $PrinterWMIObject | Select-Object -First 1
        }
        Write-Verbose -Message ('Setting Default Printer to "{0}"' -f $PrinterWMIObject.Name)
        $PrinterSet = $PrinterWMIObject.SetDefaultPrinter()
        
        if ($null -eq $PrinterSet) {
            Write-Warning -Message 'Failed to Set Default Printer.'
            return $null
        } else {
            Write-Verbose -Message 'Setting Default Printer succeeded.'

            if ($PrinterWMIObject.ShareName) {
                # Specify .SetDefaultPrinter against ShareName
                return ('Default Printer: {0}' -f $(Get-Printer -Default | Select-Object -Property ShareName).ShareName)
            } else {
                # Specify .SetDefaultPrinter against Printer 'Name'
                return ('Default Printer: {0}' -f $(Get-Printer -Default | Select-Object -Property Name).Name)
            }

        }
    }
}