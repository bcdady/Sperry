#Requires -Version 3.0
<#
    .SYNOPSIS
        Examines current Internet Explorer cookies by source site (URL) and clears those that contain a matching URL
        Component of Sperry module; requires functions from other module files.
    .DESCRIPTION
        Enumerates all IE cookie text files, searches their content for a string match of the URL parameter, and if matched, deletes the cookie file
    .PARAMETER $URL
        Provide the domain / URL string you'd like to match, when searching for cookies to be cleared
    .EXAMPLE
        PS C:\> Clear-Cookies msn.com
        Clears (deletes) all cookie files that contain the text 'msn.com'
    .NOTES
        NAME        :  Clear-Cookies
        VERSION     :  1.0.1  
        LAST UPDATED:  3/16/2016
        AUTHOR      :  Bryan Dady
#>

function Get-IECookie
{
    param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify web site to search within cookies for. Accepts any string, including wildcards.'
        )]
        [alias('address','site','URL')]
        [String]
        $cookieURI = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    )

    Show-Progress -msgAction Start -msgSource Sperry
    Start-Sleep -Milliseconds 20
    Write-Log -Message "Getting IE cookie files, matching search pattern: '$cookieURI'" -Function Sperry
    
    if ($cookieURI -eq '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') 
    {
        Write-Log -Message 'No URI parameter was specified, so you''ll see all cookies from an IP(v4) address' -Function Sperry -Verbose
    }
    $cookieMatches = @(Get-ChildItem ([system.environment]::getfolderpath('cookies')) |
        Select-String -Pattern "$cookieURI" |
    Select-Object -Property FileName, Line, Path)

    Show-Progress -msgAction Stop -msgSource Sperry
    # Log end timestamp
    return $cookieMatches
}

# *** RFE : only process unique file paths. Currently 

function Clear-IECookie
{
    param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify web site to search cookies files for. Can be left blank / null; accepts any string, including wildcards.'
        )]
        [alias('address','site','URL')]
        [String]
        $cookieURI = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    )
    Show-Progress -msgAction Start -msgSource Sperry
    # Log start timestamp

    Write-Log -Message "Getting IE cookie files to be cleared. Calling: Get-IECookie -cookieURI $cookieURI" -Function Sperry
    Get-IECookie -cookieURI $cookieURI |
    Select-Object -Unique -Property Path |
    ForEach-Object -Process {
        Write-Log -Message "Deleting IE Cookie file: $($PSItem.Path)" -Function Sperry
        Remove-Item -Path $PSItem.Path -Force
    }

    Show-Progress -msgAction Stop -msgSource Sperry
    # Log end timestamp
}
