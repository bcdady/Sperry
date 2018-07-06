#Requires -Version 3.0
[CmdletBinding()]
Param ()

Write-Verbose -Message 'Defining function Get-IECookie'
function Get-IECookie {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position = 0,
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
    
    if ($cookieURI -eq '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
        Write-Log -Message 'No URI parameter was specified, so you''ll see all cookies from an IP(v4) address' -Function Sperry
    }

    $cookieMatches = @(Get-ChildItem -File -Path ([system.environment]::GetFolderPath('cookies')) -Recurse | `
        Select-String -Pattern "$cookieURI" | Select-Object -Property FileName, Line, Path)

    # Log end timestamp
    Show-Progress -msgAction Stop -msgSource Sperry

    return $cookieMatches

    <#
        .SYNOPSIS
            Examines current Internet Explorer cookies by source site (URL) and returns those that contain a matching URL
            Component of Sperry module; requires functions from other module files.
        .DESCRIPTION
            Enumerates all IE cookie text files, searches their content for a string match of the URL parameter, and if matched, returns cookie file properties
            Uses a RegEx filter (via Select-String -Pattern )
        .PARAMETER $URL
            Provide the domain / URL string you'd like to match, when searching for cookies to be cleared
        .EXAMPLE
            PS >_ Get-IECookie msn.com
            Enumerates all cookie files that contain the text 'msn.com'
        .EXAMPLE
            PS >_ Get-IECookie -cookieURI .*\.com
            Enumerates all cookie files that end in '.com'
        .EXAMPLE
            PS >_ Get-IECookie
            Enumerates all cookie files that contain an IP address, instead of a DNS name URI   
        .NOTES
            NAME        :  Get-IECookie
            VERSION     :  1.0.2
            LAST UPDATED:  8/16/2017
            AUTHOR      :  Bryan Dady
    #>
}

# *** RFE : only process unique file paths. Currently 

Write-Verbose -Message 'Defining function Clear-IECookie'
function Clear-IECookie {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position = 0,
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

    Write-Log -Message ('Getting IE cookie files to be cleared. Calling: Get-IECookie -cookieURI {0}' -f $cookieURI) -Function Sperry
    Get-IECookie -cookieURI $cookieURI | `
        Select-Object -Unique -Property Path | `
            ForEach {
                Write-Log -Message ('Matched cookie URI {0}. Deleting "{1}"' -f $cookieURI, $PSItem.Path) -Function Sperry
                Remove-Item -Path $PSItem.Path -Force -ErrorAction Ignore
            }

    Show-Progress -msgAction Stop -msgSource Sperry
    # Log end timestamp

    <#
        .SYNOPSIS
            Examines current Internet Explorer cookies by source site (URL) and clears those that contain a matching URL
            Component of Sperry module; requires functions from other module files.
        .DESCRIPTION
            Enumerates all IE cookie text files, searches their content for a string match of the URL parameter, and if matched, deletes the cookie file
        .PARAMETER cookieURI
            Provide the domain / URL string you'd like to match, when searching for cookies to be cleared.
            Expects a RegEx pattern string
        .EXAMPLE
            PS >_ Clear-IECookie msn.com
            Clears (deletes) all cookie files that contain the text 'msn.com'
        .EXAMPLE
            PS >_ Get-IECookie -cookieURI .*\.com
            Clears (deletes) all cookie files that end in '.com'
        .NOTES
            NAME        :  Clear-IECookie
            VERSION     :  1.0.2
            LAST UPDATED:  8/16/2017
            AUTHOR      :  Bryan Dady
    #>
}
