#!/usr/local/bin/pwsh
#Requires -Version 3 -Module PSLogger

<#
    .SYNOPSIS
    The Sperry 'autopilot' module includes functions to automate changes related to working in a specific office network environment, vs working elsewhere, or remotely
    .DESCRIPTION
    Customizes the user's operating environment and launches specified applications, to operate in a workplace persona
    The module includes functions such as ProfileSync, CheckProcess, and utilizes the Write-Log function from the PSLogger Module.
    .NOTES
    NAME     : Sperry.psm1
    LANGUAGE : Windows PowerShell
    AUTHOR   : Bryan Dady
    DATE     : 11/2/2015

#>
#========================================
[CmdletBinding(SupportsShouldProcess)]
param ()

# Enforce coding rules in expressions, scripts, and script blocks based on latest available rules; un-comment for dev, re-comment for release

# Define PSUpdateDate variable and populate from persistent state settings file
New-Variable -Name PSHelpUpdatedDate -Description 'Date/time stamp of the last Update-Help run' -Scope Global -Force

Set-Variable -Name MySettings -Description 'Sperry Settings' -Option AllScope

<#
    Write-Output -InputObject 'Importing shared saved state info from Microsoft.PowerShell_state.json to custom object: $PSState'
    try {
        $Global:PSState = (Get-Content -Path $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json -ErrorAction Ignore) -join "`n" | ConvertFrom-Json
    }
    catch {
        Write-Warning -Message "Unable to load PowerShell saved state info from $env:PUBLIC\Documents\WindowsPowerShell\Microsoft.PowerShell_state.json to custom object: `$PSState"
    }
#>

if ((Get-Variable -Name hostOSCaption -ValueOnly -Scope Global -ErrorAction SilentlyContinue) -like '*Windows Server*') {
  [bool]$onServer = $true
} else {
  [bool]$onServer = $false
}

# Core Functions
# -- Activity / outcome specific functions are stored in their own script files
#========================================
# FYI this same function is also globally defined in ProfilePal module
function Test-LocalAdmin {
    <#
        .SYNOPSIS
            Test if the current user of the current host (e.g. Console) have Admin permissions; returns simple boolean result
        .DESCRIPTION
            Updated to take advantage of the automatic variable $IsAdmin added in v4.0
    #>
    if ((Get-Variable -Name IsAdmin -ErrorAction Ignore) -eq $true) {
    Return $IsAdmin
  } else {
    Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')
  }
} # end function Test-LocalAdmin

Function Import-Settings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SettingsFileName = 'Sperry.json'
    )

    # Enhancement : support -Force parameter
    #if (Get-Variable -Name MySettings -Scope Global -ErrorAction Ignore) {
    #    Remove-Variable -Name MySettings -Scope Global
    #}
    Write-Debug -Message ('$JSONPath = Join-Path -Path $(Split-Path -Path {0} -Parent) -ChildPath {1}' -f $PSCommandPath, $SettingsFileName)
    $JSONPath = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath $SettingsFileName
    Write-Verbose -Message ('$MySettings = (Get-Content -Path {0}) -join "`n" | ConvertFrom-Json' -f $JSONPath)
    $MySettings = (Get-Content -Path $JSONPath) -join "`n" | ConvertFrom-Json

    if ($MySettings.About) {
        Write-Verbose -Message 'Settings imported. Run Show-Settings to see details.'
        $MySettings | Select-Object -ExpandProperty About
    } else {
        Write-Warning -Message ('Critical Error loading settings from {0}' -f $JSONPath)
    }
    <#
        .SYNOPSIS
        Import (Initialize) module settings from a specified JSON file

        .DESCRIPTION

        .EXAMPLE
        PS .\>Import-Settings -SettingsFileName sperry-template.json

        name        : Sperry PowerShell Module
        type        : PowerShell
        program     : Sperry.psm1
        description : User customization for PowerShell Sperry module
        version     : 1.0.0
        updated     : 11-1-2017
        notes       : consolidated information to new 'about' category

    #>
} # end function Import-Settings

Write-Verbose -Message 'Import Sperry configs'
Import-Settings

function Show-Settings {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SettingsFileName = 'Sperry.json'
    )

    if (-not (Get-Variable -Name MySettings -ErrorAction Ignore)) {
        Write-Verbose -Message ('Import Sperry config as defined in {0}' -f $SettingsFileName)
        Import-Settings -SettingsFileName $SettingsFileName
    }

    Write-Verbose -Message ''
    Write-Verbose -Message ' # Showing $MySettings, for Sperry module #'
    return $MySettings

    <#
        .SYNOPSIS
        Shows current contents of module's custom settings data structure

        .DESCRIPTION
        In order to show settings, the settings must first be retrieved from the json file.
        If the Settings variable is not yet populated, then Import-Settings funciton is invoked first

        .EXAMPLE
        Show-Settings | select -ExpandProperty About

        name        : Sperry PowerShell Module
        type        : PowerShell
        program     : Sperry.psm1
        description : User customization for PowerShell Sperry module
        version     : 0.1.11
        updated     : 11-28-2017
        notes       : consolidated information to new 'about' category

        .EXAMPLE
        Show-Settings

        About        : {@{name=Sperry PowerShell Module; type=PowerShell; program=Sperry.psm1; description=User customization for PowerShell Sperry module; version=1.0.0; updated=11-1-2017; notes=consolidated information to new 'about' category}}
        KnownProcess : {@{Name=Chrome; Path=${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe}, @{Name=Code; Path=$env:ProgramFiles\Microsoft VS Code\code.exe}, @{Name=CodeInsider; Path=$env:ProgramFiles\Microsoft VS Code Insiders\bin\code-insiders.cmd}, @{Name=GitHub; Path=$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GitHub, Inc\GitHub.appref-ms}...}
        UNCPath      : {@{DriveName=H; FullPath=\\SMB-FQDN\ShareRoot$\$env:USERNAME}}
        Workplace    : {@{Name=Remote; function_before=System.Object[]; ServiceGroup=System.Object[]; IEHomePage=https://personal.BrowserHomePage.url; BrowserProgid=ChromeHTML; ProcessState=System.Object[]; function_after=System.Object[]}, @{Name=Office; function_before=System.Object[]; ServiceGroup=System.Object[]; IEHomePage=https://corporate.BrowserHomePage.url; BrowserProgid=IE.HTTPS; function_after=System.Object[]}}
    #>
} # end function Show-Settings

function Open-UAC {
    <#
        .SYNOPSIS
        Open Windows User Account Control Settings application window.

        .DESCRIPTION
        Detects if current UAC setting is other than this functions expected Default setting (such as Always Notify or lesser than Default options), by inspecting the ConsentPromptBehaviorAdmin value in the local Windows registry.
        If ConsentPromptBehaviorAdmin is other than the expected/Default value, the UserAccountControlSettings.exe is invoked.
    #>
    Show-Progress -msgAction 'Start' -msgSource $MyInvocation.MyCommand.Name # Log start time stamp
    # Check current UAC level via registry
    # We want ConsentPromptBehaviorAdmin = 5
    # thanks to http://forum.sysinternals.com/display-uac-status_topic18490_page3.html
    $ConsentPromptBehaviorAdmin = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'ConsentPromptBehaviorAdmin').ConsentPromptBehaviorAdmin
    if ($ConsentPromptBehaviorAdmin -eq 5) {
        # prompt for UAC update
        Write-Verbose -Message ('User Account Control set to an approved level: {0}' -f $ConsentPromptBehaviorAdmin)
    } elseif ($ConsentPromptBehaviorAdmin -eq 0) {
        Write-Verbose -Message ('User Account Control set to an approved level: {0}' -f $ConsentPromptBehaviorAdmin)
    } else {
        Write-Log -Message 'Opening User Account Control Settings dialog ...' -Function $MyInvocation.MyCommand.Name
        & $env:SystemDrive\Windows\System32\UserAccountControlSettings.exe
        Start-Sleep -Seconds 5

        # Wait for UAC to be complete before proceeding
        Test-ProcessState -ProcessName 'UserAccountControlSettings' -Wait
    }

    Show-Progress -msgAction 'Stop' -msgSource $MyInvocation.MyCommand.Name # Log end time stamp
} # end function Open-UAC

Function Open-Browser {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='URL to open in default web browser.'
        )]
        [ValidatePattern({\S+})]
        [String]
        [alias('address','site')]
        $URL
    )

    Write-Verbose -Message ('Start-Process -FilePath {0}' -f $URL)
    if (-not ($URL -match '^https?:\/\/[\S]+')) {
        Write-Verbose -Message 'Prepending ambiguous $URL with https://'
        $URL = 'https://' + $URL
    }

    Start-Process -FilePath $URL
} # end function Open-Browser

Function Set-Workplace {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(
            Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Specify workplace mode, or context, as defined in Sperry.json.'
        )]
        [String]
        [alias('context','situation','location','zone')]
        [ValidateScript({$PSItem -in ($MySettings.Workplace | Get-Member -MemberType NoteProperty | ForEach-Object -Process {$_.Name})})]
        $Mode
    )

    Show-Progress -msgAction Start -msgSource $MyInvocation.MyCommand.Name

    # Always simplify UAC prompt level, so we run this before {switching ($Mode)}
    Write-Log -Message 'Checking UserAccountControl level' -Function $MyInvocation.MyCommand.Name
    Open-UAC

    Write-Log -Message ('Loading settings for Workplace {0} as defined in {1}.' -f $Mode, $SettingsFileName) -Function $MyInvocation.MyCommand.Name
    # $ModeSettings = $MySettings.Workplace | Where-Object -FilterScript {$PSItem.Name -eq $Mode}
    $ModeSettings = $MySettings.Workplace.$Mode

    if (-not ($ModeSettings.function_before)) {
        Write-Log -Message '$ModeSettings.function_before was not found.' -Function $MyInvocation.MyCommand.Name
    } else {
        $ModeSettings.function_before | Sort-Object -Property Order | ForEach-Object -Process {
            Write-Debug -Message ('Function {0} - Message: {1}' -f $PSItem.Name, $PSItem.Message)
            Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
            Invoke-Expression -Command $PSItem.Name
            Start-Sleep -Milliseconds 777
        }
    }

    if (-not ($ModeSettings.ServiceGroup)) {
        Write-Log -Message '$ModeSettings.ServiceGroup was not found.' -Function $MyInvocation.MyCommand.Name
    } else {
        $ModeSettings.ServiceGroup | Sort-Object -Property Order | ForEach-Object -Process {
            Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
            Set-ServiceGroup -Name $PSItem.Name -Status $PSItem.Status
            Start-Sleep -Milliseconds 777
        }
    }

    if (-not ($ModeSettings.ProcessState)) {
        Write-Log -Message '$ModeSettings.ProcessState was not found.' -Function $MyInvocation.MyCommand.Name
    } else {
        $ModeSettings.ProcessState | Sort-Object -Property Order | ForEach-Object -Process {
            Write-Log -Message ('{0}' -f $PSItem.Message) -Function $MyInvocation.MyCommand.Name
            Set-ProcessState -Name $PSItem.Name -Action $PSItem.Action
            Start-Sleep -Milliseconds 777
        }
    }

    # Update IE home page
    Write-Log -Message 'Setting Internet Explorer start page to $($ModeSettings.IEHomePage)' -Function $MyInvocation.MyCommand.Name
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $ModeSettings.IEHomePage -force -ErrorAction Ignore
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Value $ModeSettings.IEHomePage -force -ErrorAction Ignore

    # Set preferred / defined default browser
    Write-Log -Message 'Updating default browser via registry edit' -Function $MyInvocation.MyCommand.Name
    Write-Log -Message ('Setting URL Progid to {0}' -f $ModeSettings.BrowserProgid) -Function $MyInvocation.MyCommand.Name
    @('http','https') | ForEach {
        $Private:URL = ('HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{0}\UserChoice' -f $PSItem)
        # In case the reg key does not yet exist, we must first create it, as New-ItemProperty can not make a new reg key item prior to setting a property of the item
        if (-not (Test-Path -Path $Private:URL)) {
            Write-Log -Message ('Creating registry key items for {0} URL Associations' -f $PSItem) -Function $MyInvocation.MyCommand.Name
            New-Item -Path $Private:URL -Force
        }
        Set-ItemProperty -Path $Private:URL -Name Progid -Value $ModeSettings.BrowserProgid -Force
    }

    Write-Log -Message 'Updating default browser via registry edit' -Function $MyInvocation.MyCommand.Name
    # In case the reg key does not yet exist, we must first create it, as New-ItemProperty can not make a new reg key item prior to setting a property of the item
    if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice)) {
        Write-Log -Message 'Creating registry key items for http URL Associations' -Function $MyInvocation.MyCommand.Name
        New-Item -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice -Force
    }

    if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice)) {
        Write-Log -Message 'Creating registry key items for https URL Associations' -Function $MyInvocation.MyCommand.Name
        New-Item -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Force
    }

    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice -Name Progid -Value $MySettings.BrowserProgid -Force

    $ModeSettings.function_after | Sort-Object -Property Order | ForEach-Object -Process {
        Write-Log -Message ('{0}' -f $PSItem.Message) -Function $PSItem.Name
        Invoke-Expression -Command $PSItem.Name
        Start-Sleep -Milliseconds 777
    }

  if (-not ($ModeSettings.Printer)) {
    Write-Log -Message '$ModeSettings.Printer preference was not found.' -Function $MyInvocation.MyCommand.Name
  } else {
    $ModeSettings.Printer | ForEach-Object -Process {
      Write-Log -Message ('Setting default printer: {0}' -f $ModeSettings.Printer) -Function $MyInvocation.MyCommand.Name
      Set-Printer -printerShareName $ModeSettings.Printer
      Start-Sleep -Milliseconds 333
    }
  }

  Write-Output -InputObject 'If you''d like to (re)open all Desktop Documents, run Show-DesktopDocuments'

  Show-Progress -msgAction Stop -msgSource $MyInvocation.MyCommand.Name  # Log end time stamp

  return ('Ready for {0} work' -f $Mode)
} # end function Set-Workplace
