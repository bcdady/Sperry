# Sperry

The Sperry 'autopilot' module includes functions to automate changes related to working in a specific office network environment, vs working remotely (away from that office network).

"Lawrence Burst Sperry ... was an aviation pioneer" and is credited with inventing autopilot -[wikipedia](https://en.wikipedia.org/wiki/Lawrence_Sperry)

## Contents

<!-- TOC -->

- [Functions](#functions)
  - [Set-Workplace](#set-workplace)
  - [Clear-IECookie](#clear-iecookie)
  - [Connect-WiFi](#connect-wifi)
  - [Disconnect-WiFi](#disconnect-wifi)
  - [Dismount-Path](#dismount-path)
  - [Get-IECookie](#get-iecookie)
  - [Get-IPAddress](#get-ipaddress)
  - [Get-NetConnStatus](#get-netconnstatus)
  - [Get-Printer](#get-printer)
  - [Get-ProcessByUser](#get-processbyuser)
  - [Get-PSFSDrive](#get-psfsdrive)
  - [Set-Printer](#set-printer)
  - [Redo-DHCP](#redo-dhcp)
  - [Set-DriveMaps](#set-drivemaps)
  - [Remove-DriveMaps](#remove-drivemaps)
  - [Test-LocalAdmin](#test-localadmin)
  - [Open-UAC](#open-uac)
  - [Set-ProcessState](#set-processstate)
  - [Test-ProcessState](#test-processstate)

<!-- /TOC -->

## Functions

(organized by module file / ScriptsToProcess)

### Set-Workplace

The primary cmdlet. If you'd like to adopt Sperry for your own use, you'll want to customize the tasks and operations called from Set-Workplace. Most of the following functions are invoked from within the Set-Workplace function, but are also exported for direct use. You may find that some of these are not useful for you, or you may want/need to customize them to your own workplace/context(s). If you review the code, and have questions about how or why it works for me, please ask; I'd be glad to share my thoughts, and perhaps learn a better way.

AdminConsole.ps1

### [Test-LocalAdmin](#test-LocalAdmin)

### [Open-AdminConsole](#open-adminconsole)

ProcessState.ps1

### [Set-ProcessState](#set-processstate)

### [Test-ProcessState](#test-processstate)

ClearCookies.ps1

### Get-IECookie

Basically just a read-only replica of Clear-IECookies

### Clear-IECookie

### Get-ProcessByUser.ps1

### Get-ServiceGroup.ps1

### Get-Connected.ps1

### Connect-WiFi

### Disconnect-WiFi

### Dismount-Path

### Get-IPAddress

### Get-NetConnStatus

EXAMPLE

     Get-NetConnStatus

    No ConnectionID specified; enumerating physical network adapters

    Name                                       NetConnectionID
    ----                                       ---------------
    Intel(R) Ethernet Connection I219-V        Local Area Connection
    Intel(R) Dual Band Wireless-AC 8260        Wireless
    Microsoft Virtual WiFi Miniport Adapter    Wireless Network Connection

### Get-Printer

### Get-PSFSDrive

### Get-ServiceGroup

### Get-WiFi

### Import-Settings

### Mount-Path

### Open-AdminConsole

### Open-Browser

### Open-UAC

### Redo-DHCP

### Set-Printer

### Set-ProcessState

### Set-ServiceGroup

### Set-Workplace

### Show-DesktopDocuments

### Show-Settings

### Test-LocalAdmin

### Test-ProcessState

#### Get-IPAddress

#### Get-NetConnStatus

#### Get-Printer

#### Get-ProcessByUser

#### Get-PSFSDrive

#### Set-Printer

#### Redo-DHCP

#### Set-DriveMaps

#### Remove-DriveMaps

#### Test-LocalAdmin

#### Open-UAC

#### Set-ProcessState

#### Test-ProcessState

SYNOPSIS

A helper function for streamlining start-process and stop-process cmdlet interactions for predefined executable file paths and their arguments / parameters.

DESCRIPTION

Using the ProcessName parameter, and the internally defined $knownPaths hash table, Set-ProcessState can be used to either Start or Stop a particular application / process, simply by specifying the -Action parameter

PARAMETERS

```-processName```

Name of process to check for, start up, or stop

```-Action```

Specify whether to start processName, or to Stop it.

```-ListAvailable```

Enumerate $knownPaths hash table

EXAMPLE

    Get-Process C:\> Set-ProcessState -ProcessName iexplore -Action Stop

Stop all running instances of Internet Explorer

EXAMPLE

    Get-Process C:\> Set-ProcessState -ProcessName Firefox -Action Start

Effectively equivalent to Start-Process Firefox browser, when the path to Firefox.exe is defined in your Sperry JSON file.
