# Sperry
The Sperry 'autopilot' module includes functions to automate changes related to working in a specific office network environment, vs working elsewhere, or remotely

### Contains 5 functions / cmdlets:

##### Set-Workplace
The primary cmdlet. If you'd like to adopt Sperry for your own use, you'll want to customize the tasks and operations called from Set-Workplace. Most of the following functions are invoked from within the Set-Workplace function, but are also exported for direct use. You may find that some of these are not useful for you, or you may want/need to customize them to your own workplace/context(s). If you review the code, and have questions about how or why it works for me, please ask; I'd be glad to share my thoughts, and perhaps learn a better way.

Parameters (copy from inline help)

##### Get-IECookies
Basically just a read-only replica of Clear-IECookies
 
##### Clear-IECookies

##### Connect-WiFi

##### Disconnect-WiFi

##### Get-Printer

##### Set-Printer

##### Get-IPAddress

##### Redo-DHCP

##### Set-DriveMaps

##### Remove-DriveMaps

##### Get-SophosFW

##### Set-SophosFW

##### Start-CitrixReceiver

##### Start-XenApp

##### Test-LocalAdmin

##### Set-UAC

##### Start-Robosync

##### Set-ProcessState

##### Test-ProcessState

##### Enter-XASession
