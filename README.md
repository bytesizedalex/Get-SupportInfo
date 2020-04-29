[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](Contributor_Covenant_Code_of_Conduct.md)

### Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.

## Contributor Convenant Code of Conduct

Please review the code of conduct - be excellent to each other!

* [Contributor Covenant Code of Conduct](Contributor_Covenant_Code_of_Conduct.md)

## Contributor Guidelines

Please review the contributor guidelines before submitting requests.

* [Contributor Guidelines](Contributor_Guidelines.md)

## Frequently Asked Questions

Please review the frequently asked questions, they may include information you are looking for!
* [Frequently Asked Questions](Frequently_Asked_Questions.md)

## Readme
This function will generate and output various log files and support information to assist in troubleshooting computer issues. The exported data is added to an archive file which can be attached to support tickets or forwarded from service desk to senior support.

The function requires a directory named 'Support' exist at 'C:\Support\'. The function will attempt to create this directory if it does not exist. As part of my standard build this is created in the operating system deployment process. If you have limited users ability to write or create directories on this drive or location you will need to amend the function.

The following summarises the data captured - 

    > MSInfo32 saved to NFO file
    > Get-ComputerInfo
    > Event Logs exported to EVTX files
        > Test for elevated access and export if running as Administrator -
            > Microsoft-Windows-Diagnostics-Performance/Operational
            > Security
        > Export at all times -
            > System
            > Application
            > Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational
            > Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational
            > Microsoft-Windows-Ntfs/Operationa
            > Microsoft-Windows-Ntfs/WHC
            > Microsoft-Windows-OfflineFiles/Operational
            > Microsoft-Windows-Storage-Storport/Operational
            > Microsoft-Windows-TaskScheduler/Maintenance
            > Microsoft-Windows-TaskScheduler/Operational
            > Microsoft-Windows-WLAN-AutoConfig/Operational
    > GPResult Report Exported to HTML file
    > Get-HotFix
    > Get-Process
    > Get-Service
    > Get-Disk
    > Get-Volume
    > Get-NetAdapter
    > Get-NetIPConfiguration
    > Get-DnsClient
    > Get-DnsClientGlobalSetting
    > Get-DnsClientServerAddress
    > Get-NetFirewallProfile
    > Get-NetFirewallRule
    > Resolve-DnsName - Test lookup of internal domain resource and external Internet resource
    > Generate Wireless LAN Report
    > Export Active Directory Site information using .Net
    > Get-BitLockerVolume - Test for elevated access and export if running as Administrator
    > Get-Tpm
    > Export computer and user certificate store information
    > Export system environment variables
    > Get-Printer
    > Export time synchronisation using W32tm /stripchart compared to current Active Directory PDC Emulator
    > Get-ScheduledTask
    > Get installed software from registry entries in HKCU and HKLM
    > Get-LocalUser
    > Get-LocalGroupMember
    > Export Physical Memory information from CIM (Win32_PhysicalMemory)
    > Export Processor information from CIM (Win32_Processor)
    > Export BIOS/EFI information from CIM (Win32_BIOS)
    > Export Reliability Records from CIM (Win32_ReliabilityRecords)
    > Export PNP Device information from CIM (Win32_PNPEntity)
    > Export PNP Device driver information from CIM (Win32_PnPSignedDriver)
    > Generate PowerCfg Power Scheme Report, including currently active scheme
    > Generate battery report if battery CIM instance exists
    > Generate system power report - Test for elevated access and export if running as Administrator
    > Generate DirectX Diagnostic Report

All output is saved to C:\Support\Logs\ and is then added to an archive file. Following archive creation the Logs folder is cleared of all files. Archive files are not removed automatically as support staff may wish to capture multiple data sets during troubleshooting.

PowerShell transcription is used to capture logging information, the log file is located at 'C:\Support\LogFile.txt'

The function is designed for Active Directory domain joined machines. Certain data captures will fail to work on a non-domain joined system or will have data missing.

Please note - on completion the function will clear the contents of $exportFolder. By default this is set to C:\Support\Logs.

Additional inline comments are made throughout the function to assist understanding. A review of the (Begin) and Variables section is recommended - you may need to modify these sections to suit your needs and operating system build.
