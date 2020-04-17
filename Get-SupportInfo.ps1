<#
.Synopsis
   Generate support logs and information to aid troubleshooting. This function is designed for Windows 10 Active Directory domain joined computers.
.DESCRIPTION
   This function will generate and output various log files and support information to assist in troubleshooting computer issues. The exported data is added to an archive file which can be attached to support tickets or forwarded from service desk to senior support.

   The function requires a directory named 'Support' exist at 'C:\Support\'. The function will attempt to create this directory if it does not exist. As part of my standard build this is created in the operating system deployment process. If you have limtied users ability to write or create directories on this drive or location you will need to amend the function.

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
.EXAMPLE
   Get-SupportInfo
.EXAMPLE
   Get-SupportInfo - Verbose
.INPUTS

.OUTPUTS

.NOTES

.COMPONENT

.ROLE

.FUNCTIONALITY

#>
function Get-SupportInfo {
    [CmdletBinding(DefaultParameterSetName = 'Parameter Set 1',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        HelpUri = 'https://github.com/bytesizedalex/Get-SupportInfo/',
        ConfirmImpact = 'Medium')]
    [Alias("GSI")]
    [OutputType([String])]
    Param
    (
    )

    Begin {

        # Create Support Folder. In my standard build this folder already exists as part of the operating system deployment process. If you have blocked access to the C:\ drive or limited users ability to write to this location the script will fail/encounter problems running.
        Write-Verbose -Message 'Test for existence of C:\Support Folder and create if necessary'
        if (!(Test-Path -Path 'C:\Support')) {
            New-Item -ItemType Directory -Path 'C:\Support\' -Force | Out-Null
        }
        # Setup Transcription Logging
        Write-Verbose -Message 'Start PowerShell Transcription Logging'
        $ErrorActionPreference = "SilentlyContinue"
        Stop-Transcript | Out-Null
        Start-Transcript -Path 'C:\Support\LogFile.txt' -Append | Out-Null

        # Variables
        Write-Verbose -Message 'Defining Variables and Preferences'

        # Define target folders and locations of required executables
        $exportFolder = 'C:\Support\Logs'
        $archiveFolder = 'C:\Support\'
        $wevtutilLocation = "$env:SystemRoot\System32\wevtutil.exe"
        $gpresultLocation = "$env:SystemRoot\System32\gpresult.exe"
        $powerCfgLocation = "$env:SystemRoot\System32\powercfg.exe"
        $netshLocation = "$env:SystemRoot\System32\netsh.exe"
        $directxDiagLocation = "$env:SystemRoot\System32\dxdiag.exe"
        $gsiTempOutput = "Temp Variable for Redirected Output"
        
        # Define date and time for timestamp purposes
        $timeStamp = (Get-Date -Format yyyyMMddTHHmm).ToString()

        # Define powercfg duration - 7 days, amend as required
        $powerCfgDuration = '7'

        # Define Windows Registry key locations
        $HKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $HKLM64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $regKeys = "$HKCU", "$HKLM", "$HKLM64"

        # Determine current Active Directory domain PDC Emulator via .Net
        $pdcEmulator = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain().PDCRoleOwner).Name

        # Internal DNS testing
        # This is the name of the internal DNS record you wish to lookup. Third parties should replace this entry with an appropriate internal DNS name
        $internalDNSName = 'f5-dns-pri'
        # This is the name of the external DNS server you wish to perform the lookup against. Third parties should replace this entry with a highly available internal DNS server target
        $internalDNSServer = 'f5-dns-pri.ad.bytesizedalex.com'

        # External DNS testing
        # This is the name of the external DNS record you wish to lookup. By default the function will attempt to resolve 'one.one.one.one' which is the name of the Cloudflare 1.1.1.1 DNS service
        $externalDNSName = 'one.one.one.one'
        # This is the name of the external DNS server you wish to perform the lookup against. By default the function will attempt to perform name resolution against the Cloudflare 1.1.1.1 DNS service
        $externalDNSServer = '1.1.1.1'

        # Script Error and Warning Preferences
        $ErrorActionPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"

        # Clear directories and create required folder structure - please note the C:\Support folder is not created as this is already defined as part of the standard OS build. If your build does not include this directory you should either amend the script to create it for you or update your operating system deployement task sequence to include it
        Write-Verbose -Message 'Clearing Log Folder'
        Remove-Item -Path "$exportFolder\*" -Force -Recurse
        Write-Verbose -Message 'Creating Output Directories'
        New-Item -ItemType Directory -Path 'C:\Support\Logs\EventLogs' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\Support\Logs\EventLogs\EVTX' -Force | Out-Null
    }

    Process {

        # Gather MSInfo32 Output
        Write-Verbose -Message 'Gather MSInfo32 Output'
        Start-Process -Wait -FilePath "$env:SystemRoot\System32\msinfo32.exe" -ArgumentList "/nfo $exportFolder\msinfo32.nfo"

        # Gather ComputerInfo cmdlet Output
        Write-Verbose -Message 'Gather ComputerInfo Information'
        Get-ComputerInfo | ForEach-Object {
            [PSCustomObject]@{
                BiosBIOSVersion                                         = [string]$_.BiosBIOSVersion -join ","
                BiosBuildNumber                                         = $_.BiosBuildNumber
                BiosCaption                                             = $_.BiosCaption
                BiosCharacteristics                                     = [string]$_.BiosCharacteristics -join ","
                BiosCodeSet                                             = $_.BiosCodeSet
                BiosCurrentLanguage                                     = $_.BiosCurrentLanguage
                BiosDescription                                         = $_.BiosDescription
                BiosEmbeddedControllerMajorVersion                      = $_.BiosEmbeddedControllerMajorVersion
                BiosEmbeddedControllerMinorVersion                      = $_.BiosEmbeddedControllerMinorVersion
                BiosFirmwareType                                        = $_.BiosFirmwareType
                BiosIdentificationCode                                  = $_.BiosIdentificationCode
                BiosInstallableLanguages                                = $_.BiosInstallableLanguages
                BiosInstallDate                                         = $_.BiosInstallDate
                BiosLanguageEdition                                     = $_.BiosLanguageEdition
                BiosListOfLanguages                                     = [string]$_.BiosListOfLanguages -join ","
                BiosManufacturer                                        = $_.BiosManufacturer
                BiosName                                                = $_.BiosName
                BiosOtherTargetOS                                       = $_.BiosOtherTargetOS
                BiosPrimaryBIOS                                         = $_.BiosPrimaryBIOS
                BiosReleaseDate                                         = $_.BiosReleaseDate
                BiosSeralNumber                                         = $_.BiosSeralNumber
                BiosSMBIOSBIOSVersion                                   = $_.BiosSMBIOSBIOSVersion
                BiosSMBIOSMajorVersion                                  = $_.BiosSMBIOSMajorVersion
                BiosSMBIOSMinorVersion                                  = $_.BiosSMBIOSMinorVersion
                BiosSMBIOSPresent                                       = $_.BiosSMBIOSPresent
                BiosSoftwareElementState                                = $_.BiosSoftwareElementState
                BiosStatus                                              = $_.BiosStatus
                BiosSystemBiosMajorVersion                              = $_.BiosSystemBiosMajorVersion
                BiosSystemBiosMinorVersion                              = $_.BiosSystemBiosMinorVersion
                BiosTargetOperatingSystem                               = $_.BiosTargetOperatingSystem
                BiosVersion                                             = $_.BiosVersion
                CsAdminPasswordStatus                                   = $_.CsAdminPasswordStatus
                CsAutomaticManagedPagefile                              = $_.CsAutomaticManagedPagefile
                CsAutomaticResetBootOption                              = $_.CsAutomaticResetBootOption
                CsAutomaticResetCapability                              = $_.CsAutomaticResetCapability
                CsBootOptionOnLimit                                     = $_.CsBootOptionOnLimit
                CsBootOptionOnWatchDog                                  = $_.CsBootOptionOnWatchDog
                CsBootROMSupported                                      = $_.CsBootROMSupported
                CsBootStatus                                            = [string]$_.CsBootStatus -join ","
                CsBootupState                                           = $_.CsBootupState
                CsCaption                                               = $_.CsCaption
                CsChassisBootupState                                    = $_.CsChassisBootupState
                CsChassisSKUNumber                                      = $_.CsChassisSKUNumber
                CsCurrentTimeZone                                       = $_.CsCurrentTimeZone
                CsDaylightInEffect                                      = $_.CsDaylightInEffect
                CsDescription                                           = $_.CsDescription
                CsDNSHostName                                           = $_.CsDNSHostName
                CsDomain                                                = $_.CsDomain
                CsDomainRole                                            = $_.CsDomainRole
                CsEnableDaylightSavingsTime                             = $_.CsEnableDaylightSavingsTime
                CsFrontPanelResetStatus                                 = $_.CsFrontPanelResetStatus
                CsHypervisorPresent                                     = $_.CsHypervisorPresent
                CsInfraredSupported                                     = $_.CsInfraredSupported
                CsInitialLoadInfo                                       = $_.CsInitialLoadInfo
                CsInstallDate                                           = $_.CsInstallDate
                CsKeyboardPasswordStatus                                = $_.CsKeyboardPasswordStatus
                CsLastLoadInfo                                          = $_.CsLastLoadInfo
                CsManufacturer                                          = $_.CsManufacturer
                CsModel                                                 = $_.CsModel
                CsName                                                  = $_.CsName
                CsNetworkAdaptersDescription                            = $_.CsNetworkAdapters.Description -join ","
                CsNetworkAdaptersIPAddresses                            = $_.CsNetworkAdapters.IPAddresses -join ","
                CsNetworkServerModeEnabled                              = $_.CsNetworkServerModeEnabled
                CsNumberOfLogicalProcessors                             = $_.CsNumberOfLogicalProcessors
                CsNumberOfProcessors                                    = $_.CsNumberOfProcessors
                CsOEMStringArray                                        = [string]$_.CsOEMStringArray -join ","
                CsPartOfDomain                                          = $_.CsPartOfDomain
                CsPauseAfterReset                                       = $_.CsPauseAfterReset
                CsPCSystemType                                          = $_.CsPCSystemType
                CsPCSystemTypeEx                                        = $_.CsPCSystemTypeEx
                CsPhyicallyInstalledMemory                              = $_.CsPhyicallyInstalledMemory
                CsPowerManagementCapabilities                           = $_.CsPowerManagementCapabilities
                CsPowerManagementSupported                              = $_.CsPowerManagementSupported
                CsPowerOnPasswordStatus                                 = $_.CsPowerOnPasswordStatus
                CsPowerState                                            = $_.CsPowerState
                CsPowerSupplyState                                      = $_.CsPowerSupplyState
                CsPrimaryOwnerContact                                   = $_.CsPrimaryOwnerContact
                CsPrimaryOwnerName                                      = $_.CsPrimaryOwnerName
                CsProcessors                                            = $_.CsProcessors.Name
                CsResetCapability                                       = $_.CsResetCapability
                CsResetCount                                            = $_.CsResetCount
                CsResetLimit                                            = $_.CsResetLimit
                CsRoles                                                 = [string]$_.CsRoles -join ","
                CsStatus                                                = $_.CsStatus
                CsSupportContactDescription                             = $_.CsSupportContactDescription
                CsSystemFamily                                          = $_.CsSystemFamily
                CsSystemSKUNumber                                       = $_.CsSystemSKUNumber
                CsSystemType                                            = $_.CsSystemType
                CsThermalState                                          = $_.CsThermalState
                CsTotalPhysicalMemory                                   = $_.CsTotalPhysicalMemory
                CsUserName                                              = $_.CsUserName
                CsWakeUpType                                            = $_.CsWakeUpType
                CsWorkgroup                                             = $_.CsWorkgroup
                DeviceGuardAvailableSecurityProperties                  = [string]$_.DeviceGuardAvailableSecurityProperties -join ","
                DeviceGuardCodeIntegrityPolicyEnforcementStatus         = $_.DeviceGuardCodeIntegrityPolicyEnforcementStatus
                DeviceGuardRequiredSecurityProperties                   = [string]$_.DeviceGuardRequiredSecurityProperties -join ","
                DeviceGuardSecurityServicesConfigured                   = [string]$_.DeviceGuardSecurityServicesConfigured -join ","
                DeviceGuardSecurityServicesRunning                      = [string]$_.DeviceGuardSecurityServicesRunning -join ","
                DeviceGuardSmartStatus                                  = $_.DeviceGuardSmartStatus
                DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus = $_.DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus
                HyperVisorPresent                                       = $_.HyperVisorPresent
                HyperVRequirementDataExecutionPreventionAvailable       = $_.HyperVRequirementDataExecutionPreventionAvailable
                HyperVRequirementSecondLevelAddressTranslation          = $_.HyperVRequirementSecondLevelAddressTranslation
                HyperVRequirementVirtualizationFirmwareEnabled          = $_.HyperVRequirementVirtualizationFirmwareEnabled
                HyperVRequirementVMMonitorModeExtensions                = $_.HyperVRequirementVMMonitorModeExtensions
                KeyboardLayout                                          = $_.KeyboardLayout
                LogonServer                                             = $_.LogonServer
                OsArchitecture                                          = $_.OsArchitecture
                OsBootDevice                                            = $_.OsBootDevice
                OsBuildNumber                                           = $_.OsBuildNumber
                OsBuildType                                             = $_.OsBuildType
                OsCodeSet                                               = $_.OsCodeSet
                OsCountryCode                                           = $_.OsCountryCode
                OsCSDVersion                                            = $_.OsCSDVersion
                OsCurrentTimeZone                                       = $_.OsCurrentTimeZone
                OsDataExecutionPrevention32BitApplications              = $_.OsDataExecutionPrevention32BitApplications
                OsDataExecutionPreventionAvailable                      = $_.OsDataExecutionPreventionAvailable
                OsDataExecutionPreventionDrivers                        = $_.OsDataExecutionPreventionDrivers
                OsDataExecutionPreventionSupportPolicy                  = $_.OsDataExecutionPreventionSupportPolicy
                OsDebug                                                 = $_.OsDebug
                OsDistributed                                           = $_.OsDistributed
                OsEncryptionLevel                                       = $_.OsEncryptionLevel
                OsForegroundApplicationBoost                            = $_.OsForegroundApplicationBoost
                OsFreePhysicalMemory                                    = $_.OsFreePhysicalMemory
                OsFreeSpaceInPagingFiles                                = $_.OsFreeSpaceInPagingFiles
                OsFreeVirtualMemory                                     = $_.OsFreeVirtualMemory
                OsHardwareAbstractionLayer                              = $_.OsHardwareAbstractionLayer
                OsHotFixes                                              = $_.OsHotFixes.HotFixID -join ","
                OsInstallDate                                           = $_.OsInstallDate
                OsInUseVirtualMemory                                    = $_.OsInUseVirtualMemory
                OsLanguage                                              = $_.OsLanguage
                OsLastBootUpTime                                        = $_.OsLastBootUpTime
                OsLocalDateTime                                         = $_.OsLocalDateTime
                OsLocale                                                = $_.OsLocale
                OsLocaleID                                              = $_.OsLocaleID
                OsManufacturer                                          = $_.OsManufacturer
                OsMaxNumberOfProcesses                                  = $_.OsMaxNumberOfProcesses
                OsMaxProcessMemorySize                                  = $_.OsMaxProcessMemorySize
                OsMuiLanguages                                          = [string]$_.OsMuiLanguages
                OsName                                                  = $_.OsName
                OsNumberOfLicensedUsers                                 = $_.OsNumberOfLicensedUsers
                OsNumberOfProcesses                                     = $_.OsNumberOfProcesses
                OsNumberOfUsers                                         = $_.OsNumberOfUsers
                OsOperatingSystemSKU                                    = $_.OsOperatingSystemSKU
                OsOrganization                                          = $_.OsOrganization
                OsOtherTypeDescription                                  = $_.OsOtherTypeDescription
                OsPAEEnabled                                            = $_.OsPAEEnabled
                OsPagingFiles                                           = [string]$_.OsPagingFiles -join ","
                OsPortableOperatingSystem                               = $_.OsPortableOperatingSystem
                OsPrimary                                               = $_.OsPrimary
                OsProductSuites                                         = [string]$_.OsProductSuites -join ","
                OsProductType                                           = $_.OsProductType
                OsRegisteredUser                                        = $_.OsRegisteredUser
                OsSerialNumber                                          = $_.OsSerialNumber
                OsServerLevel                                           = $_.OsServerLevel
                OsServicePackMajorVersion                               = $_.OsServicePackMajorVersion
                OsServicePackMinorVersion                               = $_.OsServicePackMinorVersion
                OsSizeStoredInPagingFiles                               = $_.OsSizeStoredInPagingFiles
                OsStatus                                                = $_.OsStatus
                OsSuites                                                = [string]$_.OsSuites -join ","
                OsSystemDevice                                          = $_.OsSystemDevice
                OsSystemDirectory                                       = $_.OsSystemDirectory
                OsSystemDrive                                           = $_.OsSystemDrive
                OsTotalSwapSpaceSize                                    = $_.OsTotalSwapSpaceSize
                OsTotalVirtualMemorySize                                = $_.OsTotalVirtualMemorySize
                OsTotalVisibleMemorySize                                = $_.OsTotalVisibleMemorySize
                OsType                                                  = $_.OsType
                OsUptime                                                = $_.OsUptime
                OsVersion                                               = $_.OsVersion
                OsWindowsDirectory                                      = $_.OsWindowsDirectory
                PowerPlatformRole                                       = $_.PowerPlatformRole
                TimeZone                                                = $_.TimeZone
                WindowsBuildLabEx                                       = $_.WindowsBuildLabEx
                WindowsCurrentVersion                                   = $_.WindowsCurrentVersion
                WindowsEditionId                                        = $_.WindowsEditionId
                WindowsInstallationType                                 = $_.WindowsInstallationType
                WindowsInstallDateFromRegistry                          = $_.WindowsInstallDateFromRegistry
                WindowsProductId                                        = $_.WindowsProductId
                WindowsProductName                                      = $_.WindowsProductName
                WindowsRegisteredOrganization                           = $_.WindowsRegisteredOrganization
                WindowsRegisteredOwner                                  = $_.WindowsRegisteredOwner
                WindowsSystemRoot                                       = $_.WindowsSystemRoot
                WindowsVersion                                          = $_.WindowsVersion
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ComputerInfo.csv"
        }

        # Gather Event Logs
        Write-Verbose -Message 'Gathering Event Logs - Export to EVTX'
        If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-Diagnostics-Performance/Operational $exportFolder\EventLogs\EVTX\Diagnostics-Performance-Operational.evtx"
            Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Security $exportFolder\EventLogs\EVTX\SecurityLog.evtx"
        }
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl System $exportFolder\EventLogs\EVTX\SystemLog.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Application $exportFolder\EventLogs\EVTX\ApplicationLog.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational $exportFolder\EventLogs\EVTX\CertificateServicesClient-System-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational $exportFolder\EventLogs\EVTX\CertificateServicesClient-User-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-Ntfs/Operational $exportFolder\EventLogs\EVTX\NTFS-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-Ntfs/WHC $exportFolder\EventLogs\EVTX\OfflineFiles-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-OfflineFiles/Operational $exportFolder\EventLogs\EVTX\NTFS-WHC.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-Storage-Storport/Operational $exportFolder\EventLogs\EVTX\Storport-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-TaskScheduler/Maintenance $exportFolder\EventLogs\EVTX\TaskScheduler-Maintenance.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-TaskScheduler/Operational $exportFolder\EventLogs\EVTX\TaskScheduler-Operational.evtx"
        Start-Process -NoNewWindow -FilePath $wevtutilLocation -ArgumentList "epl Microsoft-Windows-WLAN-AutoConfig/Operational $exportFolder\EventLogs\EVTX\WLAN-AutoConfig-Operational.evtx"

        # Gather Group Policy Results
        Write-Verbose -Message 'Gathering Group Policy Results'
        Start-Process -NoNewWindow -Wait -FilePath $gpresultLocation -ArgumentList "/H $exportFolder\GroupPolicyResults.html"

        # Gather Installed Windows HotFix
        Write-Verbose -Message 'Gathering Windows Hotfix Information'
        Get-HotFix | ForEach-Object {
            [PSCustomObject]@{
                Description = $_.Description
                HotFixID    = $_.HotFixID
                InstalledBy = $_.InstalledBy
                InstalledOn = $_.InstalledOn
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\WindowsHotfix.csv"
        }

        # Gather Running Processes
        Write-Verbose -Message 'Gather Running Processes'
        Get-Process | ForEach-Object {
            [PSCustomObject]@{
                Id             = $_.ID
                PriorityClass  = $_.PriorityClass
                FileVersion    = $_.FileVersion
                Path           = $_.Path
                Company        = $_.Company
                ProductVersion = $_.ProductVersion
                Description    = $_.Description
                Product        = $_.Product
                Responding     = $_.Responding
                StartTime      = $_.StartTime
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\RunningProcesses.csv"
        }

        # Gather Services Information
        Write-Verbose -Message 'Gather Services Information'
        Get-Service | ForEach-Object {
            [PSCustomObject]@{
                Name                = $_.Name
                DisplayName         = $_.DisplayName
                ServiceName         = $_.ServiceName
                Status              = $_.Status
                StartType           = $_.StartType
                ServicesDependedOn  = $_.ServicesDependedOn -join ","
                RequiredServices    = $_.RequiredServices -join ","
                CanPauseAndContinue = $_.CanPauseAndContinue
                CanShutdown         = $_.CanShutdown
                CanStop             = $_.CanStop
                ServiceType         = $_.ServiceType
                Site                = $_.Site
                Container           = $_.Container
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Services.csv"
        }

        # Gather Disk Information
        Write-Verbose -Message 'Gather Disk Information'
        Get-Disk | ForEach-Object {
            [PSCustomObject]@{
                DiskNumber         = $_.DiskNumber
                PartitionStyle     = $_.PartitionStyle
                ProvisioningType   = $_.ProvisioningType
                OperationalStatus  = $_.OperationalStatus
                HealthStatus       = $_.HealthStatus
                BusType            = $_.BusType
                BootFromDisk       = $_.BootFromDisk
                FirmwareVersion    = $_.FirmwareVersion
                FriendlyName       = $_.FriendlyName
                Guid               = $_.Guid
                IsBoot             = $_.IsBoot
                IsClustered        = $_.IsClustered
                IsHighlyAvailable  = $_.IsHighlyAvailable
                IsOffline          = $_.IsOffline
                IsReadOnly         = $_.IsReadOnly
                IsScaleOut         = $_.IsScaleOut
                IsSystem           = $_.IsSystem
                Location           = $_.Location
                LogicalSectorSize  = $_.LogicalSectorSize
                Manufacturer       = $_.Manufacturer
                Model              = $_.Model
                Number             = $_.Number
                NumberOfPartitions = $_.NumberOfPartitions
                PhysicalSectorSize = $_.PhysicalSectorSize
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Disks.csv"
        }

        # Gather Volume Information
        Write-Verbose -Message 'Gather Volume Information'
        Get-Volume | ForEach-Object {
            [PSCustomObject]@{
                DriveLetter        = $_.DriveLetter
                FileSystemLabel    = $_.FileSystemLabel
                FileSystem         = $_.FileSystem
                DriveType          = $_.DriveType
                HealthStatus       = $_.HealthStatus
                OperationalStatus  = $_.OperationalStatus
                AllocationUnitSize = $_.AllocationUnitSize
                SizeGB             = [math]::Round((($_.Size) / 1GB), 2)
                SizeRemainingGB    = [math]::Round((($_.SizeRemaining) / 1GB), 2)
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Volumes.csv"
        }

        # Gather Network Information
        Write-Verbose -Message 'Gather Network Information'
        Get-NetAdapter | ForEach-Object {
            [pscustomobject]@{
                InterfaceAlias                                   = $_.InterfaceAlias
                LinkLayerAddress                                 = $_.LinkLayerAddress
                ActiveMaximumTransmissionUnit                    = $_.ActiveMaximumTransmissionUnit
                AdditionalAvailability                           = $_.AdditionalAvailability
                AdminLocked                                      = $_.AdminLocked
                AutoSense                                        = $_.AutoSense
                Availability                                     = $_.Availability
                AvailableRequestedStates                         = $_.AvailableRequestedStates
                Caption                                          = $_.Caption
                CommunicationStatus                              = $_.CommunicationStatus
                ComponentID                                      = $_.ComponentID
                ConnectorPresent                                 = $_.ConnectorPresent
                CreationClassName                                = $_.CreationClassName
                Description                                      = $_.Description
                DetailedStatus                                   = $_.DetailedStatus
                DeviceID                                         = $_.DeviceID
                DeviceName                                       = $_.DeviceName
                DeviceWakeUpEnable                               = $_.DeviceWakeUpEnable
                DriverDate                                       = $_.DriverDate
                DriverDateData                                   = $_.DriverDateData
                DriverDescription                                = $_.DriverDescription
                DriverMajorNdisVersion                           = $_.DriverMajorNdisVersion
                DriverMinorNdisVersion                           = $_.DriverMinorNdisVersion
                DriverName                                       = $_.DriverName
                DriverProvider                                   = $_.DriverProvider
                DriverVersion                                    = $_.DriverVersion
                DriverVersionString                              = $_.DriverVersionString
                ElementName                                      = $_.ElementName
                EnabledDefault                                   = $_.EnabledDefault
                EnabledState                                     = $_.EnabledState
                EndPointInterface                                = $_.EndPointInterface
                ErrorCleared                                     = $_.ErrorCleared
                ErrorDescription                                 = $_.ErrorDescription
                FullDuplex                                       = $_.FullDuplex
                HardwareInterface                                = $_.HardwareInterface
                HealthState                                      = $_.HealthState
                Hidden                                           = $_.Hidden
                HigherLayerInterfaceIndices                      = [string]$_.HigherLayerInterfaceIndices
                ifAlias                                          = $_.ifAlias
                ifDesc                                           = $_.ifDesc
                ifIndex                                          = $_.ifIndex
                ifName                                           = $_.ifName
                IdentifyingDescriptions                          = $_.IdentifyingDescriptions
                IMFilter                                         = $_.IMFilter
                InstallDate                                      = $_.InstallDate
                InstanceID                                       = $_.InstanceID
                InterfaceAdminStatus                             = $_.InterfaceAdminStatus
                InterfaceDescription                             = $_.InterfaceDescription
                InterfaceGuid                                    = $_.InterfaceGuid
                InterfaceIndex                                   = $_.InterfaceIndex
                InterfaceName                                    = $_.InterfaceName
                InterfaceOperationalStatus                       = $_.InterfaceOperationalStatus
                InterfaceType                                    = $_.InterfaceType
                iSCSIInterface                                   = $_.iSCSIInterface
                LastErrorCode                                    = $_.LastErrorCode
                LinkTechnology                                   = $_.LinkTechnology
                LowerLayerInterfaceIndices                       = [string]$_.LowerLayerInterfaceIndices
                MajorDriverVersion                               = $_.MajorDriverVersion
                MaxQuiesceTime                                   = $_.MaxQuiesceTime
                MaxSpeed                                         = $_.MaxSpeed
                MediaConnectState                                = $_.MediaConnectState
                MediaDuplexState                                 = $_.MediaDuplexState
                MinorDriverVersion                               = $_.MinorDriverVersion
                MtuSize                                          = $_.MtuSize
                Name                                             = $_.Name
                NdisMedium                                       = $_.NdisMedium
                NdisPhysicalMedium                               = $_.NdisPhysicalMedium
                NetLuid                                          = $_.NetLuid
                NetLuidIndex                                     = $_.NetLuidIndex
                NetworkAddresses                                 = [string]$_.NetworkAddresses
                NotUserRemovable                                 = $_.NotUserRemovable
                OperatingStatus                                  = $_.OperatingStatus
                OperationalStatus                                = $_.OperationalStatus
                OperationalStatusDownDefaultPortNotAuthenticated = $_.OperationalStatusDownDefaultPortNotAuthenticated
                OperationalStatusDownInterfacePaused             = $_.OperationalStatusDownInterfacePaused
                OperationalStatusDownLowPowerState               = $_.OperationalStatusDownLowPowerState
                OperationalStatusDownMediaDisconnected           = $_.OperationalStatusDownMediaDisconnected
                OtherEnabledState                                = $_.OtherEnabledState
                OtherIdentifyingInfo                             = $_.OtherIdentifyingInfo
                OtherLinkTechnology                              = $_.OtherLinkTechnology
                OtherNetworkPortType                             = $_.OtherNetworkPortType
                OtherPortType                                    = $_.OtherPortType
                PermanentAddress                                 = $_.PermanentAddress
                PnPDeviceID                                      = $_.PnPDeviceID
                PortNumber                                       = $_.PortNumber
                PortType                                         = $_.PortType
                PowerManagementCapabilities                      = $_.PowerManagementCapabilities
                PowerManagementSupported                         = $_.PowerManagementSupported
                PowerOnHours                                     = $_.PowerOnHours
                PrimaryStatus                                    = $_.PrimaryStatus
                PromiscuousMode                                  = $_.PromiscuousMode
                PSComputerName                                   = $_.PSComputerName
                ReceiveLinkSpeed                                 = $_.ReceiveLinkSpeed
                RequestedSpeed                                   = $_.RequestedSpeed
                RequestedState                                   = $_.RequestedState
                Speed                                            = $_.Speed
                State                                            = $_.State
                StatusDescriptions                               = $_.StatusDescriptions
                StatusInfo                                       = $_.StatusInfo
                SupportedMaximumTransmissionUnit                 = $_.SupportedMaximumTransmissionUnit
                SystemCreationClassName                          = $_.SystemCreationClassName
                SystemName                                       = $_.SystemName
                TimeOfLastStateChange                            = $_.TimeOfLastStateChange
                TotalPowerOnHours                                = $_.TotalPowerOnHours
                TransitioningToState                             = $_.TransitioningToState
                TransmitLinkSpeed                                = $_.TransmitLinkSpeed
                UsageRestriction                                 = $_.UsageRestriction
                Virtual                                          = $_.Virtual
                VlanID                                           = $_.VlanID
                WdmInterface                                     = $_.WdmInterface
                AdminStatus                                      = $_.AdminStatus
                DriverFileName                                   = $_.DriverFileName
                DriverInformation                                = $_.DriverInformation
                ifOperStatus                                     = $_.ifOperStatus
                LinkSpeed                                        = $_.LinkSpeed
                MacAddress                                       = $_.MacAddress
                MediaConnectionState                             = $_.MediaConnectionState
                MediaType                                        = $_.MediaType
                NdisVersion                                      = $_.NdisVersion
                PhysicalMediaType                                = $_.PhysicalMediaType
                Status                                           = $_.Status
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\NetworkAdapters.csv"
        }

        Get-NetIPConfiguration | ForEach-Object {
            [pscustomobject]@{
                InterfaceAlias            = $_.InterfaceAlias
                AllIPAddresses            = $_.AllIPAddresses.IPAddress -join ","
                CompartmentId             = $_.CompartmentId
                ComputerName              = $_.ComputerName
                Detailed                  = $_.Detailed
                DNSServer                 = $_.DNSServer.ServerAddresses -join ","
                InterfaceDescription      = $_.InterfaceDescription
                InterfaceIndex            = $_.InterfaceIndex
                IPv4Address               = [string]$_.IPv4Address
                IPv4DefaultGateway        = $_.IPv4DefaultGateway.NextHop
                IPv6Address               = [string]$_.IPv6Address -join ","
                IPv6DefaultGateway        = $_.IPv6DefaultGateway.NextHop
                IPv6LinkLocalAddress      = [string]$_.IPv6LinkLocalAddress -join ","
                IPv6TemporaryAddress      = [string]$_.IPv6TemporaryAddress
                NetAdapter                = $_.NetAdapter.Name
                NetIPv4Interface          = $_.NetIPv4Interface.InterfaceAlias
                NetIPv6Interface          = $_.NetIPv6Interface.InterfaceAlias
                NetProfileNetworkCategory = $_.NetProfile.NetworkCategory
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\NetIPConfiguration.csv"
        }

        Get-DnsClient | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias                     = $_.InterfaceAlias
                Suffix                             = $_.Suffix
                SuffixSearchList                   = [string]$_.SuffixSearchList -join ","
                AvailableRequestedStates           = $_.AvailableRequestedStates
                Caption                            = $_.Caption
                CommunicationStatus                = $_.CommunicationStatus
                ConnectionSpecificSuffix           = $_.ConnectionSpecificSuffix
                ConnectionSpecificSuffixSearchList = [string]$_.ConnectionSpecificSuffixSearchList -join ","
                CreationClassName                  = $_.CreationClassName
                Description                        = $_.Description
                DetailedStatus                     = $_.DetailedStatus
                DHCPOptionsToUse                   = $_.DHCPOptionsToUse
                ElementName                        = $_.ElementName
                EnabledDefault                     = $_.EnabledDefault
                EnabledState                       = $_.EnabledState
                HealthState                        = $_.HealthState
                Hostname                           = $_.Hostname
                InstallDate                        = $_.InstallDate
                InstanceID                         = $_.InstanceID
                InterfaceIndex                     = $_.InterfaceIndex
                Name                               = $_.Name
                NameFormat                         = $_.NameFormat
                OperatingStatus                    = $_.OperatingStatus
                OperationalStatus                  = $_.OperationalStatus
                OtherEnabledState                  = $_.OtherEnabledState
                OtherTypeDescription               = $_.OtherTypeDescription
                PrimaryStatus                      = $_.PrimaryStatus
                ProtocolIFType                     = $_.ProtocolIFType
                ProtocolType                       = $_.ProtocolType
                PSComputerName                     = $_.PSComputerName
                RegisterThisConnectionsAddress     = $_.RegisterThisConnectionsAddress
                RequestedState                     = $_.RequestedState
                Status                             = $_.Status
                StatusDescriptions                 = $_.StatusDescriptions
                SystemCreationClassName            = $_.SystemCreationClassName
                SystemName                         = $_.SystemName
                TimeOfLastStateChange              = $_.TimeOfLastStateChange
                TransitioningToState               = $_.TransitioningToState
                UseSuffixWhenRegistering           = $_.UseSuffixWhenRegistering
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\DnsClient.csv"
        }

        Get-DnsClientGlobalSetting | ForEach-Object {
            [PSCustomObject]@{
                Caption               = $_.Caption
                Description           = $_.Description
                ElementName           = $_.ElementName
                InstanceID            = $_.InstanceID
                AddressOrigin         = $_.AddressOrigin
                ProtocolIFType        = $_.ProtocolIFType
                AppendParentSuffixes  = $_.AppendParentSuffixes
                AppendPrimarySuffixes = $_.AppendPrimarySuffixes
                DNSSuffixesToAppend   = $_.DNSSuffixesToAppend -join "'"
                DevolutionLevel       = $_.DevolutionLevel
                SuffixSearchList      = $_.SuffixSearchList -join ","
                UseDevolution         = $_.UseDevolution
                UseSuffixSearchList   = $_.UseSuffixSearchList
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\DnsClientGlobalSetting.csv"
        }

        Get-DnsClientServerAddress | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias             = $_.InterfaceAlias
                AccessContext              = $_.AccessContext
                AccessInfo                 = $_.AccessInfo
                AddressFamily              = $_.AddressFamily
                AvailableRequestedStates   = $_.AvailableRequestedStates
                Caption                    = $_.Caption
                CommunicationStatus        = $_.CommunicationStatus
                CreationClassName          = $_.CreationClassName
                Description                = $_.Description
                DetailedStatus             = $_.DetailedStatus
                ElementName                = $_.ElementName
                EnabledDefault             = $_.EnabledDefault
                EnabledState               = $_.EnabledState
                HealthState                = $_.HealthState
                InfoFormat                 = $_.InfoFormat
                InstallDate                = $_.InstallDate
                InstanceID                 = $_.InstanceID
                InterfaceIndex             = $_.InterfaceIndex
                Name                       = $_.Name
                OperatingStatus            = $_.OperatingStatus
                OperationalStatus          = $_.OperationalStatus
                OtherAccessContext         = $_.OtherAccessContext
                OtherEnabledState          = $_.OtherEnabledState
                OtherInfoFormatDescription = $_.OtherInfoFormatDescription
                PrimaryStatus              = $_.PrimaryStatus
                PSComputerName             = $_.PSComputerName
                RequestedState             = $_.RequestedState
                ServerAddresses            = $_.ServerAddresses -join ","
                Status                     = $_.Status
                StatusDescriptions         = $_.StatusDescriptions
                SystemCreationClassName    = $_.SystemCreationClassName
                SystemName                 = $_.SystemName
                TimeOfLastStateChange      = $_.TimeOfLastStateChange
                TransitioningToState       = $_.TransitioningToState
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\DnsClientServerAddress.csv"
        }

        # Gather Firewall Information
        Write-Verbose -Message 'Gather Firewall Information'
        Get-NetFirewallProfile | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\FirewallProfiles.csv"
        Get-NetFirewallRule | ForEach-Object {
            [PSCustomObject]@{
                Name                  = $_.Name
                DisplayName           = $_.DisplayName
                Description           = $_.Description
                DisplayGroup          = $_.DisplayGroup
                Group                 = $_.Group
                Enabled               = $_.Enabled
                Profile               = $_.Profile
                Platform              = $_.Platform
                Direction             = $_.Direction
                Action                = $_.Action
                EdgeTraversalPolicy   = $_.EdgeTraversalPolicy
                LooseSourceMapping    = $_.LooseSourceMapping
                LocalOnlyMapping      = $_.LocalOnlyMapping
                Owner                 = $_.Owner
                PrimaryStatus         = $_.PrimaryStatus
                Status                = $_.Status
                EnforcementStatus     = $_.EnforcementStatus
                PolicyStoreSource     = $_.PolicyStoreSource
                PolicyStoreSourceType = $_.PolicyStoreSourceType
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\FirewallRules.csv"
        }

        # Test DNS - Internal Record and External Record
        Write-Verbose -Message 'Testing DNS - Internal and External Records'
        Resolve-DnsName -Name $internalDNSName -Type 'A' -Server $internalDNSServer | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ResolveDNS.csv"
        Resolve-DnsName -Name $externalDNSName -Type 'A' -Server $externalDNSServer | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ResolveDNS.csv"

        # Generate WLAN Report - Requires Administrator Permissions
        Write-Verbose -Message 'Generate WLAN Report - - Requires Administrator Permissions'
        If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Start-Process -RedirectStandardOutput $gsiTempOutput -Wait -NoNewWindow -FilePath $netshLocation -ArgumentList 'wlan show wlanreport duration="7"'
            Copy-Item -Path 'C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html' -Destination $exportFolder
        }

        # Gather Active Directory Site Information
        Write-Verbose -Message 'Gather Active Directory Site Information'
        [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite() | ForEach-Object {
            [PSCustomObject]@{
                Name                       = $_.Name
                Domains                    = $_.Domains.Name
                Servers                    = $_.Servers -join ","
                AdjacentSites              = $_.AdjacentSites -join ","
                SiteLinks                  = $_.SiteLinks -join ","
                InterSiteTopologyGenerator = $_.InterSiteTopologyGenerator
                BridgeheadServers          = $_.BridgeheadServers -join ","
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ActiveDirectorySite.csv"
        }

        # Gather BitLocker Information - Requires Administrator Permissions
        Write-Verbose -Message 'Gather BitLocker Information - Requires Administrator Permissions'
        If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Get-BitLockerVolume | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\BitLocker.csv"
        }
        
        # Gather TPM Information
        Write-Verbose -Message 'Gather TPM Information'
        Get-Tpm | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Tpm.csv"

        # Gather Certificate Information
        Write-Verbose -Message 'Gather Certificate Information'
        Get-ChildItem -Path 'Cert:\LocalMachine\My' | ForEach-Object {
            [PSCustomObject]@{
                Thumbprint           = $_.Thumbprint
                Subject              = $_.Subject
                EnhancedKeyUsageList = $_.EnhancedKeyUsageList
                DNSNameList          = $_.DnsNameList
                PolicyId             = $_.PolicyId
                NotBefore            = $_.NotBefore
                NotAfter             = $_.NotAfter
                HasPrivateKey        = $_.HasPrivateKey
                SerialNumber         = $_.SerialNumber
                Issuer               = $_.Issuer
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\CertificateInformation-Computer.csv"
        }

        Get-ChildItem -Path 'Cert:\CurrentUser\My' | ForEach-Object {
            [PSCustomObject]@{
                Thumbprint           = $_.Thumbprint
                Subject              = $_.Subject
                EnhancedKeyUsageList = $_.EnhancedKeyUsageList
                DNSNameList          = $_.DnsNameList
                PolicyId             = $_.PolicyId
                NotBefore            = $_.NotBefore
                NotAfter             = $_.NotAfter
                HasPrivateKey        = $_.HasPrivateKey
                SerialNumber         = $_.SerialNumber
                Issuer               = $_.Issuer
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\CertificateInformation-User.csv"
        }

        # Gather Environment Variables
        Write-Verbose -Message 'Gather Environment Variables'
        Get-ChildItem ENV: | ForEach-Object {
            [PSCustomObject]@{
                Name  = $_.Name
                Key   = $_.Key
                Value = $_.Value
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\EnvironmentVariables.csv"
        }

        # Gather Printer Information
        Write-Verbose -Message 'Gather Printer Information'
        Get-Printer | foreach-object {
            [PSCustomObject]@{
                Name                         = $_.Name
                DriverName                   = $_.DriverName
                Location                     = $_.Location
                Type                         = $_.Type
                PrinterStatus                = $_.PrinterStatus
                Published                    = $_.Published
                Shared                       = $_.Shared
                ShareName                    = $_.ShareName
                BranchOfficeOfflineLogSizeMB = $_.BranchOfficeOfflineLogSizeMB
                Caption                      = $_.Caption
                Comment                      = $_.Comment
                CommunicationStatus          = $_.CommunicationStatus
                ComputerName                 = $_.ComputerName
                Datatype                     = $_.Datatype
                DefaultJobPriority           = $_.DefaultJobPriority
                Description                  = $_.Description
                DetailedStatus               = $_.DetailedStatus
                DisableBranchOfficeLogging   = $_.DisableBranchOfficeLogging
                ElementName                  = $_.ElementName
                HealthState                  = $_.HealthState
                InstallDate                  = $_.InstallDate
                InstanceID                   = $_.InstanceID
                JobCount                     = $_.JobCount
                KeepPrintedJobs              = $_.KeepPrintedJobs
                OperatingStatus              = $_.OperatingStatus
                OperationalStatus            = $_.OperationalStatus
                PermissionSDDL               = $_.PermissionSDDL
                PortName                     = $_.PortName
                PrimaryStatus                = $_.PrimaryStatus
                PrintProcessor               = $_.PrintProcessor
                Priority                     = $_.Priority
                PSComputerName               = $_.PSComputerName
                SeparatorPageFile            = $_.SeparatorPageFile
                StartTime                    = $_.StartTime
                Status                       = $_.Status
                StatusDescriptions           = $_.StatusDescriptions
                UntilTime                    = $_.UntilTime
                WorkflowPolicy               = $_.WorkflowPolicy
                DeviceType                   = $_.DeviceType
                RenderingMode                = $_.RenderingMode
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Printers.csv"
        }

        # Gather Time Information - Compare PDC Time
        Write-Verbose -Message 'Gather Time Information - Compare PDC Time'
        Start-Process -RedirectStandardOutput "$exportFolder\w32tm.txt" -NoNewWindow -Wait -FilePath "$env:SystemRoot\system32\w32tm.exe" -ArgumentList "/stripchart /computer:$pdcEmulator /period:1 /samples:5"

        # Gather Scheduled Task Information
        Write-Verbose -Message 'Gather Scheduled Task Information'
        Get-ScheduledTask | ForEach-Object {
            [PSCustomObject]@{
                TaskName                           = $_.TaskName
                Author                             = $_.Author
                Date                               = $_.Date
                Description                        = $_.Description
                State                              = $_.State
                Command                            = $_.Actions.execute
                Arguments                          = $_.Actions.Arguments
                LastRun                            = $(($_ | Get-ScheduledTaskInfo).LastRunTime)
                LastResult                         = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
                NextRun                            = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
                Version                            = $_.Version
                TaskPath                           = $_.TaskPath
                Documentation                      = $_.Documentation
                Principal                          = $_.Principal.UserID
                PSComputerName                     = $_.PSComputerName
                SecurityDescriptor                 = $_.SecurityDescriptor
                SettingsAllowDemandStart           = $_.Settings.AllowDemandStart
                SettingsAllowHardTerminate         = $_.Settings.AllowHardTerminate
                SettingsCompatibility              = $_.Settings.Compatibility
                SettingsDeleteExpiredTaskAfter     = $_.Settings.DeleteExpiredTaskAfter
                SettingsDisallowStartIfOnBatteries = $_.Settings.DisallowStartIfOnBatteries
                SettingsExecutionTimeLimit         = $_.Settings.ExecutionTimeLimit
                SettingsHidden                     = $_.Settings.Hidden
                SettingsMultipleInstances          = $_.Settings.MultipleInstances
                SettingsPriority                   = $_.Settings.Priority
                SettingsRestartCount               = $_.Settings.RestartCount
                SettingsRestartInterval            = $_.Settings.RestartInterval
                SettingsRunOnlyIfIdle              = $_.Settings.RunOnlyIfIdle
                SettingsRunOnlyIfNetworkAvailable  = $_.Settings.RunOnlyIfNetworkAvailable
                SettingsStartWhenAvailable         = $_.Settings.StartWhenAvailable
                SettingsStopIfGoingOnBatteries     = $_.Settings.StopIfGoingOnBatteries
                SettingsWakeToRun                  = $_.Settings.WakeToRun
                Source                             = $_.Source
                URI                                = $_.URI
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ScheduledTasks.csv"
        }
        
        # Gather Installed Software Information
        Write-Verbose -Message 'Gather Installed Software Information'
        Get-ItemProperty -Path $regKeys | ForEach-Object {
            [PSCustomObject]@{
                PSChildName       = $_.PSChildName
                DisplayName       = $_.DisplayName
                AssignmentType    = $_.AssignmentType
                Caption           = $_.Caption
                Description       = $_.Description
                DisplayIcon       = $_.DisplayIcon
                DisplayVersion    = $_.DisplayVersion
                HelpLink          = $_.HelpLink
                HelpTelephone     = $_.HelpTelephone
                IdentifyingNumber = $_.IdentifyingNumber
                InstallDate       = $_.InstallDate
                InstallDate2      = $_.InstallDate2
                InstallLocation   = $_.InstallLocation
                InstallSource     = $_.InstallSource
                InstallState      = $_.InstallState
                Language          = $_.Language
                LocalPackage      = $_.LocalPackage
                ModifyPath        = $_.ModifyPath
                Name              = $_.Name
                PackageCache      = $_.PackageCache
                PackageCode       = $_.PackageCode
                PackageName       = $_.PackageName
                ProductID         = $_.ProductID
                PSComputerName    = $_.PSComputerName
                PSPath            = $_.PSPath
                PSParentPath      = $_.PSParentPath
                PSDrive           = $_.PSDrive
                PSProvider        = $_.PSProvider
                Publisher         = $_.Publisher
                RegCompany        = $_.RegCompany
                RegOwner          = $_.RegOwner
                RepairPath        = $_.RepairPath
                SKUNumber         = $_.SKUNumber
                Transforms        = $_.Transforms
                UninstallString   = $_.UninstallString
                URLInfoAbout      = $_.URLInfoAbout
                URLUpdateInfo     = $_.URLUpdateInfo
                Vendor            = $_.Vendor
                Version           = $_.Version
                WordCount         = $_.WordCount
                PSStatus          = $_.PSStatus
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\InstalledSoftware.csv"
        }

        # Gather Local User and Administrator Group Information
        Write-Verbose -Message 'Gather Local User and Administrator Group Information'
        Get-LocalUser | ForEach-Object {
            [PSCustomObject]@{
                Name                   = $_.Name
                FullName               = $_.FullName
                Description            = $_.Description
                Enabled                = $_.Enabled
                AccountExpires         = $_.AccountExpires
                PasswordChangeableDate = $_.PasswordChangeableDate
                PasswordExpires        = $_.PasswordExpires
                UserMayChangePassword  = $_.UserMayChangePassword
                PasswordRequired       = $_.PasswordRequired
                PasswordLastSet        = $_.PasswordLastSet
                LastLogon              = $_.LastLogon
                SID                    = $_.SID
                PrincipalSource        = $_.PrincipalSource
                ObjectClass            = $_.ObjectClass
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\LocalUsers.csv"
        }

        Get-LocalGroupMember -Name 'Administrators' | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
                SID             = $_.SID
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\LocalAdministrators.csv"
        }

        # Gather Device Information
        Write-Verbose -Message 'Gather Device Information'
        Get-CimInstance -ClassName 'Win32_PhysicalMemory' | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\PhysicalMemory.csv"
        Get-CimInstance -ClassName 'Win32_Processor' -Property * | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\Processor.csv"
        
        Get-CimInstance -ClassName 'Win32_BIOS' | ForEach-Object {
            [PSCustomObject]@{
                Name                           = $_.Name
                Status                         = $_.Status
                Caption                        = $_.Caption
                Description                    = $_.Description
                InstallDate                    = $_.InstallDate
                ReleaseDate                    = $_.ReleaseDate
                BuildNumber                    = $_.BuildNumber
                CodeSet                        = $_.CodeSet
                IdentificationCode             = $_.IdentificationCode
                LanguageEdition                = $_.LanguageEdition
                Manufacturer                   = $_.Manufacturer
                OtherTargetOS                  = $_.OtherTargetOS
                SerialNumber                   = $_.SerialNumber
                SoftwareElementID              = $_.SoftwareElementID
                SoftwareElementState           = $_.SoftwareElementState
                TargetOperatingSystem          = $_.TargetOperatingSystem
                Version                        = $_.Version
                PrimaryBIOS                    = $_.PrimaryBIOS
                BiosCharacteristics            = $_.BiosCharacteristics -join ","
                BIOSVersion                    = $_.BIOSVersion -join ","
                CurrentLanguage                = $_.CurrentLanguage
                EmbeddedControllerMajorVersion = $_.EmbeddedControllerMajorVersion
                EmbeddedControllerMinorVersion = $_.EmbeddedControllerMinorVersion
                InstallableLanguages           = $_.InstallableLanguages
                ListOfLanguages                = $_.ListOfLanguages -join ","
                SMBIOSBIOSVersion              = $_.SMBIOSBIOSVersion
                SMBIOSMajorVersion             = $_.SMBIOSMajorVersion
                SMBIOSMinorVersion             = $_.SMBIOSMinorVersion
                SMBIOSPresent                  = $_.SMBIOSPresent
                SystemBiosMajorVersion         = $_.SystemBiosMajorVersion
                SystemBiosMinorVersion         = $_.SystemBiosMinorVersion
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\BIOS.csv"
        }

        # Gather Reliability Records Information
        Write-Verbose -Message 'Gather Reliability Records Information'
        Get-CimInstance -ClassName 'Win32_ReliabilityRecords' | ForEach-Object {
            [PSCustomObject]@{
                EventIdentifier  = $_.EventIdentifier
                InsertionStrings = $_.InsertionStrings -join ","
                Logfile          = $_.Logfile
                Message          = $_.Message
                ProductName      = $_.ProductName
                RecordNumber     = $_.RecordNumber
                SourceName       = $_.SourceName
                TimeGenerated    = $_.TimeGenerated
                User             = $_.User
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\ReliabilityRecords.csv"
        }

        # Gather PNP Device Information
        Write-Verbose -Message 'Gather PNP Device Information'
        Get-CimInstance -ClassName 'Win32_PNPEntity' | ForEach-Object {
            [PSCustomObject]@{
                Name                        = $_.Name
                Status                      = $_.Status
                StatusInfo                  = $_.StatusInfo
                Manufacturer                = $_.Manufacturer
                PNPClass                    = $_.PNPClass
                Present                     = $_.Present
                Service                     = $_.Service
                Caption                     = $_.Caption
                ClassGuid                   = $_.ClassGuid
                CompatibleID                = $_.CompatibleID
                ConfigManagerErrorCode      = $_.ConfigManagerErrorCode
                ConfigManagerUserConfig     = $_.ConfigManagerUserConfig
                Description                 = $_.Description
                DeviceID                    = $_.DeviceID
                ErrorCleared                = $_.ErrorCleared
                ErrorDescription            = $_.ErrorDescription
                HardwareID                  = [string]$_.HardwareID
                InstallDate                 = $_.InstallDate
                LastErrorCode               = $_.LastErrorCode
                PNPDeviceID                 = $_.PNPDeviceID
                Availability                = $_.Availability
                PowerManagementCapabilities = $_.PowerManagementCapabilities
                PowerManagementSupported    = $_.PowerManagementSupported
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\PNPDevices.csv"
        }

        # Gather PNP Device Driver Information
        Write-Verbose -Message 'Gather PNP Device Driver Information'
        Get-CimInstance -ClassName 'Win32_PnPSignedDriver' | ForEach-Object {
            [PSCustomObject]@{
                FriendlyName            = $_.FriendlyName
                Description             = $_.Description
                Name                    = $_.Name
                Manufacturer            = $_.Manufacturer
                InstallDate             = $_.InstallDate
                IsSigned                = $_.IsSigned
                Signer                  = $_.Signer
                DriverDate              = $_.DriverDate
                DriverVersion           = $_.DriverVersion
                DriverProviderName      = $_.DriverProviderName
                Status                  = $_.Status
                CreationClassName       = $_.CreationClassName
                Started                 = $_.Started
                StartMode               = $_.StartMode
                SystemCreationClassName = $_.SystemCreationClassName
                SystemName              = $_.SystemName
                ClassGuid               = $_.ClassGuid
                CompatID                = $_.CompatID
                DeviceClass             = $_.DeviceClass
                DeviceID                = $_.DeviceID
                DeviceName              = $_.DeviceName
                DevLoader               = $_.DevLoader
                DriverName              = $_.DriverName
                HardWareID              = $_.HardWareID
                InfName                 = $_.InfName
                Location                = $_.Location
                PDO                     = $_.PDO
            } | Export-Csv -NoTypeInformation -Append -Path "$exportFolder\PNPDrivers.csv"
        }

        # Gather list of power configurations including indication of currently active scheme
        Write-Verbose -Message 'Gather list of power configurations including indication of currently active scheme'
        Start-Process -RedirectStandardOutput "$exportFolder\PowerConfiguration.txt" -Wait -NoNewWindow -FilePath $powerCfgLocation -ArgumentList "/LIST"

        # Gather Battery Report - Generates a report of battery usage if battery exists
        Write-Verbose -Message 'Gather Battery Report - Generates a report of battery usage if battery exists'
        If (Get-CimInstance Win32_Battery) {
            Start-Process -RedirectStandardOutput $gsiTempOutput -Wait -NoNewWindow -FilePath $powerCfgLocation -ArgumentList "/BATTERYREPORT /DURATION $powerCfgDuration /OUTPUT $exportFolder\BatteryReport.html"
        }

        # Gather System Power Report - Generates a diagnostic system power transition report - Requires Administrator Permissions
        Write-Verbose -Message 'Gather System Power Report - Generates a diagnostic system power transition report'
        If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Start-Process -RedirectStandardOutput $gsiTempOutput -Wait -NoNewWindow -FilePath $powerCfgLocation -ArgumentList "/SYSTEMPOWERREPORT /DURATION $powerCfgDuration /OUTPUT $exportFolder\SystemPowerReport.html"
        }

        # Gather DirectX Diagnostic Report
        Write-Verbose -Message 'Gather DirectX Diagnostic Report'
        Start-Process -NoNewWindow -Wait -FilePath $directxDiagLocation -ArgumentList "/t $exportFolder\DirectXDiagnostics.txt"

        # Generate Support Archive
        Write-Verbose -Message 'Generate Support Archive'
        Compress-Archive -Path $exportFolder -DestinationPath "$archiveFolder\$env:COMPUTERNAME-$timeStamp"
    }

    End {

        # Clear Log Folder
        Write-Verbose -Message 'Clearing Log Folder'
        Remove-Item -Path "$exportFolder\*" -Force -Recurse
        Write-Verbose -Message 'Stop PowerShell Transcription Logging'
        Stop-Transcript | Out-Null
    }
}