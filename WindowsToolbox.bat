@echo off

:menu
echo Needed to do before debloat
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
cls
echo - Type 1 to disable Windows Update (optional)
echo - Type 2 to optimize network options (recommended)
echo - Type 3 to clear temp files (recommended)
echo - Type 4 to check and fix errors in Windows (recommended)
echo - Type 5 to install a program (optional)
echo - Type 6 for a menu that shows more optimizations (recommended)
echo - Type 7 to Remove bloat and loggers (very recommended)
echo - Type 8 for other optimizations/performance tweaks (very recommended)
echo - Type 9 to disable Windows Defender (not recommended)
echo - Type 10 to enable Windows Defender
echo - Type 11 to disable power savings (recommended only for desktops)
echo - Type 12 for UI improvements (recommended)
echo - Type 13 to implement STIGs (recommended for volintile environments (forensics, Government, banking etc))
echo - Type exit to exit
set /p message1=
if %message1% == 1 goto :UpdateRemoval
if %message1%==2 goto :network
if %message1%==3 goto :cleartemp
if %message1%==4 goto :fix
if %message1%==5 goto :install
if %message1%==6 goto :misc
if %message1%==7 goto :debloat
if %message1%==8 goto :others
if %message1%==9 goto :DefenderDisable
if %message1%==10 goto :DefenderEnable
if %message1%==11 goto :power
if %message1%==12 goto :QoL
if %message1%==13 goto :STIG
if %message1%==exit exit
else echo - Invalid input
goto :menu


:UpdateRemoval
echo Stop and disable services concerning Windows Update
sc config "Windows Update" start= disabled
NET STOP "Windows Update"
sc config "UsoSvc" start= disabled
NET STOP "UsoSvc"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaaSMedicAgent.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\System32\taskkill.exe" /f
echo Disable updates through registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableDualScan" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdatesPeriodInDays" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAUAsDefaultShutdownOption" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUServer" /t REG_SZ /d " " /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "SusClientId" /t REG_SZ /d "00000000-0000-0000-0000-000000000000" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d "1" /f
echo Disable re-enabling updates
taskkill /f /im upfc.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\upfc.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\System32\taskkill.exe" /f
pause
goto :menu 

:network
cls
echo Clearing network cache...
IPCONFIG /release
IPCONFIG /renew
IPCONFIG /flushdns
IPCONFIG /registerdns
echo Optimizing netsh settings
echo Enable Memory Pressure Protection
netsh int tcp set security mpp=enabled
echo Enable Direct Cache Access (DCA)
netsh int tcp set global dca=enabled
echo Disable TCP timestamps
netsh int tcp set global timestamps=disabled
echo Increase icw
netsh int tcp set supplemental template=custom icw=10
echo Set initial RTO
:: It is 3000 by default. However I do wanna make sure it's set to that (like if someone used another bad optimizer)
netsh int tcp set global initialRto=3000
echo Disable Media Sense
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v " DisableDHCPMediaSense" /t REG_DWORD /d 1 /f
echo Enable Packet Coalescing
powershell -ExecutionPolicy Unrestricted Set-NetOffloadGlobalSetting -PacketCoalescingFilter enabled
echo Disable unused/bloat network devices
powershell -ExecutionPolicy Unrestricted "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_msclient, ms_server, ms_lldp, ms_lltdio, ms_rspndr"
echo Set all networks to Private
powershell -NoProfile "$net=get-netconnectionprofile; Set-NetConnectionProfile -Name $net.Name -NetworkCategory Private"
echo done
pause
goto :menu


:cleartemp
cls
echo Clearing uneeded files...
del /s /f /q %windir%\temp\*.*
del /s /f /q %temp%\*.*
cd C:\Windows\SoftwareDistribution\Download
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
rd /s /q %WINDIR%\Logs
cd C:\ProgramData\Microsoft\Windows\WER\Temp
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
Cleanmgr /sagerun:65535 /autoclean
if exist C:/Windows.old (
	echo Old Windows installation found. deleting it now
	del C:/Windows.old
)
:: another thanks to Privacy.Sexy lol
cd C:\Windows\Logs\CBS
del /s *.log
del /s *.cab
cd C:\Windows\Logs\DISM
del /s *.log
del /s *.cab
del %PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
del %ProgramData%\Microsoft\Windows Defender\Scans\History
echo Files now cleared.
pause
goto :menu

:fix
cls
echo Fixing errors in Windows...
sfc /scannow
DISM /online /cleanup-image /RestoreHealth
sfc /scannow
cls
color F6
 set /p check=Do you want to check the disk for errors? Warning: it may ask you to reboot. checking disk may take a while. (y/n) 
if %check%==y CHKDSK /F
if %check%==n goto :menu

:install
cls
echo Supported programs:
echo Type 1 to install 7zip
echo Type 2 to install brave
echo Type 3 to install VScode
echo Type 4 to install Discord
echo Type 5 to install Github Desktop
echo Type 6 to install powertoys
echo Type 7 to install Windows Command Terminal
echo Type 8 to install git
echo Type 9 to install VLC
echo Type 10 to install Firefox
echo Type 11 to install Python 3.10
echo Type 12 to install EarTrumpet
echo Type 13 to upgrade all installs from winget
echo Type 14 to go back to the main menu
set /p program=
if %program%==1 winget install 7zip.7zip
if %program%==2 winget install brave
if %program%==3 winget install VScode
if %program%==4 winget install Discord.Discord
if %program%==5 winget install GitHub.GitHubDesktop
if %program%==6 winget install Microsoft.PowerToys
if %program%==7 winget install Microsoft.WindowsTerminal
if %program%==8 winget install git.git
if %program%==9 winget install VideoLAN.VLC
if %program%==10 winget install Mozilla.Firefox
if %program%==11 winget install Python
if %program%==12 winget install File-New-Project.EarTrumpet
if %program%==13 winget upgrade --all
if %program%==14 goto :menu
set /p back= Do you want to install another program? (y/n)
if %back%==y goto :install
if %back%==n goto :menu


:misc
cls
echo Type 1 to disable backround apps
echo Type in 2 to enable backround apps
echo Type in 3 to uninstall OneDrive
echo Type in 4 to install OneDrive 
echo Type in 5 to uninstall Edge
echo Type in 6 to disable Windows Search Indexing
echo Type in 7 to disable User Account Control
echo Type in 8 to enable User Account Control
echo Type in 9 to disable Update Health Tools
echo Type in 10 to disable Readyboost
echo Type in 11 to uninstall Windows Store
echo Type in 12 to uninstall Calculator
echo Type in 13 to disable Storage Sense
echo Type in 14 to enable Storage Sense
echo Type in 15 to go back to the main menu
set /p menu2msg=
if %menu2msg%==1 goto :backroundstop
if %menu2msg%==2 goto :backroundstart
if %menu2msg%==3 goto :onedriveuninstall
if %menu2msg%==4 goto :onedriveinstall
if %menu2msg%==5 goto :edgeuninstall
if %menu2msg%==6 goto :Indexing
if %menu2msg%==7 goto :DisableUAC
if %menu2msg%==8 goto :EnableUAC
if %menu2msg%==9 goto :HealthTools
if %menu2msg%==10 goto :ReadyboostDeletion
if %menu2msg%==11 goto :StoreRemoval
if %menu2msg%==12 goto :CalcRemoval
if %menu2msg%==13 goto :disablestorage
if %menu2msg%==13 goto :enablestorage
if %menu2msg%==15 goto :menu
pause
goto :menu

:backroundstop
echo Disabling backround apps...
reg add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
:: 2 is force deny go look at https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.AppPrivacy::LetAppsRunInBackground
reg add HKLM\Software\Policies\Microsoft\Windows\AppPrivacy /v LetAppsRunInBackground /t REG_DWORD /d 2 /f
goto :misc

:backroundstart
echo Enabling backround apps...
reg add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
:: 0 is user decision. 1 is force allow if you want to set it to that
reg add HKLM\Software\Policies\Microsoft\Windows\AppPrivacy /v LetAppsRunInBackground /t REG_DWORD /d 0 /f
goto :misc

:OneDriveuninstall
echo Uninstalling OneDrive
echo Killing OneDrive processes...
IF EXIST %SystemRoot%\System32\OneDriveSetup.exe (
    echo Uninstalling OneDrive
    taskkill /f /im OneDrive.exe
    %SystemRoot%\System32\OneDriveSetup.exe /uninstall
    rmdir /q /s "%ProgramData%\Microsoft OneDrive"
    rmdir /q /s "%LOCALAPPDATA%\Microsoft\OneDrive"
    echo done
)
else (
    echo OneDrive not installed.
    timeout 5
)
echo Prevent auto reinstallation (or updating) of OneDrive
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup" /f
goto :misc

:onedriveinstall
echo installing OneDrive...
%SystemRoot%\System32\OneDriveSetup.exe
echo done
goto :misc

:edgeuninstall
echo Killing Edge processes...
taskkill /F /IM MicrosoftEdgeUpdate.exe
taskkill /F /IM msedge.exe
taskkill /F /IM MicrosoftEdge*
taskkill /F /FI "MODULES eq edgehtml.dll"
:: Not removing WebView2. However I have a feeling keeping the task active could cause problems
taskkill /F /FI "MODULES eq msedgewebview2.exe"
echo deleting Edge processes
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\System32\taskkill.exe" /f
sc delete edgeupdate
sc delete edgeupdatem
sc delete MicrosoftEdgeElevationService
echo deleting Edge files...
del /f /q "C:\Program Files (x86)\Microsoft\EdgeUpdate"
del /f /q "C:\Users\%USERNAME%\AppData\Local\Microsoft\EdgeUpdate"
start 


echo Edge regkeys
reg add "HKLM\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "InstallDefault" /t REG_DWORD /d 0 /f
echo Delete Edge shortcuts
del "C:\Users\%USERNAME%\Desktop\edge.lnk" /f /q
del "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\edge.lnk" /f /q
del "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\edge.lnk" /f /q
echo Done!
pause
goto :misc

:Indexing 
NET STOP "WSearch"
sc config "WSearch" start=disabled
pause
goto :misc


:DisableUAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
pause
goto :misc

:EnableUAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
pause
goto :misc


:HealthTools
IF EXIST "C:\Program Files\Microsoft Update Health Tools" (
cls
echo Changing regkeys
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\UpdateHealthTools" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\rempl" /f
reg delete "HKLM\SOFTWARE\Microsoft\CloudManagedUpdate" /f
echo delete UPD files
rmdir /s /q "C:\Program Files\Microsoft Update Health Tools"
)
goto :misc

:ReadyboostDeletion
echo Changing regkeys
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "GroupPolicyDisallowCaches" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "AllowNewCachesByDefault" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t Reg_MULTI_SZ /d "fvevol\0iorate" /f
reg delete "HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers\{55B3A0BD-4D28-42fe-8CFB-FA3EDFF969B8}" /f
goto :misc

:StoreRemoval
echo Removing Windows Store
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage '*Microsoft.WindowsStore*' | Remove-AppxPackage"
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage '*Microsoft.StorePurchaseApp*' | Remove-AppxPackage"
goto :misc

:CalcRemoval
:: a lot of people like calculator so...
echo Remove the Calculator
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*Microsoft.WindowsCalculator*' | Remove-AppxPackage"
goto :misc

:disablestorage
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d 0 /f
goto :misc

:enablestorage
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d 1 /f
goto :misc

:debloat
cls
echo debloating Windows
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
setx POWERSHELL_TELEMETRY_OPTOUT 1
echo Changing registry keys
echo Disable Inventory
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
echo Disable ntvdm.exe (MS-DOS/16 bit programs)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "VDMDisallowed" /t REG_DWORD /d "1" /f
echo Disable Application Compatibility Engine (ACE)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f
echo Disable Program Compatibility Assistant (PCA)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
echo Disable Device Health monitoring
reg add "HKLM\Software\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f
echo Disable the Diagnostic Data Viewer
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableDiagnosticDataViewer" /t REG_DWORD /d 1 /f
echo Disable TIPC/Input telemetry
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
echo Disable CEIP
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\aitstatic.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\System32\taskkill.exe" /f
echo Disallow data collection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /v "DisableDiagnosticTracing" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
echo Disable advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
echo Restrict Windows' communication
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f
echo Disable Scheduled Diagnosis/Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
echo Disable experimentation/insights
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
echo Disable Bluetooth telemetry
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
echo Disable telemetry services by debug taskkill
:: sorry Nyne.............
echo DeviceCensus.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t REG_SZ /d "%WinDir%\System32\taskkill.exe" /f
echo AggregatorHost.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AggregatorHost.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
echo CompactTelRunner.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%WinDir%\System32\taskkill.exe" /f
echo Configure user activity telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t Reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t Reg_DWORD /d "0" /f
echo Disable Error Reporting
NET STOP WerSvc
sc config WerSvc start= disabled
NET STOP wercplsupport
sc config wercplsupport start= disabled
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoExternalURL" /t REG_DWORD /d "1" /f
echo Disable Windows Liscense telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "AllowWindowsEntitlementReactivation" /t REG_DWORD /d "1" /f
echo Disable keylogger service
NET STOP dmwappushservice
sc config dmwappushservice start= disabled
echo Allow Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
echo Disabling/deleting Services
 :: big thanks Nyne lol
 wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false
 wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false
 wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false
 echo Disabling the Intel Telemetry Service
 reg add "HKLM\SYSTEM\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d 4 /f
 echo SMB 1.x MiniRedirector
 reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v "Start" /t REG_DWORD /d 4 /f
 echo DiagTrack
 sc config "DiagTrack" start= disabled
 NET STOP DiagTrack
 echo Desktop Actvity Moderator (DAM)
 sc config "dam" start= disabled
 NET STOP dam
 echo AJRouter
 sc config "AJRouter" start= disabled
 NET STOP AJRouter
 echo PhoneSvc
 sc config "PhoneSvc" start= disabled
 NET STOP PhoneSvc
 echo TermService
 sc config "TermService" start= disabled
 NET STOP TermService
 echo RemoteRegistry
 sc config "RemoteRegistry" start= disabled
 NET STOP RemoteRegistry
 echo RetailDemo
 sc delete RetailDemo
 NET STOP RetailDemo
 echo RemoteAccess
 sc config "RemoteAccess" start= disabled
 NET STOP RemoteAccess
 echo OneSyncSvc
 sc config "OneSyncSvc"
 NET STOP OneSyncSvc
 echo UevAgentService
 sc config "UevAgentService" start= disabled
 NET STOP UevAgentService
 echo WbioSrvc
 sc config "WbioSrvc" start= disabled
 NET STOP WbioSrvc
 echo XblAuthManager
 sc config "XblAuthManager" start= disabled
 NET STOP XblAuthManager
 echo XblGameSave
 sc config "XblGameSave" start= disabled
 NET STOP XblGameSave
 echo XboxNetApiSvc
 sc config "XboxNetApiSvc" start= disabled
 NET STOP XboxNetApiSvc
 echo XboxGipSvc
 sc config "XboxGipSvc" start= disabled
 NET STOP XboxGipSvc
 echo FontCache
 sc config "FontCache" start= disabled
 NET STOP FontCache
 echo iphlpsvc
 sc config "iphlpsvc" start= disabled
 NET STOP iphlpsvc
 echo BcastDVRUserService_48486de
 sc config "BcastDVRUserService_48486de" start= disabled
 NET STOP BcastDVRUserService_48486de
 echo WpnService
 sc config "WpnService" start= disabled
 NET STOP WpnService
 echo AssignedAccessManagerSvc
 sc delete AssignedAccessManagerSvc
 NET STOP AssignedAccessManagerSvc
 echo diagnosticshub.standardcollector.service
 sc config "diagnosticshub.standardcollector.service" start= disabled
 NET STOP diagnosticshub.standardcollector.service
 sc delete AssignedAccessManagerSvc
 echo SharedAccess
 sc config "SharedAccess" start= disabled
 NET STOP SharedAccess
 echo StorSvc
 sc config "StorSvc" start= disabled
 NET STOP StorSvc
 echo BITS
 sc config "bits" start= disabled
 NET STOP bits
 echo LicenseManager
 sc config "LicenseManager" start= disabled
 NET STOP LicenseManager
 echo RemoteAccess
 sc config RemoteAccess start= disabled
 NET STOP RemoteAccess
 echo applockerfltr
 sc config "applockerfltr" start= disabled
 NET STOP "applockerfltr"
 echo AppIDSvc
 sc config AppIDSvc start= disabled
 NET STOP AppIDSvc
cls
echo This breaks Bluetooth. are you sure you wanna disable the following
set /p BTH=BluetoothUserService, BTAGService, BthAvctpSvc and bthserv (y/n)
if %BTH%==y goto :Bluetooth
if %BTH%==n goto :afterBluetooth
:Bluetooth
echo Microsoft-Windows-CoreSystem-Bluetooth-Telemetry
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-CoreSystem-Bluetooth-Telemetry | ForEach-Object { $_.Name }"
echo BluetoothUserService
sc config BluetoothUserService start= disabled
NET STOP BluetoothUserService
echo BTAGService
sc config BTAGService start= disabled
NET STOP BTAGService
echo BthAvctpSvc
sc config BthAvctpSvc start= disabled
NET STOP BthAvctpSvc
echo bthserv
sc config bthserv start= disabled
NET STOP bthserv
echo NetBT
sc config NetBT start=disabled
NET STOP NETBt
goto :afterBluetooth
:afterBluetooth
echo CryptSvc
sc config CryptSvc start= disabled
NET STOP CryptSvc
echo diagsvc
sc config diagsvc start= disabled
NET STOP diagsvc
echo DispBrokerDesktopSvc
sc config DispBrokerDesktopSvc start= disabled
NET STOP DispBrokerDesktopSvc
echo DoSvc
sc config DoSvc start= disabled
NET STOP DoSvc
echo DPS
sc config DPS start= disabled
NET STOP DPS
echo FDResPub
sc config FDResPub start= disabled
NET STOP FDResPub
echo fdPHost
sc config fdPHost start= disabled
NET STOP fdPHost
echo InstallService
sc config InstallService start= disabled
NET STOP InstallService
echo IpxlatCfgSvc
sc config IpxlatCfgSvc start= disabled
NET STOP IpxlatCfgSvc
echo KtmRm
sc config KtmRm start= disabled
NET STOP KtmRm
echo LanmanServer
sc config LanmanServer start= disabled
NET STOP LanmanServer
echo LanmanWorkstation
sc config LanmanWorkstation start= disabled
NET STOP LanmanWorkstation
echo lmhosts
sc config lmhosts start= disabled
NET STOP lmhosts
echo luafv
sc config luafv start= disabled
NET STOP luafv
echo MSDTC
sc config MSDTC start= disabled
NET STOP MSDTC
echo PcaSvc
sc config PcaSvc start= disabled
NET STOP PcaSvc
echo RasMan
sc config RasMan start= disabled
NET STOP RasMan
echo SmsRouter
sc config SmsRouter start= disabled
NET STOP SmsRouter
echo Spooler
sc config Spooler start= disabled
NET STOP Spooler
echo SSDPSRV
sc config SSDPSRV start= disabled
NET STOP SSDPSRV
echo sppsvc
sc config sppsvc start= disabled
NET STOP sppsvc
echo SstpSvc
sc config SstpSvc start= disabled
NET STOP SstpSvc
echo Themes
sc config Themes start= disabled
NET STOP Themes
echo TrkWks
sc config TrkWks start= disabled
NET STOP TrkWks
echo W32Time
sc config W32Time start= disabled
NET STOP W32Time
echo WarpJITSvc
sc config WarpJITSvc start= disabled
NET STOP WarpJITSvc
echo NetBios Interface System
sc config NetBIOS start= disabled
NET STOP NetBIOS
echo WdiServiceHost
sc config WdiServiceHost start= disabled
NET STOP WdiServiceHost
echo WdiSystemHost
sc config WdiSystemHost start= disabled
NET STOP WdiSystemHost
echo Wecsvc
sc config Wecsvc start= disabled
NET STOP Wecsvc
echo wercplsupport
sc config wercplsupport start= disabled
NET STOP wercplsupport
echo WEPHOSTSVC
sc config WEPHOSTSVC start= disabled
NET STOP WEPHOSTSVC
echo WMPNetworkSvc
sc config WMPNetworkSvc start= disabled
NET STOP WMPNetworkSvc
echo WPDBusEnum
sc config WPDBusEnum start= disabled
NET STOP WPDBusEnum
echo WpnService
sc config WpnService start= disabled
NET STOP WpnService
echo wuauserv
sc config wuauserv start= disabled
NET STOP wuauserv
echo SEMgrSvc
sc config SEMgrSvc start= disabled
NET STOP SEMgrSvc
echo OneSyncSvc
sc config OneSyncSvc start= disabled
NET STOP OneSyncSvc
echo wbengine
sc config wbengine start= disabled
NET STOP wbengine
echo MapsBroker
sc config MapsBroker start= disabled
NET STOP MapsBroker
echo lfsvc
sc config lfsvc start= disabled
NET STOP lfsvc
echo MessagingService
sc config MessagingService start= disabled
NET STOP MessagingService
echo GraphicsPerfSvc
sc config GraphicsPerfSvc start= disabled
NET STOP GraphicsPerfSvc
echo autotimesvc
sc config autotimesvc start= disabled
NET STOP autotimesvc
echo Smartcard
sc config Smartcard start= disabled
NET STOP Smartcard
echo AarSvc
sc config AarSvc start= disabled
NET STOP AarSvc
echo tzautoupdate
sc config tzautoupdate start= disabled
NET STOP tzautoupdate
echo PeerDistSvc
sc config PeerDistSvc start= disabled
NET STOP PeerDistSvc
echo embeddedmode
sc config embeddedmode start= disabled
NET STOP embeddedmode
echo fhsvc
sc config fhsvc start= disabled
NET STOP fhsvc
echo wlpasvc
sc config wlpasvc start= disabled
NET STOP wlpasvc
echo Windows Insider Service
sc config wisvc start= disabled
NET STOP wisvc
set /p RAID=Disabling VSTXRAID will possibly break RAID. are you sure you want to do this? (y/n)
if %RAID%==y sc config VSTXRAID start= disabled
echo AppVClient
sc config AppVClient start= disabled
NET STOP AppVClient

echo Removing unused apps/bloat
echo 1527c705-839a-4832-9118-54d4Bd6a0c89
:: I actually forgot what this is lmao
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  1527c705-839a-4832-9118-54d4Bd6a0c89*' | Remove-AppxPackage"

echo Cortana
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.549981C3F5F10*' | Remove-AppxPackage"

echo Mixed Reality Portal
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.MixedReality.Portal*' | Remove-AppxPackage"

echo Communication Apps
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*microsoft.windowscommunicationsapps*' | Remove-AppxPackage"

echo Secure Assessment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Windows.SecureAssessmentBrowser*' | Remove-AppxPackage"

echo Advertising.Xaml
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Advertising.Xaml*' | Remove-AppxPackage"

:: Xbox?
echo Gaming App
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage -AllUsers '*Microsoft.GamingApp*' | Remove-AppxPackage"

echo Bing Weather
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.BingWeather*' | Remove-AppxPackage"

echo Bing News
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*Microsoft.BingNews*' | Remove-AppxPackage"

echo Get Help
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.GetHelp*' | Remove-AppxPackage"

echo Get Started
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Getstarted*' | Remove-AppxPackage"

echo 3D Viewer
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Microsoft3DViewer*' | Remove-AppxPackage"

echo Clipchamp
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage -AllUsers '*Clipchamp.Clipchamp*' | Remove-AppxPackage"

echo Microsoft Todos
PowerShell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.Todos' | Remove-AppxPackage"

echo Microsoft Office
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.MicrosoftOfficeHub*' | Remove-AppxPackage"

echo Solitaire
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.MicrosoftSolitaireCollection*' | Remove-AppxPackage"

echo Sticky Notes
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.MicrosoftStickyNotes*' | Remove-AppxPackage"
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"

echo Power Automate
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*Microsoft.PowerAutomateDesktop*' | Remove-AppxPackage"

echo Microsoft Paint
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.MSPaint*' | Remove-AppxPackage"

echo OneNote
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Office.OneNote*' | Remove-AppxPackage"

echo Office Sway
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.Sway' | Remove-AppxPackage"

echo People
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.People*' | Remove-AppxPackage"
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Windows.PeopleExperienceHost*' | Remove-AppxPackage"

echo Snipping Tool
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.ScreenSketch*' | Remove-AppxPackage"

echo Skype
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.SkypeApp*' | Remove-AppxPackage"

echo Wallet
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Wallet*' | Remove-AppxPackage"

echo Photos
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.Windows.Photos*' | Remove-AppxPackage"

echo Alarms
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.WindowsAlarms*' | Remove-AppxPackage"

echo Camera
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.WindowsCamera*' | Remove-AppxPackage"

echo Feedback Hub
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.WindowsFeedbackHub*' | Remove-AppxPackage"

echo Maps
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.WindowsMaps*' | Remove-AppxPackage"

echo Sound Recorder
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage  '*Microsoft.WindowsSoundRecorder*' | Remove-AppxPackage"

echo Windows Terminal
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*Microsoft.WindowsTerminal*' | Remove-AppxPackage"

echo Quick Assist
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*MicrosoftCorporationII.QuickAssist*' | Remove-AppxPackage"

echo Phone Link
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"

echo Your Phone (already deprovisioned)
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage"

echo Microsoft Phone
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.Windows.Phone' | Remove-AppxPackage"

echo Groove Music
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage '*Microsoft.ZuneMusic*' | Remove-AppxPackage"

echo Videos
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"

echo Game Bar
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage"

echo Game Bar Plugins
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage -AllUsers *Microsoft.XboxGameOverlay* | Remove-AppxPackage" 

echo Xbox Game UI
powershell -ExecutionPolicy Unrestricted "Get-Appxpackage -AllUsers *Microsoft.XboxGameUI* | Remove-AppxPackage"

echo Xbox App
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.XboxApp' | Remove-AppxPackage"

echo Xbox Identity Provider
PowerShell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.XboxIdentityProvider' | Remove-AppxPackage"

echo Xbox Text to Speech
PowerShell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxPackage"

echo Xbox TCUI 
PowerShell -ExecutionPolicy Unrestricted "Get-AppxPackage 'Microsoft.Xbox.TCUI' | Remove-AppxPackage"

echo Microsoft-Windows-OOBENetworkCaptivePortal.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-OOBENetworkCaptivePortal.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-OOBENetworkCaptivePortal.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-OOBENetworkCaptivePortal.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DesktopFileExplorer-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DesktopFileExplorer-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DesktopFileExplorer-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DesktopFileExplorer-Deployment | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Internal-ShellCommon-FilePickerExperienceMEM
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Internal-ShellCommon-FilePickerExperienceMEM | ForEach-Object { $_.Name }"

echo Microsoft-Windows-OOBENetworkConnectionFlow.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-OOBENetworkConnectionFlow.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-OOBENetworkConnectionFlow.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-OOBENetworkConnectionFlow.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-PeopleExperienceHost.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-PeopleExperienceHost.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-PeopleExperienceHost.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-PeopleExperienceHost.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Disk-Failure-Diagnostic-Module
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Disk-Failure-Diagnostic-Module | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Disk-Failure-Diagnostic-User-Resolver
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Disk-Failure-Diagnostic-User-Resolver | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskDiagnosis-Events
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskDiagnosis-Events | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskDiagnostic-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskDiagnostic-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskManagement-Snapin
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskManagement-Snapin | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskManagement-VDSInterface
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskManagement-VDSInterface | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskManagement
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskManagement | ForEach-Object { $_.Name }"

echo Microsoft-Windows-dskquota
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-dskquota | ForEach-Object { $_.Name }"

echo Microsoft-Windows-dskquoui
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-dskquoui | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Diskraid
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Diskraid | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DiskQuota-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DiskQuota-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-EnhancedStorage-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-EnhancedStorage-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-EnhancedStorage-API
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-EnhancedStorage-API | ForEach-Object { $_.Name }"

echo Microsoft-Windows-EnhancedStorage-ClassDriver
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-EnhancedStorage-ClassDriver | ForEach-Object { $_.Name }"

echo Microsoft-Windows-EnhancedStorage-EhStorTcgDrv
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-EnhancedStorage-EhStorTcgDrv | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-Angle
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-Angle | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-AXHost
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-AXHost | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-EdgeContent
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-EdgeContent | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-EdgeManager
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-EdgeManager | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-MicrosoftEdgeBCHost
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-MicrosoftEdgeBCHost | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-MicrosoftEdgeCP
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-MicrosoftEdgeCP | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-MicrosoftEdgeDevTools
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-MicrosoftEdgeDevTools | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-MicrosoftEdgeEnlightenment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-MicrosoftEdgeEnlightenment | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Edge-MicrosoftEdgeSH
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Edge-MicrosoftEdgeSH | ForEach-Object { $_.Name }"

echo Microsoft-Windows-MicrosoftEdgeDevToolsClient.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-MicrosoftEdgeDevToolsClient.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-MicrosoftEdgeDevToolsClient.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-MicrosoftEdgeDevToolsClient.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ParentalControls.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ParentalControls.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ParentalControls.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ParentalControls.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockApp.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockApp.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockApp.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockApp.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockAppBroker-WinRT
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockAppBroker-WinRT | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockAppHost-AboveLockAppHost
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockAppHost-AboveLockAppHost | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockAppHost-LockHostingFramework
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockAppHost-LockHostingFramework | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LockAppHost
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LockAppHost | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AppRep-ChxApp.appxmain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AppRep-ChxApp.appxmain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AppRep-ChxApp.appxsetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AppRep-ChxApp.appxsetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AppRep
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AppRep | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DeviceManagement-PolicyDefinition-SmartScreen
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DeviceManagement-PolicyDefinition-SmartScreen | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SmartScreen-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SmartScreen-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SmartScreen
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SmartScreen | ForEach-Object { $_.Name }"

echo Windows-Defender-AM-Default-Definitions-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-AM-Default-Definitions-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Windows-Defender-AM-Default-Definitions-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-AM-Default-Definitions-Deployment | ForEach-Object { $_.Name }"

echo Windows-Defender-AppLayer-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-AppLayer-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Windows-Defender-AppLayer-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-AppLayer-Group-Deployment | ForEach-Object { $_.Name }"

echo Windows-Defender-ApplicationGuard-Inbox-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-ApplicationGuard-Inbox-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Windows-Defender-ApplicationGuard-Inbox-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-ApplicationGuard-Inbox-Deployment | ForEach-Object { $_.Name }"

echo Windows-Defender-ApplicationGuard-Inbox-WOW64-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-ApplicationGuard-Inbox-WOW64-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Windows-Defender-ApplicationGuard-Inbox-WOW64-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-ApplicationGuard-Inbox-WOW64-Deployment | ForEach-Object { $_.Name }"

echo Windows-Defender-Branding
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Branding | ForEach-Object { $_.Name }"

echo Windows-Defender-Core-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Core-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"

echo Windows-Defender-Core-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Core-Group-Deployment | ForEach-Object { $_.Name }"

echo Windows-Defender-Events
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Events | ForEach-Object { $_.Name }"

echo Windows Backup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -Name *WindowsBackup* | Remove-AppxPackage"

echo Microsoft-Windows-SecHealthUI.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SecHealthUI.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SecHealthUI.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SecHealthUI.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AllJoyn-Api
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AllJoyn-Api | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AllJoyn-Capabilities
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AllJoyn-Capabilities | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AllJoyn-Router
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AllJoyn-Router | ForEach-Object { $_.Name }"

echo Microsoft-Windows-AllJoyn-Runtime
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-AllJoyn-Runtime | ForEach-Object { $_.Name }"

echo Networking-MPSSVC-Rules-AllJoyn
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Networking-MPSSVC-Rules-AllJoyn | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager-Capabilities
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager-Capabilities | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager-Utilities
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager-Utilities | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain.FeatureManagement
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain.FeatureManagement | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain.PreInstalledApps
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain.PreInstalledApps | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain.Ratings
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain.Ratings | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain.SoftLanding
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain.SoftLanding | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain.SubscribedContent
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain.SubscribedContent | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxMain
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxMain | ForEach-Object { $_.Name }"

echo Microsoft-Windows-ContentDeliveryManager.AppxSetup
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-ContentDeliveryManager.AppxSetup | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SystemSettings-SettingsHandlers-ContentDeliveryManager
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SystemSettings-SettingsHandlers-ContentDeliveryManager | ForEach-Object { $_.Name }"

echo Microsoft-OneCore-DictationManager-Component
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-OneCore-DictationManager-Component | ForEach-Object { $_.Name }"

echo Microsoft-OneCore-SpeechService-Component
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-OneCore-SpeechService-Component | ForEach-Object { $_.Name }"

echo Microsoft-OneCore-SystemSettings-SettingsHandlers-SpeechPrivacy
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-OneCore-SystemSettings-SettingsHandlers-SpeechPrivacy | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-IEKillBits
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-IEKillBits | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-Pal-Desktop
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-Pal-Desktop | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-Shell
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-Shell | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-UserExperience-Common
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-UserExperience-Common | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-UserExperience
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-UserExperience | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Speech-Windows
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Speech-Windows | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SpeechCommon-OneCore
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SpeechCommon-OneCore | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SpeechCommonNoIA64
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SpeechCommonNoIA64 | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SpeechDiagnostic
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SpeechDiagnostic | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SpeechEngine-OneCore
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SpeechEngine-OneCore | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SpeechEngine
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SpeechEngine | ForEach-Object { $_.Name }"

echo Microsoft-Windows-VoiceActivation-HW
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-VoiceActivation-HW | ForEach-Object { $_.Name }"

echo Windows-Media-Speech-WinRT
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Media-Speech-WinRT | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Geolocation-Framework
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Geolocation-Framework | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Geolocation-Service-Modern
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Geolocation-Service-Modern | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Geolocation-Service
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Geolocation-Service | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Geolocation-WinComponents
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Geolocation-WinComponents | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Geolocation-WinRT
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Geolocation-WinRT | ForEach-Object { $_.Name }"

echo Microsoft-Windows-LocationProvider-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-LocationProvider-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SystemSettings-SettingsHandlers-Geolocation
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SystemSettings-SettingsHandlers-Geolocation | ForEach-Object { $_.Name }"

echo Microsoft-WindowsPhone-LocationServiceProvider-Events
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-WindowsPhone-LocationServiceProvider-Events | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Application-Experience-AIT-Static
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Application-Experience-AIT-Static | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Application-Experience-Inventory-Data-Sources
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Application-Experience-Inventory-Data-Sources | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Application-Experience-Mitigations-C8
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Application-Experience-Mitigations-C8 | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Application-Experience-Program-Data
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Application-Experience-Program-Data | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-Appraiser-InboxDataFiles
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-Appraiser-InboxDataFiles | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-Appraiser-Logger
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-Appraiser-Logger | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-Appraiser
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-Appraiser | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-CompatTelRunner-DailyTask
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-CompatTelRunner-DailyTask | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-CompatTelRunner
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-CompatTelRunner | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Compat-GeneralTel
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Compat-GeneralTel | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DataCollection-Adm
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DataCollection-Adm | ForEach-Object { $_.Name }"

echo Microsoft-Windows-DeviceCensus-Schedule-ClientServer
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-DeviceCensus-Schedule-ClientServer | ForEach-Object { $_.Name }"

echo Microsoft-Windows-SetupPlatform-Telemetry-AutoLogger
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-SetupPlatform-Telemetry-AutoLogger | ForEach-Object { $_.Name }"

echo Microsoft-Windows-TelemetryClient
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-TelemetryClient | ForEach-Object { $_.Name }"

echo Microsoft-Windows-TelemetryPermission
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-TelemetryPermission | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client-Aggregators
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client-Aggregators | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client-AutoLogger-Default
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client-AutoLogger-Default | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client-Decoder-Host
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client-Decoder-Host | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client-Settings-WindowsClient
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client-Settings-WindowsClient | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client-WoWOnly
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client-WoWOnly | ForEach-Object { $_.Name }"

echo Microsoft-Windows-Unified-Telemetry-Client
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Microsoft-Windows-Unified-Telemetry-Client | ForEach-Object { $_.Name }"

echo Windows-System-Diagnostics-Telemetry-PlatformTelemetryClient
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-System-Diagnostics-Telemetry-PlatformTelemetryClient | ForEach-Object { $_.Name }"

echo Disable telemetry packages
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-OneCoreUAP-Feedback-StringFeedbackEngine*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReporting-Adm-Deployment-LanguagePack*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingConsole*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingConsole.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingCore*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingDumpTypeControl*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingDumpTypeControl-Deployment*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingPowershell*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReportingUI*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Feedback-CourtesyEngine*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Feedback-DeploymentMgrClient*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Feedback-DeploymentMgrClient-Desktop-TaskSch*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-FeedbackNotifications-Adm*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-FeedbackNotifications-Adm.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Feedback-Service*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Feedback-Service.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-OneCore-SystemSettings-InputCloudStore*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-AIT-Static*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-AppInv*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Core-Inventory-Service*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Core-Inventory-Service.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Infrastructure*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Inventory-Data-Sources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Program-Data*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Application-Experience-Program-Data.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-CodeIntegrity-Aggregator*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-Appraiser*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-Appraiser.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-Appraiser-InboxDataFiles*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-Appraiser-Logger*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-CompatTelRunner*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-CompatTelRunner.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-CompatTelRunner-DailyTask*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compat-GeneralTel*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Compatibility-Aggregator*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-DataCollection-Adm*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-DataCollection-Adm.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-DeviceCensus-Schedule-ClientServer*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-KeyboardDiagnostic*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-KeyboardDiagnostic.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-MediaFoundation-MediaFoundationAggregator*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Power-EnergyEstimationEngine-Client-Overrides*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Security-PwdlessPlat-Aggregator*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SetupPlatform-Telemetry-AutoLogger*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SystemSettings-SettingsHandlers-SIUF*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SystemSettings-SettingsHandlers-SIUF.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-TelemetryClient*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client.resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client-Aggregators*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client-Decoder-Host*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client-Settings-WindowsClient*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Unified-Telemetry-Client-WoWOnly*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Update-Aggregators*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Windows-System-Diagnostics-Telemetry-PlatformTelemetryClient*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-AcProxy*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-AcProxy.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-CEIPEnable-Adm*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-CEIPEnable-Adm.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-Client-SQM-Consolidator*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SQMApi*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SQM-Consolidator-Base*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-SQM-Consolidator-Base.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-UsbCeip*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-UsbCeip.Resources*' | Remove-WindowsPackage -Online"
powershell -ExecutionPolicy Unrestricted "Get-WindowsPackage -Online -PackageName '* Microsoft-Windows-ErrorReporting-Adm-Deployment*' | Remove-WindowsPackage -Online"

echo Disallow Windows Update to reinstall bloat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.3DBuilder_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingWeather_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingSports_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingNews_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingFinance_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.OneNote_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.Sway_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsStore_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.StorePurchaseApp_8wekyb3d8bbwe" /f
:: Xbox Console Companion is technically already deprovisioned as it was replaced by the main Xbox app and Game Bar
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxApp_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Xbox.TCUI_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxGameOverlay_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsPhone_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.Phone_8wekyb3d8bbwe" /f
:: In case Edge is removed (like through [misc < uninstall Edge] or another program)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" /f
:: File Picker is not removed here, however in case someone removes it through other means
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy" /f
:: same for Cloud Experience Host
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy" /f


echo Disallow tracking services to start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diaglog" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NetCore" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RadioMgr" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v Start /t REG_DWORD /d 0 /f

echo Disable WMI Autologgers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{A0C1853B-5C40-4B15-8766-3CF1C58F985A}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{A9C11050-9E93-4FA4-8FE0-7C4750A345B2}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4CB314DF-C11F-47D7-9C04-65FB0051561B}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{34B02AA4-BE24-55E0-4EB1-D29469A2D79C}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{BC1BDB57-71A2-581A-147B-E0B49474A2D4}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B447B4DF-7780-11E0-ADA3-18A90531A85A}" /v "Enabled" /t REG_DWORD /d 0 /f

echo Disable ShellBags
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam\BagMRU" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam\Bags" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags" /f
reg add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /v "BagMRU Size" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /v "BagMRU Size" /t REG_DWORD /d 1 /f

echo Disable Content Delivery
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f

echo Blocking telemetry IP addresses...
curl -l -s https://winhelp2002.mvps.org/hosts.txt -o %SystemRoot%\System32\drivers\etc\hosts.temp
if exist %SystemRoot%\System32\drivers\etc\hosts.temp (
    cd %SystemRoot%\System32\drivers\etc
    del /f /q hosts
    ren hosts.temp hosts
)

echo Delete tasks
:: killing DeviceCensus is needed so all of this works
:: the tasks in AppID, Application Experience, Device Information, Feedback and Windows Error Reporting are telemetry that always run
taskkill /f /im DeviceCensus.exe
schtasks /Delete /TN "\Microsoft\Windows\AppID\EDP Policy Manager" /F
schtasks /Delete /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /F
schtasks /Delete /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" /F
schtasks /Delete /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /F
schtasks /Delete /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /F
schtasks /Delete /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /F
schtasks /Delete /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /F
schtasks /Delete /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /F
schtasks /delete /TN "\Microsoft\Windows\Application Experience\AitAgent" /F
:: DbTask and MareBackup are only seen on Windows 11. Exactly why I say if you want privacy, stick with 10
schtasks /delete /TN "\Microsoft\Windows\Application Experience\SdbinstMergeDbTask" /F
schtasks /delete /TN "\Microsoft\Windows\Application Experience\MareBackup" /F
schtasks /Delete /TN "\Microsoft\Windows\Autochk\Proxy" /F
schtasks /Delete /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /F
schtasks /Delete /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /F
schtasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F
schtasks /Delete /TN "\Microsoft\Windows\Device Information\Device" /F
schtasks /delete /TN "\Microsoft\Windows\Device Information\Device User" /F
schtasks /Delete /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" /F
schtasks /Delete /TN "\Microsoft\Windows\Diagnosis\Scheduled" /F
schtasks /Delete /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /F
schtasks /Delete /TN "\Microsoft\Windows\InstallService\ScanForUpdates" /F
schtasks /Delete /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /F
schtasks /Delete /TN "\Microsoft\Windows\InstallService\SmartRetry" /F
schtasks /Delete /TN "\Microsoft\Windows\Maintenance\WinSAT" /F
schtasks /Delete /TN "\Microsoft\Windows\Management\Provisioning\Cellular" /F
schtasks /Delete /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /F
schtasks /Delete /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /F
schtasks /Delete /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /F
schtasks /Delete /TN "\Microsoft\Windows\MUI\LPRemove" /F
schtasks /Delete /TN "\Microsoft\Windows\PI\Sqm-Tasks" /F
schtasks /Delete /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /F
schtasks /Delete /TN "\Microsoft\Windows\Printing\EduPrintProv" /F
schtasks /Delete /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /F
schtasks /Delete /TN "\Microsoft\Windows\Ras\MobilityManager" /F
schtasks /Delete /TN "\Microsoft\Windows\Registry\RegIdleBackup" /F
schtasks /Delete /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /F
schtasks /Delete /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /F
schtasks /Delete /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /F
schtasks /Delete /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /F
schtasks /Delete /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /F
schtasks /Delete /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" /F
schtasks /Delete /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /F
schtasks /Delete /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /F
schtasks /Delete /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" /F
schtasks /Delete /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" /F
schtasks /Delete /TN "\Microsoft\Windows\WaaSMedic\PerformRemediation" /F
schtasks /Delete /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /F
schtasks /Delete /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /F
schtasks /Delete /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /F
schtasks /Delete /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /F
schtasks /Delete /TN "\Microsoft\Windows\Wininet\CacheTask" /F
schtasks /delete /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /F
schtasks /delete /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /F

echo Disable WINEVT loggers
:: Intel loggers
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-GFX-Info/Application" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-GFX-Info/System" /v "Enabled" /t "REG_DWORD" /d 0 /f
:: Windows loggers
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-All-User-Install-Agent/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppID/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/CaptureMonitor" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Biometrics/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Help/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/CompatAfterUpgrade" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UniversalTelemetryClient/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Compat-Appraiser/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Operational" /v "Enabled" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Admin" /v "Enabled" /t "REG_DWORD" /d 0 /f


echo Disable Windows WPBT execution (pretty much a built in rootkit for computer manufactuers)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableWpbtExecution" /t REG_DWORD /d "1" /f
goto :menu

:others
echo Disable/delete optional features
:: Steps Recorder is being planned to be removed in the latest Windows 11 dev builds along with the Tips app
DISM /Online /Remove-Capability /CapabilityName:"App.StepsRecorder~~~~0.0.1.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"App.Support.QuickAssist~~~~0.0.1.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"Browser.InternetExplorer~~~~0.0.11.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"Hello.Face.18967~~~~0.0.1.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"MathRecognizer~~~~0.0.1.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"OpenSSH.Client~~~~0.0.1.0" /NoRestart
DISM /Online /Remove-Capability /CapabilityName:"Print.Fax.Scan~~~~0.0.1.0" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-amd64" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"WCF-TCP-PortSharing45" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Printing-Foundation-InternetPrinting-Client" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"LPDPrintService" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Printing-Foundation-LPRPortMonitor" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"MSRDC-Infrastructure" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Client" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Server" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"Windows-Defender-Default-Definitions" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"WorkFolders-Client" /NoRestart




echo Disable reserved storage
DISM /Online /Set-ReservedStorageState /State:Disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
echo fsutil (thanks DuckOS)
set /p PagingQuestion= Do you want to disable paging file encryption (n/y)? (increases performance but decreases security slightly)
if %PagingQuestion%==y goto :Paging
if %PagingQuestion%==n goto :AfterPaging
:Paging
echo Disable encryption on paging file
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
fsutil behavior set encryptpagingfile 0
fsutil behavior set quotanotify 86400
fsutil behavior set symlinkevaluation L2L:1
:AfterPaging
echo Don't generate a bug check
:: might put this before a question like "do you want to disable IT and developer specialty features"
fsutil behavior set Bugcheckoncorrupt 0
echo disable compression in NTFS
fsutil behavior set disablecompression 1
echo Enable TRIM for SSDs
fsutil behavior set disabledeletenotify 0
echo Disable last access (as the command implies)
fsutil behavior set disablelastaccess 1
echo disable 8.3 (short filename) types
fsutil behavior set disable8dot3 1

echo Enable GPU Preemption
reg add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d 1 /f

:: Gonna keep this commented until i figure this out. Fault Tolerant Heap (FTH) stops a repeatedly crashing process.
:: However that program takes a performance hit when FTH is on it
:: echo Disable Fault Tolerant Heap
:: reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d 0 /f

echo BSOD settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f
echo Disable settings sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
echo Disable Clipboard Sync
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d 0 /f
echo Disable changing of Desktop icons and mouse pointers by programs
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "ThemeChangesMousePointers" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "ThemeChangesDesktopIcons" /t REG_DWORD /d "0" /f
echo Disable File History
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f
echo Faster startup and shutdown
echo Disable boot circle (boot loading icon)
bcdedit /set quietboot yes
echo Legacy boot menu
bcdedit /set bootmenupolicy Legacy
echo Shutdown
echo Shut down apps and services quicker
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
echo Disable GameDVR and enable fullscreen optimizations
echo Disable GameDVR/Game Bar
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
echo Enable fullscreen optimizations
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
echo Audio enhancements
echo Disable any audio schemes
powershell "New-ItemProperty -Path 'HKCU:\AppEvents\Schemes' -Name '(Default)' -Value '.None' -Force | Out-Null"
powershell "Get-ChildItem -Path 'HKCU:\AppEvents\Schemes\Apps' | Get-ChildItem | Get-ChildItem | Where-Object {$_.PSChildName -eq '.Current'} | Set-ItemProperty -Name '(Default)' -Value ''"
echo Split audio services
copy /y "%windir%\System32\svchost.exe" "%windir%\System32\audiosvchost.exe"
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv" /v "ImagePath" /t Reg_EXPAND_SZ /d "%SystemRoot%\System32\audiosvchost.exe -k LocalServiceNetworkRestricted -p" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" /v "ImagePath" /t Reg_EXPAND_SZ /d "%SystemRoot%\System32\audiosvchost.exe -k LocalSystemNetworkRestricted -p" /f
echo Dont show unconnected audio devices
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowHiddenDevices" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowDisconnectedDevices" /t REG_DWORD /d "0" /f
echo Disable Push to Install
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d 1 /f
echo Do not allow Sound Recorder to run if not uninstalled
:: for one reason or another, 1 is disable execution. no idea why
reg add "HKLM\Software\Policies\Microsoft\SoundRecorder" /v "Soundrec" /t REG_DWORD /d 1 /f

echo Security
echo Permissions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
echo Delete DefaultUser0
net user defaultuser0 /delete
echo Disable voice activation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
echo .NET cryptogrophy
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f
echo Enable DEP (Data Execution Prevention)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
echo Harden SAM share security
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictRemoteSAM" /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f
echo Disable the lock screen camera
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
echo Disable remote connections
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fLogonDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
echo Harden remote connection security if its turned back on
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f
echo Encrypt channel traffic
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
echo Disable Autorun/Autoplay
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
echo Disable WDigest
NET STOP WinRM
sc config WinRM= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
echo harden LSASS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
echo Disable LLMNR. Replaced by DNS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t Reg_DWORD /d "0" /f
echo Make sure CFG is enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t Reg_DWORD /d "1" /f
echo Make sure ASLR is enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t Reg_DWORD /d "1" /f
echo Mitigate Office ActiveX attacks
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d 00000003 /f
echo Disable the Message Cloud Sync service
:: According to Nyne, this harms privacy. Otherwise this would go in debloat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
echo Disable WiFi Sense
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f
echo Harden SMB
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
echo Block unsigned fonts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" /v "MitigationOptions_FontBocking" /t REG_QWORD /d "1000000000000" /f
echo mitigate msdt
reg delete HKEY_CLASSES_ROOT\ms-msdt /f
set /p Hibernation= Do you want to disable hibernation? (y/n)
if %Hibernation%==y powercfg /h off >nul
if %Hibernation%==n goto :QuestionLol

:QuestionLol
set /p Location= Would you like to disable location/Find my Device? (y/n)
if %Location%==y goto :Location
if %Location%==n goto :AfterLocation
:Location
echo Disable location
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
echo Disable Find my Device
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f
echo Disable location sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
goto :AfterLocation
:AfterLocation
echo Online speech stuff
reg add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings" /v "OnlineSpeechPrivacy" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
goto :menu

:DefenderDisable
echo Removing Windows Defender may increase performance. However may leave you more vunerable to attacks.
echo This will remove Firewall, real-time protection, tamper protection and file scanning
echo If you dont know what those are, i'd recommend not removing Defender.
echo Would you like to remove Windows Defender? (y/n)
set /p DefenderQuestion=
if %DefenderQuestion%==y goto :DefenderRemove
if %DefenderQuestion%==n goto :menu

:DefenderRemove
:: Gonna be honest. This was taken mostly from Privacy.Sexy. so shoutout to them lol
echo Disable Windows Firewall
:: message for me. DO NOT disable MpsSvc *before* any netsh settings
netsh advfirewall set allprofiles state off
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
echo Remove the Firewall settings in Windows Defender app
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
echo Disable scanning
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealTimeScanDirection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxSize" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxDepth" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisablePackedExeScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d "8" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "QuickScanInterval" /t REG_DWORD /d "24" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f

echo Disable real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
echo Disable Defender updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateHttpLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateDownloadLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d 4294967295 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d 4294967295 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateInterval" /t REG_DWORD /d 24 /f
echo Disable Defender tracking and Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /v "Enabled" /t Reg_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /v "Enabled" /t Reg_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingLevel" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppHVSI" /v "AuditApplicationGuard" /t REG_DWORD /d 0 /f
echo Remove Defender packages
echo Windows-Defender-Group-Policy-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Group-Policy-Deployment-LanguagePack | ForEach-Object { $_.Name }"
echo Windows-Defender-Group-Policy-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Group-Policy-Deployment | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-Group-Deployment | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-MDM-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-MDM-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-MDM-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-MDM-Group-Deployment | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-Powershell-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-Powershell-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-Powershell-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-Powershell-Group-Deployment | ForEach-Object { $_.Name }"
echo Windows-Defender-Management-Powershell
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Management-Powershell | ForEach-Object { $_.Name }"
echo Windows-Defender-Nis-Group-Deployment-LanguagePack
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Nis-Group-Deployment-LanguagePack | ForEach-Object { $_.Name }"
echo Windows-Defender-Nis-Group-Deployment
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Nis-Group-Deployment | ForEach-Object { $_.Name }"
echo Windows-Defender-Service-MpClientEtw
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Service-MpClientEtw | ForEach-Object { $_.Name }"
echo Windows-Defender-Service
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-Service | ForEach-Object { $_.Name }"
echo Windows-Defender-UI
powershell -ExecutionPolicy Unrestricted "Get-AppxPackage -AllUsers -Name Windows-Defender-UI | ForEach-Object { $_.Name }"
echo Disable UI of Windows Defender
:: there is supposed to be a command to allow it to uninstall. but i cannot figure out how to get the SID of the user and use it for the regkey
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.SecHealthUI' | Remove-AppxPackage"
echo Hide Defender
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
echo Don't reinstall Windows Defender
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" /f
echo Disable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /f
echo Other Defender stuff
echo Disable file hash computation
:: Thanks Nyne :D
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d 0 /f
echo Disable WD services
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
NET STOP WdNisDrv
sc config WdNisDrv start= disabled
NET STOP WdFilter
sc config WdFilter start= disabled
NET STOP WdBoot
sc config WdBoot start= disabled
NET STOP WinDefend
sc config WinDefend start= disabled
NET STOP WdNisSvc
sc config WdNisSvc start= disabled
NET STOP Sense
sc config Sense start= disabled
NET STOP SecurityHealthService
sc config SecurityHealthService start= disabled
echo Security Center
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d 4 /f
echo Done!
goto :menu

:DefenderEnable
echo Enable Defender services
sc config WdNisDrv start= auto
sc config WdFilter start= auto
sc config WdBoot start= auto
sc config WinDefend start= auto
sc config WdNisSvc start= auto
sc config Sense start= auto
sc config SecurityHealthService start= auto
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d 2 /f
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Enable
echo Enable file hash computation
:: Again. Thanks Nyne :D
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d 1 /f
echo Enable Firewall
:: MpsSvc is needed for Netsh advfirewall
NET START MpsSvc
sc config MpsSvc= auto
Netsh Advfirewall set allprofiles state on
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d 0 /f
echo Enable scanning
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "0" /f
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection/IOAVMaxSize"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealTimeScanDirection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxSize" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxDepth" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisablePackedExeScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "0" /f
echo Enable real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "0" /f
echo Enable Defender updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateHttpLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateDownloadLocation" /t REG_DWORD /d "1" /f
echo Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f
echo Enable the reinstallation of Defender
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" /f
echo Done!
goto :menu

:power
echo Setting power plan to High Performance
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
echo Power settings
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0
powercfg -setacvalueindex scheme_current sub_none CONSOLELOCK 0
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0
powercfg -setacvalueindex scheme_current SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0
powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 1
powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 1
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 100
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 100
powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 0
powercfg -setactive scheme_current
goto :menu

:QoL
echo Remove annoying keyboard features
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f
echo Disable online features in search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
echo Other search settings
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
echo Show Command Prompt instead of PowerShell on Winkey+X menu
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /d "1" /f
echo Verbose status! (more detail on boot and shutdown screens)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
echo File Explorer stuff
echo Always show more detail on file transfers
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f
echo Disable Network Navigation
reg add "HKEY_CLASSES_ROOT\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d 2962489444 /f
echo Enable file extentions
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
echo Enable checkboxes in File Explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 1 /f
echo Enable showing hidden files in File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
echo Open to 'This PC'
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
echo Hide 'Quick Access' menu
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
echo Remove 3D Objects
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
echo Show full filepath
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d "1" /f
echo Make sure encrypted drives are shown as monocrome
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d "0" /f
echo Show drive letters in full filepath
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowDriveLettersFirst" /t REG_DWORD /d "4" /f
echo Desktop stuff
echo Dont reduce quality on wallpaper image
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
echo Reduce selection window visual effects
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
echo Create Desktop.ini cache
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "UseDesktopIniCache" /t REG_DWORD /d 1 /f
echo Visual stuff
:: Why did i put these in?
:: Only for very low end devices. Might make a section just for that
:: reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
:: reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
echo Clean up start menu and Taskbar
echo Hide search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
echo Hide 'Meet Now'
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f
echo Remove 'People'
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
echo Hide the 'task view' button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"/v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
echo Disable 'News and Intrests'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f
echo Configure the right click menu 
echo Disable 'Share'
reg delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\ModernSharing" /f
echo Remove 'Rich Text Format' text file in 'create'
reg delete "HKCR\.rtf\ShellNew" /f
echo Hide 'add to favorites'
reg delete "HKCR\*\shell\pintohomefile" /f
echo Hide Restore previous versions
Reg delete "HKCR\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
Reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
echo Disable new app alerts
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d 1 /f
echo Clipboard stuff!
echo Enable Clipboard History
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "	AllowClipboardHistory" /t REG_DWORD /d 1 /f
goto :menu

:STIG
echo Disable LAN Manager Hash (LMH) storage of passwords
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f
echo send NTLMv2 responses only and refuse NTLMv1 and LM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f
:: Uninstall IIS (Internet Information Services if on the system) filler
echo Enable Data Execution Prevention
bcdedit /set {current} nx OptOut
echo Enable Structured Exception Handling Overwrite Protection (SEHOP)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0 /f
echo Disable "Always install with elevated privileges"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f
echo Disallow basic authentication on WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d 0 /f
echo Enforce Credential Guard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d 0x00000001 /f
echo Disable AutoRun/AutoPlay
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f

echo Enable Anti-Spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v "EnhancedAntiSpoofing" /t REG_DWORD /d 1 /f
echo Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f
echo Disable any telemetry settings not compliant with DoD standerds
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
setx POWERSHELL_TELEMETRY_OPTOUT 1
echo Changing registry keys
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "VDMDisallowed" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableDiagnosticDataViewer" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\aitstatic.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /v "DisableDiagnosticTracing" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t REG_SZ /d "%WinDir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AggregatorHost.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%WinDir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t Reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t Reg_DWORD /d "0" /f
NET STOP WerSvc
sc config WerSvc start= disabled
NET STOP wercplsupport
sc config wercplsupport start= disabled
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoExternalURL" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "AllowWindowsEntitlementReactivation" /t REG_DWORD /d "1" /f
NET STOP dmwappushservice
sc config dmwappushservice start= disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
echo Disable Kerberos from using RC4 or DES
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f
echo Prevent PKU2U authentication from online identities
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u" /v "AllowOnlineID" /t REG_DWORD /d 0 /f
echo Disallow NTLM from falling back to a null session
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v "allownullsessionfallback" /t REG_DWORD /d 0 /f
echo Require LDAP signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v "LDAPClientIntegrity" /t REG_DWORD /d 1 /f
echo Enforce a large event log size
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v "MaxSize" /t REG_DWORD /d 32768 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v "MaxSize" /t REG_DWORD /d 1024000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d 32768 /f
echo When powered on, always require a password
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d 1 /f
echo Enforce DMA Protection as a mitigation against drive-by DMA attacks
reg add "HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection" /v "DeviceEnumerationPolicy" /d 0 /f
echo Enforce File Explorer shell protected mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d 0 /f
echo Require a strong session key for a domain controller
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "RequireStrongKey" /t REG_DWORD /d 1 /f
echo Disable PowerShell V2
DISM /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
echo and SMB 1.0
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f
echo Enable Windows Defender Firewall
NET START MpsSvc
sc config MpsSvc= auto
Netsh Advfirewall set allprofiles state on
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
echo Encrypt outgoing secure channels when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d 1 /f
echo Make sure RPC is generally enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 1 /f
echo Harden RPC security
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCdm" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fEncryptRPCTraffic" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fPromptForPassword" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d 1 /f
echo DIsable attachments from being downloaded from RSS feeds
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v "DisableEnclosureDownload" /t REG_DWORD /d 1 /f
echo Disable basic authentication for RSS over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v "AllowBasicAuthInClear" /t REG_DWORD /d 0 /f
echo Do not index encrypted files
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f
echo Only allow admins to change installation options
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "EnableUserControl" /t REG_DWORD /d 0 /f
echo Notify users if a web-based program attempts to install software
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "SafeForScripting" /t REG_DWORD /d 0 /f
echo Disable Bluetooth unless approved by an admin
sc config BluetoothUserService start= disabled
NET STOP BluetoothUserService
sc config BTAGService start= disabled
NET STOP BTAGService
sc config BthAvctpSvc start= disabled
NET STOP BthAvctpSvc
sc config bthserv start= disabled
NET STOP bthserv
sc config NetBT start=disabled
NET STOP NETBt
echo Disable WinRM from using unencrypted channels
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0 /f
echo Disable camera when not in use
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
echo Disable IP source routing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIpSourceRouting" /t REG_DWORD /d 2 /f
echo Do not show slideshows on the lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenSlideshow" /t REG_DWORD /d 1 /f
echo Disable the Secondary Logon service
NET STOP seclogon
sc config seclogon start= disabled
echo Disable password managers on Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
echo Do not ignore SSL certificate errors
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" /v "PreventCertErrorOverrides" /t REG_DWORD /d 1 /f
echo Do not ignore Edge SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d 1 /f
echo Enforce PINs with six charecters or more for login (assuming no Biometrics)
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v "MinimumPINLength" /t REG_DWORD /d 6 /f
echo Enable a hardware key device
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "RequireSecurityDevice" /t REG_DWORD /d 1 /f
echo Enable SmartScreen for Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
echo Dont enumerate administrators during elevation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d 0 /f
echo Disable the convenience PIN
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogon" /t REG_DWORD /d 0 /f
echo Attempt device authentication using certificates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "DevicePKInitEnabled" /t REG_DWORD /d 1 /f
echo Do not allow users to change network settings without signing in
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d 1 /f
echo Disable WDigest authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" /v "UseLogonCredential" /t REG_DWORD /d 0 /f
echo Disable Portproxy
netsh interface portproxy delete
echo Limit accounts with no passwords from the internet
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f
echo Do not allow RPC to export credentials
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d 1 /f
echo Enable an audit policy using subcategories
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1 /f
echo Enable PowerShell transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableTranscripting" /t REG_DWORD /d 1 /f
echo Meet the minimum session security requirement for NTLM SSP based clients and servers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinClientSec" /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinServerSec" /t REG_DWORD /d 537395200 /f
echo Hide/disable the Explorer Preview pane
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPreviewPane" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoReadingPane" /t REG_DWORD /d 1 /f
echo Disable WinRM from using unencrypted traffic
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0 /f
echo Concerning hardened UNC paths
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f
echo Save zone information on attachments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v " SaveZoneInformation" /t REG_DWORD /d 2 /f
echo Enable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
echo Force GPO to reprocess even if no changes are made
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d 0 /f
echo Do not download printing driver updates over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f
echo Disable Windows wizards from downloading providers
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f
echo Disallow printing over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d 1 /f
echo Make sure Early Launch Antimalware gets launched first, and allow good, unknown and bad but critical
reg add "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d 3 /f
echo Force WinRM to not use Digest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowDigest" /t REG_DWORD /d 0 /f
echo Deny elevation requests for standerd users
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0 /f
echo Block PowerShell scripts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
echo Use FIPS algorithms
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" /v "Enabled" /t REG_DWORD /d 1 /f
echo Harden SAM share security
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictRemoteSAM" /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f
echo Handle RPC STIGs
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f
echo Encrypt channel traffic
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
echo Make sure CFG is enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t Reg_DWORD /d "1" /f
echo Make sure ASLR is enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t Reg_DWORD /d "1" /f
echo .NET cryptogrophy
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f
echo Enable DEP (Data Execution Prevention)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
echo Prioritize longer ECC auth curves
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "EccCurves" /t REG_MULTI_SZ /d "NistP384 NistP256" /f
echo DIsable Internet Sharing
reg add  "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d 0 /f
echo Do not allow insecure SMB servers
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 0 /f
echo Turn off display after 15 minutes
powercfg -setacvalueindex 11111111-1111-1111-1111-111111111111 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 15
echo Force logoff when smart card is removed
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "SCRemoveOption" /t REG_DWORD /d 2 /f
echo Force SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
echo WinRM must not store RunAs credentials
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v "DisableRunAs" /t REG_DWORD /d 1 /f
echo Uninstall IE
DISM /Online /Remove-Capability /CapabilityName:"Browser.InternetExplorer~~~~0.0.11.0" /NoRestart
echo Disable Microsoft consumer experiences
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
echo Disable Delivery Optimization
reg add  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
echo Do not disable File Explorer heap termination on corruption
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d 0 /f
echo Make MS Accounts optional
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MSAOptional" /t REG_DWORD /d 1 /f
echo OSPF over ICMP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f
echo Ignore NetBIOS except from WINS servers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v "NoNameReleaseOnDemand" /t REG_DWORD /d 1 /f
echo Disable third-party suggestions
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d 1 /f
echo Do not prevent resetting of the password
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DisablePasswordChange" /t REG_DWORD /d 0 /f
echo Enable Virtual-Based Security (VBS)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d 2 /f
echo Disable toast Notifications on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f
echo Limit cache of logon credentials
reg add  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d 8 /f
echo Increase default permissions of global system objects
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 1 /f
echo Finished STIG implementation
pause
goto :menu