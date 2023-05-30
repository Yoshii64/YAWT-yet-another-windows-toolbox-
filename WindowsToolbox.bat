@echo off
wmic process where name="cmd.exe" CALL setpriority 32768 >nul

:menu
cls
echo - type 1 for restore Windows Restore Point options
echo - type 2 to optimize network options
echo - type 3 to clear temp files
echo - type 4 to check and fix errors in Windows
echo - type 5 to install a program
echo - type 6 for a menu that shows more optimizations
echo - type 7 to debloat Windows
echo - type 8 to enhance security
echo - type 9 for other optimizations/performance tweaks
echo - type exit to exit
set /p message1=
if %message1% == 1 goto :RestoreOptions
if %message1%==2 goto :network
if %message1%==3 goto :cleartemp
if %message1%==4 goto :fix
if %message1%==5 goto :install
if %message1%==6 goto :misc
if %message1%==7 goto :debloat
if %message1%==8 goto :security
if %message1%==9 goto :others
if %message1%==exit exit
else echo - invalid input
goto :menu




:network
cls
echo clearing network cache...
IPCONFIG /release
IPCONFIG /renew
IPCONFIG /flushdns
IPCONFIG /registerdns
netsh winsock reset
echo setting optimizations for network...
netsh int tcp set supplemental
netsh int tcp set heuristics disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global autotuninglevel=normal
netsh interface Teredo set state type=enterpriseclient
netsh int tcp set global rsc=disabled
netsh interface Teredo set state servername=default
echo setting up DNS optimizations...
netsh interface ip delete dnsservers "Local Area Connection" all
netsh interface iADD dns name="Local Area Connection" addr=8.8.4.4 index=1
netsh interface iADD dns name="Local Area Connection" addr=8.8.8.8 index=2
ipconfig /all | findstr /c:"8.8.4.4"
ipconfig /all | findstr /c:"8.8.8.8"
int ipv4 set glob defaultcurhoplimit=65
int ipv6 set glob defaultcurhoplimit=65
powershell -NoProfile "$net=get-netconnectionprofile; Set-NetConnectionProfile -Name $net.Name -NetworkCategory Private" >nul 2>&1
REG ADD "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t reg_DWORD /d "00000001" /f >NUL 2>&1  
for /f %%s in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s') do set "str=%%i" & if "!str:ServiceName_=!" neq "!str!" (
 	REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TCPNoDelay" /t reg_DWORD /d "1" /f >NUL 2>&1
	REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpAckFrequency" /t reg_DWORD /d "1" /f >NUL 2>&1
	REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpDelAckTicks" /t reg_DWORD /d "0" /f >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpInitialRTT" /d "300" /t REG_DWORD /f >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "DeadGWDetectDefault" /d "1" /t REG_DWORD /f >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "UseZeroBroadcast" /d "0" /t REG_DWORD /f >NUL 2>&1
   REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t reg_DWORD /d "00065534" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t reg_DWORD /d "00000030" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t reg_DWORD /d "00000000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t reg_DWORD /d "00000001" /f >NUL 2>&1 
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t reg_DWORD /d "00000001" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t reg_DWORD /d "00000016" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t reg_DWORD /d "00000016" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t reg_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t reg_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >NUL 2>&1
)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t reg_DWORD /d "00000000" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t reg_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t reg_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t reg_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t reg_DWORD /d "7" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t reg_DWORD /d "0" /f >NUL 2>&1
echo done
pause
goto :menu




:cleartemp
cls
echo clearing uneeded files...
del /s /f /q %windir%\temp\*.*
del /s /f /q %temp%\*.*
cd C:\Windows\SoftwareDistribution\Download
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
del /s /f /q %windir%\Prefetch\*.*
rd /s /q %WINDIR%\Logs
del /q %WINDIR%\Downloaded Program Files\*.*
cd C:\ProgramData\Microsoft\Windows\WER\Temp
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
Cmd.exe /c Cleanmgr /sagerun:65535
rd /s /q %SYSTEMDRIVE%\$RECYCLE.BIN
echo files now cleared.
pause
goto :menu

:fix
cls
echo fixing errors in Windows...
sfc /scannow
DISM /online /cleanup-image /RestoreHealth
sfc /scannow
cls
color F6
 set /p check=do you want to check the disk for errors? warning: it may ask you to reboot. checking disk may take a while. 
if %check%==yes CHKDSK /F
pause
goto :menu

:install
cls
echo supported programs:
echo type 1 to install 7zip
echo type 2 to install brave
echo type 3 to install VScode
echo type 4 to install Discord
echo type 5 to install Github Desktop
echo type 6 to install powertoys
echo type 7 to install Windows Command Terminal
echo type 8 to install git
echo type 9 to install VLC
echo type 10 to install Firefox
echo type 11 to install Python 3.10
echo type 12 to install EarTrumpet
echo type 13 to upgrade all installs from winget
echo type 14 to go back to the main menu
set /p program=
if %program%==1 winget install 7zip.7zip
if %program%==2 winget install brave
if %program%==3 goto :VScode
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
set /p back= do you want to install another program?
if %back%==yes goto :install
if %back%==no goto :menu


:VScode
winget install VScode
powershell.exe -ExecutionPolicy Unrestricted -Command "New-Item -Path 'HKCU:\Software\Microsoft\VisualStudio\Telemetry' -Force"
PowerShell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\VisualStudio\Telemetry' -Name TurnOffSwitch -Type 'DWORD' -Value 1 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command  "New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command  "New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command  "New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command  "Set-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM' -Name OptIn -Type 'DWORD' -Value 0 -Forcez'
powershell.exe -ExecutionPolicy Unrestricted -Command  "Set-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM' -Name OptIn -Type 'DWORD' -Value 0 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command  "Set-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM' -Name OptIn -Type 'DWORD' -Value 0 -Force"
goto :install

:misc
cls
color F
echo type 1 to disable backround apps
echo type in 2 to enable backround apps
echo type in 3 to uninstall onedrive
echo type in 4 to install onedrive 
echo type in 5 to uninstall edge
echo type in 6 to disable Cortana
echo type in 7 to disable Windows Search Indexing
echo type in 8 to disable User Account Control
echo type in 9 to enable User Account Control
echo type in 10 to go back to the main menu
set /p menu2msg=
if %menu2msg%==1 goto :backroundstop
if %menu2msg%==2 goto :backroundstart
if %menu2msg%==3 goto :onedriveuninstall
if %menu2msg%==4 goto :onedriveinstall
if %menu2msg%==5 goto :edgeuninstall
if %menu2msg%==6 goto :cortana
if %menu2msg%==7 goto :Indexing
if %menu2msg%==8 goto :DisableUAC
if %menu2msg%==9 goto :EnableUAC
if %menu2msg%==10 goto :menu
pause
goto :menu

:backroundstop
echo disabling backround apps...
REG ADD HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
goto :misc

:backroundstart
echo enabling backround apps...
REG ADD HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
goto :misc

:OneDriveuninstall
echo uninstalling onedrive...
echo killing OneDrive processes...
taskkill /f /im OneDrive.exe
echo deleting onedrive files...
%SystemRoot%\System32\OneDriveSetup.exe /uninstall
%SystemRoot%\System32\OneDrive.exe /uninstall
cd %UserProfile%\AppData\Local\Microsoft\OneDrive
taskkill /F /IM "explorer.exe"
DEL "." /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
start Explorer.exe
cd %UserProfile%\AppData\Local\OneDrive
DEL "."
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
echo deleting regkeys associated with onedrive...
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /F
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /F
reg delete "HKCR\Environment\OneDrive" /F
reg delete "HKCR\Software\Microsoft\OneDrive"
reg delete "\HKEY_CURRENT_USER\Software\Microsoft\OneDrive"
echo done
pause
goto :misc

:onedriveinstall
echo installing onedrive...
winget install Microsoft.OneDrive
echo done
goto :misc

:edgeuninstall
echo uninstalling edge...
echo killing edge processes...
taskkill "msedge.exe"
taskkill "msedgewebview2.exe"
sc delete "edgeupdate"
sc delete "edgeupdatem"
sc delete "MicrosoftEdgeElevationService"
echo deleting edge files...
cd "%UserProfile%\AppData\Local\Microsoft"
DEL "Edge"
DEL "Internet Explorer"
cd "%UserProfile%\AppData\LocalLow\Microsoft"
DEL "Internet Explorer"
cd "%UserProfile%\AppData\Roaming\Microsoft"
DEL "Internet Explorer"
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
reg delete "HKCR\Software\Microsoft\Edge" /F

echo deleting regkeys associated with edge...
reg delete "HKCR\Software\Microsoft\EdgeUpdate" /F
reg delete "HKCR\Software\Microsoft\Internet Explorer" /F
reg delete "HKCR\Software\Policies\Microsoft\Edge" /F
reg delete "HKLM\SOFTWARE\Microsoft\Edge"
reg delete "HKLM\SOFTWARE\Microsoft\Internet Explorer"
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge"
reg delete "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftEdge_44.22000.120.0_neutral__8wekyb3d8bbwe"
reg delete "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.MicrosoftEdge_44.22000.120.0_neutral__8wekyb3d8bbwe"
reg delete "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MicrosoftEdge_44.22000.120.0_neutral__8wekyb3d8bbwe"
reg delete "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.File\PackageId\Microsoft.MicrosoftEdge_44.22000.120.0_neutral__8wekyb3d8bbwe"
echo done
pause
goto :misc


:cortana
echo disabling Cortana...
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

:Indexing 
NET STOP "WSearch"
sc config "WSearch" start=disabled
pause
goto :menu2msg


:DisableUAC
C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
pause
goto :menu2msg

:EnableUAC
C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
pause
goto :menu2msg


:debloat
cls
set /p debloat=do you want to remove all the programs that are not needed?
if %debloat%==yes echo debloating Windows...
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
setx POWERSHELL_TELEMETRY_OPTOUT 1
 echo changing registry keys...
 REG ADD "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f
 REG ADD "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
 REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t "REG_DWORD" /d "4" /F
 REG ADD "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
 REG ADD "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
 REG ADD "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
 REG DELETE "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.ParentalControls_1000.22000.1.0_neutral_neutral_cw5n1h2txyewy"
 REG DELETE "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.PeopleExperienceHost_10.0.22000.1_neutral_neutral_cw5n1h2txyewy"
 REG DELETE "HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.22000.1.0_neutral_neutral_cw5n1h2txyewy"
 echo disabling Services...
 echo DiagTrack
 sc config "DiagTrack" start= disabled
    NET STOP DiagTrack
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
 sc config "RetailDemo" start= disabled
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
 schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
 echo uninstalling Windows programs...
 echo Windowscamera
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-appxpackage -AllUsers *Microsoft.WindowsCamera* | remove-appxpackage"
 echo WindowsCalculator
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsCalculator* | Remove-AppxPackage"
 echo MicrosoftTeams_22115
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *MicrosoftTeams_22115.300.1313.2464_x64__8wekyb3d8bbwe* | Remove-AppxPackage"
 echo YourPhone
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.YourPhone* | Remove-AppxPackage"
 echo MicrosoftEdge.Stable
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage"
 echo XboxGameOverlay
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.XboxGameOverlay* | Remove-AppxPackage" 
 echo XboxGameUI
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.XboxGameUI* | Remove-AppxPackage"
 echo Todos
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.Todos* | Remove-AppxPackage"
 echo MicrosoftStickyNotes
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
 echo Cortana
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.Windows.Cortana* | Remove-AppxPackage"
 echo Clipchamp
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Clipchamp.Clipchamp* | Remove-AppxPackage"
 echo WindowsStore
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.WindowsStore* | Remove-AppxPackage"
 echo PowerAutomateDesktop
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage"
 echo WindowsPhotos
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.Windows.Photos* | Remove-AppxPackage"
 echo MicrosoftTeams
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *MicrosoftTeams* | Remove-AppxPackage"
 echo ZuneVideo
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.ZuneVideo* | Remove-AppxPackage"
 echo ZuneMusic
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.ZuneMusic* | Remove-AppxPackage"
 echo WindowsSoundRecorder
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
 echo WindowsFeedbackHub
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
 echo windowscommunicationsapps
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *microsoft.windowscommunicationsapps* | Remove-AppxPackage"
 echo ScreenSketch
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.ScreenSketch* | Remove-AppxPackage"
 echo MicrosoftSolitaireCollection
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
 echo MicrosoftOfficeHub
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
 echo Getstarted
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.Getstarted* | Remove-AppxPackage"
 echo GamingApp
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.GamingApp* | Remove-AppxPackage"
 echo BingNews
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingNews*  | Remove-AppxPackage"
 echo BingWeather
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-Appxpackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage"
 echo GetHelp
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage"
 echo StorePurchaseApp
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.StorePurchaseApp* | Remove-AppxPackage"
 echo WindowsMaps
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsMaps* | Remove-AppxPackage"
 echo Xbox.TCUI
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
 echo XboxSpeechToTextOverlay
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | Remove-Appxpackage"
 echo WindowsNotepad
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsNotepad* |Remove-AppxPackage"
 echo 3DBuilder
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.3DBuilder* |Remove-AppxPackage"
 echo Microsoft3DViewer
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.Microsoft3DViewer* |Remove-AppxPackage"
 echo BingFinance
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingFinance* |Remove-AppxPackage"
 echo BingNews
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingNews* |Remove-AppxPackage"
 echo BingSports
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingSports* |Remove-AppxPackage"
 echo BingWeather
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingWeather* |Remove-AppxPackage"
 echo BingTranslator
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingTranslator* |Remove-AppxPackage"
 echo BingFoodAndDrink
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingFoodAndDrink* |Remove-AppxPackage"
 echo BingHealthAndFitness
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingHealthAndFitness* |Remove-AppxPackage"
 echo BingTravel
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers *Microsoft.BingTravel* |Remove-AppxPackage"
 echo Cortana
 powershell.exe -ExecutionPolicy Unrestricted -Command "Get-AppxPackage -AllUsers * Microsoft.549981C3F5F10* |Remove-AppxPackage"
 echo blocking telemetry IP addresses...
 NETSH advfirewall firewalADD rule name="telemetry_service.xbox.com" dir=out action=block remoteip=157.55.129.21 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft22.com" dir=out action=block remoteip=52.178.178.16 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft21.com" dir=out action=block remoteip=65.55.64.54 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft20.com" dir=out action=block remoteip=40.80.145.27 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft17.com" dir=out action=block remoteip=40.80.145.78 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft16.com" dir=out action=block remoteip=23.99.116.116 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft15.com" dir=out action=block remoteip=77.67.29.176 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft14.com" dir=out action=block remoteip=65.55.223.0-65.55.223.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft13.com" dir=out action=block remoteip=65.39.117.230 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft12.com" dir=out action=block remoteip=64.4.23.0-64.4.23.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft11.com" dir=out action=block remoteip=23.223.20.82 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft10.com" dir=out action=block remoteip=213.199.179.0-213.199.179.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft09.com" dir=out action=block remoteip=2.22.61.66 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft08.com" dir=out action=block remoteip=195.138.255.0-195.138.255.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft07.com" dir=out action=block remoteip=157.55.56.0-157.55.56.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft06.com" dir=out action=block remoteip=157.55.52.0-157.55.52.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft05.com" dir=out action=block remoteip=157.55.236.0-157.55.236.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft04.com" dir=out action=block remoteip=157.55.235.0-157.55.235.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft03.com" dir=out action=block remoteip=157.55.130.0-157.55.130.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft02.com" dir=out action=block remoteip=111.221.64.0-111.221.127.255 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft01.com" dir=out action=block remoteip=11.221.29.253 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_microsoft.com" dir=out action=block remoteip=104.96.147.3 enable=yes
 NETSH advfirewall firewalADD rule name="telemetry_telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.9 enable=yes
 echo disabling Windows to repair itself through updates...
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "**del.RepairContentServerSource" /t REG_SZ /d " " /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 echo deleting uneeded files
 cd C:\Program Files\WindowsApps\DeletedAllUserPackages
 DEL *.* /f
 DEL "C:\Program Files\WindowsApps\Microsoft.GamingApp_2021.427.138.0_neutral_~_8wekyb3d8bbwe" /F
 DEL "C:\Program Files\WindowsApps\Microsoft.GamingApp_2105.900.24.0_neutral_split.scale-100_8wekyb3d8bbwe" /F
 DEL "C:\Program Files\WindowsApps\Microsoft.GamingApp_2105.900.24.0_x64__8wekyb3d8bbwe" /f
 DEL "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.822.6271.0_neutral_~_8wekyb3d8bbwe" /f
 DEL "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.822.6271.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
 DEL "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.822.6271.0_x64__8wekyb3d8bbwe" /F

 echo disabling PowerShell telemetry
 powershell.exe -ExecutionPolicy -Unrestricted -Command "$POWERSHELL_Telemetry_OPTOUT = $true"

 echo changing regkeys 
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Value 0 -Type 'DWORD' -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value '0' -Type 'DWORD' -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WMDRM' -Name 'DisableOnline' -Type 'DWORD' -Value 1 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name 'DontReportInfectionInformation' -Type 'DWORD' -Value 1 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -Type 'DWORD' -Value 0 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -Type 'DWORD' -Value 2 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\EdgeUI' -Name 'DisableRecentApps' -Type 'DWORD' -Value 1 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name 'UsageTracking' -Type 'DWORD' -Value 0 -Force"

 echo you may need to restart for all changes to take effect...
if %debloat%==no goto :menu
pause
goto :menu


:others
echo setting power plan to high performance...
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
taskkill /f /im explorer.exe
echo changing registry keys...
sc config W32Time start=demand >nul 2>nul
sc start W32Time >nul 2>nul
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
w32tm /config /update
w32tm /resync
net stop w32time
sc config W32Time start=disabled
%windir%\System32\SystemSettingsAdminFlows.exe SetInternetTime 1
start "" "%windir%\System32\SystemSettingsAdminFlows.exe" SetAutoTimeZoneUpdate 1
start "" "%windir%\System32\SystemSettingsAdminFlows.exe" ForceTimeSync 1
REG ADD "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "25" /f
REG ADD "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "25" /f
REG ADD "HKLM\System\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /d 1 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
taskkill /f /im explorer.exe

REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
start explorer.exe
REG ADD "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
REG ADD "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
REG ADD "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
REG ADD "HKCR\*\shell\runas\command" /v /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
REG ADD "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
REG ADD "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
REG ADD "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
REG ADD "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
REG ADD "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
REG ADD "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "9" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "42" /f
REG ADD "HKLM\Software\Microsoft\FTH" /v "Enabled" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t reg_DWORD /d "0" /f >NUL 2>&1
echo storage optimizations (which is what the DuckOS script told me? loks like memory ones too)
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 2
fsutil behavior set allowextchar 0
fsutil behavior set Bugcheckoncorrupt 0
fsutil behavior set disablecompression 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set disabledeletenotify refs 0
fsutil behavior set disableencryption
fsutil behavior set disablelastaccess
fsutil behavior set encryptpagingfile
fsutil behavior set quotanotify 86400
fsutil behavior set symlinkevaluation L2L:1
fsutil behavior set disablelastaccess 1
fsutil behavior set disable8dot3 1
echo disabling unused Windows features...
PowerShell -ExecutionPolicy Unrestricted -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WorkFolders-Client"
echo done
pause
goto :menu


:RestoreOptions
cls
Echo will be here soon
goto :menu


:security
cls
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverride' -Type DWORD -Value 72 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverrideMask' -Type DWORD -Value 3 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name 'MinVmVersionForCpuBasedMitigations' -Type String -Value '1.0' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks' -Name 'Value' -Type String -Value 'Deny' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AlwaysUseAutoLangDetection' -type DWORD -Value 0 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'Wpad' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\' -Name 'Wpad' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Type 'DWORD' -Value 1 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Type 'DWORD' -Value 1 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name 'UseLogonCredential' -Type DWORD -Value 0 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled"
powershell.exe -ExecutionPolicy Unrestricted -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled"
powershell.exe -ExecutionPolicy Unrestricted -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled"
powershell.exe -ExecutionPolicy Unrestricted -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart"
powershell.exe -ExecutionPolicy Unrestricted -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-MpPreference -DisableRemovableDriveScanning 0"
powershell.exe -ExecutionPolicy Unrestricted -Command "New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name ServerMinKeyBitLength -Type 'DWORD' -Value 0x00001000 -FOrce"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name ClientMinKeyBitLength -Type 'DWORD' -Value 0x00001000 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name Enabled -Type 'DWORD' -Value 0x00000001 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type 'DWORD' -Value 1 -Force"
PowerShell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name 'DontReportInfectionInformation' -Type 'DWORD' -Value 1 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\FindMyDevice' -Name AllowFindMyDevice -Type 'DWORD' -Value 0 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name HttpAcceptLanguageOptOut -Type 'DWORD' -Value 1 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\' -Name 'MitigationOptions' -Type 'QWORD' -Value '1000000000000' -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Input\TIPC' -Name 'Enabled' -Type 'DWORD' -Value 0 -Force"
powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' -Name 'Enabled' -Type 'DWORD' -Value 0 -Force"
 powershell.exe -ExecutionPolicy Unrestricted -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'CallLegacyWCMPolicies' -Type 'DWORD' -Value 0 -Force"
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d 1 /f
pause
goto :menu 