@echo off
:restore
set /p message0=it is hightly recommended to create a restore point. would you like to make one now?
if %message0%==yes Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "My Restore Point", 100, 12
 goto :menu
if %message0%==no goto :menu


:menu
cls
echo - type 1 to optimize network options
echo - type 2 to clear temp files
echo - type 3 to check and fix errors in Windows
echo - type 4 to install a program
echo - type 5 for a menu that shows more optimizations
echo - type 6 to debloat Windows
echo - type 7 for other optimizations
echo - type exit to exit
set  /p message1=
if %message1%==1 goto :network
if %message1%==2 goto :cleartemp
if %message1%==3 goto :fix
if %message1%==4 goto :install
if %message1%==5 goto :misc
if %message1%==6 goto :debloat
if %message1%==7 goto :others
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
echo setting up DNS optimizations...
netsh interface ip delete dnsservers "Local Area Connection" all
netsh interface ip add dns name="Local Area Connection" addr=8.8.4.4 index=1
netsh interface ip add dns name="Local Area Connection" addr=8.8.8.8 index=2
ipconfig /all | findstr /c:"8.8.4.4"
ipconfig /all | findstr /c:"8.8.8.8"
echo done
pause
goto :menu




:cleartemp
cls
echo clearing uneeded files...
cd C:\Windows\Temp
del *.* /F 
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd %UserProfile%\AppData\Local\Temp
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd C:\$Recycle.Bin\S-1-5-21-610696990-1213007965-522507228-1001
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd C:\Windows\SoftwareDistribution\Download
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd C:\Windows\Prefetch
del *.* /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
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
set /p program=type 8 to install git
if %program%==1 winget install 7zip.7zip
if %program%==2 winget install brave
if %program%==8 winget install git.git
if %program%==3 winget install VScode
if %program%==4 winget install Discord.Discord
if %program%==5 winget install GitHub.GitHubDesktop
if %program%==6 winget install Microsoft.PowerToys
if %program%==7 winget install Microsoft.WindowsTerminal
set /p back= do you want to install another program?
if %back%==yes goto :install
if %back%==no goto :menu

pause


:misc
cls
color F
echo type 1 to disable backround apps
echo type in 2 to enable backround apps
echo type in 3 to uninstall onedrive
echo type in 4 to install onedrive 
set /p menu2msg=type in 5 to uninstall edge
if %menu2msg%==1 goto :backroundstop
if %menu2msg%==2 goto :backroundstart
if %menu2msg%==3 goto :onedriveuninstall
if %menu2msg%==4 goto :onedriveinstall
if %menu2msg%==5 goto :edgeuninstall
pause
goto :menu

:backroundstop
echo disabling backround apps...
Reg Add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
goto :misc

:backroundstart
echo enabling backround apps...
Reg Add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
goto :misc

:OneDriveuninstall
echo uninstalling onedrive...
echo killing OneDrive processes...
taskkill /f /im OneDrive.exe
echo deleting onedrive files...
%Systemroot%\System32\OneDriveSetup.exe /uninstall
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
echo done
pause
goto :misc

:debloat
cls
set /p debloat=do you want to remove all the programs that are not needed?
if %debloat%==yes echo debloating Windows...
 echo changing registry keys...
 reg add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
 reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t "REG_DWORD" /d "4" /F
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
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
 NETSH advfirewall firewall add rule name="telemetry_service.xbox.com" dir=out action=block remoteip=157.55.129.21 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft22.com" dir=out action=block remoteip=52.178.178.16 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft21.com" dir=out action=block remoteip=65.55.64.54 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft20.com" dir=out action=block remoteip=40.80.145.27 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft17.com" dir=out action=block remoteip=40.80.145.78 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft16.com" dir=out action=block remoteip=23.99.116.116 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft15.com" dir=out action=block remoteip=77.67.29.176 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft14.com" dir=out action=block remoteip=65.55.223.0-65.55.223.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft13.com" dir=out action=block remoteip=65.39.117.230 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft12.com" dir=out action=block remoteip=64.4.23.0-64.4.23.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft11.com" dir=out action=block remoteip=23.223.20.82 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft10.com" dir=out action=block remoteip=213.199.179.0-213.199.179.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft09.com" dir=out action=block remoteip=2.22.61.66 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft08.com" dir=out action=block remoteip=195.138.255.0-195.138.255.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft07.com" dir=out action=block remoteip=157.55.56.0-157.55.56.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft06.com" dir=out action=block remoteip=157.55.52.0-157.55.52.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft05.com" dir=out action=block remoteip=157.55.236.0-157.55.236.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft04.com" dir=out action=block remoteip=157.55.235.0-157.55.235.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft03.com" dir=out action=block remoteip=157.55.130.0-157.55.130.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft02.com" dir=out action=block remoteip=111.221.64.0-111.221.127.255 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft01.com" dir=out action=block remoteip=11.221.29.253 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_microsoft.com" dir=out action=block remoteip=104.96.147.3 enable=yes
 NETSH advfirewall firewall add rule name="telemetry_telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.9 enable=yes
 echo disabling Windows to repair itself through updates...
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "**del.RepairContentServerSource" /t REG_SZ /d " " /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 echo you may need to restart for all changes to take effect...
if %debloat%==no goto :menu
pause
goto :menu


:others
echo setting power plan to high performance...
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
wusa /uninstall /kb:3035583 /quiet /norestart
taskkill /f /im explorer.exe
echo changing registry keys...
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f 1>NUL 2>NUL
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
taskkill /f /im explorer.exe
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
start explorer.exe
REG ADD "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
REG ADD "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
REG ADD "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
REG ADD "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
REG ADD "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
REG ADD "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
REG ADD "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
REG ADD "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
REG ADD "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
REG ADD "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
echo disabling unused Windows features...
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WorkFolders-Client"
echo done
pause
goto :menu