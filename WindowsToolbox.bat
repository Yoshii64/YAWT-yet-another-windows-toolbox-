@echo off

color 9
set /p q1=do you want to run this? 
if %q1%==yes goto :restore
if %q1%==no exit
:restore
set /p message0=it is hightly recommended to create a restore point. would you like to make one now?
if %message0%==yes Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "My Restore Point", 100, 12
 goto :menu
if %message0%==no goto :menu


:menu
cls
color 1
echo - type 1 to optimize network options
echo - type 2 to clear temp files
echo - type 3 to run optimizing software
echo - type 4 to check and fix errors in Windows
echo - type 5 to install a program
echo - type 6 for a menu that shows more optimizations
echo - type 7 to debloat Windows
echo - type 8 for other optimizations
echo - type exit to exit
set  /p message1= - to list these again type in 'help' or 'menu' 
if %message1%==help goto :menu
if %message1%==menu goto :menu
if %message1%==1 goto :network
if %message1%==2 goto :cleartemp
if %message1%==3 goto :runoptimize
if %message1%==4 goto :fix
if %message1%==5 goto :install
if %message1%==6 goto :misc
if %message1%==7 goto :debloat
if %message1%==8 goto :others
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
netsh int tcp set supplemental
netsh int tcp set heuristics disabled
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
cd C:\Windows\Temp+

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



:runoptimize
cls
echo click "clean up system files" and check everything. then click OK
start cleanmgr.exe
pause
cls
color 47
echo CLOSE PROGRAM IF ON SSD. IF YOU ARE NOT SURE, CLOSE PROGRAM.
start dfrgui.exe
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
Reg Add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
goto :misc

:backroundstart
Reg Add HKCU\Software\Microsoft\WindowsNT\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
goto :misc

:OneDriveuninstall
taskkill /f /im OneDrive.exe
%Systemroot%\System32\OneDriveSetup.exe /uninstall
cd %UserProfile%\AppData\Local\Microsoft\OneDrive
taskkill /F /IM "explorer.exe"
DEL "." /F
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
start Explorer.exe
cd %UserProfile%\AppData\Local\OneDrive
DEL "."
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
pause
goto :misc




pause
goto :misc

:onedriveinstall
winget install Microsoft.OneDrive
goto :misc

:edgeuninstall
taskkill "msedge.exe"
taskkill "msedgewebview2.exe"
cd "%UserProfile%\AppData\Local\Microsoft"
DEL "Edge"
DEL "Internet Explorer"
cd "%UserProfile%\AppData\LocalLow\Microsoft"
DEL "Internet Explorer"
cd "%UserProfile%\AppData\Roaming\Microsoft"
DEL "Internet Explorer"
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd %UserProfile%\AppData\Local\Microsoft
taskkill /F /IM "COM surrogate"
DEL "Internet Explorer"
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
pause

:debloat
cls
set /p debloat=do you want to remove all the programs that are not needed?
if %debloat%==yes powershell.exe -ExecutionPolicy Unrestricted -Command ./debloat.ps1
if %debloat%==no goto :menu
pause
goto :menu


:others
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
del %UserProfile%\AppData\Roaming\Microsoft\Windows\StartMenu\Programs\Startup
wusa /uninstall /kb:3035583 /quiet /norestart
taskkill /f /im explorer.exe
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
start explorer.exe
pause
goto :menu
