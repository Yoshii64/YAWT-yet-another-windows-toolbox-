@echo off

color 9
set /p q1=do you want to run this? 
if %q1%==yes goto :menu
if %q1%==no goto :end

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
set /p program=type 6 to install git
if %program%==1 winget install 7zip.7zip
if %program%==2 winget install brave
if %program%==6 winget install git.git
if %program%==3 winget install VScode
if %program%==4 winget install Discord.Discord
if %program%==5 winget install GitHub.GitHubDesktop
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

:debloat
cls
set /p debloat=do you want to remove all the programs that are not needed?
if %debloat%==yes powershell.exe -ExecutionPolicy Unrestricted -Command ./debloat.ps1
if %debloat%==no goto :menu
pause
goto :menu