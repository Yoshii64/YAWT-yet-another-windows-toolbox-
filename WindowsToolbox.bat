@echo off

color 9
set /p q1=do you want to run this? 
if %q1%==yes goto :menu
if %q1%==no goto :end

:menu
cls
color 1
echo - type in 1 to optimize network options
echo - type 2 to clear temp files
echo - type 3 to run optimizing software
echo - type 4 to check and fix errors in Windows
echo - type 5 to install a program
echo - type 6 to exit
set  /p message1= - to list these again type in 'help' or 'menu' 
if %message1%==help goto :menu
if %message1%==menu goto :menu
if %message1%==1 goto :network
if %message1%==2 goto :cleartemp
if %message1%==3 goto :runoptimize
if %message1%==4 goto :fix
if %message1%==5 goto :install
if %message1%==6 exit
if %message1%==exit exit




:network
cls
IPCONFIG /release
IPCONFIG /renew
IPCONFIG /flushdns
IPCONFIG /registerdns
pause
goto :menu




:cleartemp
cls
echo clearing uneeded files...
cd C:\Windows\Temp
del *.* /F 
for /F "delims="  %%i in ('dir /b') do (rmdir "%%i" /s /q  || del "%%i"  /S /Q)
cd C:\Users\yoshi11\AppData\Local\Temp
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
goto :diskcheckquestion

:diskcheckquestion
cls
color F6
set /p check=do you want to check the disk for errors? warning: it may ask you to reboot. checking disk may take a while.
if %check%==yes goto :checkdisk
if %check%==no goto :menu

:checkdisk
CHKDSK /f
pause
goto :menu


:install
cls
echo supported programs:
echo 7zip
echo brave
set /p program= git
if %program%==7zip winget install 7zip.7zip
if %program%==brave winget install brave
if %program%==git winget install git.git
set /p back= do you want to install another program?
if %back%==yes goto :install
if %back%==no goto :menu

pause