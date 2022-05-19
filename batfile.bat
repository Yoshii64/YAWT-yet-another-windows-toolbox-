@echo off

set /p q1=do you want to run this? 
if %q1%==yes goto :menu
if %q1%==no goto :end

:menu
cls

echo - type in 'network' to optimize network options
echo - type 'cleartemp' to clear temp files
echo - type 'runoptimize' to run optimizing software
echo - type 'fix' to check and fix errors in Windows
echo - type 'install' to install a program
echo - type 'exit' to exit
set  /p message1= - to list these again type in 'help' or 'menu'
if %message1%==help goto :menu
if %message1%==menu goto :menu
if %message1%==network goto :network
if %message1%==cleartemp goto :cleartemp
if %message1%==runoptimize goto :runoptimize
if %message1%==fix goto :fix
if %message1%==install goto :install
if %message1%==exit goto :end




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
color A
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

:end
exit





