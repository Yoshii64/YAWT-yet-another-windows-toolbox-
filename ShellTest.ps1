add-type -AssemblyName System.Windows.Forms

$FormObject = [System.Windows.Forms.Form]
$LabelObject = [System.Windows.Forms.Label]
$ButtonObject = [System.Windows.Forms.Button]


$Window=New-Object $FormObject
$Window.ClientSize ='650,650'
$Window.BackColor = '#ffffff'
$Window.Text ='Windows Toolbox'
$Window.StartPosition ='CenterScreen'


$CleanupSystem = New-Object $ButtonObject
$CleanupSystem.text ='Clean up System'
$CleanupSystem.ClientSize ='100,100'
$CleanupSystem.location = New-Object System.Drawing.Point(280,0)
$CleanupSystem.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$network = New-Object $ButtonObject
$network.text = 'optimize network'
$network.CLientSize = '100,100'
$network.location = New-Object System.Drawing.Point(280,100)
$network.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$fix = New-Object $ButtonObject
$fix.text = 'fix errors in Windows'
$fix.ClientSize = '100,100'
$fix.location = New-Object System.Drawing.Point(280,200)
$fix.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$OneDriveUninstall = New-Object $ButtonObject
$OneDriveUninstall.text = 'uninstall OneDrive'
$OneDriveUninstall.ClientSize = '100,100'
$OneDriveUninstall.Location = New-Object System.Drawing.Point(180,0)
$OneDriveUninstall.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$OneDriveinstall = New-Object $ButtonObject
$OneDriveinstall.Text = 'install OneDrive'
$OneDriveinstall.ClientSize = '100,100'
$oneDriveinstall.Location = New-Object System.Drawing.Point(180,100)
$OneDriveinstall.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$debloat = New-Object $ButtonObject
$debloat.Text = 'debloat Windows'
$debloat.ClientSize = '100,100'
$debloat.Location = New-Object System.Drawing.Point(180,200)
$debloat.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$Window.Controls.AddRange(@($CleanupSystem, $network, $fix, $OneDriveUninstall, $OneDriveinstall, $debloat))


$CleanupSystem.Add_Click({

Clear-Host
Write-Output clearing uneeded files...
Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Windows\Prefetch" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
})

$count = $network.Add_click({
Clear-Host
Write-Output clearing network cache...
IPCONFIG /release
IPCONFIG /renew
IPCONFIG /flushdns
IPCONFIG /registerdns
netsh winsock reset
echo setting optimizations for network...
netsh int tcp set supplemental
netsh int tcp set heuristics disabled
netsh int tcp set global timestamps=disabled
Write-Output setting up DNS optimizations...
netsh interface ip delete dnsservers "Local Area Connection" all
netsh interface ip add dns name="Local Area Connection" addr=8.8.4.4 index=1
netsh interface ip add dns name="Local Area Connection" addr=8.8.8.8 index=2
ipconfig /all | findstr /c:"8.8.4.4"
ipconfig /all | findstr /c:"8.8.8.8"
Write-Output done
})


$fix.Add_Click({
sfc /scannow
DISM /online /cleanup-image /RestoreHealth
sfc /scannow
CHKDSK /F
})
 
 $OneDriveUninstall.Add_Click({
Write-Output uninstalling onedrive...
Write-Output killing OneDrive processes...
taskkill /f /im "OneDrive.exe"
taskkill /F /IM "explorer.exe"
Remove-Item -Force C:\Windows\System32\OneDrive.exe 
Remove-Item -Force $env:UserProfile\AppData\Local\Microsoft\OneDrive 
start Explorer.exe
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /F
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /F
reg delete "HKCR\Environment\OneDrive" /F
reg delete "HKCR\Software\Microsoft\OneDrive"
reg delete "HKCR\Software\Microsoft\OneDrive"
 })

$OneDriveinstall.Add_Click({
Write-Output 'installing OneDrive'
winget install Microsoft.OneDrive
Write-Output 'Done'
})



$debloat.Add_Click({
 reg add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
 reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t "REG_DWORD" /d "4" /F
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
 reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
 sc delete "DiagTrack"
    NET STOP DiagTrack
 sc delete "AJRouter"
    NET STOP AJRouter
 sc delete "PhoneSvc"
    NET STOP PhoneSvc
 sc delete "TermService"
    NET STOP TermService
 sc delete "RemoteRegistry"
    NET STOP RemoteRegistry
 sc delete "RetailDemo"
    NET STOP RetailDemo
 sc delete "RemoteAccess"
    NET STOP RemoteAccess
 sc delete "OneSyncSvc"
    NET STOP OneSyncSvc
 sc delete "UevAgentService"
    NET STOP UevAgentService
 sc delete "WbioSrvc"
    NET STOP WbioSrvc
 sc delete "XblAuthManager"
    NET STOP XblAuthManager
 sc delete "XblGameSave"
    NET STOP XblGameSave
 sc delete "XboxNetApiSvc"
    NET STOP XboxNetApiSvc
 sc delete "XboxGipSvc"
    NET STOP XboxGipSvc
 sc delete "FontCache"
    NET STOP FontCache
 sc delete "iphlpsvc"
    NET STOP iphlpsvc
 sc delete "BcastDVRUserService_48486de"
    NET STOP BcastDVRUserService_48486de
 sc delete "WpnService"
    NET STOP WpnService


})




$Window.ShowDialog()
$Window.Dispose()