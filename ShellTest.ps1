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
$CleanupSystem.location = New-Object System.Drawing.Point(300,0)
$CleanupSystem.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$network = New-Object $ButtonObject
$network.text = 'optimize network'
$network.CLientSize = '100,100'
$network.location = New-Object System.Drawing.Point(300,100)
$network.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$fix = New-Object $ButtonObject
$fix.text = 'fix errors in Windows'
$fix.ClientSize = '100,100'
$fix.location = New-Object System.Drawing.Point(300,200)
$fix.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$OneDriveUninstall = New-Object $ButtonObject
$OneDriveUninstall.text = 'uninstall OneDrive'
$OneDriveUninstall.ClientSize = '100,100'
$OneDriveUninstall.Location = New-Object System.Drawing.Point(200,0)
$OneDriveUninstall.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$OneDriveinstall = New-Object $ButtonObject
$OneDriveinstall.Text = 'install OneDrive'
$OneDriveinstall.ClientSize = '100,100'
$oneDriveinstall.Location = New-Object System.Drawing.Point(200,100)
$OneDriveinstall.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$debloat = New-Object $ButtonObject
$debloat.Text = 'debloat Windows'
$debloat.ClientSize = '100,100'
$debloat.Location = New-Object System.Drawing.Point(200,200)
$debloat.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)

$OtherStuff = New-Object $ButtonObject
$OtherStuff.Text = 'other optimizations'
$OtherStuff.ClientSize = '100,100'
$OtherStuff.Location = New-Object System.Drawing.Point(100,0)
$OtherStuff.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$Window.Controls.AddRange(@($CleanupSystem, $network, $fix, $OneDriveUninstall, $OneDriveinstall, $debloat, $OtherStuff))


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
Get-AppxPackage -AllUsers *Microsoft.BingNews*  | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.StorePurchaseApp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.WindowsMaps* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.WindowsTerminal* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.Xbox.TCUI* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage 
Get-appxpackage -AllUsers *Microsoft.WindowsCamera* | Remove-AppPackage
Get-AppxPackage -AllUsers *Microsoft.WindowsCalculator* | Remove-AppxPackage
Get-Appxpackage -AllUsers *MicrosoftTeams_22115.300.1313.2464_x64__8wekyb3d8bbwe* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.YourPhone* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.XboxGameOverlay* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.Todos* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.Windows.Cortana* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Clipchamp.Clipchamp* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.WindowsStore* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.Windows.Photos* | Remove-AppxPackage
Get-Appxpackage -AllUsers *MicrosoftTeams* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.ZuneVideo* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.ZuneMusic* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
Get-Appxpackage -AllUsers *microsoft.windowscommunicationsapps* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.ScreenSketch* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.Getstarted* | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.GamingApp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingNews*  | Remove-AppxPackage
Get-Appxpackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.3DBuilder* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.Microsoft3DViewer* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingFinance* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingNews* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingSports* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingWeather* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingTranslator* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingFoodAndDrink* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingHealthAndFitness* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.BingTravel* |Remove-AppxPackage
Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* |Remove-AppxPackage
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
  REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d 2 /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d %NOURL% /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "**del.RepairContentServerSource" /t REG_SZ /d " " /f
 REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7C0F6EBB-E44C-48D1-82A9-0561C4650831}Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f
 Write-Output you may need to restart for all changes to take effect
})

$OtherStuff.Add_click({
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WorkFolders-Client"
})


$Window.ShowDialog()
$Window.Dispose()