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
$OneDriveUninstall.Location = '180,0'
$OneDriveUninstall.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)


$Window.Controls.AddRange(@($CleanupSystem, $network, $fix, $OneDriveUninstall))


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
taskkill /f /im "OneDrive.exe" -ErrorAction SilentlyContinue
taskkill /F /IM "explorer.exe"
Remove-Item -Force C:\Windows\System32\OneDrive.exe -ErrorAction SilentlyContinue
Remove-Item -Force $env:UserProfile\AppData\Local\Microsoft\OneDrive -ErrorAction SilentlyContinue
start Explorer.exe
 })



$Window.ShowDialog()
$Window.Dispose()