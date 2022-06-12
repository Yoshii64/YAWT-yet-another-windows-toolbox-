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


$Window.Controls.AddRange(@($CleanupSystem, $network))


$CleanupSystem.Add_Click({

Clear-Host
Write-Output clearing uneeded files...
Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Windows\Prefetch" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
})

$network.Add_click({
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
})


$Window.ShowDialog()
$Window.Dispose()