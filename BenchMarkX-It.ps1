<#
A simple script that will check for certain services, firewall rules and reg edits that are needed for a smooth authenticated Nessus CIS Scan. Will save all results into a folder to easily revert settings.

Version 1.1 - 22nd February 2023.
#>

# ASCI ART
$t = @"
______                 _    ___  ___           _   __   __    _____ _   
| ___ \               | |   |  \/  |          | |  \ \ / /   |_   _| |  
| |_/ / ___ _ __   ___| |__ | .  . | __ _ _ __| | __\ V /______| | | |_ 
| ___ \/ _ \ '_ \ / __| '_ \| |\/| |/ _` | '__| |/ //   \______| | | __|
| |_/ /  __/ | | | (__| | | | |  | | (_| | |  |   </ /^\ \    _| |_| |_ 
\____/ \___|_| |_|\___|_| |_\_|  |_/\__,_|_|  |_|\_\/   \/    \___/ \__|
                                                                        
                                                                                                                        
"@

for ($i = 0; $i -lt $t.length; $i++) {
    if ($i % 2) {
        $c = "green"
    }
    elseif ($i % 5) {
        $c = "green"
    }
    elseif ($i % 7) {
        $c = "green"
    }
    else {
        $c = "green"
    }
    Write-Host $t[$i] -NoNewline -ForegroundColor $c
}

# CHECK IF ADMIN
Write-Host "`nChecking user permissions:"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Not running with administrator permissions. Please run this script as admin."
    Break
}
else {
    Write-Host "Script executed with correct permissions`n" -ForegroundColor Green
}

# VARIABLES
$UserPath = "$($env:USERPROFILE)\Desktop"

# CREATING SCAFFOLDING
Write-Output "Creating new folder $UserPath\FF_BM that will contain all results"

if (-not (Test-Path $UserPath\FF_BM)) {
    New-Item -Path $UserPath -Name FF_BM -ItemType "directory" | Out-Null
}
else {
    Remove-Item $UserPath\FF_BM -Recurse -Force | Out-Null
    New-Item -Path $UserPath -Name FF_BM -ItemType "directory" | Out-Null
}

# GET CURRENT STATE OF FACTORS
Write-Host "`nChecking services:"
Get-Service RemoteRegistry | Select-Object Name, Status, StartType -OutVariable RemoteRegSrv | Out-Null 
Get-Service Winmgmt | Select-Object Name, Status, StartType -OutVariable WMISrv | Out-Null 

Write-Host "`nSettings detected for Remote Registry service:"
$RemoteRegSrv
Write-Host "`nSettings detected for WMI service:"
$WMISrv

# ADDING TO FILE
$RemoteRegSrv | Out-File $UserPath\FF_BM\RemoteRegistry.txt
$WMISrv | Out-File $UserPath\FF_BM\WMI.txt

Write-Output "`nChecking for registry key:"
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).LocalAccountTokenFilterPolicy -ne 1) {
    Write-Output "LATFP key does not exist"
    New-Item -Path $UserPath\FF_BM\ -Name "UAC.txt" -ItemType "file" | Out-Null
    Add
net start RemoteRegistry
} else {
Write-Output "Service already started"
}

Write-Output "`nStarting Windows Management Instrumentation service:"
If (Select-String -Path $UserPath\FF_BM\WMI.txt -Pattern "Disabled") {
Write-Output "Enabling service..."
net start winmgmt | Out-Null
Write-Output "Successfully started!"
} else {
Write-Output "Service already started"
}

#FINAL REPORT
Write-Host "nnAll done!" -ForegroundColor Green

Write-Output "To revert all changes, run the following commands:"
Write-Output "REG DELETE HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /f"
Write-Output "netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No"
Write-Output "net stop RemoteRegistry"
Write-Output "sc config RemoteRegistry start=disabled"
Write-Output "net stop winmgmt"
Write-Output "sc config winmgmt start=disabled"

Write-Output "`nScript execution complete! Please check the FF_BM folder on your Desktop for more details."
