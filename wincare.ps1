<#
===============================================================================
Win Care Pro - Intelligent Windows Maintenance Tool
Filename: Win-Care-Pro.ps1
Author: Mahmoud Almezali (Multitech)
Language: English/Arabic Support
Version: 2.0
Description:
  A professional, terminal-based, intelligent Windows maintenance tool.
  - Works on Windows 7, 8.1, 10 and 11 (x86/x64)
  - Enhanced features: improved detection, better error handling, 
    detailed progress reporting, performance optimization
===============================================================================
#>

#region --- Header & Configuration ---
$Global:AppName     = "Win Care Pro"
$Global:Version     = "2.0"
$Global:LogFolder   = "$env:ProgramData\WinCare\Logs"
$Global:LogFile     = Join-Path $Global:LogFolder ("wincare-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
$Global:DryRun      = $false
$Global:ApproveAll  = $false
$Global:PromptEach  = $true
$Global:ColorOutput = $true
$Global:VerboseMode = $false

# Ensure log folder exists
if (-not (Test-Path $Global:LogFolder)) {
    try {
        New-Item -Path $Global:LogFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        $Global:LogFolder = $env:TEMP
        $Global:LogFile = Join-Path $Global:LogFolder ("wincare-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
    }
}
#endregion

#region --- Utility Functions ---
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")] [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$timestamp] [$Level] $Message"
    
    try {
        $entry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    
    if ($Global:ColorOutput) {
        switch ($Level) {
            "INFO"    { Write-Host $entry -ForegroundColor Cyan }
            "WARN"    { Write-Host $entry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $entry -ForegroundColor Red }
            "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        }
    } else {
        Write-Host $entry
    }
}

function Ensure-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "===========================================================" -ForegroundColor Red
        Write-Host "  Administrator privileges required!" -ForegroundColor Yellow
        Write-Host "  Attempting to restart with elevated permissions..." -ForegroundColor Yellow
        Write-Host "===========================================================" -ForegroundColor Red
        Write-Host ""
        
        try {
            $scriptPath = $MyInvocation.MyCommand.Path
            if ([string]::IsNullOrEmpty($scriptPath)) {
                $scriptPath = $PSCommandPath
            }
            $scriptArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            Start-Process -FilePath "powershell.exe" -ArgumentList $scriptArgs -Verb RunAs
            exit
        } catch {
            Write-Host "Failed to elevate. Please run PowerShell as Administrator manually." -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit
        }
    }
}

function Write-Banner {
    Clear-Host
    
    if ($Global:ColorOutput) {
        # Large bold banner with colors
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor White
        Write-Host ""
        
        # Professional ASCII banner
        Write-Host '     ___                       ___                    ___           ___           ___           ___     ' -ForegroundColor DarkBlue
        Write-Host '    /__/\        ___          /__/\                  /  /\         /  /\         /  /\         /  /\    ' -ForegroundColor Blue
        Write-Host '   _\_ \:\      /  /\         \  \:\                /  /:/        /  /::\       /  /::\       /  /:/_   ' -ForegroundColor Blue
        Write-Host '  /__/\ \:\    /  /:/          \  \:\              /  /:/        /  /:/\:\     /  /:/\:\     /  /:/ /\  ' -ForegroundColor Blue
        Write-Host ' _\_ \:\ \:\  /__/::\      _____\__\:\            /  /:/  ___   /  /:/~/::\   /  /:/~/:/    /  /:/ /:/_ ' -ForegroundColor Green
        Write-Host '/__/\ \:\ \:\ \__\/\:\__  /__/::::::::\          /__/:/  /  /\ /__/:/ /:/\:\ /__/:/ /:/___ /__/:/ /:/ /\' -ForegroundColor Green
        Write-Host '\  \:\ \:\/:/    \  \:\/\ \  \:\~~\~~\/          \  \:\ /  /:/ \  \:\/:/__\/ \  \:\/:::::/ \  \:\/:/ /:/' -ForegroundColor Green
        Write-Host ' \  \:\ \::/      \__\::/  \  \:\  ~~~            \  \:\  /:/   \  \::/       \  \::/~~~~   \  \::/ /:/ ' -ForegroundColor Green
        Write-Host '  \  \:\/:/       /__/:/    \  \:\                 \  \:\/:/     \  \:\        \  \:\        \  \:\/:/  ' -ForegroundColor Magenta
        Write-Host '   \  \::/        \__\/      \  \:\                 \  \::/       \  \:\        \  \:\        \  \::/   ' -ForegroundColor Magenta
        Write-Host '    \__\/                     \__\/                  \__\/         \__\/         \__\/         \__\/    ' -ForegroundColor Magenta
        Write-Host ""
        Write-Host "                     Professional Maintenance Tool" -ForegroundColor Gray
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor White
        Write-Host ""
        Write-Host "                        Version: $Global:Version" -ForegroundColor Magenta
        Write-Host "                        Author: Mahmoud Almezali" -ForegroundColor DarkGray
        Write-Host "                        Log: $Global:LogFile" -ForegroundColor DarkGray
        Write-Host ""
    } else {
        # Simple text banner for non-color terminals
        Write-Host ""
        Write-Host "============================================================"
        Write-Host ""
        Write-Host '     ___                       ___                    ___           ___           ___           ___     '
        Write-Host '    /__/\        ___          /__/\                  /  /\         /  /\         /  /\         /  /\    '
        Write-Host '   _\_ \:\      /  /\         \  \:\                /  /:/        /  /::\       /  /::\       /  /:/_   '
        Write-Host '  /__/\ \:\    /  /:/          \  \:\              /  /:/        /  /:/\:\     /  /:/\:\     /  /:/ /\  '
        Write-Host ' _\_ \:\ \:\  /__/::\      _____\__\:\            /  /:/  ___   /  /:/~/::\   /  /:/~/:/    /  /:/ /:/_ '
        Write-Host '/__/\ \:\ \:\ \__\/\:\__  /__/::::::::\          /__/:/  /  /\ /__/:/ /:/\:\ /__/:/ /:/___ /__/:/ /:/ /\'
        Write-Host '\  \:\ \:\/:/    \  \:\/\ \  \:\~~\~~\/          \  \:\ /  /:/ \  \:\/:/__\/ \  \:\/:::::/ \  \:\/:/ /:/'
        Write-Host ' \  \:\ \::/      \__\::/  \  \:\  ~~~            \  \:\  /:/   \  \::/       \  \::/~~~~   \  \::/ /:/ '
        Write-Host '  \  \:\/:/       /__/:/    \  \:\                 \  \:\/:/     \  \:\        \  \:\        \  \:\/:/  '
        Write-Host '   \  \::/        \__\/      \  \:\                 \  \::/       \  \:\        \  \:\        \  \::/   '
        Write-Host '    \__\/                     \__\/                  \__\/         \__\/         \__\/         \__\/    '
        Write-Host ""
        Write-Host "                     Professional Maintenance Tool"
        Write-Host ""
        Write-Host "============================================================"
        Write-Host ""
        Write-Host "                        Version: $Global:Version"
        Write-Host "                        Author: Mahmoud Almezali"
        Write-Host "                        Log: $Global:LogFile"
        Write-Host ""
    }
}

function Prompt-YesNo([string]$Message, [bool]$DefaultYes = $true) {
    if ($Global:DryRun) { 
        Write-Log "DRY-RUN: Prompted: $Message" "WARN"
        return $true 
    }
    if ($Global:ApproveAll) { 
        Write-Log "AUTO-APPROVE: $Message" "INFO"
        return $true 
    }
    
    $default = if ($DefaultYes) { "Y" } else { "N" }
    $prompt = "$Message [Y/N] (default: $default)"
    
    while ($true) {
        Write-Host $prompt -ForegroundColor Yellow -NoNewline
        Write-Host " : " -NoNewline
        $resp = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $default }
        
        if ($resp -match '^[YyYes]') { return $true } 
        if ($resp -match '^[NnNo]') { return $false }
        
        Write-Host "Please answer Y or N." -ForegroundColor Red
    }
}

function Show-Progress {
    param(
        [string]$Activity,
        [int]$Seconds = 4
    )
    
    $end = (Get-Date).AddSeconds($Seconds)
    $totalMs = $Seconds * 1000
    
    while ((Get-Date) -lt $end) {
        $remaining = ($end - (Get-Date)).TotalMilliseconds
        $percent = [int](100 - (($remaining / $totalMs) * 100))
        
        if ($percent -lt 0) { $percent = 0 }
        if ($percent -gt 100) { $percent = 100 }
        
        Write-Progress -Activity $Activity -Status "$percent% complete" -PercentComplete $percent
        Start-Sleep -Milliseconds 200
    }
    
    Write-Progress -Activity $Activity -Completed
}

function Task-CleanBrowserCache {
    Write-Log "Task: Clean Browser Cache started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would clean browser cache from Chrome, Edge, Firefox" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Cleaning browser cache" -Seconds 4
    
    $totalCleaned = 0
    $browsers = @()
    
    # Chrome
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache"
    )
    
    # Edge
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\GPUCache"
    )
    
    # Firefox
    $firefoxPaths = @()
    $firefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -ErrorAction SilentlyContinue
    foreach ($firefoxProfile in $firefoxProfiles) {
        $firefoxPaths += "$($firefoxProfile.FullName)\cache2"
    }
    
    $allPaths = $chromePaths + $edgePaths + $firefoxPaths
    
    foreach ($path in $allPaths) {
        if (Test-Path $path) {
            try {
                $beforeSize = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $afterSize = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                
                $cleaned = ($beforeSize - $afterSize) / 1MB
                $totalCleaned += $cleaned
                
                if ($cleaned -gt 0) {
                    $browser = if ($path -like "*Chrome*") { "Chrome" } 
                              elseif ($path -like "*Edge*") { "Edge" } 
                              else { "Firefox" }
                    $browsers += $browser
                }
            } catch {
                Write-Log ("Failed to clean browser cache at {0}: {1}" -f $path, $_.Exception.Message) "WARN"
            }
        }
    }
    
    if ($totalCleaned -gt 0) {
        Write-Log ("Browser cache cleaned: {0:N2} MB from {1}" -f $totalCleaned, ($browsers -join ", ")) "SUCCESS"
        Write-Host ("[OK] Cleaned {0:N2} MB from browser cache ({1})" -f $totalCleaned, ($browsers -join ", ")) -ForegroundColor Green
    } else {
        Write-Log "No browser cache found to clean" "INFO"
        Write-Host "[OK] No browser cache found to clean" -ForegroundColor Green
    }
}

function Task-DisableStartupApps {
    Write-Log "Task: Disable Startup Apps started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would analyze and suggest disabling startup apps" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Analyzing startup applications" -Seconds 3
    
    try {
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue
        
        if ($startupItems) {
            Write-Host "`nCurrent Startup Applications:" -ForegroundColor Cyan
            Write-Host ("=" * 80) -ForegroundColor DarkGray
            
            $startupItems | ForEach-Object {
                $name = $_.Name
                $command = $_.Command
                $location = $_.Location
                
                Write-Host "Name: $name" -ForegroundColor White
                Write-Host "Command: $command" -ForegroundColor Gray
                Write-Host "Location: $location" -ForegroundColor DarkGray
                Write-Host ("-" * 80) -ForegroundColor DarkGray
            }
            
            Write-Host "`nNote: To disable startup apps, use Task Manager > Startup tab" -ForegroundColor Yellow
            Write-Host "Or run: Get-CimInstance Win32_StartupCommand | Remove-CimInstance" -ForegroundColor DarkGray
            
            Write-Log ("Found {0} startup applications" -f $startupItems.Count) "INFO"
        } else {
            Write-Host "No startup applications found" -ForegroundColor Green
            Write-Log "No startup applications found" "INFO"
        }
        
    } catch {
        Write-Log "DisableStartupApps error: $_" "ERROR"
        Write-Host "[ERROR] Failed to analyze startup applications" -ForegroundColor Red
    }
}

function Task-OptimizeServices {
    Write-Log "Task: Optimize Services started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would analyze and suggest service optimizations" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Analyzing Windows services" -Seconds 4
    
    try {
        # Services that can typically be set to Manual or Disabled
        $optimizableServices = @(
            @{Name="Fax"; Description="Fax Service"},
            @{Name="WSearch"; Description="Windows Search"},
            @{Name="TabletInputService"; Description="Tablet PC Input Service"},
            @{Name="XblAuthManager"; Description="Xbox Live Auth Manager"},
            @{Name="XblGameSave"; Description="Xbox Live Game Save"},
            @{Name="XboxNetApiSvc"; Description="Xbox Live Networking Service"},
            @{Name="TrkWks"; Description="Distributed Link Tracking Client"},
            @{Name="RemoteRegistry"; Description="Remote Registry"},
            @{Name="RemoteAccess"; Description="Routing and Remote Access"},
            @{Name="WMPNetworkSvc"; Description="Windows Media Player Network Sharing Service"}
        )
        
        Write-Host "`nService Optimization Analysis:" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor DarkGray
        
        $foundServices = 0
        
        foreach ($serviceInfo in $optimizableServices) {
            $service = Get-Service -Name $serviceInfo.Name -ErrorAction SilentlyContinue
            if ($service) {
                $foundServices++
                $status = $service.Status
                $startType = $service.StartType
                
                $color = if ($status -eq 'Running' -and $startType -eq 'Automatic') { 'Red' } 
                        elseif ($startType -eq 'Automatic') { 'Yellow' } 
                        else { 'Green' }
                
                Write-Host ("Service: {0}" -f $serviceInfo.Name) -ForegroundColor $color
                Write-Host ("  Description: {0}" -f $serviceInfo.Description) -ForegroundColor Gray
                Write-Host ("  Status: {0}, Start Type: {1}" -f $status, $startType) -ForegroundColor Gray
                
                if ($status -eq 'Running' -and $startType -eq 'Automatic') {
                    Write-Host ("  Suggestion: Can be set to Manual or Disabled" -f $serviceInfo.Name) -ForegroundColor Yellow
                }
                Write-Host ("-" * 60) -ForegroundColor DarkGray
            }
        }
        
        if ($foundServices -gt 0) {
            Write-Host "`nNote: Use 'sc config <service> start= demand' to set to Manual" -ForegroundColor Yellow
            Write-Host "Use 'sc config <service> start= disabled' to disable" -ForegroundColor Yellow
            Write-Log ("Analyzed {0} optimizable services" -f $foundServices) "INFO"
        } else {
            Write-Host "No commonly optimizable services found" -ForegroundColor Green
        }
        
    } catch {
        Write-Log "OptimizeServices error: $_" "ERROR"
        Write-Host "[ERROR] Failed to analyze services" -ForegroundColor Red
    }
}

function Task-GenerateReport {
    Write-Log "Task: Generate Report started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would generate text system report" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Generating system report" -Seconds 5
    
    try {
        $reportPath = Join-Path $env:TEMP "WinCare_SystemReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        
        # Gather system information
        $sysInfo = Detect-System
        $recommendations = Recommend-Tasks $sysInfo
        
        # Create text report content using safe line-joining (avoid here-strings)
        $lines = @(
            "============================================================",
            "Win Care Pro - System Report",
            ("Generated on: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
            "============================================================",
            "",
            "SYSTEM INFORMATION:",
            "==================",
            "Operating System: $($sysInfo.OS) (Build $($sysInfo.BuildNumber))",
            "Architecture: $($sysInfo.Architecture)",
            "Computer: $($sysInfo.ComputerName)",
            "RAM: $($sysInfo.TotalRAM_GB) GB",
            "C: Drive: $($sysInfo.FreeSpaceGB) GB free of $($sysInfo.TotalSpaceGB) GB $($sysInfo.DiskUsagePercent) percent used",
            "Uptime: $([math]::Round($sysInfo.Uptime.TotalDays, 1)) days",
            "Pending Reboot: $(if($sysInfo.PendingReboot){'Yes'}else{'No'})",
            "",
            "RECOMMENDATIONS:",
            "================"
        )

        if ($recommendations) {
            $lines += ($recommendations | ForEach-Object { "* $_" })
        }

        $lines += @(
            "",
            "AVAILABLE TOOLS:",
            "================",
            "SFC (System File Checker): $(if($sysInfo.SFCAvailable){'Available'}else{'Not Available'})",
            "DISM: $(if($sysInfo.DISMAvailable){'Available'}else{'Not Available'})",
            "Windows Defender: $(if($sysInfo.DefenderPresent){'Available'}else{'Not Available'})",
            "",
            "NEXT STEPS:",
            "===========",
            "1. Run cleanup tasks to free disk space",
            "2. Execute system file checker if corruption suspected",
            "3. Check for Windows updates",
            "4. Create a system restore point before major changes",
            "5. Schedule regular maintenance using Win Care Pro",
            "",
            "============================================================",
            "Report generated by Win Care Pro v$Global:Version",
            "Author: Mahmoud Almezali",
            "============================================================"
        )

        $reportContent = ($lines -join [Environment]::NewLine)

        $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-Log ("System report generated: {0}" -f $reportPath) "SUCCESS"
        Write-Host "[OK] System report generated successfully" -ForegroundColor Green
        Write-Host "  Report location: $reportPath" -ForegroundColor Cyan
        
        # Try to open the report
        try {
            Start-Process $reportPath
            Write-Host "  Report opened in default editor" -ForegroundColor Green
        } catch {
            Write-Host "  Please open the report manually" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "GenerateReport error: $_" "ERROR"
        Write-Host "[ERROR] Failed to generate system report" -ForegroundColor Red
    }
}
#endregion

#region --- System Detection & Smart Recommendation ---
function Detect-System {
    Write-Log "Starting system detection..." "INFO"
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -like "*:\" }
        $cDrive = $drives | Where-Object { $_.Name -eq 'C' }
        $free = if ($cDrive) { [math]::Round(($cDrive.Free / 1GB), 2) } else { 0 }
        $used = if ($cDrive) { [math]::Round(($cDrive.Used / 1GB), 2) } else { 0 }
        $total = $free + $used
        
        $pendingReboot = Test-PendingReboot
        $dismAvailable = $null -ne (Get-Command -Name dism -ErrorAction SilentlyContinue)
        $defenderPresent = Test-Path "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
        $sfcAvailable = $null -ne (Get-Command -Name sfc -ErrorAction SilentlyContinue)
        
        $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        
        $info = [PSCustomObject]@{
            OS              = $os.Caption
            Version         = $os.Version
            BuildNumber     = $os.BuildNumber
            Architecture    = $arch
            ComputerName    = $cs.Name
            TotalRAM_GB     = $ramGB
            FreeSpaceGB     = $free
            UsedSpaceGB     = $used
            TotalSpaceGB    = $total
            DiskUsagePercent = if ($total -gt 0) { [math]::Round(($used / $total) * 100, 1) } else { 0 }
            PendingReboot   = $pendingReboot
            DISMAvailable   = $dismAvailable
            DefenderPresent = $defenderPresent
            SFCAvailable    = $sfcAvailable
            LastBootTime    = $os.LastBootUpTime
            Uptime          = (Get-Date) - $os.LastBootUpTime
        }
        
        Write-Log ("Detected: {0} [{1}], Build: {2}, RAM: {3}GB, C: {4}GB free of {5}GB {6} percent used" -f $info.OS, $info.Architecture, $info.BuildNumber, $info.TotalRAM_GB, $info.FreeSpaceGB, $info.TotalSpaceGB, $info.DiskUsagePercent) "INFO"
        
        return $info
        
    } catch {
        Write-Log "System detection failed: $_" "ERROR"
        return $null
    }
}

function Test-PendingReboot {
    
    $rebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    
    foreach ($key in $rebootKeys) {
        if (Test-Path $key) { return $true }
    }
    
    # Check pending file rename operations
    try {
        $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pfro) { return $true }
    } catch {}
    
    return $false
}

function Recommend-Tasks($sysInfo) {
    $recommend = @()
    
    if ($sysInfo.FreeSpaceGB -lt 10) { 
        $recommend += ("[CRITICAL] Low disk space " + $sysInfo.FreeSpaceGB + " GB free - Run cleanup tasks")
    }
    
    if ($sysInfo.DiskUsagePercent -gt 90) {
        $recommend += ("[WARNING] Disk usage very high " + $sysInfo.DiskUsagePercent + " percent - Clean temporary files urgently")
    }
    
    if ($sysInfo.SFCAvailable) { 
        $recommend += "Run System File Checker (SFC) for system integrity"
    }
    
    if ($sysInfo.PendingReboot) { 
        $recommend += "[IMPORTANT] System requires a reboot (pending updates/changes)"
    }
    
    if ($sysInfo.DISMAvailable) { 
        $recommend += "DISM RestoreHealth available for component store repair"
    }
    
    if (-not $sysInfo.DefenderPresent) { 
        $recommend += "[NOTE] Windows Defender not detected - ensure antivirus protection"
    }
    
    $uptimeDays = [math]::Round($sysInfo.Uptime.TotalDays, 1)
    if ($uptimeDays -gt 30) {
        $recommend += "System uptime: ${uptimeDays} days - Consider rebooting soon"
    }
    
    if ($recommend.Count -eq 0) { 
        $recommend += "System appears healthy - Run general maintenance tasks"
    }
    
    Write-Log -Message ("Recommended tasks: " + ($recommend -join "; ")) -Level 'INFO'
    return $recommend
}
#endregion

#region --- Task Implementations ---
function Task-CleanupTemp {
    Write-Log "Task: Cleanup Temp started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would remove temp files from multiple locations" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Cleaning temporary files" -Seconds 3
    
    $paths = @(
        $env:TEMP,
        "$env:windir\Temp",
        "$env:windir\Prefetch",
        "$env:LocalAppData\Temp"
    )
    
    $totalCleaned = 0
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                $beforeSize = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $afterSize = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                
                $cleaned = ($beforeSize - $afterSize) / 1MB
                $totalCleaned += $cleaned
                
                if ($Global:VerboseMode) {
                    Write-Log ("Cleaned {0}: {1:N2} MB" -f $path, $cleaned) "INFO"
                }
            } catch {
                Write-Log ("Failed to clean {0}: {1}" -f $path, $_.Exception.Message) "WARN"
            }
        }
    }
    
    Write-Log ("Total space freed: {0:N2} MB" -f $totalCleaned) "SUCCESS"
    Write-Host ("[OK] Cleaned {0:N2} MB of temporary files" -f $totalCleaned) -ForegroundColor Green
}

function Task-RunSFC {
    Write-Log "Task: Run SFC started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would run: sfc /scannow" -ForegroundColor Yellow
        return 
    }
    
    Write-Host "Running System File Checker (this may take 10-15 minutes)..." -ForegroundColor Cyan
    Show-Progress -Activity "Running SFC /SCANNOW" -Seconds 6
    
    try {
        $proc = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait -PassThru
        
        switch ($proc.ExitCode) {
            0 { Write-Log "SFC: No integrity violations found" "SUCCESS" }
            default { Write-Log ("SFC completed with exit code: {0}" -f $proc.ExitCode) "INFO" }
        }
        
        Write-Host "[OK] SFC scan completed. Check CBS.log for details." -ForegroundColor Green
        
    } catch {
        Write-Log "SFC failed: $_" "ERROR"
        Write-Host "[ERROR] SFC failed. See log for details." -ForegroundColor Red
    }
}

function Task-RunDISM {
    Write-Log "Task: Run DISM started." "INFO"
    
    if (-not (Get-Command -Name dism -ErrorAction SilentlyContinue)) {
        Write-Log "DISM not found on this machine." "WARN"
        Write-Host "DISM not available on this system." -ForegroundColor Yellow
        return
    }
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would run: DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Yellow
        return 
    }
    
    Write-Host "Running DISM RestoreHealth (this may take 15-30 minutes)..." -ForegroundColor Cyan
    Show-Progress -Activity "Running DISM RestoreHealth" -Seconds 8
    
    try {
        $proc = Start-Process -FilePath "dism.exe" -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -NoNewWindow -Wait -PassThru
        
        if ($proc.ExitCode -eq 0) {
            Write-Log "DISM RestoreHealth completed successfully" "SUCCESS"
            Write-Host "[OK] DISM repair completed successfully" -ForegroundColor Green
        } else {
            Write-Log ("DISM exit code: {0}" -f $proc.ExitCode) "WARN"
            Write-Host ("DISM completed with code: {0}" -f $proc.ExitCode) -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "DISM failed: $_" "ERROR"
        Write-Host "[ERROR] DISM failed. See log for details." -ForegroundColor Red
    }
}

function Task-CleanupWindowsUpdate {
    Write-Log "Task: Cleanup Windows Update cache started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would stop wuauserv and clean SoftwareDistribution\Download" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Cleaning Windows Update cache" -Seconds 4
    
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        if ($wuService -and $wuService.Status -eq 'Running') {
            Stop-Service -Name wuauserv -Force -ErrorAction Stop
            Write-Log "Windows Update service stopped" "INFO"
        }
        
        $downloadPath = "$env:SystemRoot\SoftwareDistribution\Download"
        
        if (Test-Path $downloadPath) {
            $beforeSize = (Get-ChildItem $downloadPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            Get-ChildItem $downloadPath -Recurse -Force -ErrorAction SilentlyContinue | 
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            
            Write-Log ("Cleaned Windows Update cache: {0:N2} MB" -f $beforeSize) "SUCCESS"
            Write-Host ("[OK] Cleaned {0:N2} MB from Windows Update cache" -f $beforeSize) -ForegroundColor Green
        }
        
        if ($wuService) {
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-Log "Windows Update service restarted" "INFO"
        }
        
    } catch {
        Write-Log "CleanupWindowsUpdate error: $_" "ERROR"
        Write-Host "[ERROR] Failed to clean Windows Update cache" -ForegroundColor Red
    }
}

function Task-ResetNetwork {
    Write-Log "Task: Reset Network started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would run network reset commands" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Resetting network stack" -Seconds 4
    
    try {
        Write-Host "Resetting Winsock..." -ForegroundColor Cyan
        netsh winsock reset 2>&1 | Out-Null
        
        Write-Host "Flushing DNS cache..." -ForegroundColor Cyan
        ipconfig /flushdns 2>&1 | Out-Null
        
        Write-Host "Resetting TCP/IP stack..." -ForegroundColor Cyan
        netsh int ip reset 2>&1 | Out-Null
        
        Write-Log "Network reset completed successfully" "SUCCESS"
        Write-Host "[OK] Network stack reset completed. Reboot recommended." -ForegroundColor Green
        
    } catch {
        Write-Log "ResetNetwork error: $_" "ERROR"
        Write-Host "[ERROR] Network reset failed" -ForegroundColor Red
    }
}

function Task-DefenderQuickScan {
    Write-Log "Task: Defender Quick Scan started." "INFO"
    
    $defPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    
    if (-not (Test-Path $defPath)) {
        Write-Log "Windows Defender not present or path not found." "WARN"
        Write-Host "Windows Defender not found. Skipping scan." -ForegroundColor Yellow
        return
    }
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would start Windows Defender quick scan" -ForegroundColor Yellow
        return 
    }
    
    Write-Host "Starting Windows Defender quick scan..." -ForegroundColor Cyan
    Show-Progress -Activity "Starting Windows Defender quick scan" -Seconds 6
    
    try {
        $proc = Start-Process -FilePath $defPath -ArgumentList "-Scan","-ScanType","1" -Wait -PassThru -NoNewWindow
        
        if ($proc.ExitCode -eq 0) {
            Write-Log "Defender quick scan completed - no threats found" "SUCCESS"
            Write-Host "[OK] Defender scan completed successfully" -ForegroundColor Green
        } else {
            Write-Log ("Defender scan exit code: {0}" -f $proc.ExitCode) "WARN"
            Write-Host "Defender scan completed. Check Windows Security for details." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "Defender scan error: $_" "ERROR"
        Write-Host "[ERROR] Defender scan failed" -ForegroundColor Red
    }
}

function Task-Defrag {
    Write-Log "Task: Defragmentation started." "INFO"
    
    # Check if C: is SSD
    try {
        $disk = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq 0 }
        if ($disk.MediaType -eq 'SSD') {
            Write-Host "SSD detected. Running optimization instead of defragmentation..." -ForegroundColor Cyan
        }
    } catch {}
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would run disk optimization" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Optimizing disk (may take several minutes)" -Seconds 6
    
    try {
        Start-Process -FilePath "defrag.exe" -ArgumentList "C:","/U","/V" -Wait -PassThru -NoNewWindow | Out-Null
        
        Write-Log "Disk optimization completed" "SUCCESS"
        Write-Host "[OK] Disk optimization completed" -ForegroundColor Green
        
    } catch {
        Write-Log "Defrag error: $_" "ERROR"
        Write-Host "[ERROR] Disk optimization failed" -ForegroundColor Red
    }
}

function Task-CheckDisk {
    Write-Log "Task: CheckDisk (chkdsk) started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would run: chkdsk C: /scan" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Running CHKDSK scan" -Seconds 4
    
    try {
        Write-Host "Scanning disk for errors..." -ForegroundColor Cyan
        chkdsk C: /scan 2>&1 | Out-Null
        
        Write-Log "CHKDSK scan completed" "SUCCESS"
        Write-Host "[OK] CHKDSK scan completed" -ForegroundColor Green
        Write-Host "  For full repair, run: chkdsk C: /F /R (requires reboot)" -ForegroundColor DarkGray
        
    } catch {
        Write-Log "CHKDSK error: $_" "ERROR"
        Write-Host "[ERROR] CHKDSK failed" -ForegroundColor Red
    }
}

function Task-CreateSystemRestore {
    Write-Log "Task: Create System Restore Point started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would create System Restore point" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Creating system restore point" -Seconds 3
    
    try {
        if (Get-Command -Name Checkpoint-Computer -ErrorAction SilentlyContinue) {
            $description = "WinCare_PreMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            
            Write-Log ("System restore point created: {0}" -f $description) "SUCCESS"
            Write-Host "[OK] Restore point created successfully" -ForegroundColor Green
            
        } else {
            Write-Log "Checkpoint-Computer not available on this system" "WARN"
            Write-Host "System Restore not supported or disabled" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "CreateSystemRestore error: $_" "ERROR"
        Write-Host "[ERROR] Failed to create restore point" -ForegroundColor Red
    }
}

function Task-ListStartupItems {
    Write-Log "Task: List Startup Items." "INFO"
    
    try {
        Show-Progress -Activity "Gathering startup items" -Seconds 2
        
        $items = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | 
            Select-Object Name, Command, Location, User
        
        if ($items -and $items.Count -gt 0) {
            Write-Host "`nStartup Items Found: $($items.Count)" -ForegroundColor Cyan
            Write-Host ("=" * 80) -ForegroundColor DarkGray
            $items | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "No startup items found or insufficient permissions" -ForegroundColor Yellow
        }
        
        Write-Log ("Listed {0} startup items" -f $items.Count) "INFO"
        
    } catch {
        Write-Log "ListStartupItems error: $_" "ERROR"
        Write-Host "[ERROR] Failed to list startup items" -ForegroundColor Red
    }
}

function Task-ListInstalledUpdates {
    Write-Log "Task: List Installed Updates." "INFO"
    
    try {
        Show-Progress -Activity "Querying installed updates" -Seconds 3
        
        Write-Host "`nQuerying installed Windows updates..." -ForegroundColor Cyan
        
        $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
        
        if ($updates) {
            Write-Host "`nLast 20 Installed Updates:" -ForegroundColor Cyan
            Write-Host ("=" * 80) -ForegroundColor DarkGray
            $updates | Format-Table HotFixID, Description, InstalledOn, InstalledBy -AutoSize
        } else {
            Write-Host "No update information available" -ForegroundColor Yellow
        }
        
        Write-Log "Installed updates listed" "INFO"
        
    } catch {
        Write-Log "ListInstalledUpdates error: $_" "ERROR"
        Write-Host "[ERROR] Failed to list updates" -ForegroundColor Red
    }
}

function Task-DriverInventory {
    Write-Log "Task: Driver inventory started." "INFO"
    
    try {
        Show-Progress -Activity "Collecting driver list" -Seconds 3
        
        Write-Host "`nCollecting driver information..." -ForegroundColor Cyan
        $drivers = pnputil /enum-drivers 2>$null
        
        if ($drivers) {
            $drivers | Select-Object -First 100
            Write-Host "`n(Showing first 100 drivers)" -ForegroundColor DarkGray
        }
        
        Write-Log "Driver inventory completed" "INFO"
        
    } catch {
        Write-Log "DriverInventory error: $_" "ERROR"
        Write-Host "[ERROR] Failed to inventory drivers" -ForegroundColor Red
    }
}

function Task-WindowsUpdateCheck {
    Write-Log "Task: Windows Update check started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would check Windows Update status" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Checking Windows Update service" -Seconds 3
    
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        if ($wuService) {
            $status = $wuService.Status
            $startType = $wuService.StartType
            
            Write-Host "`nWindows Update Service Status:" -ForegroundColor Cyan
            Write-Host ("  Status: {0}" -f $status) -ForegroundColor $(if ($status -eq 'Running') { 'Green' } else { 'Yellow' })
            Write-Host ("  Start Type: {0}" -f $startType) -ForegroundColor DarkGray
            
            Write-Log ("Windows Update service - Status: {0}, StartType: {1}" -f $status, $startType) "INFO"
        } else {
            Write-Host "Windows Update service not found" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "WindowsUpdateCheck error: $_" "ERROR"
        Write-Host "[ERROR] Failed to check Windows Update status" -ForegroundColor Red
    }
}

function Task-ClearRecycleBin {
    Write-Log "Task: Clear Recycle Bin started." "INFO"
    
    if ($Global:DryRun) { 
        Write-Host "[DRY-RUN] Would empty Recycle Bin" -ForegroundColor Yellow
        return 
    }
    
    Show-Progress -Activity "Emptying Recycle Bin" -Seconds 3
    
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xa)  # 0xa = RecycleBin
        
        if ($recycleBin.Items().Count -gt 0) {
            $itemCount = $recycleBin.Items().Count
            $recycleBin.Items() | ForEach-Object { $_.InvokeVerb("delete") }
            
            Write-Log -Message ("Recycle Bin cleared: " + $itemCount + " items removed") -Level "SUCCESS"
            Write-Host ("[OK] Recycle Bin cleared (" + $itemCount + " items)") -ForegroundColor Green
        } else {
            Write-Log -Message "Recycle Bin is already empty" -Level "INFO"
            Write-Host "[OK] Recycle Bin is already empty" -ForegroundColor Green
        }
        
    } catch {
        Write-Log "ClearRecycleBin error: $_" "ERROR"
        Write-Host "[ERROR] Failed to clear Recycle Bin" -ForegroundColor Red
    }
}
#endregion

#region --- Main Menu ---
function Show-SystemInfo($sysInfo) {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "  SYSTEM INFORMATION" -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    
    Write-Host "  OS: $($sysInfo.OS) ($($sysInfo.Architecture))" -ForegroundColor White
    Write-Host "  Build: $($sysInfo.BuildNumber)" -ForegroundColor Gray
    Write-Host "  Computer: $($sysInfo.ComputerName)" -ForegroundColor Gray
    Write-Host "  RAM: $($sysInfo.TotalRAM_GB) GB" -ForegroundColor Gray
    Write-Host "  C: Drive: $($sysInfo.FreeSpaceGB) GB free of $($sysInfo.TotalSpaceGB) GB $($sysInfo.DiskUsagePercent) percent used" -ForegroundColor Gray
    Write-Host "  Uptime: $([math]::Round($sysInfo.Uptime.TotalDays, 1)) days" -ForegroundColor Gray
    
    if ($sysInfo.PendingReboot) {
        Write-Host "  [WARNING] PENDING REBOOT REQUIRED" -ForegroundColor Yellow
    }
    
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu($SystemInfo, $Recommendations) {
    do {
        Clear-Host
        Write-Banner
        Show-SystemInfo $SystemInfo
        
        # Show recommendations if any
        if ($Recommendations -and $Recommendations.Count -gt 0) {
            Write-Host "[RECOMMEND] RECOMMENDATIONS:" -ForegroundColor Yellow
            foreach ($rec in $Recommendations) {
                $color = if ($rec -like "*CRITICAL*") { "Red" } 
                        elseif ($rec -like "*WARNING*" -or $rec -like "*IMPORTANT*") { "Yellow" } 
                        else { "Green" }
                Write-Host "  * $rec" -ForegroundColor $color
            }
            Write-Host ""
        }
        
        Write-Host "[REPAIR] MAINTENANCE OPTIONS:" -ForegroundColor Cyan
        Write-Host ""
        
        # Cleaning Tasks
        Write-Host "  [CLEAN] CLEANING TASKS:" -ForegroundColor Green
        Write-Host "    [1] Clean Temporary Files" -ForegroundColor White
        Write-Host "    [2] Clear Recycle Bin" -ForegroundColor White
        Write-Host "    [3] Clean Browser Cache (Chrome/Edge/Firefox)" -ForegroundColor White
        Write-Host "    [4] Clean Windows Update Cache" -ForegroundColor White
        Write-Host "    [5] Clean All Above" -ForegroundColor Yellow
        Write-Host ""
        
        # System Repair
        Write-Host "  [REPAIR] SYSTEM REPAIR:" -ForegroundColor Blue
        Write-Host "    [6] Run System File Checker (SFC)" -ForegroundColor White
        Write-Host "    [7] Run DISM RestoreHealth" -ForegroundColor White
        Write-Host "    [8] Check Disk (CHKDSK)" -ForegroundColor White
        Write-Host "    [9] Reset Network Stack" -ForegroundColor White
        Write-Host ""
        
        # Optimization
        Write-Host "  [OPTIMIZE] OPTIMIZATION:" -ForegroundColor Magenta
        Write-Host "    [10] Optimize Disk (Defrag/SSD Trim)" -ForegroundColor White
        Write-Host "    [11] Analyze Startup Applications" -ForegroundColor White
        Write-Host "    [12] Optimize Windows Services" -ForegroundColor White
        Write-Host ""
        
        # Security
        Write-Host "  [SECURITY] SECURITY:" -ForegroundColor Red
        Write-Host "    [13] Windows Defender Quick Scan" -ForegroundColor White
        Write-Host "    [14] Create System Restore Point" -ForegroundColor White
        Write-Host ""
        
        # Information
        Write-Host "  [INFO] INFORMATION:" -ForegroundColor DarkCyan
        Write-Host "    [15] List Installed Updates" -ForegroundColor White
        Write-Host "    [16] Driver Inventory" -ForegroundColor White
        Write-Host "    [17] List Startup Items" -ForegroundColor White
        Write-Host "    [18] Generate System Report (HTML)" -ForegroundColor White
        Write-Host ""
        
        # Special Options
        Write-Host "  [AUTO] SPECIAL OPTIONS:" -ForegroundColor Yellow
        Write-Host "    [19] Auto Mode (Run Safe Tasks Only)" -ForegroundColor White
        Write-Host "    [20] Toggle Dry-Run Mode (Currently: $(if($Global:DryRun){'ON'}else{'OFF'}))" -ForegroundColor White
        Write-Host ""
        
        Write-Host "  [0] Exit" -ForegroundColor Red
        Write-Host ""
        
        Write-Host "===========================================================" -ForegroundColor DarkGray
        Write-Host "Choose an option [0-20]: " -ForegroundColor Yellow -NoNewline
        $choice = Read-Host
        
        switch ($choice) {
            "1" { 
                if (Prompt-YesNo "Clean temporary files?") { 
                    Task-CleanupTemp 
                    Read-Host "Press Enter to continue..."
                }
            }
            "2" { 
                if (Prompt-YesNo "Clear Recycle Bin?") { 
                    Task-ClearRecycleBin 
                    Read-Host "Press Enter to continue..."
                }
            }
            "3" { 
                if (Prompt-YesNo "Clean browser cache?") { 
                    Task-CleanBrowserCache 
                    Read-Host "Press Enter to continue..."
                }
            }
            "4" { 
                if (Prompt-YesNo "Clean Windows Update cache?") { 
                    Task-CleanupWindowsUpdate 
                    Read-Host "Press Enter to continue..."
                }
            }
            "5" { 
                if (Prompt-YesNo "Run all cleaning tasks?") { 
                    Write-Log "Starting comprehensive cleanup..." "INFO"
                    Task-CleanupTemp
                    Task-ClearRecycleBin
                    Task-CleanBrowserCache
                    Task-CleanupWindowsUpdate
                    Write-Host "[OK] All cleaning tasks completed!" -ForegroundColor Green
                    Read-Host "Press Enter to continue..."
                }
            }
            "6" { 
                if (Prompt-YesNo "Run System File Checker? (May take 10-15 minutes)") { 
                    Task-RunSFC 
                    Read-Host "Press Enter to continue..."
                }
            }
            "7" { 
                if (Prompt-YesNo "Run DISM RestoreHealth? (May take 15-30 minutes)") { 
                    Task-RunDISM 
                    Read-Host "Press Enter to continue..."
                }
            }
            "8" { 
                if (Prompt-YesNo "Run disk check?") { 
                    Task-CheckDisk 
                    Read-Host "Press Enter to continue..."
                }
            }
            "9" { 
                if (Prompt-YesNo "Reset network stack? (Requires reboot)") { 
                    Task-ResetNetwork 
                    Read-Host "Press Enter to continue..."
                }
            }
            "10" { 
                if (Prompt-YesNo "Optimize disk?") { 
                    Task-Defrag 
                    Read-Host "Press Enter to continue..."
                }
            }
            "11" { 
                Task-DisableStartupApps
                Read-Host "Press Enter to continue..."
            }
            "12" { 
                Task-OptimizeServices
                Read-Host "Press Enter to continue..."
            }
            "13" { 
                if (Prompt-YesNo "Run Windows Defender scan?") { 
                    Task-DefenderQuickScan 
                    Read-Host "Press Enter to continue..."
                }
            }
            "14" { 
                if (Prompt-YesNo "Create system restore point?") { 
                    Task-CreateSystemRestore 
                    Read-Host "Press Enter to continue..."
                }
            }
            "15" { 
                Task-ListInstalledUpdates
                Read-Host "Press Enter to continue..."
            }
            "16" { 
                Task-DriverInventory
                Read-Host "Press Enter to continue..."
            }
            "17" { 
                Task-ListStartupItems
                Read-Host "Press Enter to continue..."
            }
            "18" { 
                Task-GenerateReport
                Read-Host "Press Enter to continue..."
            }
            "19" { 
                if (Prompt-YesNo "Run Auto Mode? (Safe tasks only - cleaning and optimization)") { 
                    Write-Log "Starting Auto Mode..." "INFO"
                    Write-Host "[AUTO] Starting Auto Mode - Safe tasks only..." -ForegroundColor Green
                    
                    # Safe cleaning tasks
                    Task-CleanupTemp
                    Task-ClearRecycleBin
                    Task-CleanBrowserCache
                    Task-CleanupWindowsUpdate
                    
                    # Safe optimization tasks
                    Task-DisableStartupApps
                    Task-OptimizeServices
                    
                    # Information tasks
                    Task-ListStartupItems
                    Task-GenerateReport
                    
                    Write-Host "[OK] Auto Mode completed successfully!" -ForegroundColor Green
                    Write-Host "Note: System repair tasks (SFC, DISM, CHKDSK) were skipped for safety." -ForegroundColor Yellow
                    Read-Host "Press Enter to continue..."
                }
            }
            "20" { 
                $Global:DryRun = -not $Global:DryRun
                Write-Host "Dry-Run Mode: $(if($Global:DryRun){'ENABLED'}else{'DISABLED'})" -ForegroundColor $(if($Global:DryRun){'Yellow'}else{'Green'})
                Start-Sleep -Seconds 2
            }
            "0" { 
                Write-Host ""
                Write-Host "Thank you for using Win Care Pro!" -ForegroundColor Cyan
                Write-Host "Log saved to: $Global:LogFile" -ForegroundColor DarkGray
                Write-Host ""
                return
            }
            default { 
                Write-Host "Invalid option. Please choose 0-20." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}
#endregion

#region --- Main Entry Point ---
# Main execution
try {
    Ensure-Admin
    Write-Banner
    $sysInfo = Detect-System
    $recommendations = Recommend-Tasks $sysInfo
    Show-MainMenu -SystemInfo $sysInfo -Recommendations $recommendations
} catch {
    Write-Log "Fatal error in main execution: $_" "ERROR"
    Write-Host "Fatal error occurred. Check log for details: $Global:LogFile" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
#endregion