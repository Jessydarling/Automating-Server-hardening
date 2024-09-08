# Windows Server Update Script

$logFilePath = "C:\Logs\WindowsUpdate.log"
$inactiveStartHour = 19 # Start of inactive hours (7 PM)
$inactiveEndHour = 8    # End of inactive hours (8 AM)

# Ensure the log directory exists
$logDir = Split-Path -Path $logFilePath -Parent
if (-not (Test-Path -Path $logDir)) {
    Write-Output "Creating log directory at $logDir"
    New-Item -Path $logDir -ItemType Directory -Force
}

# Function to Log messages for this script
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry = "$timestamp - $message"
    Add-Content -Path $logFilePath -Value $LogEntry
}

# Function to check if current time is within inactive hours
function Is-InactiveHours {
    $currentHour = (Get-Date).Hour
    if ($inactiveStartHour -lt $inactiveEndHour) {
        return ($currentHour -ge $inactiveStartHour -or $currentHour -lt $inactiveEndHour)
    } else {
        return ($currentHour -ge $inactiveStartHour -or $currentHour -lt $inactiveEndHour)
    }
}

# Checking for updates
$updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose

if ($updates) {
    Log-Message "Updates found, installing updates..."
    Write-Host "Updates found, installing updates..."

    Install-WindowsUpdate -AcceptAll -AutoReboot
} else {
    Log-Message "No updates found."
    Write-Host "No updates found."
}

# Check if a reboot is required and schedule it during inactive hours
if (Is-InactiveHours) {
    Log-Message "System is in inactive hours. Rebooting now."
    Write-Host "System is in inactive hours. Rebooting now."
} else {
    Log-Message "System is not in inactive hours. Reboot will be scheduled."
    Write-Host "System is not in inactive hours. Scheduling reboot."

    # Schedule reboot at the start of the next inactive period
    $rebootTime = [datetime]::Now.Date.AddHours($inactiveStartHour)
    if ([datetime]::Now.Hour -ge $inactiveStartHour) {
        $rebootTime = $rebootTime.AddDays(1)
    }
    $rebootTime = $rebootTime.ToString("yyyy-MM-ddTHH:mm:ss")
    Log-Message "Scheduled reboot at $rebootTime."
    Write-Host "Scheduled reboot at $rebootTime."

    # Add scheduled task for reboot
    $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0"
    $trigger = New-ScheduledTaskTrigger -At $rebootTime
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "ScheduledReboot" -RunLevel Highest
}

# After reboot, add a log entry indicating update completion
if ($env:COMPUTERNAME -eq $env:COMPUTERNAME) {
    Log-Message "Update done after reboot."
    Write-Host "Update done after reboot."
}
