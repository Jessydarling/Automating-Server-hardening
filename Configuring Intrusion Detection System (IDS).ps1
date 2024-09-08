# IDS SCRIPT

# Define the path for the log file
$logFilePath = "C:\Logs\Security.log"

# Ensure the log directory exists
$logDir = Split-Path -Path $logFilePath -Parent
if (-not (Test-Path -Path $logDir)) {
    Write-Output "Creating log directory at $logDir"
    New-Item -Path $logDir -ItemType Directory -Force
}

# Function to log messages to the log file
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $logFilePath -Value $logEntry
}

# Function to check for high CPU usage processes
function Check-SuspiciousProcesses {
    Write-Output "Checking for suspicious processes..."
    
    # Define criteria for suspicious processes (example: processes running with high CPU usage)
    $highCpuUsageThreshold = 80
    $suspiciousProcesses = Get-Process | Where-Object { $_.CPU -gt $highCpuUsageThreshold }
    
    if ($suspiciousProcesses) {
        foreach ($process in $suspiciousProcesses) {
            Log-Message -Message "Suspicious process detected: $($process.Name) (PID: $($process.Id), CPU Usage: $($process.CPU))"
            Write-Output "Suspicious process detected: $($process.Name) (PID: $($process.Id), CPU Usage: $($process.CPU))"
	}
    } else {
        Log-Message -Message "No suspicious processes detected."
	Write-Output "No suspicious processes detected."
    }
}


# Function to check for failed login attempts
function Check-FailedLoginAttempts {
    Write-Output "Checking for failed login attempts..."
    
    # Check the Security event log for failed login attempts (Event ID 4625)
    $eventLogEntries = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 100 | 
                        Select-Object -Property Id, TimeCreated, Message

    $seenEvents = @{}  # Hash table to track seen events
    
    foreach ($entry in $eventLogEntries) {
        $eventId = $entry.Id
        $eventTime = $entry.TimeCreated
        $message = $entry.Message

        # Generate a unique key based on event ID and time to avoid duplicate logging
        $uniqueKey = "$eventId-$eventTime"

        if (-not $seenEvents.ContainsKey($uniqueKey)) {
            $seenEvents[$uniqueKey] = $true
            Log-Message -Message "Failed login attempt detected: $message"
	    Write-Output "Failed login attempt detected: $message"
        }
    }

    if (-not $seenEvents) {
        Log-Message -Message "No failed login attempts detected."
	Write-Output "Failed login attempt detected: $message"
    }
}

# Execute checks
Check-SuspiciousProcesses
Check-FailedLoginAttempts