#Security Policy Configuration

function Security-Policy {
    # Set password policy
    secedit /export /cfg C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MaximumPasswordAge = 42", "MaximumPasswordAge = 30") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set account lockout policy
    (Get-Content C:\SecConfig.cfg).replace("LockoutBadCount = 0", "LockoutBadCount = 5") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("ResetLockoutCount = 30", "ResetLockoutCount = 15") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("LockoutDuration = 30", "LockoutDuration = 15") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set user rights assignment
    (Get-Content C:\SecConfig.cfg).replace("SeDenyInteractiveLogonRight = ", "SeDenyInteractiveLogonRight = *S-1-5-32-546") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set audit policy
    Auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    Auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

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

# Function to configure the firewall
function Configure-Firewall {
    Write-Output "Configuring firewall rules..."

    # Clear existing rules
    Write-Output "Clearing existing firewall rules..."
    Get-NetFirewallRule | Remove-NetFirewallRule

    #Turn on Windows Firewall for all network profiles
    Set-NetFirewallProfile -All -Enabled True
    Write-Output "Firewall turned on"

    # Block all incoming and outgoing connections by default
    Write-Output "Blocking all incoming and outgoing connections by default..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

    # Detect active connections and allow them
    Write-Output "Allowing active connections..."
    $activeConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object -Property LocalPort

    foreach ($connection in $activeConnections) {
        $port = $connection.LocalPort
        Write-Output "Allowing active connection on port $port"
        New-NetFirewallRule -DisplayName "Allow Active Connection on Port $port" -Direction Outbound -Protocol TCP -LocalPort $port -Action Allow
    }

    # Enable firewall logging (Optional)
    Write-Output "Enabling firewall logging..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName "C:\Logs\Firewall.txt" -LogMaxSizeKilobytes 32767

    # Allow necessary inbound connections
    Write-Output "Allowing necessary inbound connections..."

    # List of inbound rules
    $inboundRules = @{
        "Allow RDP"              = @{ Protocol = 'TCP'; Port = 3389 }
        "Allow HTTPS"            = @{ Protocol = 'TCP'; Port = 443 }
        "Allow DNS"              = @{ Protocol = 'UDP'; Port = 53 }
        "Allow SMTP"             = @{ Protocol = 'TCP'; Port = 25 }
        "Allow FTP Control"      = @{ Protocol = 'TCP'; Port = 21 }
        "Allow FTP Data"         = @{ Protocol = 'TCP'; Port = 20 }
        "Allow DHCP Client"      = @{ Protocol = 'UDP'; Port = 68 }
        "Allow NTP"              = @{ Protocol = 'UDP'; Port = 123 }
    }

    foreach ($rule in $inboundRules.GetEnumerator()) {
        $name = $rule.Key
        $params = $rule.Value
        Write-Output "Creating inbound rule: $name"
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol $params.Protocol -LocalPort $params.Port -Action Allow
    }

    # Allow necessary outbound connections
    Write-Output "Allowing necessary outbound connections..."

    # List of outbound rules
    $outboundRules = @{
        "Allow Outbound DNS"     = @{ Protocol = 'UDP'; Port = 53 }
        "Allow Outbound HTTPS"   = @{ Protocol = 'TCP'; Port = 443 }
        "Allow Outbound SMTP"    = @{ Protocol = 'TCP'; Port = 25 }
        "Allow Outbound FTP Control" = @{ Protocol = 'TCP'; Port = 21 }
        "Allow Outbound FTP Data" = @{ Protocol = 'TCP'; Port = 20 }
        "Allow DHCP Client Outbound" = @{ Protocol = 'UDP'; Port = 67 }
        "Allow NTP Outbound"     = @{ Protocol = 'UDP'; Port = 123 }
    }

    foreach ($rule in $outboundRules.GetEnumerator()) {
        $name = $rule.Key
        $params = $rule.Value
        Write-Output "Creating outbound rule: $name"
        New-NetFirewallRule -DisplayName $name -Direction Outbound -Protocol $params.Protocol -RemotePort $params.Port -Action Allow
    }

    Write-Output "Firewall configuration completed."
}

# Run the function
Configure-Firewall

# Define parameters for the checks
$cpuThreshold = 80  # Threshold for high CPU usage
$unusualLoginStartHour = 22  # Start hour for unusual login times (10 PM)
$unusualLoginEndHour = 6     # End hour for unusual login times (6 AM)
$unauthorizedExecutables = @("cmd.exe", "powershell.exe", "wmic.exe", "mshta.exe")  # List of executables considered unauthorized

# Define the output file path
$outputFile = "C:\Logs\SecurityAudit.txt"

# Create the output directory if it doesn't exist
$outputDir = Split-Path $outputFile
if (-not (Test-Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory | Out-Null
}

# Function to log the results to the file
function Log-Results {
    param (
        [string]$message
    )
    $message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# Start logging
Log-Results "Security Audit Report - $(Get-Date)"

# Check for logins at unusual times
$unusualLogins = Get-EventLog -LogName Security -InstanceId 4624 -After (Get-Date).AddDays(-1) |
                 Where-Object {
                     $_.TimeGenerated.Hour -ge $unusualLoginStartHour -or
                     $_.TimeGenerated.Hour -lt $unusualLoginEndHour
                 }

Log-Results "`nLogins at Unusual Times:"
if ($unusualLogins) {
    $unusualLogins | Select-Object TimeGenerated, UserName, EventID | Format-Table | Out-String | Log-Results
} else {
    Log-Results "No unusual logins found."
}

# Check for unauthorized executables running
$unauthorizedProcesses = Get-Process | Where-Object { $unauthorizedExecutables -contains $_.Name }

Log-Results "`nUnauthorized Executables Running:"
if ($unauthorizedProcesses) {
    $unauthorizedProcesses | Select-Object Name, CPU | Format-Table | Out-String | Log-Results
} else {
    Log-Results "No unauthorized executables running."
}

# Check for high CPU usage processes
$highCpuProcesses = Get-Process | Where-Object { $_.CPU -gt $cpuThreshold } | Sort-Object CPU -Descending

Log-Results "`nHigh CPU Usage Processes (>$cpuThreshold%):"
if ($highCpuProcesses) {
    $highCpuProcesses | Select-Object Name, CPU | Format-Table | Out-String | Log-Results
} else {
    Log-Results "No processes with CPU usage higher than $cpuThreshold%."
}

# Check for privilege escalation attempts (Event ID 4672)
$privEscalationAttempts = Get-EventLog -LogName Security -InstanceId 4672 -After (Get-Date).AddDays(-1)

Log-Results "`nPrivilege Escalation Attempts:"
if ($privEscalationAttempts) {
    $privEscalationAttempts | Select-Object TimeGenerated, UserName, EventID | Format-Table | Out-String | Log-Results
} else {
    Log-Results "No privilege escalation attempts found."
}

# Notify that the script has completed
Log-Results "`nAudit report saved to $outputFile"