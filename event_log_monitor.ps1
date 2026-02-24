# =============================================================================
#  Windows Event Log Monitor - PowerShell Edition
#  Monitors Security + System logs for Event IDs 4625, 4672, 7045
#  Run as Administrator in PowerShell 5.1+
# =============================================================================

#Requires -RunAsAdministrator

# -- Configuration -------------------------------------------------------------

$Config = @{
    PollIntervalSeconds = 2

    Thresholds = @{
        4625 = @{ Count = 5;  WindowSeconds = 60;  CooldownSeconds = 120 }
        4672 = @{ Count = 10; WindowSeconds = 60;  CooldownSeconds = 60  }
        7045 = @{ Count = 2;  WindowSeconds = 300; CooldownSeconds = 300 }
    }

    LogFile = "$PSScriptRoot\event_monitor.log"

    # Optional: set to $true to send Windows Toast notifications
    ToastAlerts = $false
}

$EventSources = @{
    4625 = "Security"
    4672 = "Security"
    7045 = "System"
}

$EventDescriptions = @{
    4625 = "Failed Logon Attempt"
    4672 = "Special Privileges Assigned (Privilege Escalation)"
    7045 = "New Service Installed"
}

# -- Sliding-window state ------------------------------------------------------

$EventTimestamps = @{
    4625 = [System.Collections.Generic.Queue[datetime]]::new()
    4672 = [System.Collections.Generic.Queue[datetime]]::new()
    7045 = [System.Collections.Generic.Queue[datetime]]::new()
}

$LastAlertTime = @{
    4625 = $null
    4672 = $null
    7045 = $null
}

# -- Logging helpers ------------------------------------------------------------

function Write-Log {
    param([string]$Level, [string]$Message)
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts  $($Level.PadRight(8))  $Message"
    if ($Level -eq "ALERT") {
        Write-Host $line -ForegroundColor Red
    } elseif ($Level -eq "WARN") {
        Write-Host $line -ForegroundColor Yellow
    } else {
        Write-Host $line -ForegroundColor Cyan
    }
    Add-Content -Path $Config.LogFile -Value $line -Encoding UTF8
}

# -- Alert dispatcher -----------------------------------------------------------

function Invoke-Alert {
    param([int]$EventId, [hashtable]$Extras)

    $threshold = $Config.Thresholds[$EventId]
    $count     = $EventTimestamps[$EventId].Count
    $desc      = $EventDescriptions[$EventId]

    $divider = "=" * 70
    Write-Log "ALERT" $divider
    Write-Log "ALERT" "  *** ALERT  |  EventID $EventId  |  $desc"
    Write-Log "ALERT" "  Count in last $($threshold.WindowSeconds)s : $count  (threshold: $($threshold.Count))"
    foreach ($k in $Extras.Keys) {
        Write-Log "ALERT" "  $($k.PadRight(20)): $($Extras[$k])"
    }
    Write-Log "ALERT" $divider

    if ($Config.ToastAlerts) {
        Send-ToastNotification -EventId $EventId -Description $desc -Count $count
    }

    # -- Extend here: email, webhook, SIEM push --------------------------------
    # Invoke-RestMethod -Uri $SlackWebhook -Method Post -Body (ConvertTo-Json @{text="ALERT: $desc ($count events)"})
}

# -- Optional Toast notification -----------------------------------------------

function Send-ToastNotification {
    param([int]$EventId, [string]$Description, [int]$Count)
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    $xmlString = "<toast><visual><binding template='ToastGeneric'><text>Security Alert - EventID $EventId</text><text>$Description - $Count events detected</text></binding></visual></toast>"
    $xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $xml.LoadXml($xmlString)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Event Monitor").Show($toast)
}

# -- Sliding-window counter -----------------------------------------------------

function Test-Threshold {
    param([int]$EventId, [datetime]$EventTime)

    $threshold = $Config.Thresholds[$EventId]
    $queue     = $EventTimestamps[$EventId]
    $queue.Enqueue($EventTime)

    # Evict events outside the window
    $cutoff = $EventTime.AddSeconds(-$threshold.WindowSeconds)
    while ($queue.Count -gt 0 -and $queue.Peek() -lt $cutoff) {
        [void]$queue.Dequeue()
    }

    if ($queue.Count -ge $threshold.Count) {
        $last = $LastAlertTime[$EventId]
        $now  = Get-Date
        if ($null -eq $last -or ($now - $last).TotalSeconds -ge $threshold.CooldownSeconds) {
            $script:LastAlertTime[$EventId] = $now
            return $true
        }
    }
    return $false
}

# -- Field extractors -----------------------------------------------------------

function Get-EventExtras {
    param([int]$EventId, $Record)

    $extras = @{}
    try {
        switch ($EventId) {
            4625 {
                $extras["Target Account"]  = $Record.ReplacementStrings[5]
                $extras["Subject Account"] = $Record.ReplacementStrings[1]
                $extras["Workstation"]     = $Record.ReplacementStrings[13]
                $extras["Source IP"]       = $Record.ReplacementStrings[19]
                $extras["Logon Type"]      = $Record.ReplacementStrings[10]
                $extras["Failure Reason"]  = $Record.ReplacementStrings[8]
            }
            4672 {
                $extras["Account Name"]    = $Record.ReplacementStrings[1]
                $extras["Account Domain"]  = $Record.ReplacementStrings[2]
                $extras["Logon ID"]        = $Record.ReplacementStrings[3]
                $extras["Privileges"]      = $Record.ReplacementStrings[4]
            }
            7045 {
                $extras["Service Name"]    = $Record.ReplacementStrings[0]
                $extras["Image Path"]      = $Record.ReplacementStrings[1]
                $extras["Service Type"]    = $Record.ReplacementStrings[2]
                $extras["Start Type"]      = $Record.ReplacementStrings[3]
                $extras["Account"]         = $Record.ReplacementStrings[4]
            }
        }
    } catch {
        $extras["ParseError"] = $_.Exception.Message
    }
    return $extras
}

# -- Main monitoring loop -------------------------------------------------------

function Start-EventMonitor {

    Write-Log "INFO" "Event Log Monitor starting..."
    Write-Log "INFO" "Watching Event IDs: $($Config.Thresholds.Keys -join ', ')"
    Write-Log "INFO" "Poll interval: $($Config.PollIntervalSeconds)s | Log: $($Config.LogFile)"

    # Bookmark: track the newest RecordNumber seen per source
    $bookmarks = @{}
    foreach ($src in ($EventSources.Values | Sort-Object -Unique)) {
        try {
            $latest = Get-EventLog -LogName $src -Newest 1 -ErrorAction Stop
            $bookmarks[$src] = $latest.Index
            Write-Log "INFO" "Opened log '$src' (latest record: $($latest.Index))"
        } catch {
            Write-Log "ERROR" "Cannot open log '$src': $_"
            exit 1
        }
    }

    Write-Log "INFO" "Monitoring active. Press Ctrl+C to stop."

    while ($true) {
        foreach ($eventId in $Config.Thresholds.Keys) {
            $src = $EventSources[$eventId]
            try {
                $records = Get-EventLog -LogName $src -InstanceId $eventId `
                           -After ([datetime]::MinValue) -ErrorAction SilentlyContinue |
                           Where-Object { $_.Index -gt $bookmarks[$src] } |
                           Sort-Object Index

                foreach ($rec in $records) {
                    $bookmarks[$src] = [Math]::Max($bookmarks[$src], $rec.Index)

                    $extras = Get-EventExtras -EventId $eventId -Record $rec
                    $info   = ($extras.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "

                    Write-Log "INFO" "Event $eventId ($($EventDescriptions[$eventId])) | $info"

                    if (Test-Threshold -EventId $eventId -EventTime $rec.TimeGenerated) {
                        Invoke-Alert -EventId $eventId -Extras $extras
                    }
                }
            } catch {
                Write-Log "WARN" "Error polling $src for $eventId : $_"
            }
        }

        Start-Sleep -Seconds $Config.PollIntervalSeconds
    }
}

# -- Entry point ----------------------------------------------------------------

try {
    Start-EventMonitor
} catch [System.Management.Automation.PipelineStoppedException] {
    Write-Log "INFO" "Monitor stopped (Ctrl+C)."
} catch {
    Write-Log "ERROR" "Fatal: $_"
    exit 1
}




1..6 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential("fakeuser", (ConvertTo-SecureString "wrongpass" -AsPlainText -Force))
    Start-Process cmd -Credential $cred -ErrorAction SilentlyContinue
}