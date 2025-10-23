$now = Get-Date "2024-10-14 23:59:59"
$weekAgo = $now.AddDays(-7)
$regex = '\b(20\d{2}-\d{2}-\d{2})(?:\s+([0-2]\d:[0-5]\d(?::[0-5]\d)?))?\b'
$ipv4regex = '\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?!$)|$)){4}\b'
$BackupPath = 'network_configs\backups'
$BaselineFile = Join-Path -Path $PSScriptRoot -ChildPath 'network_configs\baseline\baseline-router.conf'

#Function to get parsed date from file
function Get-ParsedDateFromFile {
    param([string]$Path)

    $getdates = Select-String -Path $Path -Pattern $regex -AllMatches -ErrorAction SilentlyContinue
    if (-not $getdates) { return $null }

    $parsedDates = foreach ($hit in $getdates) {
        foreach ($m in $hit.Matches) {
            $txt = $m.Value
            foreach ($fmt in @('yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm', 'yyyy-MM-dd')) {
                try {
                    $dt = [datetime]::ParseExact($txt, $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
                    break
                }
                catch { $dt = $null }
            }
            if ($dt) { $dt }
        }
    } Where-Object { $_ -ne $null }

    if ($parsedDates) { $parsedDates | Sort-Object -Descending | Select-Object -First 1 } else { $null }
}
#Function to count keywords in files
function Get-KeywordInFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$keywords = @('ERROR', 'FAILED', 'DENIED')
    )

    $pattern = '(?i)\b(' + ($keywords -join '|') + ')\b'
    $filematches = Select-String -Path $Path -Pattern $pattern -AllMatches -ErrorAction SilentlyContinue
    $counts = @{}
    foreach ($k in $keywords) { $counts[$k.ToUpper()] = 0 }

    if ($filematches) {
        foreach ($mi in $filematches) {
            foreach ($m in $mi.Matches) {
                $val = $m.Value.ToUpper()
                if ($counts.ContainsKey($val)) { $counts[$val] += 1 }
            }
        }
    }

    [PSCustomObject]@{
        Name      = [System.IO.Path]::GetFileName($Path)
        ERROR     = $counts['ERROR']
        FAILED    = $counts['FAILED']
        DENIED    = $counts['DENIED']
        TOTALHITS = ($counts.Values | Measure-Object -Sum).Sum
    }
}

function Find-SecurityIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$FileExtensions = @('*'),
        [switch]$IncludeContext
    )

    $patterns = @{
        ClearTextSecret = '(?i)\b(password|secret)\b\s*[:=]\s*["'']?([^\s""'']+)'
        SNMPCommunity   = '(?i)\b(public|private)\b'
        EnablePassword  = '(?i)(enable\s+password)\s+([^\s]+)'
    }


    $files = Get-ChildItem -Path $Path -Recurse -File | 
    Where-Object {
        $FileExtensions -contains '*' -or
        $FileExtensions -contains $_.Extension.ToLower()
    }
    
    foreach ($f in $files) {
        # use Select-String once per pattern to keep memory predictable
        foreach ($key in $patterns.Keys) {
            $pat = $patterns[$key]
            $matcheserrors = Select-String -Path $f.FullName -Pattern $pat -AllMatches -ErrorAction SilentlyContinue
            if ($matcheserrors) {
                foreach ($mi in $matcheserrors) {
                    foreach ($m in $mi.Matches) {
                        $matchText = if ($m.Groups.Count -gt 1) { $m.Groups[1].Value.Trim() } else { $m.Value.Trim() }
                        $capture = if ($m.Groups.Count -gt 2) { $m.Groups[2].Value.Trim() } else { $null }
                        [PSCustomObject]@{
                            Name      = $f.Name
                            IssueType = $key
                            Match     = $matchText
                            Captured  = if ($capture) { $capture } else { $null }
                            Line      = $mi.LineNumber
                            LineText  = if ($IncludeContext) { $mi.Line.Trim() } else { $null }
                        }
                    }
                }
            }
        }
    }
}

#Function to generate auditreport
function AuditReport {
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$BackupPath
    )

    $logFiles = Get-ChildItem -Path $LogPath -Recurse -File -Filter '*.log'

    $report = @()
    $report += "----ERROR SUMMARY----"
    foreach ($file in $logFiles) {
        $errors = Select-String -Path $file.Fullname -Pattern '(?i)\bERROR\b' -ErrorAction SilentlyContinue
        if ($errors) {
            $report += "`n$file"
            $report += ($errors | ForEach-Object { "  Line $($_.LineNumber): $($_.Line.Trim())" })
        }
    }
    $report += "`n`n----Failed Logins----"
    foreach ($file in $logFiles) {
        $failed = Select-String -Path $file.FullName -Pattern '(?i)\bFAILED\b' -ErrorAction SilentlyContinue |
        Where-Object { $_.Line -match 'Authentication failed' }
        if ($failed) {
            $report += "`n$file"
            $report += ($failed | ForEach-Object { "  Line $($_.LineNumber): $($_.Line.Trim())" })
        }
    }
    $report += "`n`n----Weak Configuration Warnings----"
    $weakPatterns = '(?i)weak password|unauthorized SNMP|SQL injection|enable password'
    foreach ($file in $logFiles) {
        $weak = Select-String -Path $file.FullName -Pattern $weakPatterns -ErrorAction SilentlyContinue
        if ($weak) {
            $report += "`n$file"
            $report += ($weak | ForEach-Object { "  Line $($_.LineNumber): $($_.Line.Trim())" })
        }
    }
    $report += "`n`n----Files Missing Backup----"
    $configFiles = Get-ChildItem -Path $LogPath -Recurse -File |
    Where-Object { $_.Extension -in '.conf', '.rules' }
    $backupFiles = Get-ChildItem -Path $BackupPath -Recurse -File |
    Where-Object { $_.Name -match '\.bak$' } |
    ForEach-Object {
        $_.Name -replace '\.bak$', ''
    }

    foreach ($cfg in $configFiles) {
        if (-not ($backupFiles -contains $cfg.Name)) {
            $report += "  $($cfg.Name) (no backup found)"
        }
    }
    return $report
}

function CompareConfigs {
    param(
        [Parameter(Mandatory)][string]$ConfigFolder,
        [Parameter(Mandatory)][string]$BaselineFileRelativePath
    )
    $BaselineFile = Join-Path -Path $PSScriptRoot -ChildPath $BaselineFileRelativePath

    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile"
        return
    }
    $baselineContent = Get-Content -Path $BaselineFile -Encoding UTF8 | 
    Where-Object {
        ($words = $_.Trim()) -and
        $words -notmatch '^(#|!)' -and
        $words -match 'aaa|tacacs|radius|enable secret|service password-encryption|username|privilege|access-list|firewall|crypto|ipsec|certificate|key|ssh|snmp|ntp|logging|security|auth|password|vpn|snmp-server community|transport input ssh'
    } | ForEach-Object { $_ }

    if (-not $baselineContent) {
        Write-Error "Baseline file is empty or invalid."
        return
    }

    $report = @()
    $report += "---- Baseline Comparison Report ----"

    $configFiles = Get-ChildItem -Path $ConfigFolder -Recurse -File |
    Where-Object { $_.Extension -in '.conf', '.rules' }

    foreach ($file in $configFiles) {
        $currentContent = Get-Content -Path $file.FullName -Encoding UTF8 | 
        Where-Object {
            ($words = $_.Trim()) -and
            $words -notmatch '^(#|!)' -and
            $words -match 'aaa|tacacs|radius|enable secret|service password-encryption|username|privilege|access-list|firewall|crypto|ipsec|certificate|key|ssh|snmp|ntp|logging|security|auth|password|vpn|snmp-server community|transport input ssh'
        } | ForEach-Object { $_ }

        if (-not $currentContent) {
            $report += "`n$($file.Name): Skipped (empty or unreadable)"
            continue
        }

        $differences = Compare-Object -ReferenceObject $baselineContent -DifferenceObject $currentContent -IncludeEqual:$false | 
        Where-Object { $_.SideIndicator -eq '<=' }

        if ($differences) {
            $report += "`n$($file.Name): Differences found"
            foreach ($diff in $differences) {
                $side = 'Missing from config'
                $report += "  [$side] $($diff.InputObject)"
            }
        }
        else {
            $report += "`n$($file.Name): No differences"
        }
    }

    return $report
}
#Find all configfiles
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -in '.conf', '.rules', '.log' } |
ForEach-Object {
    $f = $_
    $parsed = Get-ParsedDateFromFile -Path $f.FullName
    [PSCustomObject]@{
        Name       = $f.Name
        SizeKB     = [math]::Round($f.Length / 1KB, 2)
        ParsedDate = if ($parsed) { $parsed } else { $f.LastWriteTime }
    }
} |
Where-Object { $_.ParsedDate -and ($_.ParsedDate -ge $weekAgo) -and ($_.ParsedDate -le $now) } |
Sort-Object ParsedDate -Descending |
Export-Csv -Path .\1_config_files.csv -NoTypeInformation -Encoding UTF8

#Find files that last changed
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -in '.conf', '.rules', '.log', '.bak' } |
ForEach-Object {
    $f = $_
    $parsed = Get-ParsedDateFromFile -Path $f.FullName

    if ($parsed) {
        [PSCustomObject]@{
            Name       = $f.Name
            SizeKB     = [math]::Round($f.Length / 1KB, 2)
            ParsedDate = $parsed
        }
    }
} |
Where-Object { $_.ParsedDate -and ($_.ParsedDate -ge $weekAgo) -and ($_.ParsedDate -le $now) } |
Sort-Object ParsedDate -Descending |
Select-Object Name, SizeKB, ParsedDate |
Export-Csv -Path .\2_last_changed_files.csv -NoTypeInformation -Encoding UTF8

#Group files after type
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -in '.conf', '.rules', '.log', '.bak' } |
Group-Object -Property Extension |
Select-Object @{
    Name = 'Extension'; Expression = { $_.Name }
}, @{
    Name = 'FileCount'; Expression = { $_.Count }
}, @{
    Name = 'TotalSizeKB'; Expression = { [math]::Round( ($_.Group | Measure-Object -Property Length -Sum).Sum / 1KB, 2) }
} |
Sort-Object FileCount -Descending |
Export-Csv -Path .\3_group_files_after_type.csv -NoTypeInformation -Encoding UTF8

#Five biggest logfiles in MB
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -ieq '.log' } |
ForEach-Object {
    $f = $_
    $parsed = Get-ParsedDateFromFile -Path $f.FullName
    [PSCustomObject]@{
        Name       = $f.Name
        SizeKB     = [math]::Round($f.Length / 1KB, 2)
        SizeMB     = [math]::Round($f.Length / 1MB, 6)
        ParsedDate = if ($parsed) { $parsed } else { $null }
    }
} |
Sort-Object SizeMB -Descending |
Select-Object -First 5 Name, SizeKB, SizeMB, ParsedDate |
Export-Csv -Path .\4_top5_logfiles.csv -NoTypeInformation -Encoding UTF8

#List with unique IP-adresses
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -ieq '.conf' } |
Select-String -Pattern $ipv4regex -AllMatches |
ForEach-Object { foreach ($m in $_.Matches) { $m.Value } } |
Sort-Object -Unique |
ForEach-Object { [PSCustomObject]@{ Unique_IP_Adresses = $_ } } |
Export-Csv -Path .\5_unique_ipadresses.csv -NoTypeInformation -Encoding UTF8

#Count securityproblems
Get-ChildItem -Path 'network_configs' -Recurse -File -Filter '*.log' |
ForEach-Object { Get-KeywordInFile -Path $_.Fullname } |
Sort-Object TotalHits -Descending |
Export-Csv -Path .\6_security_problem_counts.csv -NoTypeInformation -Encoding UTF8

#Export fileinventory
Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -in '.conf', '.rules' } |
ForEach-Object {
    $f = $_
    $parsed = Get-ParsedDateFromFile -Path $f.FullName
    [PSCustomObject]@{
        Name       = $f.Name
        Fullpath   = $f.FullName
        SizeKB     = [math]::Round($f.Length / 1KB, 2)
        ParsedDate = if ($parsed) { $parsed } else { $f.LastWriteTime }
    }
} |
Where-Object { $_.ParsedDate -and ($_.ParsedDate -ge $weekAgo) -and ($_.ParsedDate -le $now) } |
Export-Csv -Path .\7_config_inventory.csv -NoTypeInformation -Encoding UTF8

Find-SecurityIssues -Path 'network_configs' -IncludeContext |
Export-Csv -Path .\8_security_issues.csv -NoTypeInformation -Encoding UTF8

#Generate Auditreport
$reportContent = AuditReport -LogPath 'network_configs' -BackupPath 'network_configs\backups'
$reportContent | Set-Content -Path '.\security_audit.txt' -Encoding UTF8

#Generate Comparion configfiles
$reportContent = CompareConfigs -ConfigFolder 'network_configs\routers' -BaselineFileRelativePath 'network_configs\baseline\baseline-router.conf'
$reportContent | Set-Content -Path '.\10_comparison_configs.txt' -Encoding UTF8