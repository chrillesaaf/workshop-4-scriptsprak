$now = Get-Date "2024-10-14 23:59:59"
$weekAgo = $now.AddDays(-7)
$regex = '\b(20\d{2}-\d{2}-\d{2})(?:\s+([0-2]\d:[0-5]\d(?::[0-5]\d)?))?\b'
$ipv4regex = '\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?!$)|$)){4}\b'

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