$now = Get-Date "2024-10-14 23:59:59"
$weekAgo = $now.AddDays(-7)
$regex = '\b(20\d{2}-\d{2}-\d{2})(?:\s+([0-2]\d:[0-5]\d(?::[0-5]\d)?))?\b'

Get-ChildItem -Path 'network_configs' -Recurse -File |
Where-Object { $_.Extension -in '.conf', '.rules', '.log' } |
Select-Object Name,
@{Name = 'SizeKB'; Expression = { [math]::Round($_.Length / 1KB, 2) } },
LastWriteTime |
Export-Csv -Path .\1_config_files.csv -NoTypeInformation -Encoding UTF8

Get-ChildItem -Path 'network_configs' -Recurse -File |
ForEach-Object {
    $f = $_
    $matches = Select-String -Path $f.FullName -Pattern $regex -AllMatches
    if (-not $matches) { return }

    $dates = foreach ($hit in $matches) {
        foreach ($m in $hit.Matches) {
            $datePart = $m.Groups[1].Value
            $timePart = $m.Groups[2].Value

            if ($timePart) {
                foreach ($fmt in @('yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm')) {
                    try { 
                        $dt = [datetime]::ParseExact("$datePart $timePart", $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
                        break
                    }
                    catch { $dt = $null }
                }
                if ($dt) { $dt; continue }
            }

            try { [datetime]::ParseExact($datePart, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) } catch { $null }
        }
    } Where-Object { $_ -ne $null }

    if ($dates) {
        $latest = $dates | Sort-Object -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Name       = $f.Name
            SizeKB     = [math]::Round($f.Length / 1KB, 2)
            ParsedDate = $latest
        }
    }
} |
Where-Object { $_.ParsedDate.Date -and ($_.ParsedDate -ge $weekAgo) -and ($_.ParsedDate -le $now) } |
Sort-Object ParsedDate -Descending |
Select-Object Name, SizeKB, ParsedDate |
Export-Csv -Path .\2_last_changed_files.csv -NoTypeInformation -Encoding UTF8
