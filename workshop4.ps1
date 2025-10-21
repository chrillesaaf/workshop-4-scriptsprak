Get-ChildItem -Path 'network_configs' -Recurse -File -Include *.conf, *.rules, *.log |
Select-Object Name,
@{Name = 'Size KB'; Expression = { [math]::Round($_.Length / 1KB, 2) } },
LastWriteTime |

Export-Csv -Path 1_config_files.csv -NoTypeInformation -Encoding UTF8