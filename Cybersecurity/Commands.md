# Good commands


1. Get-NetIPAddress | Where-Object { $_.IPAddress -match '\d+.\d+.\d+.\d+' } | Select-Object IPAddress, InterfaceAlias
    - it lists the IPv4 addresses on your computer and the network interface names