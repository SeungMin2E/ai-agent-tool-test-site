param([int]$BasePort = 8100)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
py -3 .\server.py --base-port $BasePort
