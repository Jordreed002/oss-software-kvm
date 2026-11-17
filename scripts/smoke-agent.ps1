# Explicit development-only process smoke. Requires an already-built binary.
[CmdletBinding()]
param([switch]$Run, [string]$Binary, [switch]$Help)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output 'Usage: powershell -NoProfile -File scripts/smoke-agent.ps1 -Run [-Binary PATH]'
    Write-Output 'Starts only a development serve child and makes two read-only status queries. No build or install. Windows cleanup forcibly stops its own child; this does not prove graceful shutdown. Logs remain under ignored target.'
    exit 0
}
if (-not $Run) { throw 'Explicit opt-in required: -Run. Use -Help for usage.' }
if ($env:OS -ne 'Windows_NT') { throw 'Use smoke-agent.sh on Unix.' }
$root = Split-Path $PSScriptRoot -Parent
if (-not $Binary) { $Binary = Join-Path $root 'target/debug/kvm-agent.exe' }
$Binary = (Resolve-Path -LiteralPath $Binary).Path
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw 'Binary must be an existing file.' }
$artifacts = Join-Path $root ('target/smoke-agent-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $artifacts
$server = $null
function Read-Shared([string]$path) {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $reader = New-Object IO.StreamReader($stream)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}
function Assert-Live {
    $server.Refresh()
    if ($server.HasExited) { throw 'Own serve child exited; refusing status from another agent.' }
}
function Require-String($value, [string]$expected) {
    if ($value -isnot [string] -or $value -cne $expected) { throw "Expected string '$expected'." }
}
try {
    $server = Start-Process -FilePath $Binary -ArgumentList 'serve' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $artifacts 'serve.out') -RedirectStandardError (Join-Path $artifacts 'serve.err')
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Assert-Live
        $ready = (Read-Shared (Join-Path $artifacts 'serve.err')).Contains('Development agent ready; input unavailable')
        if ($ready) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Own serve child readiness timed out.' }
        Start-Sleep -Milliseconds 50
    } while ($true)
    $instance = $null
    foreach ($query in 1..2) {
        Assert-Live
        $out = Join-Path $artifacts "status-$query.json"
        $client = Start-Process -FilePath $Binary -ArgumentList 'status' -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError (Join-Path $artifacts "status-$query.err")
        try {
            $null = $client.Handle
            if (-not $client.WaitForExit(5000)) { throw 'Status deadline exceeded.' }
            if ($client.ExitCode -ne 0) { throw "Status failed with exit $($client.ExitCode)." }
        } finally {
            if (-not $client.HasExited) { $client.Kill(); $null = $client.WaitForExit(5000) }
            $client.Dispose()
        }
        Assert-Live
        $reply = [IO.File]::ReadAllText($out) | ConvertFrom-Json -ErrorAction Stop
        if ($reply -isnot [pscustomobject] -or $reply.snapshot -isnot [pscustomobject]) { throw 'Expected snapshot objects.' }
        Require-String $reply.type 'snapshot'
        $s = $reply.snapshot
        if ($s.input_destination -isnot [pscustomobject] -or $s.capabilities -isnot [pscustomobject]) { throw 'Expected destination and capabilities objects.' }
        Require-String $s.lifecycle 'idle'
        Require-String $s.user_intent 'paused'
        Require-String $s.input_destination.destination 'unknown'
        foreach ($name in 'pause','resume','failsafe','quit') { Require-String $s.capabilities.$name 'unsupported' }
        Require-String $s.capabilities.snapshot 'supported'
        if ($s.instance -isnot [string]) { throw 'Instance must be a UUID string.' }
        $uuid = [guid]::ParseExact($s.instance, 'D')
        if ($uuid -eq [guid]::Empty) { throw 'Nil instance.' }
        if ($null -ne $instance -and $instance -cne $s.instance) { throw 'Instance changed between queries.' }
        $instance = $s.instance
    }
    Write-Output "PASS: two idle/paused read-only snapshots from instance $instance. Artifacts: $artifacts"
} finally {
    if ($null -ne $server) {
        try {
            if (-not $server.HasExited) {
                $server.Kill()
                if (-not $server.WaitForExit(5000)) { throw 'Own child did not stop within cleanup deadline.' }
                Write-Output 'Cleanup: forcibly stopped own serve PID. Graceful shutdown was not tested.'
            }
        } finally { $server.Dispose() }
    }
}
