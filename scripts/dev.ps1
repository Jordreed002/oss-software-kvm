# Dev runner for the two-host KVM stack on Windows.
#
# Usage (from a PowerShell prompt in the repo root):
#   .\scripts\dev.ps1          # build + (re)start the stack once
#   .\scripts\dev.ps1 watch    # hot-reload: rebuild + restart whenever a
#                              # workspace crate changes
#
# Windows twin of scripts/dev.sh. The panel spawns target\release\kvm-runtime.exe
# as a managed child, so a rebuilt daemon needs a stack bounce to take over.
# Workspace-crate changes are invisible to `tauri dev` (it only watches
# src-tauri), so the watcher covers them too.
param(
    [ValidateSet('once', 'watch')]
    [string]$Mode = 'once'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$PanelDir = 'apps/control-panel'
$RuntimeBin = 'target/release/kvm-runtime.exe'
$DevLog = Join-Path $env:TEMP 'kvm-dev.log'
$Marker = 'target/.dev-watch-marker'
# The panel stores managed runtime files under Tauri's app-local-data dir
# plus the WINDOWS_SETUP_DIRECTORY suffix ("runtime").
$ServiceDir = Join-Path $env:LOCALAPPDATA 'dev.software-kvm.control-panel\runtime'

function Write-Log([string]$Message) {
    Write-Host "[dev] $Message"
}

function Stop-Stack {
    foreach ($name in @('kvm-runtime', 'software-kvm-control-panel')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    # A killed tauri dev can leave vite holding port 1420.
    Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 1
}

function Build-Runtime {
    Write-Log "building $RuntimeBin ..."
    cargo build --release -p kvm-runtime
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed"
    }
}

function Start-Stack {
    Write-Log "starting stack (log: $DevLog)"
    Set-Content -Path $DevLog -Value '' -NoNewline
    $vite = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'npm run dev:desktop' `
        -WorkingDirectory (Join-Path $Root $PanelDir) `
        -RedirectStandardOutput $DevLog -RedirectStandardError "$DevLog.err" `
        -PassThru -WindowStyle Hidden

    Activate-Daemon
}

# Mirrors the panel's start_runtime command (apps/control-panel/src-tauri/
# src/setup.rs): write `run` to the control file, then spawn the managed
# runtime. The panel only spawns the daemon from its UI toggle, so doing it
# here makes restarts hands-free.
function Activate-Daemon {
    if (-not (Test-Path (Join-Path $ServiceDir 'runtime.toml'))) {
        Write-Log 'no provisioned profile yet - enable KVM in the panel once'
        return
    }
    Start-Sleep -Seconds 5 # let the panel finish binding its control pipe first
    Write-Log 'activating managed runtime'
    Set-Content -Path (Join-Path $ServiceDir 'runtime.control') -Value 'run'
    Remove-Item (Join-Path $ServiceDir 'runtime.status') -ErrorAction SilentlyContinue
    $env:SOFTWARE_KVM_DATA_DIR = $ServiceDir
    $env:SOFTWARE_KVM_DEV_LOG = '1'
    $stdout = Join-Path $ServiceDir 'runtime.log'
    $stderr = Join-Path $ServiceDir 'runtime.stderr.log'
    Start-Process -FilePath (Join-Path $Root $RuntimeBin) `
        -ArgumentList 'run-managed', (Join-Path $ServiceDir 'runtime.toml'), (Join-Path $ServiceDir 'runtime.control') `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -WindowStyle Hidden
}

function Get-LatestSourceWrite {
    $latest = $null
    foreach ($path in @('crates', (Join-Path $PanelDir 'src-tauri\src'))) {
        Get-ChildItem -Path $path -Recurse -File -Include '*.rs', 'Cargo.toml' |
            ForEach-Object {
                if ($null -eq $latest -or $_.LastWriteTimeUtc -gt $latest) {
                    $latest = $_.LastWriteTimeUtc
                }
            }
    }
    $latest
}

switch ($Mode) {
    'once' {
        Stop-Stack
        Build-Runtime
        Start-Stack
    }
    'watch' {
        New-Item -ItemType File -Path $Marker -Force | Out-Null
        $markerTime = (Get-Item $Marker).LastWriteTimeUtc
        Write-Log 'watching workspace crates for changes (ctrl-c stops)'
        while ($true) {
            $latest = Get-LatestSourceWrite
            if ($null -ne $latest -and $latest -gt $markerTime) {
                # Debounce editor save bursts: wait for writes to settle.
                Start-Sleep -Seconds 3
                try {
                    Stop-Stack
                    Build-Runtime
                } catch {
                    Write-Log "BUILD FAILED - fix errors; stack stays down until clean"
                    $markerTime = [datetime]::UtcNow
                    while ($true) {
                        Start-Sleep -Seconds 2
                        $check = Get-LatestSourceWrite
                        if ($null -ne $check -and $check -gt $markerTime) { break }
                    }
                    continue
                }
                $markerTime = [datetime]::UtcNow
                Start-Stack
            }
            Start-Sleep -Seconds 1
        }
    }
}
