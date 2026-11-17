[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Panel,
    [switch]$Tauri,
    [switch]$MacOS,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output 'Usage: check-rebuild.ps1 [-Panel] [-Tauri] [-MacOS]'
    Write-Output 'Core: focused fmt, locked offline library/integration tests, strict all-target clippy.'
    Write-Output 'Panel: existing npm test/build. Tauri: separately excluded crate checks.'
    Write-Output 'MacOS: strict cross-clippy for installed Apple targets only; never installs.'
    Write-Output 'Software checks only; no physical/native input certification.'
    exit 0
}
function Invoke-Check {
    param([string]$Program, [string[]]$Arguments)
    Write-Host "Running: $Program $($Arguments -join ' ')"
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
$repo = Split-Path -Parent $PSScriptRoot
$previousAutoInstall = $env:RUSTUP_AUTO_INSTALL
Push-Location -LiteralPath $repo
try {
    $env:RUSTUP_AUTO_INSTALL = '0'
    Write-Host 'Software checks only; no physical/native input certification.'
    $packages = @('-p', 'kvm-foundation', '-p', 'kvm-agent-model', '-p', 'kvm-agent-ipc', '-p', 'kvm-agent-api', '-p', 'kvm-agent')
    Invoke-Check cargo (@('fmt') + $packages + @('--', '--check'))
    Invoke-Check cargo (@('test', '--locked', '--offline') + $packages + @('--lib', '--tests'))
    Invoke-Check cargo (@('clippy', '--locked', '--offline') + $packages + @('--all-targets', '--', '-D', 'warnings'))
    if ($MacOS) {
        $installed = @(& rustup target list --installed)
        if ($LASTEXITCODE -ne 0) { throw 'Cannot list installed Rust targets' }
        $found = $false
        foreach ($target in @('aarch64-apple-darwin', 'x86_64-apple-darwin')) {
            if ($installed -contains $target) {
                $found = $true
                Invoke-Check cargo (@('clippy', '--locked', '--offline') + $packages + @('--all-targets', '--target', $target, '--', '-D', 'warnings'))
            }
        }
        if (-not $found) { Write-Host 'Skipping macOS: no Apple target installed.' }
    }
    if ($Panel) {
        Push-Location -LiteralPath (Join-Path $repo 'apps/control-panel')
        try {
            Invoke-Check npm @('run', 'test')
            Invoke-Check npm @('run', 'build')
        } finally { Pop-Location }
    }
    if ($Tauri) {
        $manifest = @('--manifest-path', 'apps/control-panel/src-tauri/Cargo.toml')
        Invoke-Check cargo (@('fmt') + $manifest + @('--', '--check'))
        Invoke-Check cargo (@('test') + $manifest + @('--locked', '--offline', '--lib', '--tests'))
        Invoke-Check cargo (@('clippy') + $manifest + @('--locked', '--offline', '--all-targets', '--', '-D', 'warnings'))
    }
    Write-Host 'Selected software checks passed. Physical/native input certification remains pending.'
} finally {
    Pop-Location
    $env:RUSTUP_AUTO_INSTALL = $previousAutoInstall
}
