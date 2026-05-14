# zig-version-kit stage0 installer (Windows PowerShell)
#
# Downloads a prebuilt `zvk.exe`, runs `zvk self-install` then `zvk install`.
#
# Usage:
#   irm https://raw.githubusercontent.com/zoptia/zig-version-kit/main/install.ps1 | iex
#
# Env:
#   $env:ZVK_VERSION   release tag to pin to (default: "latest")

$ErrorActionPreference = 'Stop'

$repo = 'zoptia/zig-version-kit'
$version = if ($env:ZVK_VERSION) { $env:ZVK_VERSION } else { 'latest' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { Write-Error "[zvk] unsupported architecture: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

$asset = "zvk-${arch}-windows-gnu.exe"
$url = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download/$asset"
} else {
    "https://github.com/$repo/releases/download/$version/$asset"
}

$tmp = Join-Path $env:TEMP "zvk-installer-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$exe = Join-Path $tmp 'zvk.exe'

try {
    Write-Host "[zvk] downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing

    & $exe self-install
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    # Idempotently add ~/.zoptia/zig/bin to the user's PATH (User scope, persists
    # across shells). zvk itself doesn't manage PATH on Windows — see setupPath.
    $binDir = Join-Path $env:USERPROFILE '.zoptia\zig\bin'
    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if (-not $userPath -or ($userPath.Split(';') -notcontains $binDir)) {
        $newPath = if ($userPath) { "$binDir;$userPath" } else { $binDir }
        [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
        Write-Host "[zvk] added $binDir to user PATH (restart your shell to pick it up)"
    } else {
        Write-Host "[zvk] PATH already configured"
    }
    # Make the new bin dir visible to the current process so subsequent zvk calls work.
    $env:PATH = "$binDir;$env:PATH"

    & $exe install
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
