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

    & $exe install
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
