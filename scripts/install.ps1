# Installs the binfera command-line tool from a GitHub release (Windows, PowerShell 5.1 or later).
#
#   irm https://binfera.io/install.ps1 | iex
#
# It downloads the archive, checks it against the release's SHA256SUMS, and puts binfera.exe in
# $env:BINFERA_HOME\bin (default %LOCALAPPDATA%\binfera\bin), then adds that folder to your user PATH.
# The capability rules and the decompiler are inside the binary, so nothing else is installed.
#
# $env:BINFERA_VERSION   a release tag such as v1.0.0 (default: the latest release)
# $env:BINFERA_HOME      where to install
# $env:BINFERA_BASE_URL  where release files are downloaded from (for testing)
# $env:BINFERA_API_URL   the releases list used to find the latest version (for testing)
$ErrorActionPreference = "Stop"
$repo = "Karib0u/binfera"
$home_ = if ($env:BINFERA_HOME) { $env:BINFERA_HOME } else { Join-Path $env:LOCALAPPDATA "binfera" }
$target = "x86_64-pc-windows-msvc"

$version = $env:BINFERA_VERSION
if (-not $version) {
  # Not GitHub's "latest release": the desktop app is released under desktop-v* tags, can become
  # the latest, and carries no command-line archives. Take the newest release tagged v<number>.
  $api = if ($env:BINFERA_API_URL) { $env:BINFERA_API_URL } else { "https://api.github.com/repos/$repo/releases?per_page=50" }
  # Parentheses make Windows PowerShell 5.1 pass the releases one by one; without them it passes
  # the whole array as one object and no release matches.
  $release = (Invoke-RestMethod -Uri $api) | Where-Object { $_.tag_name -match '^v\d' -and -not $_.draft } | Select-Object -First 1
  if (-not $release) { throw "could not find a command-line release of binfera" }
  $version = $release.tag_name
}
$base = if ($env:BINFERA_BASE_URL) { $env:BINFERA_BASE_URL } else { "https://github.com/$repo/releases/download/$version" }
$name = "binfera-$version-$target"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("binfera-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading binfera $version for $target"
  Invoke-WebRequest -Uri "$base/$name.zip" -OutFile "$tmp\$name.zip" -UseBasicParsing
  Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing

  $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match [regex]::Escape("$name.zip") } | Select-Object -First 1
  if (-not $line) { throw "$name.zip is not listed in SHA256SUMS" }
  $expected = ($line -split "\s+")[0].ToLower()
  $actual = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "checksum mismatch for $name.zip: expected $expected, got $actual" }

  Expand-Archive -Path "$tmp\$name.zip" -DestinationPath $tmp -Force
  $bin = Join-Path $home_ "bin"
  New-Item -ItemType Directory -Path $bin -Force | Out-Null
  Copy-Item "$tmp\$name\binfera.exe" (Join-Path $bin "binfera.exe") -Force

  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($path -split ";") -notcontains $bin) {
    [Environment]::SetEnvironmentVariable("Path", "$path;$bin", "User")
    Write-Host "Added $bin to your user PATH. Open a new terminal to use it."
  }
  Write-Host "Installed $(& (Join-Path $bin 'binfera.exe') --version) to $bin"
  Write-Host "Next: claude mcp add --scope user binfera -- $bin\binfera.exe mcp"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
