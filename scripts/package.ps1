param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $projectRoot "dist\package-$Configuration"
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($arch in @('x64', 'x86')) {
    $build = Join-Path $projectRoot "build\windows-$arch"
    & cmake --install $build --config $Configuration --prefix $stage
    if ($LASTEXITCODE -ne 0) { throw "Install failed for $arch" }
}
$manifest = Join-Path $stage 'MANIFEST.XML'
# ZIP entry names are case-sensitive even when packaging on Windows.
if (Test-Path -LiteralPath $manifest) { Remove-Item -LiteralPath $manifest }
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\MANIFEST.XML') -Destination $manifest
# Remove documentation left by previous versions of the packaging script.
foreach ($name in @('README.md', 'TESTING.md', 'SFTP.bsl')) {
    $obsolete = Join-Path $stage $name
    if (Test-Path -LiteralPath $obsolete) { Remove-Item -LiteralPath $obsolete }
}
$archive = Join-Path $projectRoot "dist\SFTPAddIn-$Configuration.zip"
$contents = @('MANIFEST.XML', 'info.xml', 'VerInfo.txt', 'SFTPAddIn_x86.dll', 'SFTPAddIn_x64.dll', 'licenses') |
    ForEach-Object { Join-Path $stage $_ }
Compress-Archive -Path $contents -DestinationPath $archive -Force
Get-Item -LiteralPath $archive
