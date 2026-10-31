# syft/grype Windows 바이너리를 poc/bin/ 에 다운로드한다. Docker 불필요 (registry 직접 스캔).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $root "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null

$syftVer = "1.55.0"
$grypeVer = "0.121.0"

$tmp = Join-Path $env:TEMP "poc_tools_dl"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Invoke-WebRequest -Uri "https://github.com/anchore/syft/releases/download/v$syftVer/syft_${syftVer}_windows_amd64.zip" -OutFile "$tmp\syft.zip"
Invoke-WebRequest -Uri "https://github.com/anchore/grype/releases/download/v$grypeVer/grype_${grypeVer}_windows_amd64.zip" -OutFile "$tmp\grype.zip"

Expand-Archive -Path "$tmp\syft.zip" -DestinationPath "$tmp\syft_extract" -Force
Expand-Archive -Path "$tmp\grype.zip" -DestinationPath "$tmp\grype_extract" -Force

Copy-Item "$tmp\syft_extract\syft.exe" "$bin\syft.exe" -Force
Copy-Item "$tmp\grype_extract\grype.exe" "$bin\grype.exe" -Force
Remove-Item -Recurse -Force $tmp

& "$bin\syft.exe" version
& "$bin\grype.exe" version
Write-Host "`nOK: poc\bin\syft.exe, poc\bin\grype.exe 준비 완료"
