# Build winevdm.
# Preferred: VS 2022 Win32 (v143) if MSVC x86 exists.
# Fallback: MSYS2 mingw32 gcc + ninja (AppVeyor cmake path).
param(
    [ValidateSet('Debug','Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('Auto','VS','MinGW')]
    [string]$Generator = 'Auto'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Test-MsysTools {
    foreach ($n in @('as.exe','bison.exe','flex.exe')) {
        $p = Join-Path 'C:\msys64\usr\bin' $n
        if (-not (Test-Path $p)) { throw "$p missing. In MSYS2: pacman -S --noconfirm binutils bison flex" }
    }
}

function Get-MsvcX86Cl {
    Get-ChildItem 'C:\Program Files\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x86\cl.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}

function Invoke-VsBuild {
    Test-MsysTools
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw 'MSBuild not found' }
    Write-Host "MSBuild: $msbuild"
    & $msbuild (Join-Path $root 'otvdm.sln') `
        /m `
        /p:Configuration=$Configuration `
        /p:Platform=Win32 `
        /p:PlatformToolset=v143 `
        /p:WindowsTargetPlatformVersion=10.0.22621.0
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed ($LASTEXITCODE)" }
    Write-Host "Output: $(Join-Path $root $Configuration)"
}

function Invoke-MingwBuild {
    Test-MsysTools
    $gcc = 'C:\msys64\mingw32\bin\gcc.exe'
    if (-not (Test-Path $gcc)) {
        throw 'C:\msys64\mingw32\bin\gcc.exe missing. In MSYS2: pacman -S --noconfirm mingw-w64-i686-gcc mingw-w64-i686-cmake make'
    }
    $build = Join-Path $root 'build'
    New-Item -ItemType Directory -Force -Path $build | Out-Null
    $type = if ($Configuration -eq 'Debug') { 'Debug' } else { 'Release' }
    $bash = @'
set -e
export MSYSTEM=MINGW32
export MSYSTEM_CARCH=i686
export MSYSTEM_CHOST=i686-w64-mingw32
export MSYSTEM_PREFIX=/mingw32
export PATH=/mingw32/bin:/usr/local/bin:/usr/bin:$PATH
cd /c/tmp/winevdm-master/build
cmake -G Ninja -DCMAKE_BUILD_TYPE=TYPE_PLACEHOLDER -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w ..
ninja
'@
    $bash = $bash.Replace('TYPE_PLACEHOLDER', $type)
    Write-Host "CMake/Ninja mingw32 $type"
    & 'C:\msys64\usr\bin\bash.exe' -lc $bash
    if ($LASTEXITCODE -ne 0) { throw "MinGW build failed ($LASTEXITCODE)" }
    $mingwBin = 'C:\msys64\mingw32\bin'
    foreach ($dll in @('libgcc_s_dw2-1.dll','libstdc++-6.dll','libwinpthread-1.dll')) {
        Copy-Item -Force (Join-Path $mingwBin $dll) $build
    }
    Write-Host "Copied MinGW runtime DLLs into $build"
    Write-Host "Output: $build"
}

$useVs = $false
if ($Generator -eq 'VS') { $useVs = $true }
elseif ($Generator -eq 'MinGW') { $useVs = $false }
elseif (Get-MsvcX86Cl) { $useVs = $true }

if ($useVs) { Invoke-VsBuild } else { Invoke-MingwBuild }
