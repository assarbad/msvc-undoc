<# ::
@echo off
:: Rename this file to .ps1.cmd to have this NT script wrapper take effect
set PSSCRIPT=%~dpnx0
set PSSCRIPT=%PSSCRIPT:.cmd=%
@echo on
copy /y "%~dpnx0" "%PSSCRIPT%" > nul
PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NoProfile -File "%PSSCRIPT%" %*
set ERR=%ERRORLEVEL%
del /f "%PSSCRIPT%" > nul
@exit /b %ERR%
#>
#Requires -Version 6.0
Set-StrictMode -Version Latest
Set-PSDebug -Off
$VerbosePreference = "continue"

$tools = (
    "armasm.exe",
    "armasm64.exe",
    "cl.exe",
    "lib.exe",
    "link.exe",
    "ml.exe",
    "ml64.exe",
    "nmake.exe"
)

Get-ChildItem -Recurse -Path $pwd|%{
    $fname = $_.FullName
    if ($null -ne ($tools|? {$fname.EndsWith($_)}))
    {
        $ver = (Get-Item -Path $fname).VersionInfo.FileVersion
        $ver = $ver | Select-String "^\d+(\.\d+)+" | % { $_.Matches[0].Groups[0].Value } # handle some wonky version strings
        echo "$fname ($ver)"
        if ($_.Name.Contains("arm"))
        {
            & $fname -h 2>&1 | Tee-Object -Path "${fname}-${ver}.txt" | Out-Null
        }
        else
        {
            & $fname /? 2>&1 | Tee-Object -Path "${fname}-${ver}.txt" | Out-Null
        }
    }
}
