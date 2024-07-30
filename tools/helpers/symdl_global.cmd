@echo off
if not defined _NT_SYMBOL_PATH echo ERROR: _NT_SYMBOL_PATH must be defined & exit /b 1
setlocal
set PATH=%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64;%PATH%
for /R "%CD%" %%i in (*.dll *.exe *.sys *.dll_ *.exe_ *.sys_) do @(
    echo %%i
    symchk /v "%%i"
)
endlocal
