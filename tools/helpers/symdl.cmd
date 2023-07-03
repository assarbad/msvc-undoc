@echo off
setlocal
set PATH=%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64;%PATH%
set SYMDIR=%CD%\syms
if not exist "%SYMDIR%" md "%SYMDIR%"
set _NT_SYMBOL_PATH=srv*%SYMDIR%*http://msdl.microsoft.com/download/symbols
for %%i in (*.dll *.exe) do @(
    echo %%i
    symchk /v "%%i"
)
endlocal
