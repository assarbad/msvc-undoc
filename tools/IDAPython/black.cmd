@echo off
for %%i in (%~dp0*.py) do @(
    @echo %%i
    py -3 -m black "%%i"
)
