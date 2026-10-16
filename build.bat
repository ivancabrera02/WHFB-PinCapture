@echo off
REM Build the non-intrusive PIN-capture DLL (ngccap.dll) with MSVC.
REM Adjust the vcvars64.bat path if your Visual Studio / Build Tools version differs.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /LD /MT ngccap.c /link /OUT:ngccap.dll kernel32.lib user32.lib
