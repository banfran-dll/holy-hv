@echo off
set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0

echo [1] Setting up VS environment...
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo [2a] Assembling HolyCpuid.asm...
ml64 /c /nologo /Zi /Fo HolyCpuid.obj HolyCpuid.asm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

echo.
echo [2b] Compiling HolyHvProbe Driver...
cl /c /O2 /nologo /W3 /WX- /Z7 /Gy /GS- /wd4201 /wd4100 /D_AMD64_ /D_WIN64 /D_KERNEL_MODE /I"%WDK_INC%\km" /I"%WDK_INC%\shared" /I"%WDK_INC%\km\crt" HolyHvProbe.c
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

echo.
echo [3] Linking HolyHvProbe.sys...
link /nologo /subsystem:native /driver /entry:DriverEntry /nodefaultlib /machine:x64 /out:HolyHvProbe.sys HolyHvProbe.obj HolyCpuid.obj "%WDK_LIB%\km\x64\ntoskrnl.lib" "%WDK_LIB%\km\x64\hal.lib" /OPT:REF /OPT:ICF /MERGE:.rdata=.text
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

echo.
echo [4] Compiling User-mode Test Exes...
cl /nologo cpuid_via_driver.c /Fe:cpuid_via_driver.exe
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

cl /nologo holyctl.c /Fe:holyctl.exe
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

echo.
echo [SUCCESS] HolyHvProbe.sys, cpuid_via_driver.exe, and holyctl.exe built successfully.

echo.
echo [5] Signing the Driver...
powershell.exe -ExecutionPolicy Bypass -File .\sign.ps1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Signing failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [ALL DONE] Build and Signing complete!
pause
