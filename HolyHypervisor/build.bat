@echo off
echo ========================================
echo HolyHypervisor Auto Builder
echo ========================================
echo.

echo [1] Building HolyHypervisor (Release/x64)...
"C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" "projects\samples.sln" /p:Configuration=Release /p:Platform=x64 /t:HolyHypervisor:Rebuild

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed! Please check the error messages above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [2] Build succeeded! Copying HolyHypervisor.efi to Release folder...
copy /Y "projects\x64\Release\HolyHypervisor.efi" "..\HolyHypervisor_Release\HolyHypervisor.efi"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to copy the EFI file! Check your folder paths.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [SUCCESS] All done! The EFI file is ready in HolyHypervisor_Release.
echo ========================================
pause
