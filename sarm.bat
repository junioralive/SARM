@echo off
if "%1"=="" (
    echo Usage: %0 [hide|unhide]
    
    exit /b 1
)

if "%1"=="hide" goto hide
if "%1"=="unhide" goto unhide

echo Invalid command! Use "hide" or "unhide".

exit /b 1

:hide
net session >nul 2>&1
if %errorLevel% == 0 (
    call :clear_temp_files
    call :hide_alive_partition
) else (
    powershell -Command "Start-Process cmd -ArgumentList '/c %~f0 hide' -Verb runAs"
)

goto end

:unhide
net session >nul 2>&1
if %errorLevel% == 0 (
    call :unhide_alive_partition
) else (
    powershell -Command "Start-Process cmd -ArgumentList '/c %~f0 unhide' -Verb runAs"
)

goto end

:hide_alive_partition
echo list volume > diskpart_script.txt
diskpart /s diskpart_script.txt > diskpart_output.txt

rem Find the volume number of the "Alive" partition
for /f "tokens=2" %%a in ('findstr /C:" Alive " diskpart_output.txt') do (
    set volume_number=%%a
)

echo Volume Number Detected: %volume_number%

rem Select the volume and remove the letter (if exists)
echo select volume %volume_number% > diskpart_script.txt
echo remove letter=P >> diskpart_script.txt
diskpart /s diskpart_script.txt
echo Partition "Alive" hidden (Volume %volume_number%)

rem Clean up temporary files (only on hide)
call :clear_temp_files

rem Delete the diskpart script and output files
del /q diskpart_script.txt diskpart_output.txt


goto :EOF

:unhide_alive_partition
echo list volume > diskpart_script.txt
diskpart /s diskpart_script.txt > diskpart_output.txt

rem Find the volume number of the "Alive" partition
for /f "tokens=2" %%a in ('findstr /C:" Alive " diskpart_output.txt') do (
    set volume_number=%%a
)

echo Volume Number Detected: %volume_number%

rem Force assign letter P to the "Alive" partition
echo select volume %volume_number% > diskpart_script.txt
echo assign letter=P >> diskpart_script.txt
diskpart /s diskpart_script.txt
echo Partition "Alive" unhidden and assigned letter P (Volume %volume_number%)

rem Delete the diskpart script and output files
del /q diskpart_script.txt diskpart_output.txt


goto :EOF

:clear_temp_files
echo Cleaning up temp files...
set TEMP_DIR=%TEMP%
del /q /f %TEMP_DIR%\*.* >nul 2>&1
rd /s /q %TEMP_DIR% >nul 2>&1
echo Temp files cleared.
goto :EOF

:end
