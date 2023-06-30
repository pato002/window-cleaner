@echo off

:: PLEASE RUN AFTER APPLYING CHANGES AND REBOOTING
echo "This script will fix possible minor file corruption after settings applied to the computer."
PAUSE

:: Ask for admin permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Check errors on filesystem
start /b /wait chkntfs C:

:: Check corrupted files
start /b /wait sfc /scannow

:: Run online repair
set dism=
set /p "dism=Would you also like to run an online repair of Windows using DISM? You need to be connected to the internet. If you do, type YES: "
if /i "%dism%"=="YES" (
  start /b /wait dism /online /cleanup-image /restorehealth
)

:: RESTART TO FINISH
set restart=
set /p "restart=System checked and repaired. You need to restart your computer. If you would like to do it now, type YES: "
if /i "%restart%"=="YES" (
  shutdown /r /t 0
)

PAUSE

