@echo off

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

:: Are you sure?
set consent=
set /p "consent=This script will disable some Windows features, disable telemetry, and set a few settings for better security. Please, read what it can do before you run it, and comment or delete the lines with settings you don't want to be applied to the system. If you already did that, type YES to run the script: "
if /i not "%consent%"=="YES" goto EOF

:: Downloading and unzipping LGPO
echo "Downloading and unzipping LGPO"
if not exist ".\LGPO_30\LGPO.exe" (
  curl -o LGPO.zip https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip
  if errorlevel 1 (goto INTERNET)
  tar -xf LGPO.zip -k
)

:: Backing up registry and group policy
echo "Backing up registry and group policy"
if not exist ".\BACKUP" (
  mkdir ".\BACKUP"
  if not errorlevel 1 (
    mkdir ".\BACKUP\Registry"
    reg export HKEY_CLASSES_ROOT .\BACKUP\Registry\HKCR.reg /y
    reg export HKEY_LOCAL_MACHINE .\BACKUP\Registry\HKLM.reg /y
    reg export HKEY_CURRENT_USER .\BACKUP\Registry\HKCU.reg /y
    reg export HKEY_USERS .\BACKUP\Registry\HKU.reg /y
    
    mkdir ".\BACKUP\GroupPolicy"
    xcopy "C:\Windows\System32\GroupPolicy" ".\BACKUP\GroupPolicy" /h /i /c /k /e /r /y
	attrib -s -h ".\BACKUP\GroupPolicy"
  )
)


:: SETTINGS APPLIED TO THE SYSTEM
echo "Applying system settings"

:: Disable superfetch service
sc config "SysMain" start= disabled
sc stop "SysMain"

:: Disable prefetch
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x00000000 /f

:: Set Windows Compatibility Manager to manual start
sc config "PcaSvc" start= demand

:: Set State Repository browser monitoring service to manual start
:: sc config "StateRepository" start= demand
:: CURRENTLY NOT WORKING 

:: Set Storage Sense to manual start
sc config "StorSvc" start= demand

:: Disable search indexing
sc config "WSearch" start= disabled
sc stop "WSearch"

:: Disable Windows Autotune
netsh int tcp set global autotuninglevel=disabled

:: Disable fast startup 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0x00000000 /f

:: Prevent Teams from installing 
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0x00000000 /f
:: CURRENTLY NOT WORKING

:: Completely uninstall OneDrive
TASKKILL /f /im OneDrive.exe
start /b /wait %systemroot%\System32\OneDriveSetup.exe /uninstall
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
rd C:\OneDriveTemp /Q /S >NUL 2>&1

:: Disable getting updates asap
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 0x00000000 /f

:: Disable automatic update of offline maps
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable Delivery Optimization
reg add "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v DownloadModeProvider /t REG_DWORD /d 0x00000008 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 0x00000004 /f
:: sc config "DoSvc" start= disabled
:: CURRENTLY NOT WORKING
sc stop "DoSvc"

:: Disable DiagTrack Service
sc config "DiagTrack" start= disabled
sc stop "DiagTrack"

:: Disable Error Reporting Service
sc config "WerSvc" start= disabled
sc stop "WerSvc"

:: Disable USB info collecting task
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable

:: Disable task collecting usage data
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable

:: Disable disk diagnostic data sending to Microsoft
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable

:: Disable device compatibility with Windows check
schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable

:: Disable automatic collection and sending of usage data
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable

:: Disable special survey system
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable

:: Disable Queueing of reports
schtasks /change /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable

:: Disable collection of events on DiagTrack
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0x00000000 /f

:: Disable WiFi-Sense
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0x00000000 /f


:: SETTINGS ONLY APPLIED TO THE CURRENT USER
echo "Applying current user settings"

:: Disable File Explorer OneDrive ads
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0x00000000 /f

:: Disable text suggestions on hardware keyboard 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\Settings" /v EnableHwkbTextPrediction /t REG_DWORD /d 0x00000000 /f

:: Disable text suggestions in other languages
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\Settings" /v MultilingualEnabled /t REG_DWORD /d 0x00000000 /f

::Disable text suggestions for software keyboard
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\Settings\proc_1\loc_0409\im_1" /v Prediction /t REG_DWORD /d 0x00000000 /f

:: No access to language info for websites
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 0x00000001 /f

:: Hide Windows Welcome Experiences
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0x00000000 /f

:: Do not show tips and tricks
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0x00000000 /f

:: Hide suggested content in settings
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0x00000000 /f

:: Disable Feature Management
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable OEM preinstalled apps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable preinstalled apps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable Spotlight on lock screen
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable Windows panel suggestions
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0x00000000 /f

:: Turn off Spotlight slideshow
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SlideshowEnabled /t REG_DWORD /d 0x00000000 /f

:: Turn off any new Content Delivery features
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0x00000000 /f

:: No preinstalled apps are ever enabled
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable automatic installation of apps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0x00000000 /f

:: Do not suggest ways to get the most out of windows
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0x00000000 /f		

:: Turn off Windows timeline suggestions
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0x00000000 /f

:: Disable tailored experiences
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314563Enabled /t REG_DWORD /d 0x00000000 /f

:: Disable XBOX Game Bar features
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0x00000000 /f

:: Disable AutoPlay
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoPlay /t REG_DWORD /d 0x00000001 /f

:: Disable Windows Media Player usage tracking
reg add "HKEY_CURRENT_USER\Software\Microsoft\MediaPlayer\Preferences" /v UsageTracking /t REG_DWORD /d 0x00000000 /f


:: APPLY GROUP POLICY SETTINGS FROM LGPO.txt
echo "Applying group policy"

.\LGPO_30\LGPO.exe /t .\lgpo.txt


:: RESTART TO APPLY CHANGES
set restart=
set /p "restart=You need to restart your computer to apply changes made by this script. If you would like to do it now, type YES: "
if /i "%restart%"=="YES" (
  shutdown /r /t 0
) else goto EOF

goto EOF

:INTERNET
echo "Please connect to the internet to download LGPO."

:EOF

PAUSE


:: Sources:
:: Many Windows forums
:: Sophia Script for Windows https://github.com/farag2/Sophia-Script-for-Windows
:: https://brookspeppin.com/2018/11/04/modify-local-gpo-examples/
:: CTT's Windows Utility https://github.com/ChrisTitusTech/winutil
:: Batch Got Admin script  https://gist.github.com/lances101/44118a5ab320542f9591c5fa5b74ae02
