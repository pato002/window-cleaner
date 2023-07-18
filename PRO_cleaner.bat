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
  if errorlevel 1 ( goto INTERNET )
  tar -xf LGPO.zip -k
  del /s /f LGPO.zip
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

:: Installing new group policies
echo "Installing group policies"
if not exist "C:\Windows\PolicyDefinitions\msedge.admx" ( copy .\Common\ADMX\msedge.admx C:\Windows\PolicyDefinitions\msedge.admx )
if not exist "C:\Windows\PolicyDefinitions\en-US\msedge.adml" ( copy .\Common\ADMX\en-US\msedge.adml C:\Windows\PolicyDefinitions\en-US\msedge.adml )
copy .\Common\ADMX\WindowCleaner.admx C:\Windows\PolicyDefinitions\WindowCleaner.admx /y
copy .\Common\ADMX\en-US\WindowCleaner.adml C:\Windows\PolicyDefinitions\en-US\WindowCleaner.adml /y




:: *******************************
:: --> START EDITING FILE HERE <--
:: *******************************



:: SETTINGS DISABLING MAJOR FEATURES

:: Turn off clipboard history, disabled by default as it is a quite useful feature
:: .\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoClipboardHistory.txt

:: Completely uninstall OneDrive
TASKKILL /f /im OneDrive.exe
start /b /wait %systemroot%\System32\OneDriveSetup.exe /uninstall
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
rd C:\OneDriveTemp /Q /S >NUL 2>&1

:: Disable Chat icon on taskbar
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoChat.txt

:: Do not sync anything
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoSync.txt

:: Turn off synchronizing clipboard across devices
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoClipboardAcrossDevices.txt

:: Disable synchronization of messages with the cloud
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCloudMessageSync.txt

:: Disable Cloud Search from Windows Search
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCloudSearch.txt

:: Disable Cortana
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCortana.txt

:: Disable Cortana above lock screen
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCortanaOverLock.txt

:: Disable Xbox Game Bar
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoGameBar.txt

:: Turn off automatic learning of handwriting
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoHandwritingLearn.txt

:: Hide the Meet Now icon from the notification area
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoMeet.txt

:: Prevent the use of OneDrive for file storage
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoOneDriveFileSync.txt

:: Turn off online speech recognition services
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoOnlineSpeechRecognition.txt

:: Disable News and Interests on the toolbar
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoTaskbarNews.txt

:: Disable Web Search in Windows Search
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoWebSearch.txt

:: Disable Widgets
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoWidgets.txt

:: Defer Windows Updates as much as possible for improved stability
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\WindowsUpdateDefer.txt

:: Disable a lot of Microsoft Edge features
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\MSEdge.txt



:: SETTINGS DISABLING MINOR FEATURES

:: Disable search indexing
sc config "WSearch" start= disabled
sc stop "WSearch"

:: Disable AutoPlay
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoAutoPlay.txt

:: Disable downloading of updates for Cortana speech recognition model
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCortanaUpdate.txt

:: Disable Fast Startup
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoFastStartup.txt

:: Turn off Inventory Collector telemetry
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoInventoryCollector.txt

:: Disable location services
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoLocationServices.txt

:: Disable Windows Timeline
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoWindowsTimeline.txt

:: Turn off communication with support provider in Microsoft Support Diagnostic Tool
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoMSDTTalk.txt

:: Turn off Search Companion content file updates from internet
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoSearchInternetUpdate.txt

:: Do not allow Cortana and Search to use location
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoSearchLocation.txt

:: Hide recommended section in start menu
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoStartRecommended.txt

:: Turn off Steps Recorder
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoStepsRecorder.txt

:: Disable hardware keyboard text prediction
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoHwkbPrediction.txt

:: Disable text suggestions in other languages
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoMultilingPrediction.txt

:: Disable software keyboard text prediction
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoSwkbPrediction.txt

:: No access to language info for websites
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoWebsiteAccessLang.txt



:: SETTINGS DISABLING UNNECESSARY FEATURES

:: Send only required diagnostic data
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\OnlyPRO\RequiredDiagData.txt

:: Disable superfetch service
sc config "SysMain" start= disabled
sc stop "SysMain"

:: Disable Windows Prefetcher
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoPrefetch.txt

:: Do not let apps access diagnostic info
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoAppDiagInfo.txt

:: Set Windows Compatibility Manager to manual start
sc config "PcaSvc" start= demand

:: Set State Repository browser monitoring service to manual start
:: sc config "StateRepository" start= demand
:: CURRENTLY NOT WORKING 

:: Set Storage Sense to manual start
sc config "StorSvc" start= demand

:: Disable Windows Autotune
netsh int tcp set global autotuninglevel=disabled

:: Disable Delivery Optimization
:: sc config "DoSvc" start= disabled
:: sc stop "DoSvc"
:: CURRENTLY NOT WORKING

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

:: Disable Malicious Software Reporting tool diagnostic data upload
schtasks /change /tn "Microsoft\Windows\RemovalTools\MRT_HB" /disable

:: Only send anonymous data with Bing in Search
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\AnonBing.txt

:: Hide advertising ID from apps
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\HideAdID.txt

:: Disable application telemetry
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoAppTelemetry.txt

:: Disable AutoRun
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoAutoRun.txt

:: Disable automatic sign on after restart and automatic settings after update
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoAutoSignOn.txt

:: Turn off Windows Customer Experience Improvement Program
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCEIP.txt

:: Disable Delivery Optimization
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoDeliveryOptimization.txt

:: Turn off Windows error reporting
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoErrorReport.txt

:: Set feedback frequency to never
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoFeedbackFreq.txt

:: Disable first logon animation
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoFirstLogAnimation.txt

:: Disable sending handwriting data to Microsoft
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoHandwritingData.txt

:: Disable sending of handwriting error reports
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoHandwritingError.txt

:: Prevent participation in the Customer Experience Improvement Program in Internet Explorer
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoIExplorerImprovement.txt

:: Prevent collecting device metadata from internet
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoInternetMetadata.txt

:: Disable advanced location tracking
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoLocationTrack.txt

:: Disable unwanted network traffic for offline maps
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoNetworkOfflineMap.txt

:: Disable automatic offline map updates
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoOfflineMapUpdate.txt

:: Prevent OneDrive from generating network traffic until the user signs in
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoOneDriveSyncBeforeUser.txt

:: Disable OneSettings auditing
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoOneSettingsAudit.txt

:: Disable personalized ads
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoPersonalAds.txt

:: Do not show recently added apps
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoRecentApps.txt

:: Do not improve inking and typing recognition by sending telemetry
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoTypeInkrecognition.txt

:: Turn off tracking of User Activities
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoUserActivityTrack.txt

:: Turn off the Windows Messenger Customer Experience Improvement Program
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoWMCEIP.txt

:: Turn off File Explorer ads for OneDrive
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoExplorerAds.txt

:: Disable Windows Media Player usage tracking
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoMPTrack.txt

:: Do not let Windows track app launches
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoStartTrackProgs.txt

:: Prevent Teams from installing automatically
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoTeamsAutoInstall.txt

:: Disable WiFi-Sense automatic connecting
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoWiFiSenseAuto.txt

:: Disable WiFi-Sense hotspot reporting
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\NoWiFiSenseReport.txt



:: ADVERTISEMENTS AND CLOUD CONNECTIONS

:: Disable a few cloud content settings
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\NoCloudContent.txt

:: Do not suggest third-party content in Windows Spotlight
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\OnlyPRO\No3rdPartySpotlight.txt

:: Prevent automatic installation of new apps suggested by Microsoft
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoAutoInstallApp.txt

:: Turn off Windows feature management
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoFeatureMan.txt

:: Prevent new Content Delivery Manager features from getting allowed
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoNewContentDelivery.txt

:: Prevent installation of suggested OEM apps
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoOEMPreinstallApp.txt

:: Prevent Windows from showing suggestions on the taskbar
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoPanelSug.txt

:: Prevent installation of suggested apps by Microsoft
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoPreinstallApp.txt

:: Turn off Windows Spotlight on lock screen
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoSpotlightLock.txt

:: Turn off Windows Spotlight overlay on lock screen
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoSpotlightOverLock.txt

:: Turn off Spotlight slideshow
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoSpotlightSlideshow.txt

:: Turn off suggestions in Settings
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoSugContSet.txt

:: Prevent showing the notification to get the most out of Windows
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NotGetMostWindows.txt

:: Prevent Windows from showing tips, tricks and suggestions on how to use Windows
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoTipTrickSug.txt

:: Prevent Windows from sending tips in notifications
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NotTip.txt

:: Disable Windows Welcome Experiences like forcing to sign in to Microsoft Account
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\NoWelcomeExp.txt

:: Prevent suggested applications from ever getting installed
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\PreinstallAppNever.txt

:: Prevent Microsoft from suggesting new products based on telemetry
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\TailoredExp.txt

:: Prevent showing suggestion on the timeline
.\LGPO_30\LGPO.exe /t .\Common\LGPO-settings\CustomADMX\ContentDeliveryManager\TimelineSug.txt



:: ******************************
:: --> STOP EDITING FILE HERE <--
:: ******************************




:: RESTART TO APPLY CHANGES
set restart=
set /p "restart=You need to restart your computer to apply changes made by this script. If you would like to do it now, type YES: "
if /i "%restart%"=="YES" (
  shutdown /r /t 0
) else ( goto EOF )

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
