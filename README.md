This project was abandoned.
# window-cleaner
This is a script to turn off some Windows 11 features, minimize telemetry, and set a few security settings.
The point of this project compared to other tools is using group policies instead of registry keys directly to preserve settings over time.

To use this script, clone this repository or download it as a ZIP file, carefully read and comment changes in the cleaner.bat script and in the LGPO.txt file that you don't want to be made, and then run the script. Afterwards, I suggest running RUN ME AFTER APPLYING SETTINGS AND REBOOTING.bat to fix possible system file corruption after making changes to Windows.

Currently made for Windows 11 Pro. It is very vaguely tested and needs a rewrite for easier reading of changes it makes to the system.
