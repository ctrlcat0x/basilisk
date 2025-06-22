@echo off
nuitka ^
  --onefile ^
  --standalone ^
  --enable-plugin=pyqt5 ^
  --remove-output ^
  --windows-console-mode=disable ^
  --windows-uac-admin ^
  --output-dir=dist ^
  --follow-imports ^
  --windows-icon-from-ico=media/ICON.ico ^
  --include-data-dir=configs=configs ^
  --include-data-dir=media=media ^
  --include-data-dir=scripts=scripts ^
  --include-package=screens ^
  basilisk.py
pause
