@echo off
setlocal
python "%~dp0tools\apk_builder.py" %*
exit /b %ERRORLEVEL%
