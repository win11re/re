@echo off

set "CVDUMP=D:\microsoft-pdb\cvdump\cvdump.exe"

:: see if it exists
if not exist "%CVDUMP%" (
    echo cvdump not found at %CVDUMP%
    pause
    exit /b 1
)

pushd "%~dp0"

if not exist "cvdump.exe" copy "%CVDUMP%" .

for %%f in (*.pdb) do (
    echo Processing %%f...
    cvdump.exe -p "%%f" >> publics.txt
    cvdump.exe -seccontrib %%f > seccontrib.txt
cvdump.exe -m %%f > modules.txt
)