@echo off
rem Lancer ACET depuis le dossier source (Windows) : double-cliquer sur ce fichier.
rem  - 1re fois : cree l'environnement Python prive (.venv) et installe ACET + l'interface ;
rem  - ensuite  : lance directement ; reinstalle seulement si pyproject.toml a change.
rem Options :
rem   Lancer-ACET.bat update    recupere d'abord la derniere version du code (git pull), puis lance
rem   Lancer-ACET.bat console   lance avec une console visible (pour voir une erreur de demarrage)
rem   Lancer-ACET.bat check     installe/verifie seulement, sans ouvrir l'interface (utilise par la CI)
setlocal EnableExtensions
cd /d "%~dp0"
title ACET
set "MODE=%~1"

if /i "%MODE%"=="update" (
    where git >nul 2>&1 || (echo [ACET] Git est introuvable : mise a jour impossible. & goto :fail)
    echo [ACET] Mise a jour du code...
    git pull --ff-only || goto :fail
)

set "VENV=%~dp0.venv"
set "PY=%VENV%\Scripts\python.exe"
set "MARK=%VENV%\.acet-installed"

if exist "%PY%" goto :venv_ok
echo [ACET] Premiere utilisation : creation de l'environnement Python...
set "BASEPY="
for %%v in (3.13 3.12 3.11 3) do (
    if not defined BASEPY py -%%v -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1 && set "BASEPY=py -%%v"
)
if not defined BASEPY (
    python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1 && set "BASEPY=python"
)
if not defined BASEPY (
    echo [ACET] Python 3.11 ou plus est introuvable.
    echo        Installez-le depuis https://www.python.org/downloads/windows/
    echo        ^(cochez "Add python.exe to PATH"^), puis relancez ce fichier.
    goto :fail
)
echo [ACET] Python utilise : %BASEPY%
%BASEPY% -m venv "%VENV%" || goto :fail
if exist "%MARK%" del "%MARK%"
:venv_ok

rem Empreinte de pyproject.toml : (re)installer seulement si les dependances ont change (comparee par Python,
rem plus fiable que les chaines du batch).
set "STAMP=import hashlib,pathlib,sys; h=hashlib.sha256(pathlib.Path('pyproject.toml').read_bytes()).hexdigest(); m=pathlib.Path(sys.argv[1]); w=sys.argv[2]=='write'; m.write_text(h) if w else sys.exit(0 if m.is_file() and m.read_text().strip()==h else 1)"
"%PY%" -c "%STAMP%" "%MARK%" check >nul 2>&1
if errorlevel 1 (
    echo [ACET] Installation des dependances ^(quelques minutes la premiere fois^)...
    "%PY%" -m pip install --disable-pip-version-check -q --upgrade pip || goto :fail
    "%PY%" -m pip install --disable-pip-version-check -q -e ".[ui]" || goto :fail
    "%PY%" -c "%STAMP%" "%MARK%" write || goto :fail
)

if /i "%MODE%"=="check" (
    "%PY%" -m acet --version || goto :fail
    "%PY%" -c "import PySide6, acet.ui.app; print('[ACET] interface OK')" || goto :fail
    "%PY%" -m acet engines status
    exit /b 0
)

echo [ACET] Demarrage...
if /i "%MODE%"=="console" (
    "%PY%" -m acet.ui
    if errorlevel 1 goto :fail
    exit /b 0
)
if exist "%VENV%\Scripts\pythonw.exe" (
    start "" "%VENV%\Scripts\pythonw.exe" -m acet.ui
) else (
    start "" "%PY%" -m acet.ui
)
exit /b 0

:fail
echo.
echo [ACET] Echec. Copiez le message ci-dessus pour le diagnostic
echo        ^(ou relancez avec : Lancer-ACET.bat console^).
if /i not "%MODE%"=="check" pause
exit /b 1
