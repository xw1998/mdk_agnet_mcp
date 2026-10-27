@echo off
rem ===========================================================================
rem  mdkdebug MCP Server launcher (Windows)
rem
rem  Why: hosts (MCP clients / IDEs / other agents) pass THEIR OWN PYTHONPATH /
rem  PYTHONHOME to child processes. When those point at another Python, the
rem  interpreter dies during site init ("SRE module mismatch") and our own
rem  in-process self-heal never gets a chance to run. So clean here, BEFORE
rem  python starts.
rem
rem  Usage: point your MCP client at this file (args are passed through).
rem      "command": "D:/.../mdk_agent/run_server.cmd"
rem  Optional: set MDKDEBUG_PYTHON to the interpreter you want (recommended
rem  when python is not on the host's PATH, e.g. "C:\...\python-env\python.exe").
rem ===========================================================================
setlocal

rem --- 1) clean the poisoning variables BEFORE the interpreter starts -------
set "PYTHONPATH="
set "PYTHONHOME="
set "PYTHONSTARTUP="
set "PYTHONEXECUTABLE="
set "PYTHONUSERBASE="
set "PYTHONNOUSERSITE="
set "PYTHONPLATLIBDIR="
rem keep PYTHONIOENCODING / PYTHONUTF8: they do not affect imports, and the
rem MCP JSON contains non-ASCII text

rem --- 2) pick an interpreter -----------------------------------------------
set "PY=%MDKDEBUG_PYTHON%"
if not defined PY if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if defined PY goto :run
python -c "" >nul 2>nul
if not errorlevel 1 set "PY=python" & goto :run
py -3 -c "" >nul 2>nul
if not errorlevel 1 set "PY=py" & set "PYARG=-3" & goto :run
echo [mdkdebug] python not found: set MDKDEBUG_PYTHON to python.exe 1>&2
exit /b 3

:run
rem -E -s: ignore PYTHON* vars even if one leaks through; -u: unbuffered stdio
"%PY%" %PYARG% -E -s -u "%~dp0run_server.py" %*
exit /b %ERRORLEVEL%
