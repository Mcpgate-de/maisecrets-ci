@echo off
rem Hook launcher for Windows without Git Bash. Codex runs the commandWindows entry of
rem hooks/hooks.json as   cmd.exe /C "<command>"   with the payload on stdin (codex-rs,
rem hooks/src/engine/command_runner.rs, read 2026-09-26). A batch file hands stdin to its
rem child untouched; a PowerShell launcher lost it (the host consumed the stream, measured
rem in the Windows matrix job). Same job as run.sh: find a Python 3.9+, run dispatch.py.
rem Fails closed: without Python each hook event gets the JSON refusal of its client and exit 0,
rem as from run.sh (exit 2 blocked in Claude Code only; Codex runs the tool on a failed hook).
rem Usage: run.cmd <user-prompt|pre-tool|post-tool|session-start>
set PYTHONUTF8=1
set "HERE=%~dp0"
rem One line per start, overwritten: when a hook does not act, this says whether the client started it and with
rem which environment. Codex clears the environment of a hook and replays a snapshot (codex-rs command_runner.rs);
rem on one Windows machine no hook acted with Python installed (2026-09-30). Names and paths only, never a payload.
rem Taken here, before the repairs below; written after them, into %LOCALAPPDATA%\maisecrets-launcher.
set "MS_PATH=no"
if defined PATH set "MS_PATH=yes"
set "MS_START=%DATE% %TIME% event=%~1 user=%USERNAME% profile=%USERPROFILE% localappdata=%LOCALAPPDATA% programfiles=%ProgramFiles% path=%MS_PATH%"
rem Codex clears the environment of a hook and replays a snapshot (codex-rs command_runner.rs). Without these
rem variables Python finds no home directory and run.cmd no Python (measured on windows-latest, 2026-09-30).
if not defined SystemRoot set "SystemRoot=C:\Windows"
if not defined ProgramFiles set "ProgramFiles=C:\Program Files"
if not defined PATH set "PATH=%SystemRoot%\System32;%SystemRoot%"
if defined USERPROFILE goto :profile_set
rem the plugin sits in <profile>\.codex\...: the part before \.codex\ is the profile
set "MS_UP=%HERE:\.codex\=|%"
if "%MS_UP%"=="%HERE%" goto :profile_set
for /f "tokens=1 delims=|" %%A in ("%MS_UP%") do set "USERPROFILE=%%A"
:profile_set
if not defined LOCALAPPDATA if defined USERPROFILE set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"
rem Not in this plugin's folder: Codex binds the approval of a plugin's hooks to the contents of that folder
rem (openai/codex#54619, 0.164), so one written file switched every hook off until the person approved them again.
rem 2>nul on the call: a folder the hook may not write gave "Access is denied" on every start (field report, 2026-10-19).
set "MS_DIAG="
if defined LOCALAPPDATA set "MS_DIAG=%LOCALAPPDATA%\maisecrets-launcher"
call :start_record 2>nul
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  py -3 "%HERE%dispatch.py" %*
  goto :done
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  python "%HERE%dispatch.py" %*
  goto :done
)
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  python3 "%HERE%dispatch.py" %*
  goto :done
)
rem Not on PATH: the python.org installer (also through winget) leaves PATH alone unless asked, and an
rem open client keeps the PATH it started with (reported 2026-09-30: Python 3.12 installed, not found).
rem Look where that installer puts Python, for one user and for all users.
for %%P in ("%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" "%SystemRoot%\py.exe") do (
  if exist %%P (
    %%P -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if not errorlevel 1 (
      %%P -3 "%HERE%dispatch.py" %*
      goto :done
    )
  )
)
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%ProgramFiles%\Python3*") do (
  if exist "%%~D\python.exe" (
    "%%~D\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if not errorlevel 1 (
      "%%~D\python.exe" "%HERE%dispatch.py" %*
      goto :done
    )
  )
)
call :no_python_record 2>nul
rem JSON and exit 0 for every hook event, as run.sh answers: Codex runs the tool when a hook exits 2, so exit 2 was a
rem block in Claude Code only (codex code review of the diagnostics work, 2026-10-09). One label per event: a
rem parenthesis in a message would end an if block.
if "%~1"=="post-tool-failure" goto :np_post_tool_failure
if "%~1"=="post-tool" goto :np_post_tool
if "%~1"=="pre-tool" goto :np_pre_tool
if "%~1"=="user-prompt" goto :np_user_prompt
if "%~1"=="session-start" goto :np_session_start
rem any other use of the launcher (a CLI command): fail closed with the reason on stderr
echo maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt and command is blocked; the command did not run. 1>&2
call :mark
exit /b 2
:np_post_tool_failure
rem the client shows a failed output as it is: there is nothing to withhold, only the reason to name
echo {"systemMessage":"maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt is blocked."}
call :mark
exit /b 0
:np_post_tool
rem one shape per client: Codex's strict schema drops an answer that carries Claude's updatedToolOutput, and Codex
rem sends turn_id in its payload (the same test as run.sh)
findstr /l /c:"\"turn_id\"" >nul 2>&1
if not errorlevel 1 goto :np_post_tool_codex
echo {"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]"}}
call :mark
exit /b 0
:np_post_tool_codex
echo {"decision":"block","reason":"[maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]"}
call :mark
exit /b 0
:np_pre_tool
echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt is blocked."}}
call :mark
exit /b 0
:np_user_prompt
echo {"decision":"block","reason":"maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt is blocked."}
call :mark
exit /b 0
:np_session_start
echo {"systemMessage":"maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt is blocked."}
call :mark
exit /b 0
:done
exit /b %errorlevel%

rem an incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): after the answer, one md in
rem the launcher's folder, where last-start.txt is written on every start. Not in the home: a detached child
rem inherits the hook's pipe handles on Windows (codex code review, round 3), and the home is another, configured
rem folder. The hooks fold it from there once Python runs (maisecrets/incidents.py, LAUNCHER_DIR).
:mark
if defined MS_DIAG md "%MS_DIAG%\incident-marker.launcher.no-python" >nul 2>&1
exit /b 0

:start_record
if not defined MS_DIAG exit /b 0
md "%MS_DIAG%" >nul 2>&1
>"%MS_DIAG%\last-start.txt" echo %MS_START%
exit /b 0

:no_python_record
if not defined MS_DIAG exit /b 0
>>"%MS_DIAG%\last-start.txt" echo no Python 3.9 or newer found
exit /b 0
