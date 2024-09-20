@echo off
setlocal
cls
set TYPE=exe
set VERBOSE=verbose
set CFLAGS=-O3 -w

:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="-t" (
    set VERBOSE=%~2
    shift
    shift
    goto parse_args
) else if "%~1"=="-f" (
    set TYPE=%~2
    shift
    shift
    goto parse_args
) else (
    echo Invalid option: %~1
    exit /b 1
)
:end_parse
if /i "%VERBOSE%" NEQ "verbose" if /i "%VERBOSE%" NEQ "normal" (
    echo Invalid verbosity option! Use 'verbose' or 'normal'.
    exit /b 1
)
if /i "%TYPE%" NEQ "dll" if /i "%TYPE%" NEQ "exe" (
    echo Invalid file type option! Use 'dll' or 'exe'.
    exit /b 1
)
if /i "%TYPE%"=="exe" (
    if /i "%VERBOSE%"=="verbose" (
        echo Building verbose EXE version...
        gcc src\verbose\*.c %CFLAGS% -o bizfum-verbose.exe
    ) else (
        echo Unfortunately feature not supported yet. Use default. (-t verbose -f exe)
        :: echo Building normal EXE version...
        :: gcc src\normal\*.c %CFLAGS% -o bizfum.exe -mwindows
    )
) else if /i "%TYPE%"=="dll" (
    if /i "%VERBOSE%"=="verbose" (
        echo Unfortunately feature not supported yet. Use default. (-t verbose -f exe)
        :: echo Building verbose DLL version...
        :: gcc src\verbose\DLL\dll_main.c src\verbose\browsers.c src\verbose\crypto.c %CFLAGS% -DVERBOSE -shared -o bizfum-verbose.dll
    ) else (
        echo Unfortunately feature not supported yet. Use default. (-t verbose -f exe)
        :: echo Building normal DLL version...
        :: gcc src\normal\DLL\dll_main.c src\normal\browsers.c src\normal\crypto.c %CFLAGS% -shared -o bizfum.dll
    )
)
if %errorlevel% neq 0 (
    echo Compilation failed!
    exit /b %errorlevel%
)
echo Compilation finished successfully.
endlocal
exit /b 0
