TYPE ?= exe
VERBOSE ?= verbose
CFLAGS = -O3 -w
.PHONY: all clean
all: $(TYPE)
exe: 
ifeq ($(VERBOSE), verbose)
	@echo "Building verbose EXE version..."
	gcc src/verbose/*.c $(CFLAGS) -o bizfum-verbose.exe
else
	@echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
	# @echo "Building normal EXE version..."
	# gcc src/normal/*.c $(CFLAGS) -o bizfum.exe -mwindows
endif
dll: 
ifeq ($(VERBOSE), verbose)
	@echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
	# @echo "Building verbose DLL version..."
	# gcc src/verbose/DLL/dll_main.c src/verbose/browsers.c src/verbose/crypto.c $(CFLAGS) -DVERBOSE -shared -o bizfum-verbose.dll
else
	@echo "Unfortunately feature not supported yet. Use default. (-t verbose -f exe)"
	# @echo "Building normal DLL version..."
	# gcc src/normal/DLL/dll_main.c src/normal/browsers.c src/normal/crypto.c $(CFLAGS) -shared -o bizfum.dll
endif
clean:
	@rm -f bizfum-verbose.exe bizfum.exe bizfum-verbose.dll bizfum.dll
