#ifndef EXTRA_H
#define EXTRA_H

#include <windows.h>
int SubfolderFileFinder(char Files[20][MAX_PATH], char* Folder, int *index);
int remove_directory(const char *path);
void PrintHex(BYTE* data, DWORD size);
#endif
