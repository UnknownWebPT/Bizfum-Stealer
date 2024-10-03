#include "./../../include/global.h"
#include "./../../include/extra.h"


int SubfolderFileFinder(char Files[20][MAX_PATH], char* Folder, int *index) {
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
    char sPath[2048];

    // Prepare search path
    sprintf(sPath, "%s\\*.*", Folder);

    if ((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE) {
        printf("Path not found: [%s]\n", Folder);
        return 1;
    }

    do {
        // Skip "." and ".." directories
        if (strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0) {
            // Construct the full path
            sprintf(sPath, "%s\\%s", Folder, fdFile.cFileName);

            // If it's a directory, recursively call the function
            if (fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                SubfolderFileFinder(Files, sPath, index);
            } else {
                // If it's a file, store the path in the Files array
                if (*index < 20) { // Ensure we don't go out of bounds
                    strncpy(Files[*index], sPath, MAX_PATH - 1);
                    Files[*index][MAX_PATH - 1] = '\0'; // Ensure null-termination
                    (*index)++; // Increment the index
                } else {
                    printf("File list full, can't add more files.\n");
                    return 1;
                }
            }
        }
    } while (FindNextFile(hFind, &fdFile));
    FindClose(hFind);
    return 0;
}

void PrintHex(BYTE* data, DWORD size) {
    for (DWORD i = 0; i < size; i++) {
        printf("0x%02X, ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


int remove_directory(const char *path) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    int r = -1;

    // Prepare the search path
    snprintf(searchPath, sizeof(searchPath), "%s\\*.*", path);

    hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        r = 0; // Assume success until we find an error

        do {
            // Skip the names "." and ".."
            if (strcmp(findFileData.cFileName, ".") == 0 || 
                strcmp(findFileData.cFileName, "..") == 0) {
                continue;
            }

            // Construct full file path
            char fullPath[MAX_PATH];
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", path, findFileData.cFileName);

            // Check if it's a directory or a file
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Recursively remove the directory
                r = remove_directory(fullPath);
            } else {
                // Delete the file
                if (!DeleteFile(fullPath)) {
                    r = GetLastError(); // Store the error if deletion fails
                }
            }
        } while (r == 0 && FindNextFile(hFind, &findFileData));

        FindClose(hFind);
    }

    // Remove the directory itself if it is empty
    if (r == 0) {
        if (!RemoveDirectory(path)) {
            r = GetLastError(); // Store the error if removal fails
        }
    }

    return r;
}
