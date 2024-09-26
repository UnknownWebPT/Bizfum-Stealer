#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>

int Base64DecodingFunc(const char *input, char **outputDec, DWORD *outputDecSize);
NTSTATUS AES_256_GCM(const BYTE *encryptedData, ULONG encryptedDataLength, const BYTE *aad, ULONG aadLength, const BYTE *iv, ULONG ivLength, const BYTE *authTag, ULONG authTagLength, const BYTE *key, ULONG keyLength, BYTE *decryptedData, ULONG decryptedDataLength);
typedef enum { siBuffer } SECItemType;
typedef struct SECItemStr { SECItemType type; unsigned char *data; unsigned int len; } SECItem;
typedef enum _SECStatus { SECWouldBlock = -2, SECFailure = -1, SECSuccess = 0, } SECStatus;
typedef int (NSS_InitFunc)(const char *profilePath);
typedef int (PK11SDR_DecryptFunc)(SECItem *data, SECItem *result, void *cx);
#endif
