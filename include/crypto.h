#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <winhttp.h>

int Base64DecodingFunc(const char *input, char **outputDec, DWORD *outputDecSize);
NTSTATUS AES_256_GCM(const BYTE *encryptedData, ULONG encryptedDataLength, const BYTE *aad, ULONG aadLength, const BYTE *iv, ULONG ivLength, const BYTE *authTag, ULONG authTagLength, const BYTE *key, ULONG keyLength, BYTE *decryptedData, ULONG decryptedDataLength);

#endif