#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

void PrintHardcodedValueAsCArray(BYTE* data, DWORD size) {
    printf("Replace the current variable \"PublicKey\" from crypto.c with this variable:\n");
    printf("unsigned char PublicKey[] = {");
    for (DWORD i = 0; i < size; i++) {
        printf("0x%02X", data[i]);
        if (i < size - 1) {
            printf(", ");
        }
        if ((i + 1) % 16 == 0) {
            printf("\n\t");
        }
    }
    printf("\n};\n\n");
}
void PrintPrivateKey(BYTE* data, DWORD size) {
    printf("Remember to save this private key; without it, you can't decrypt the data:\n");
    for (DWORD i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n");
        }
    }
    printf("\n");
    printf("END");
}

int GenerateKeyPair() {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    DWORD keyLength = 2048;  // Key size in bits
    DWORD pubBlobLength = 0;
    DWORD privBlobLength = 0;
    BYTE* pbKeyBlob = NULL;
    BYTE* pvKeyBlob = NULL;

    // Open an algorithm handle for RSA
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        return -1;
    }

    // Generate a new RSA key pair
    status = BCryptGenerateKeyPair(hAlgorithm, &hKey, keyLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptGenerateKeyPair failed: 0x%x\n", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Finalize the key pair
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptFinalizeKeyPair failed: 0x%x\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Export the public key in BCRYPT_RSAPUBLIC_BLOB format
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &pubBlobLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptExportKey failed to get public blob length: 0x%x\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Allocate memory for the public key blob
    pbKeyBlob = (BYTE*)malloc(pubBlobLength);
    if (pbKeyBlob == NULL) {
        printf("Memory allocation failed for public key\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Export the public key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pbKeyBlob, pubBlobLength, &pubBlobLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptExportKey failed to export public key: 0x%x\n", status);
        free(pbKeyBlob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Print the public key blob as a C array so it can be placed into the crypto.c file easily
    PrintHardcodedValueAsCArray(pbKeyBlob, pubBlobLength);

    // Export the private key in BCRYPT_RSAFULLPRIVATE_BLOB format
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &privBlobLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptExportKey failed to get private blob length: 0x%x\n", status);
        free(pbKeyBlob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Allocate memory for the private key blob
    pvKeyBlob = (BYTE*)malloc(privBlobLength);
    if (pvKeyBlob == NULL) {
        printf("Memory allocation failed for private key\n");
        free(pbKeyBlob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Export the private key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, pvKeyBlob, privBlobLength, &privBlobLength, 0);
    if (!NT_SUCCESS(status)) {
        printf("BCryptExportKey failed to export private key: 0x%x\n", status);
        free(pbKeyBlob);
        free(pvKeyBlob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Print the private key
    PrintPrivateKey(pvKeyBlob, privBlobLength);

    // Clean up
    free(pbKeyBlob);
    free(pvKeyBlob);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    
    return 0;
}

int main() {
    return GenerateKeyPair();
}
