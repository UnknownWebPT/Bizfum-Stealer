#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <windows.h>

const char *STATIC_KEY = "2l3jfezeh7";

typedef BOOL(WINAPI *CryptBinaryToStringFunc)(const BYTE *, DWORD, DWORD, LPSTR, DWORD *);
typedef BOOL(WINAPI *CryptStringToBinaryFunc)(LPCSTR, DWORD, DWORD, BYTE *, DWORD *, DWORD *, DWORD *);

int Base64DecodingFunc(const char *input, char **outputDec, DWORD *outputDecSize)
{
    HINSTANCE hCrypt32 = LoadLibrary("crypt32.dll");
    CryptStringToBinaryFunc pCryptStringToBinary = (CryptStringToBinaryFunc)GetProcAddress(hCrypt32, "CryptStringToBinaryA");
    DWORD cryptFlags = CRYPT_STRING_BASE64;
    if (!pCryptStringToBinary(input, 0, cryptFlags, NULL, outputDecSize, NULL, NULL))
    {
        CloseHandle(hCrypt32);
        return -1;
    }
    *outputDec = (char *)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, (*outputDecSize) * sizeof(char));
    if (!*outputDec)
    {
        CloseHandle(hCrypt32);
        return -1;
    }
    if (!pCryptStringToBinary(input, 0, cryptFlags, (BYTE *)*outputDec, outputDecSize, NULL, NULL))
    {
        HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, *outputDec);
        CloseHandle(hCrypt32);
        return -1;
    }
    CloseHandle(hCrypt32);
    return 0;
}
int Base64EncodingFunc(const BYTE *inputBin, DWORD inputBinSize, char *outputB64, DWORD outputB64Size)
{
    HINSTANCE hCrypt32 = LoadLibrary("crypt32.dll");
    CryptBinaryToStringFunc pCryptBinaryToString = (CryptBinaryToStringFunc)GetProcAddress(hCrypt32, "CryptBinaryToStringA");
    DWORD cryptFlags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    if (!pCryptBinaryToString(inputBin, inputBinSize, cryptFlags, outputB64, &outputB64Size))
    {
        CloseHandle(hCrypt32);
        return -4;
    }
    outputB64[outputB64Size] = '\0';
    CloseHandle(hCrypt32);
    return 0;
}
void XOR(char *input, char *output, const char *key, int length)
{
    int key_len = strlen(key);
    for (int i = 0; i < length; ++i)
        output[i] = input[i] ^ key[i % key_len];
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







void Reverse(unsigned char *data, int len)
{
    for (int i = 0; i < len / 2; ++i)
    {
        unsigned char temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}



char *BizFumEncodingEncode(char *Input)
{
    // Step 1: Split the token into 5 parts.
    char PART1[13] = {0};
    char PART2[13] = {0};
    char PART3[13] = {0};
    char PART4[13] = {0};
    char PART5[13] = {0};

    int InputLength = strlen(Input);
    int BaseSize = (InputLength - (InputLength % 5)) / 5;
    int Remainder = InputLength % 5;
    int Index = 0;

    memcpy(PART1, &Input[Index], BaseSize);
    Index += BaseSize;
    memcpy(PART2, &Input[Index], BaseSize);
    Index += BaseSize;
    memcpy(PART3, &Input[Index], BaseSize);
    Index += BaseSize;
    memcpy(PART4, &Input[Index], BaseSize);
    Index += BaseSize;
    memcpy(PART5, &Input[Index], BaseSize + Remainder);

    int part1_len = BaseSize;
    int part2_len = BaseSize;
    int part3_len = BaseSize;
    int part4_len = BaseSize;
    int part5_len = BaseSize + Remainder;

    // Step 2: XOR Encrypt the parts using the STATIC_KEY.
    char XOR1[15] = {0};
    char XOR2[15] = {0};
    char XOR3[15] = {0};
    char XOR4[15] = {0};
    char XOR5[15] = {0};

    XOR(PART1, XOR1, STATIC_KEY, part1_len);
    XOR(PART2, XOR2, STATIC_KEY, part2_len);
    XOR(PART3, XOR3, STATIC_KEY, part3_len);
    XOR(PART4, XOR4, STATIC_KEY, part4_len);
    XOR(PART5, XOR5, STATIC_KEY, part5_len);


    // Step 3: Add random bytes to XOR parts.
    int PART1_AfterRand = part1_len + 5;
    int PART2_AfterRand = part2_len + 5;
    int PART3_AfterRand = part3_len + 5;
    int PART4_AfterRand = part4_len + 5;
    int PART5_AfterRand = part5_len + 5;
    AddRandomBytes(XOR1, part1_len);
    AddRandomBytes(XOR2, part2_len);
    AddRandomBytes(XOR3, part3_len);
    AddRandomBytes(XOR4, part4_len);
    AddRandomBytes(XOR5, part5_len);


    // Step 4: Split the output of step 3 into more parts. Then reverse them.
    // Here we are basically flipping the rows from X-axis to Y-axis.
    // 04 01 09    becomes      04 05
    // 05 02 05                 01 02
    //                          09 05
    // We can do this because the Telegram's bot token will ALWAYS be between 43 and 46; hence the max amount on one row is always either 8 + 5 or 9 + 5.
    int IndexXOR = 0;
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

    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR1[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR1[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR1[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR1[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR1[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR2[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR2[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR2[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR2[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR2[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR3[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR3[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR3[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR3[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR3[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR4[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR4[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR4[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR4[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR4[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR5[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR5[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR5[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR5[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR5[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR6[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR6[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR6[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR6[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR6[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR7[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR7[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR7[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR7[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR7[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR8[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR8[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR8[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR8[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR8[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR9[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR9[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR9[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR9[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR9[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR10[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR10[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR10[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR10[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR10[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR11[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR11[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR11[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR11[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR11[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR12[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR12[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR12[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR12[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR12[i] = XOR5[IndexXOR];
        }
    }
    IndexXOR += 1;
    for (int i = 0; i <= 5; i++)
    {
        if (i == 0)
        {
            STR13[i] = XOR1[IndexXOR];
        }
        if (i == 1)
        {
            STR13[i] = XOR2[IndexXOR];
        }
        if (i == 2)
        {
            STR13[i] = XOR3[IndexXOR];
        }
        if (i == 3)
        {
            STR13[i] = XOR4[IndexXOR];
        }
        if (i == 4)
        {
            STR13[i] = XOR5[IndexXOR];
        }
    }
    if (BaseSize == 9)
    {
        IndexXOR += 1;
        for (int i = 0; i <= 5; i++)
        {
            if (i == 0)
            {
                STR14[i] = XOR1[IndexXOR];
            }
            if (i == 1)
            {
                STR14[i] = XOR2[IndexXOR];
            }
            if (i == 2)
            {
                STR14[i] = XOR3[IndexXOR];
            }
            if (i == 3)
            {
                STR14[i] = XOR4[IndexXOR];
            }
            if (i == 4)
            {
                STR14[i] = XOR5[IndexXOR];
            }
        }
    }
    if (Remainder > 0)
    {
        for (int i = 0; i < Remainder; i++)
        {
            LeftOver[i] = XOR5[PART5_AfterRand - Remainder + i];
        }
    }

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


    // Step 5: Combine the reversed STR arrays ( starting from the back ).
    char RemainderStr[3];
    sprintf(RemainderStr, "%d%d", Remainder, BaseSize);
    int total_len;
    if (BaseSize == 9)
    {
        total_len = (5 * 14) + Remainder + 1 + 1;
    }
    else
    {
        total_len = (5 * 13) + Remainder + 1 + 1;
    }

    char *Output = malloc(total_len);

    int offset = 0;
    if (Remainder > 0)
    {
        memcpy(Output + offset, LeftOver, Remainder);
        offset += Remainder;
    }
    if (BaseSize == 9)
    {
        memcpy(Output + offset, STR14, 5);
        offset += 5;
    }
    memcpy(Output + offset, STR13, 5);
    offset += 5;
    memcpy(Output + offset, STR12, 5);
    offset += 5;
    memcpy(Output + offset, STR11, 5);
    offset += 5;
    memcpy(Output + offset, STR10, 5);
    offset += 5;
    memcpy(Output + offset, STR9, 5);
    offset += 5;
    memcpy(Output + offset, STR8, 5);
    offset += 5;
    memcpy(Output + offset, STR7, 5);
    offset += 5;
    memcpy(Output + offset, STR6, 5);
    offset += 5;
    memcpy(Output + offset, STR5, 5);
    offset += 5;
    memcpy(Output + offset, STR4, 5);
    offset += 5;
    memcpy(Output + offset, STR3, 5);
    offset += 5;
    memcpy(Output + offset, STR2, 5);
    offset += 5;
    memcpy(Output + offset, STR1, 5);
    offset += 5;
    memcpy(Output + offset, RemainderStr, strlen(RemainderStr));

    // Step 6: Base64 Encode.
    char output[100];
    DWORD outSize = sizeof(output);
    Base64EncodingFunc(Output, total_len, output, outSize);

    // Clean.
    free(Output);
    free(STR1);
    free(STR2);
    free(STR3);
    free(STR4);
    free(STR5);
    free(STR6);
    free(STR7);
    free(STR8);
    free(STR9);
    free(STR10);
    free(STR11);
    free(STR12);
    free(STR13);
    if (BaseSize == 9)
    {
        free(STR14);
    }
    if (Remainder > 0)
    {
        free(LeftOver);
    }
    return strdup(output);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Wrong amount of arguments given to program (%d). Usage: .\\TokenEncoder.exe [TOKEN]", argc);
        return 0;
    }
    srand(time(NULL));
    char *Encoded = BizFumEncodingEncode(argv[1]);
    printf("%s", Encoded);
    free(Encoded);
    return 0;
}
