#pragma once

#ifndef _ENCRYPT_DECRYPT_H
#define _ENCRYPT_DECRYPT_H

#include "Common.h"


#define ENCRYPT_MARK_LEN 128
#define ENCRYPT_MARK_STRING "*****This file has been encrypted*****"
#define ENCRYPT_FILE_CONTENT_OFFSET 128

//encrypt trail
typedef struct _ENCRYPT_TRAIL
{
	CHAR mark[ENCRYPT_MARK_LEN];
}ENCRYPT_TRAIL, *PENCRYPT_TRAIL;





VOID RC4(PCHAR inBuf, PCHAR outBuf, ULONG offset, ULONG bufLen, PCHAR key);

VOID EncryptData(_In_ PVOID buff, _Inout_ PVOID outbuff, _In_ LONGLONG offset, _In_ ULONG len, PCHAR key);

VOID DecodeData(_In_ PVOID buff, _Inout_ PVOID outbuff, _In_ LONGLONG offset, _In_ ULONG len, PCHAR key);

VOID WriteEncryptTrail(PVOID buff, ULONG offset);

NTSTATUS
EncryptFile(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, PCHAR key);

VOID ClearFileCache(PFILE_OBJECT pFileObject);



#endif