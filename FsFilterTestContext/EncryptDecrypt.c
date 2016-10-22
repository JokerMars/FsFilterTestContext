#include "EncryptDecrypt.h"

VOID swap(UCHAR *a, UCHAR *b)
{
	UCHAR tmp;
	tmp = *a;
	*a = *b;
	*b = tmp;
}

VOID re_S(UCHAR *S)
{
	ULONG i;
	for (i = 0; i < 256; i++)
	{
		S[i] = (UCHAR)i;
	}
}


VOID re_T(CHAR *T, CHAR *key)
{
	INT i;
	INT keyLen;
	keyLen = strlen(key);
	for (i = 0; i < 256; i++)
	{
		T[i] = key[i%keyLen];
	}
}


VOID re_Sbox(UCHAR *S, CHAR *T)
{
	INT i, j = 0;
	for (i = 0; i < 256; i++)
	{
		j = (j + S[i] + T[i]) % 256;
		swap(&S[i], &S[j]);
	}
}

VOID re_RC4(UCHAR *S, CHAR *key)
{
	CHAR T[256] = { 0 };
	re_S(S);
	re_T(T, key);
	re_Sbox(S, T);
}

/*++
	This is the main encrypt algorithm using RC4:
		parameter:
		inBuf: input data stream the original data
		outBuf: output data stream the encrypted data
		offset: offset of the pointer of reading file
		bufLen: the length of inBuf
		key: the key we use to encrypt the data
--*/
VOID RC4(PCHAR inBuf, PCHAR outBuf, ULONG offset, ULONG bufLen, PCHAR key)
{
	UCHAR S[256] = { 0 };
	UCHAR readbuf[1];

	INT i, j, t;
	INT z;
	re_RC4(S, key);

	i = j = 0;
	z = 0;
	while (z < offset)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		z++;
	}
	z = 0;
	while (z < bufLen)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		t = (S[i] + (S[j] % 256)) % 256;
		readbuf[0] = inBuf[z];
		readbuf[0] = readbuf[0] ^ S[t];
		outBuf[z] = readbuf[0];
		z++;
	}
}




VOID EncryptData(PVOID buff, PVOID outbuff, LONGLONG offset, ULONG len, PCHAR key)
{
	PCHAR indata = (PCHAR)buff;
	PCHAR outdata = (PCHAR)outbuff;

	RC4(indata, outdata, offset, len, key);
}




VOID DecodeData(PVOID buff, PVOID outbuff, LONGLONG offset, ULONG len, PCHAR key)
{
	PCHAR indata = (PCHAR)buff;
	PCHAR outdata = (PCHAR)outbuff;

	RC4(indata, outdata, offset, len, key);
}





VOID WriteEncryptTrail(PVOID buff, ULONG offset)
{
	ENCRYPT_TRAIL trail;
	RtlZeroMemory(trail.mark, ENCRYPT_MARK_LEN);

	RtlCopyMemory((PVOID)trail.mark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

	PCHAR str = (PCHAR)buff;

	RtlCopyMemory((PVOID)(str + offset), (PVOID)trail.mark, ENCRYPT_MARK_LEN);
}




NTSTATUS EncryptFile(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PCHAR key)
{
	if (key == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status;
	FILE_STANDARD_INFORMATION fileInfo;
	ULONG len = 0;

	//get the file information
	status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &fileInfo,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &len);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FltQueryInformationFile error");
		return STATUS_UNSUCCESSFUL;
	}

	LONGLONG fileLen = fileInfo.EndOfFile.QuadPart;
	DbgPrint("File Len : %D", fileLen);

	ULONG bufLen = 1024 * 1024;
	ULONG writeLen;
	ULONG readLen;
	LARGE_INTEGER offset;
	offset.QuadPart = 0;

	//allocate a memory
	PVOID buff = ExAllocatePoolWithTag(NonPagedPool, bufLen, BUFFER_SWAP_TAG);
	if (buff == NULL)
	{
		DbgPrint("No enough memory");
		return STATUS_UNSUCCESSFUL;
	}

	PMDL newMdl = IoAllocateMdl(buff, bufLen, FALSE, FALSE, NULL);
	if (newMdl != NULL)
	{
		MmBuildMdlForNonPagedPool(newMdl);
	}
	RtlZeroMemory(buff, bufLen);

	//encrypt file begin
	LONGLONG hadWrite = 0;
	while (hadWrite < fileLen)
	{
		//read file
		status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &offset, bufLen, buff,
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &readLen, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("read file error");
			ExFreePool(buff);
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			return status;
		}

		//encrypt the buffer
		EncryptData(buff, buff, offset.QuadPart, readLen, key);

		//write in file
		status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, readLen, buff, 0, &writeLen, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("Write File Error");
			ExFreePool(buff);
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			return status;
		}
		if (readLen != writeLen)
		{
			DbgPrint("write len not equal the read len");
		}

		//updata the offset
		offset.QuadPart += readLen;
		hadWrite += readLen;
	}

	//write encrypt tail
	offset = fileInfo.EndOfFile;
	RtlZeroMemory(buff, bufLen);
	RtlCopyMemory(buff, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

	DbgPrint("buff is %s", buff);

	status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, ENCRYPT_MARK_LEN, buff, 0, &writeLen, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Write Encrypt Trail error");
		ExFreePool(buff);
		if (newMdl != NULL)
		{
			IoFreeMdl(newMdl);
		}
		return status;
	}

	ExFreePool(buff);
	if (newMdl != NULL)
	{
		IoFreeMdl(newMdl);
	}

	return status;
}






VOID ClearFileCache(PFILE_OBJECT pFileObject)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;
	LARGE_INTEGER liInterval;
	BOOLEAN bNeedReleaseResource = FALSE;
	BOOLEAN bNeedReleasePagingIoResource = FALSE;
	KIRQL irql;

	pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
	if (pFcb == NULL)
		return;

	irql = KeGetCurrentIrql();
	if (irql >= DISPATCH_LEVEL)
	{
		return;
	}

	liInterval.QuadPart = -1 * (LONGLONG)50;

	BOOLEAN bBreak;
	BOOLEAN bLockedResource;
	BOOLEAN bLockedPagingIoResource;

	while (TRUE)
	{
		bBreak = TRUE;
		bLockedResource = FALSE;
		bLockedPagingIoResource = FALSE;
		bNeedReleaseResource = FALSE;
		bNeedReleasePagingIoResource = FALSE;

		//get lock in fcb
		if (pFcb->PagingIoResource)
		{
			bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);
		}

		if (pFcb->Resource)
		{
			bLockedResource = TRUE;
			if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
			{
				bNeedReleaseResource = TRUE;
				if (bLockedPagingIoResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bNeedReleaseResource = FALSE;
						bLockedResource = FALSE;
					}
				}
				else
				{
					ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
				}
			}
		}

		if (bLockedPagingIoResource == FALSE)
		{
			if (pFcb->PagingIoResource)
			{
				bLockedPagingIoResource = TRUE;
				bNeedReleasePagingIoResource = TRUE;

				if (bLockedResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bLockedPagingIoResource = FALSE;
						bNeedReleasePagingIoResource = FALSE;
					}
				}
				else
				{
					ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
				}
			}
		}

		if (bBreak)
			break;

		if (bNeedReleasePagingIoResource)
		{
			ExReleaseResourceLite(pFcb->PagingIoResource);
		}
		if (bNeedReleaseResource)
		{
			ExReleaseResourceLite(pFcb->Resource);
		}

		if (irql == PASSIVE_LEVEL)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
		}
		else
		{
			KEVENT waitEvent;
			KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
			KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
		}
		
	}

	if (pFileObject->SectionObjectPointer)
	{
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForWrite);
		}

		CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
	}

	if (bNeedReleasePagingIoResource)
	{
		ExReleaseResourceLite(pFcb->PagingIoResource);
	}
	if (bNeedReleaseResource)
	{
		ExReleaseResourceLite(pFcb->Resource);
	}
}
