#include "Strategy.h"


PFILE_TYPE_PROCESS GetStrategyFromString(PCHAR str)
{
	ULONG len = strlen(str);

	CHAR line_div = ';';
	CHAR mid_div = '=';
	CHAR process_div = ',';

	ULONG lineStart = 0;
	ULONG lineEnd = -1;
	ULONG lineDiv = 0;

	FILE_TYPE_PROCESS head;
	head.next = NULL;

	for (ULONG i = 0; i < len; i++)
	{
		if (str[i] != line_div)continue;
		lineStart = lineEnd + 1;
		lineEnd = i;

		for (lineDiv = lineStart; lineDiv < lineEnd; lineDiv++)
		{
			if (str[lineDiv] != mid_div)continue;

			PFILE_TYPE_PROCESS ftp = (PFILE_TYPE_PROCESS)ExAllocatePoolWithTag(NonPagedPool,
				sizeof(FILE_TYPE_PROCESS), BUFFER_SWAP_TAG);
			if (ftp != NULL)
			{
				ftp->next = head.next;
				head.next = ftp;

				RtlZeroMemory(ftp->fileType, FILE_TYPE_LEN);

				size_t size = lineDiv - lineStart;
				size = size < FILE_TYPE_LEN ? size : FILE_TYPE_LEN;

				RtlCopyMemory(ftp->fileType, str + lineStart, size);

				DbgPrint("find a file type: %s", ftp->fileType);

				PROCESS_INFO proc_head;
				proc_head.next = NULL;

				ULONG proc_div_end = lineDiv;
				ULONG proc_div_start = proc_div_end;

				for (ULONG j = lineDiv + 1; j < lineEnd; j++)
				{
					if (str[j] != process_div)continue;
					proc_div_start = proc_div_end + 1;
					proc_div_end = j;

					PPROCESS_INFO pi = (PPROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO), BUFFER_SWAP_TAG);
					if (pi != NULL)
					{
						pi->next = proc_head.next;
						proc_head.next = pi;

						RtlZeroMemory(pi->procName, PROCESS_NAME_LEN);
						size = proc_div_end - proc_div_start;
						size = size < PROCESS_NAME_LEN ? size : PROCESS_NAME_LEN;
						RtlCopyMemory(pi->procName, str + proc_div_start, size);

						DbgPrint("find a process name: %s", pi->procName);
					}
				}
				ftp->processInfo = proc_head.next;
			}
		}
	}

	return head.next;
}



VOID FreeStrategy(PFILE_TYPE_PROCESS head)
{
	PFILE_TYPE_PROCESS next;
	PPROCESS_INFO tmphdr;
	PPROCESS_INFO tmpnext;
	while (head)
	{
		next = head->next;
		tmphdr = head->processInfo;
		while (tmphdr)
		{
			tmpnext = tmphdr->next;
			ExFreePool(tmphdr);
			tmphdr = tmpnext;
		}
		//free current head
		ExFreePool(head);
		head = next;
	}
}



VOID OutputStrategy(PFILE_TYPE_PROCESS head)
{
	PPROCESS_INFO tmp;
	while (head)
	{
		DbgPrint("   %s\n", head->fileType);
		tmp = head->processInfo;
		while (tmp)
		{
			DbgPrint("   %s\n", tmp->procName);
			tmp = tmp->next;
		}
		head = head->next;
	}
}



BOOLEAN IsInStrategyList(PFILE_TYPE_PROCESS head, PUNICODE_STRING fileName, PFILE_TYPE_PROCESS * out_info)
{
	if (head == NULL || fileName == NULL)
	{
		return FALSE;
	}

	UNICODE_STRING source;
	RtlUpcaseUnicodeString(&source, fileName, TRUE);

	UNICODE_STRING fileType;
	WCHAR buff[FILE_TYPE_LEN] = { 0 };
	fileType.Buffer = buff;
	fileType.Length = 0;
	fileType.MaximumLength = FILE_TYPE_LEN * 2;

	ANSI_STRING tmp;

	while (head)
	{
		RtlInitAnsiString(&tmp, head->fileType);
		RtlAnsiStringToUnicodeString(&fileType, &tmp, FALSE);

		DbgPrint(" %wZ", &fileType);
		RtlUpcaseUnicodeString(&fileType, &fileType, FALSE);
		INT pos = GetIndexFromSource(&source, &fileType);
		DbgPrint("Position is %d", pos);

		if (pos > 0)
		{
			DbgPrint("We Care this file: %wZ", fileName);
			*out_info = head;
			return TRUE;
		}

		head = head->next;
	}

	return FALSE;
}


INT GetIndexFromSource(PUNICODE_STRING source, PUNICODE_STRING value)
{
	if (source->Length < value->Length)
	{
		return -1;
	}

	INT i, j;
	BOOLEAN flag;
	INT source_len = source->Length / 2;
	INT value_len = value->Length / 2;
	INT len = source_len - value_len + 1;

	DbgPrint("source is %wZ and value is %wZ", source, value);

	for (i = 0; i < len; i++)
	{
		flag = TRUE;
		for (j = 0; j < value_len; j++)
		{
			WCHAR a = source->Buffer[i + j];
			WCHAR b = value->Buffer[j];

			if (a != b)
			{
				flag = FALSE;
				break;
			}
		}

		if (flag)
		{
			return i;
		}
	}
	return -1;
}



BOOLEAN IsSecretProcess(PFILE_TYPE_PROCESS current, PCHAR procName)
{
	if (current == NULL || procName == NULL)
	{
		return FALSE;
	}

	PPROCESS_INFO proc_info = current->processInfo;
	while (proc_info)
	{
		if (strncmp(proc_info->procName, procName, strlen(procName)) == 0)
		{
			return TRUE;
		}

		proc_info = proc_info->next;

	}
	return FALSE;
}



