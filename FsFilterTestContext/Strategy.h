#pragma once

#ifndef _STRATEGY_H
#define _STRATEGY_H

#include "Common.h"

#define PROCESS_NAME_LEN 32
typedef struct _PROCESS_INFO
{
	CHAR procName[PROCESS_NAME_LEN];
	struct _PROCESS_INFO *next;
}PROCESS_INFO, *PPROCESS_INFO;

#define FILE_TYPE_LEN 32
typedef struct _FILE_TYPE_PROCESS
{
	CHAR fileType[FILE_TYPE_LEN];
	PPROCESS_INFO processInfo;
	struct _FILE_TYPE_PROCESS *next;
}FILE_TYPE_PROCESS, *PFILE_TYPE_PROCESS;


PFILE_TYPE_PROCESS GetStrategyFromString(PCHAR str);

VOID FreeStrategy(PFILE_TYPE_PROCESS head);

VOID OutputStrategy(PFILE_TYPE_PROCESS head);

BOOLEAN IsInStrategyList(PFILE_TYPE_PROCESS head, PUNICODE_STRING fileName, PFILE_TYPE_PROCESS *out_info);

INT GetIndexFromSource(PUNICODE_STRING source, PUNICODE_STRING value);

BOOLEAN IsSecretProcess(PFILE_TYPE_PROCESS current, PCHAR procName);

#endif