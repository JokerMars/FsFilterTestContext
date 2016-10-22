#pragma once

#ifndef _CONTEXT_H
#define _CONTEXT_H

#include "Common.h"
#include "Strategy.h"



typedef struct _STREAM_HANDLE_CONTEXT
{
	FILE_STANDARD_INFORMATION fileInfo;		//current dealing with the file
	PFILE_TYPE_PROCESS ftp;					//file type and matched process
	BOOLEAN isEncryptFileType;				//if it's encrypt file type
	BOOLEAN isEncrypted;					//if file has been encrypted
}STREAM_HANDLE_CONTEXT, *PSTREAM_HANDLE_CONTEXT;


typedef struct _PRE_2_POST_CONTEXT
{
	PSTREAM_HANDLE_CONTEXT pStreamCtx;     //carry the file information
	PVOID SwappedBuffer;
}PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

VOID CleanupStreamHandleContext(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);






#endif
