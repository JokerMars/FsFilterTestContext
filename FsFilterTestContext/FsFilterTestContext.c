/*++

Module Name:

    FsFilterTestContext.c

Abstract:

    This is the main module of the FsFilterTestContext miniFilter driver.

Environment:

    Kernel mode

--*/

#include "Common.h"
#include "Context.h"
#include "EncryptDecrypt.h"
#include "Strategy.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

//
// global variable
//
ULONG procNameOffset;
PFILE_TYPE_PROCESS head;
PCHAR key = "123";

NPAGED_LOOKASIDE_LIST Pre2PostContextList;


#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilterTestContextInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FsFilterTestContextInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FsFilterTestContextInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FsFilterTestContextUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsFilterTestContextInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );


//
//  My designed proctol
//

FLT_PREOP_CALLBACK_STATUS
PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);


FLT_PREOP_CALLBACK_STATUS
PreClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);



//
// Assisted functions
//

ULONG GetProcessNameOffset();

PCHAR GetCurrentProcessName();




EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilterTestContextUnload)
#pragma alloc_text(PAGE, FsFilterTestContextInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilterTestContextInstanceSetup)
#pragma alloc_text(PAGE, FsFilterTestContextInstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilterTestContextInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{
		IRP_MJ_CREATE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreCreate,
		PostCreate
	},

	{
		IRP_MJ_CLEANUP,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreCleanup,
		NULL
	},

	{
		IRP_MJ_CLOSE,
		0,
		PreClose,
		NULL
	},

    { IRP_MJ_OPERATION_END }
};


//
// Context 
//

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

	{
		FLT_STREAMHANDLE_CONTEXT,
		0,
		CleanupStreamHandleContext,
		sizeof(STREAM_HANDLE_CONTEXT),
		STREAM_HANDLE_CONTEXT_TAG
	},


	{FLT_CONTEXT_END}
};



//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextNotifications,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsFilterTestContextUnload,                           //  MiniFilterUnload

    FsFilterTestContextInstanceSetup,                    //  InstanceSetup
    FsFilterTestContextInstanceQueryTeardown,            //  InstanceQueryTeardown
    FsFilterTestContextInstanceTeardownStart,            //  InstanceTeardownStart
    FsFilterTestContextInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsFilterTestContextInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!FsFilterTestContextInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FsFilterTestContextInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!FsFilterTestContextInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FsFilterTestContextInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!FsFilterTestContextInstanceTeardownStart: Entered\n") );
}


VOID
FsFilterTestContextInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!FsFilterTestContextInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!DriverEntry: Entered\n") );

	//
	// Initialize the non paged pool
	//
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//
	// Init the look aside list
	//

	ExInitializeNPagedLookasideList(
		&Pre2PostContextList,
		NULL,
		NULL,
		0,
		sizeof(PRE_2_POST_CONTEXT),
		PRE_2_POST_TAG,
		0
	);

	//
	// Init the process name offset and the strategy list
	//

	procNameOffset = GetProcessNameOffset();

	PCHAR str = ".txt=notepad.exe,;.doc=winword.exe,;";
	head = GetStrategyFromString(str);
	OutputStrategy(head);
	DbgPrint("Process Name Offset: %d", procNameOffset);



    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }
	else
	{
		ExDeleteNPagedLookasideList(&Pre2PostContextList);

		FreeStrategy(head);
	}

    return status;
}

NTSTATUS
FsFilterTestContextUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
 )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTestContext!FsFilterTestContextUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

	//
	// Delete the paged look aside list and free
	// strategy
	//

	ExDeleteNPagedLookasideList(&Pre2PostContextList);

	FreeStrategy(head);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/





FLT_PREOP_CALLBACK_STATUS
PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;
	PSTREAM_HANDLE_CONTEXT pStreamCtx = NULL;

	try
	{

		//
		// Get and set stream handle context
		//

		status = FltGetStreamHandleContext(
			FltObjects->Instance,
			FltObjects->FileObject,
			&pStreamCtx
		);

		if (!NT_SUCCESS(status))
		{

			//
			// Allocate context
			//
			
			status = FltAllocateContext(
				FltObjects->Filter,
				FLT_STREAMHANDLE_CONTEXT,
				sizeof(STREAM_HANDLE_CONTEXT),
				NonPagedPool,
				&pStreamCtx
			);

			if (!NT_SUCCESS(status))
			{
				leave;
			}

			PFLT_CONTEXT oldCtx = NULL;

			status = FltSetStreamHandleContext(
				FltObjects->Instance,
				FltObjects->FileObject,
				FLT_SET_CONTEXT_KEEP_IF_EXISTS,
				pStreamCtx,
				&oldCtx
			);

			if (NULL != oldCtx)
			{
				pStreamCtx = (PSTREAM_HANDLE_CONTEXT)oldCtx;
			}

			if (!NT_SUCCESS(status))
			{
				leave;
			}

		}

		//
		// Init the stream handle context
		//

		pStreamCtx->ftp = NULL;
		pStreamCtx->isEncrypted = FALSE;
		pStreamCtx->isEncryptFileType = FALSE;

		//
		// If it's a directory, then leave
		//

		BOOLEAN isDir;
		status = FltIsDirectory(
			FltObjects->FileObject,
			FltObjects->Instance,
			&isDir
		);

		if (!NT_SUCCESS(status) || isDir)
		{
			leave;
		}

		//
		// Get the file name, full path, if not
		// succeed, then leave
		//

		status = FltGetFileNameInformation(
			Data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
			&pfNameInfo
		);

		if (!NT_SUCCESS(status) || pfNameInfo == NULL)
		{
			leave;
		}

		FltParseFileNameInformation(pfNameInfo);

		//
		//see If the file type in strategy list 
		//

		PFILE_TYPE_PROCESS current = NULL;
		if (!IsInStrategyList(head, &(pfNameInfo->Name), &current))
		{
			leave;
		}

		//
		// file type in the strategy list so we clear the cache
		//

		pStreamCtx->ftp = current;
		pStreamCtx->isEncryptFileType = TRUE;

		ClearFileCache(FltObjects->FileObject);

		DbgPrint("File: %wZ in PostCreate\n", &(pfNameInfo->Name));

		//
		// Now we should read from file, get the tail, see if
		// there is a encrypt mark, then set the stream handle context
		// file is encrypted.
		//

		FILE_STANDARD_INFORMATION fileInfo;
		status = FltQueryInformationFile(
			FltObjects->Instance,
			Data->Iopb->TargetFileObject,
			&fileInfo,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			leave;
		}

		LONGLONG offset = fileInfo.EndOfFile.QuadPart - ENCRYPT_MARK_LEN;

		DbgPrint("File Valid Length: %d\n", offset);

		if (offset > 0)
		{

			//
			// Read tail to trail from the start position of file
			//

			ENCRYPT_TRAIL trail;
			RtlZeroMemory(trail.mark, ENCRYPT_MARK_LEN);

			LARGE_INTEGER startPos;
			startPos.QuadPart = offset;

			status = FltReadFile(
				FltObjects->Instance,
				FltObjects->FileObject,
				&startPos,
				ENCRYPT_MARK_LEN,
				trail.mark,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
				NULL,
				NULL,
				NULL
			);

			if (!NT_SUCCESS(status))
			{
				leave;
			}

			//
			// compare the mark see if it's a encrypt file mark
			//

			if (strncmp(ENCRYPT_MARK_STRING, trail.mark, strlen(ENCRYPT_MARK_STRING)) == 0)
			{
				pStreamCtx->isEncrypted = TRUE;
			}

		}


		status = FltQueryInformationFile(
			FltObjects->Instance,
			Data->Iopb->TargetFileObject,
			&(pStreamCtx->fileInfo),
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation,
			NULL
		);


	}
	finally
	{
		if (NULL != pfNameInfo)
		{
			FltReleaseFileNameInformation(pfNameInfo);
		}

		if (NULL != pStreamCtx)
		{
			DbgPrint("Release Stream handle context in PostCreate\n");
			FltReleaseContext(pStreamCtx);
		}
	}

	return retValue;
}

FLT_PREOP_CALLBACK_STATUS
PreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{

	UNREFERENCED_PARAMETER(CompletionContext);
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;

	PSTREAM_HANDLE_CONTEXT pStreamCtx = NULL;

	try
	{

		//
		// if it's a directory, just leave
		//
		BOOLEAN isDir;
		status = FltIsDirectory(
			FltObjects->FileObject,
			FltObjects->Instance,
			&isDir
		);

		if (!NT_SUCCESS(status) || isDir)
		{
			leave;
		}


		//
		// get the file name
		//

		status = FltGetFileNameInformation(
			Data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
			&pfNameInfo
		);

		if (!NT_SUCCESS(status))
		{
			leave;
		}

		FltParseFileNameInformation(pfNameInfo);

		//
		// if the file type is in strategy list, clear the cache 
		// or just leave
		//

		PFILE_TYPE_PROCESS current;
		if (!IsInStrategyList(head, &(pfNameInfo->Name), &current))
		{
			leave;
		}

		DbgPrint("The Encrypt File Type In PreCleanup\n");

		//
		// Test the stream handle
		//

		status = FltGetStreamHandleContext(
			FltObjects->Instance,
			FltObjects->FileObject,
			&pStreamCtx
		);
		if (pStreamCtx != NULL) {

			if (pStreamCtx->isEncrypted)
			{
				DbgPrint("The File is Encrypted!\n");
			}
			else
			{
				DbgPrint("The File is NOT Encrypted!\n");
			}

			if (pStreamCtx->isEncryptFileType)
			{
				DbgPrint("The File is the encrypt type");
			}
			else
			{
				DbgPrint("The File is NOT THE TYPE\n");
			}

			DbgPrint("File LEN: %d", pStreamCtx->fileInfo.EndOfFile.QuadPart);

		}

		//
		// CUZ the encrypt file type, we clear the cache
		//

		ClearFileCache(FltObjects->FileObject);
	}
	finally
	{

		//
		// Release file name information
		//

		if (NULL != pfNameInfo)
		{
			FltReleaseFileNameInformation(pfNameInfo);
		}

		if (NULL != pStreamCtx)
		{
			DbgPrint("Release stream handle context in PreCleanup\n");
			FltReleaseContext(pStreamCtx);
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;

}


FLT_PREOP_CALLBACK_STATUS
PreClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status;
	PSTREAM_HANDLE_CONTEXT pStreamCtx = NULL;

	try
	{

		//
		// get stream handle context
		//

		status = FltGetStreamHandleContext(
			FltObjects->Instance,
			FltObjects->FileObject,
			&pStreamCtx
		);

		if (!NT_SUCCESS(status) || pStreamCtx == NULL)
		{
			leave;
		}

		//
		// if stream handle context's isEncryptFileType filed
		// is TRUE, then clear CACHE or leave
		//

		if (!(pStreamCtx->isEncryptFileType))
		{
			leave;
		}

		DbgPrint("The Encrypt File Type in PreClose\n");

		ClearFileCache(FltObjects->FileObject);


	}
	finally
	{
		if (NULL != pStreamCtx)
		{
			DbgPrint("Release Stream Handle Context in PreClose\n");
			FltReleaseContext(pStreamCtx);
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

















/*++
Additional function
--*/
ULONG GetProcessNameOffset()
{
	ULONG i;

	//
	// Get current process entry
	//

	PEPROCESS curproc = PsGetCurrentProcess();
	for (i = 0; i < 3 * PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
		{
			//
			// return the name offset
			//

			return i;
		}
	}
	return 0;
}

PCHAR GetCurrentProcessName()
{
	PCHAR name = NULL;
	PEPROCESS curproc = PsGetCurrentProcess();

	if (procNameOffset)
	{
		//
		// use the process name offset means in PE structure 
		// there is always process name
		//

		name = (PCHAR)curproc + procNameOffset;
	}
	return name;
}