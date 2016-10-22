#include "Context.h"





VOID CleanupStreamHandleContext(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType)
{
	UNREFERENCED_PARAMETER(ContextType);
	if (Context != NULL)
		FltReleaseContext(Context);
}

