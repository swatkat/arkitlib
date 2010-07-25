/*++
* @file: Ps.c
*
* @description: This file contains functions to detect running processes in the system
*
*--*/

#include "ARKitDrv.h"

// Globals
extern PDRIVER_OBJECT g_pMyDriverObj;
extern OS_SPEC_DATA g_globalData;
extern NTOSKRNLDATA g_NtOSKernel;

/*++
* @method: ScanAndGetProcessCount
*
* @description: Wrapper to thread function to scan running processes
*
* @input: None
*
* @output: UINT, number of processes found
*
*--*/
UINT ScanAndGetProcessCount()
{
    UINT numProcs = 0;
    __try
    {
        // Create a thread to scan for processes
        THRPARAMS stThrParams = {0};
        if( STATUS_SUCCESS == ThreadSpooler( ScanAndGetProcessCountThread, &stThrParams ) )
        {
            numProcs = GetListCount( eProcList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        numProcs = 0;
        DbgPrint( "Exception caught in ScanAndGetProcessCount()" );
    }
    return numProcs;
}

/*++
* @method: ScanAndGetProcessCountThread
*
* @description: Invokes various routines to find running processes
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID ScanAndGetProcessCountThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) )
        {
            // Initalize our internal process linked list where we store results
            if( STATUS_SUCCESS == InitList( eProcList ) )
            {
                if( eOS_ERR != g_globalData.eOSVer )
                {
                    // Scan by process id brute force
                    GetProcByPidScan();

                    // Scan by thread id brute force
                    GetProcByTidScan();

                    // Set result to true if we have found any process
                    ((PTHRPARAMS)pThrParam)->bResult = !IsMyListEmpty( eProcList );
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanAndGetProcessCountThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: GetProcByPidScan
*
* @description: Finds running processes based on pid
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetProcByPidScan()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        int nPid = -1;
        DWORD dwPidIndex = 0;
        DWORD dwPrevPid = 0;
        PEPROCESS pEproc = NULL;
        PROCLISTENTRY procEntry;

        // Loop through all possible pids
        for( dwPidIndex = 0; dwPidIndex < ARKIT_NT_PROCESS_LIMIT; dwPidIndex++ )
        {
            // Call PsLookupProcessByProcessId to get EPROCESS pointer, if exists
            pEproc = NULL;
            if( STATUS_SUCCESS == PsLookupProcessByProcessId( (HANDLE)dwPidIndex, &pEproc ) )
            {
                // Check if process is alive
                if( IsProcessAlive( pEproc ) )
                {
                    // If alive and if we have not found this pid already,
                    nPid = GetPid( pEproc );
                    if( ( nPid >= 0 ) && ( dwPrevPid != (DWORD)nPid ) )
                    {
                        // then add it to our internal list
                        RtlZeroMemory( &procEntry, sizeof( PROCLISTENTRY ) );
                        dwPrevPid = (DWORD)nPid;
                        procEntry.dwPID = dwPrevPid;
                        GetProcessPathName( pEproc, procEntry.szProcName, ARKITLIB_STR_LEN );
                        retVal = AddListEntry( eProcList, &procEntry, TRUE );
                    }
                }
                // Dereference EPROCESS pointer
                ObDereferenceObject( pEproc );
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetProcByPidScan()" );
    }
    return retVal;
}

/*++
* @method: GetProcByTidScan
*
* @description: Finds running processes based on tid
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetProcByTidScan()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        DWORD dwPrevPid = 0;
        DWORD dwTid = 0;
        DWORD dwPrevTid = 0;
        PEPROCESS pEproc = NULL;
        PETHREAD pEthread = NULL;
        PROCLISTENTRY procEntry;

        // Not supported in Win2K
        if( eOS_WIN_2K == g_globalData.eOSVer )
        {
            return retVal;
        }

        // Loop through all possible tids
        for( dwTid = 0; dwTid < ARKIT_NT_PROCESS_LIMIT; dwTid++ )
        {
            pEproc = NULL;
            pEthread = NULL;

            // Call PsLookupThreadByThreadId to get ETHREAD pointer, if exists
            if( STATUS_SUCCESS == PsLookupThreadByThreadId( (HANDLE)dwTid, &pEthread ) )
            {
                // If thread is alive and if we have not found it already,
                if( IsThreadAlive( pEthread ) )
                {
                    if( dwPrevTid != GetTid( pEthread ) )
                    {
                        if( dwPrevPid != GetPidThr( pEthread ) )
                        {
                            // then add the parent process to our internal list
                            RtlZeroMemory( &procEntry, sizeof( PROCLISTENTRY ) );
                            dwPrevPid = GetPidThr( pEthread );
                            procEntry.dwPID = dwPrevPid;
                            pEproc = GetEprocByPid( dwPrevPid );
                            GetProcessPathName( pEproc, procEntry.szProcName, ARKITLIB_STR_LEN );
                            retVal = AddListEntry( eProcList, &procEntry, TRUE );
                        }
                        dwPrevTid = GetTid( pEthread );
                    }
                }
                // Dereference ETHREAD pointer
                ObDereferenceObject( pEthread );
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetProcByTidScan()" );
    }

    return retVal;
}

/*++
* @method: ScanAndGetDllCount
*
* @description: Wrapper to thread function to get DLLs loaded for a process
*
* @input: DWORD dwPid
*
* @output: UINT, count of DLLs for the specified process
*
*--*/
UINT ScanAndGetDllCount( DWORD dwPid )
{
    UINT numDlls = 0;
    __try
    {
        // Create a thread to scan for DLLs
        THRPARAMS stThrParams = {0};
        stThrParams.pParam = &dwPid;
        stThrParams.dwParamLen = sizeof( DWORD );
        if( STATUS_SUCCESS == ThreadSpooler( ScanAndGetDllCountThread, &stThrParams ) )
        {
            numDlls = GetListCount( eDllList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        numDlls = 0;
        DbgPrint( "Exception caught in ScanAndGetDllCount()" );
    }
    return numDlls;
}

/*++
* @method: ScanAndGetDllCountThread
*
* @description: Finds DLLs loaded for a specified process
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID ScanAndGetDllCountThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) && ( STATUS_SUCCESS == InitList( eDllList ) ) )
        {
            PEPROCESS pEproc = NULL;
            DWORD dwPid = *(PDWORD)((PTHRPARAMS)pThrParam)->pParam;

            // Get the EPROCESS pointer for this process
            NTSTATUS retVal = PsLookupProcessByProcessId( (HANDLE)dwPid, &pEproc );
            if( ( STATUS_SUCCESS == retVal ) && MmIsAddressValid( pEproc ) )
            {
                PKAPC_STATE pKapcState = ExAllocatePoolWithTag( NonPagedPool, sizeof( KAPC_STATE ), ARKITLISTTAG );
                if( MmIsAddressValid( pKapcState ) )
                {
                    PPEB pPeb = NULL;
                    PLIST_ENTRY pDllListHead = NULL;
                    UNICODE_STRING usMethodName;
                    PSGETPROCESSPB pPsGetProcessPeb = NULL;

                    // Attach to process's stack
                    KeStackAttachProcess( pEproc, pKapcState );

                    // Get the address of PsGetProcessPeb
                    RtlInitUnicodeString( &usMethodName, L"PsGetProcessPeb" );
                    pPsGetProcessPeb = (PSGETPROCESSPB)MmGetSystemRoutineAddress( &usMethodName );

                    // Get pointer to PEB of this process
                    pPeb = MmIsAddressValid( pPsGetProcessPeb ) ? pPsGetProcessPeb( pEproc ) : (PPEB)( (PBYTE)pPeb + 0x7ffdf000 );
                    if( MmIsAddressValid( pPeb ) )
                    {
                        // Get DLL list entry head
                        pDllListHead = &((PPEB_LDR_DATA)(pPeb->Ldr))->InMemoryOrderModuleList;
                    }

                    if( MmIsAddressValid( pDllListHead ) )
                    {
                        PLIST_ENTRY pDllListEntry = NULL;
                        PLDR_DATA_TABLE_ENTRY pDll = NULL;
                        DLLLISTENTRY dllEntry = {0};
                        ANSI_STRING ansiDllName;

                        // Walk thorugh DLL list
                        pDllListEntry = pDllListHead->Flink;
                        while( MmIsAddressValid( pDllListEntry ) && ( pDllListEntry != pDllListHead ) )
                        {
                            // Get each DLL list entry
                            pDll = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD( pDllListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
                            if( MmIsAddressValid( pDll ) )
                            {
                                // Copy driver info to list entry
                                RtlZeroMemory( &dllEntry, sizeof( DLLLISTENTRY ) );
                                dllEntry.dwBase = (DWORD)pDll->DllBase;
                                RtlUnicodeStringToAnsiString( &ansiDllName, &( pDll->FullDllName ), 1 );
                                RtlStringCchCopyA( dllEntry.szDllName, ARKITLIB_STR_LEN, ansiDllName.Buffer );
                                RtlFreeAnsiString( &ansiDllName );

                                // Add it to our list
                                AddListEntry( eDllList, &dllEntry, TRUE );
                            }
                            pDllListEntry = pDllListEntry->Flink;
                        }
                    }

                    // Detach from process's stack
                    KeUnstackDetachProcess( pKapcState );

                    ExFreePool( pKapcState );
                    pKapcState = NULL;
                }
                ObDereferenceObject( pEproc );
            }

            // Set the result to true if we found some DLLs
            ((PTHRPARAMS)pThrParam)->bResult = !IsMyListEmpty( eDllList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanAndGetDllCountThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}