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
extern ARKNTAPI g_NtApiData;

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
                    // Scan handle table for processes
                    GetProcByHandleTableScan();

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
* @method: GetProcByHandleTableScan
*
* @description: Finds running processes by scanning handle table
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetProcByHandleTableScan()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        DWORD dwLen = 32000;
        DWORD dwRetLen = 0;
        char* pszBuffer = NULL;

        while( 1 )
        {
            // Allocate memory to hold handle info. Start with 32KB.
            pszBuffer = ExAllocatePoolWithTag( NonPagedPool, dwLen, ARKITLISTTAG );
            if( MmIsAddressValid( pszBuffer ) )
            {
                // Get all open handles
                RtlZeroMemory( pszBuffer, dwLen );
                retVal = NtQuerySystemInformation( SystemHandleInformation, pszBuffer, dwLen, &dwRetLen );
                if( STATUS_INFO_LENGTH_MISMATCH == retVal )
                {
                    // If buffer is less than expected, then retry with larger size
                    ExFreePool( pszBuffer );
                    dwLen = dwLen + (dwLen/2);
                    pszBuffer = NULL;
                }
                else
                {
                    break;
                }
            }
            else
            {
#ifdef ARKITDRV_DEBUG_PRINT
                DbgPrint( "GetProcByHandleTableScan: Memory allocation failed" );
#endif // ARKITDRV_DEBUG_PRINT

                pszBuffer = NULL;
                retVal = STATUS_UNSUCCESSFUL;
                break;
            }
        }

        if( STATUS_SUCCESS == retVal )
        {
            ULONG ulIndex = 0;
            DWORD dwPrevPid = 0;
            PEPROCESS pEproc = NULL;
            PROCLISTENTRY procEntry;
            PSYSTEM_HANDLE_INFORMATION pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)pszBuffer;

            // Loop through the handle table info array
            for( ulIndex = 0; ulIndex < pHandleInfo->NumberOfHandles; ulIndex++ )
            {
                // Get EPROCESS pointer for this PID
                pEproc = NULL;
                retVal = PsLookupProcessByProcessId( (HANDLE)(pHandleInfo->Handles[ulIndex].UniqueProcessId), &pEproc );
                if( STATUS_SUCCESS == retVal )
                {
                    // Check if process is alive
                    if( IsProcessAlive( pEproc ) )
                    {
                        // Filter out multiple handles for same PID
                        if( dwPrevPid != pHandleInfo->Handles[ulIndex].UniqueProcessId )
                        {
                            // Add the process info to our list
                            dwPrevPid = pHandleInfo->Handles[ulIndex].UniqueProcessId;
                            RtlZeroMemory( &procEntry, sizeof( PROCLISTENTRY ) );
                            procEntry.dwPID = dwPrevPid;
                            GetProcessPathName( pEproc, procEntry.szProcName, ARKITLIB_STR_LEN );
                            retVal = AddListEntry( eProcList, &procEntry, TRUE );
                        }
                    }
                    // Dereference EPROCESS pointer
                    ObDereferenceObject( pEproc );
                }
                else
                {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetProcByHandleTableScan: PsLookupProcessByProcessId failed: 0x%x, pid: %ld", retVal,
                       pHandleInfo->Handles[ulIndex].UniqueProcessId );
#endif // ARKITDRV_DEBUG_PRINT
                }
            }
        }
        else
        {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetProcByHandleTableScan: NtQuerySystemInformation failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
        }

        // Free buffer
        if( MmIsAddressValid( pszBuffer ) )
        {
            ExFreePool( pszBuffer );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetProcByHandleTableScan()" );
    }
    return retVal;
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
            DWORD dwPid = *(PDWORD)((PTHRPARAMS)pThrParam)->pParam;

            // Get DLLs by traversing PEB list
            GetDllByPeb( dwPid );

            // Get DLLs by traversing VAD tree
            GetDllByVadTree( dwPid );

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

/*++
* @method: GetDllByVadTree
*
* @description: Gets all loaded DLLs (executable images) by traversing EPROCESS VAD tree
*
* @input: DWORD dwPid
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetDllByVadTree( DWORD dwPid )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        PEPROCESS pEproc = NULL;

        // Get EPROCESS pointer by PID
        retVal = PsLookupProcessByProcessId( (HANDLE)dwPid, &pEproc );
        if( STATUS_SUCCESS == retVal )
        {
            if( IsProcessAlive( pEproc ) )
            {
                if( MmIsAddressValid( (PBYTE)pEproc + g_globalData.dwVadRootOffset ) )
                {
                    PMMVAD pVadRoot = NULL;
                    PMMADDRESS_NODE pMmAddrNode = NULL;
                    switch( g_globalData.eOSVer )
                    {
                    case eOS_WIN_2K:
                    case eOS_WIN_XP:
                        {
                            pVadRoot = (PMMVAD)*(PULONG)( (PBYTE)pEproc + g_globalData.dwVadRootOffset );
                            TraverseVadTreeInOrderWin2KXP( pVadRoot );
                        }
                        break;

                    case eOS_WIN_2K3:
                    case eOS_WIN_2K3R2:
                    case eOS_WIN_VISTA:
                        {
                            pMmAddrNode = (PMMADDRESS_NODE)( (PBYTE)pEproc + g_globalData.dwVadRootOffset );
                            TraverseVadTreeInOrderWin2K3Vista( pMmAddrNode );
                        }
                        break;
                    }
                }
            }
            ObDereferenceObject( pEproc );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetDllByVadTree()" );
    }
    return retVal;
}

/*++
* @method: TraverseVadTreeInOrderWin2K3Vista
*
* @description: Traverses VAD tree in order. Win2K3/Vista specific.
*
* @input: PMMADDRESS_NODE pVadNode
*
* @output: None
*
*--*/
VOID TraverseVadTreeInOrderWin2K3Vista( PMMADDRESS_NODE pVadNode )
{
    __try
    {
        if( MmIsAddressValid( pVadNode ) )
        {
            // Traverse left child
            TraverseVadTreeInOrderWin2K3Vista( pVadNode->LeftChild );

            {
                PMMVAD pMmVad = (PMMVAD)pVadNode;
                if( MmIsAddressValid( pMmVad->ControlArea ) && MmIsAddressValid( pMmVad->ControlArea->FilePointer ) )
                {
                    ULONG StartingVpn = 0;
                    ULONG EndingVpn = 0;
                    DLLLISTENTRY dllEntry = {0};

                    // Get base and end addresses
                    StartingVpn = pVadNode->StartingVpn << 12;
                    EndingVpn = ( ( pVadNode->EndingVpn + 1 ) << 12 ) - 1;

                    // Copy DLL info to list entry
                    RtlZeroMemory( &dllEntry, sizeof( DLLLISTENTRY ) );
                    dllEntry.dwBase = StartingVpn;
                    RtlStringCchPrintfA( dllEntry.szDllName, ARKITLIB_STR_LEN, "%S", pMmVad->ControlArea->FilePointer->FileName.Buffer );

                    // Add the DLL to our list
                    AddListEntry( eDllList, &dllEntry, TRUE );

#ifdef ARKITDRV_DEBUG_PRINT
                    DbgPrint( "TraverseVadTreeInOrderWin2K3Vista: Name: %S, Length: %d, StartingVpn: 0x%x, EndingVpn: 0x%x",
                              pMmVad->ControlArea->FilePointer->FileName.Buffer,
                              pMmVad->ControlArea->FilePointer->FileName.Length, StartingVpn, EndingVpn );
#endif // ARKITDRV_DEBUG_PRINT
                }
            }

            // Traverse right child
            TraverseVadTreeInOrderWin2K3Vista( pVadNode->RightChild );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in TraverseVadTreeInOrderWin2K3Vista()" );
    }
}

/*++
* @method: TraverseVadTreeInOrderWin2KXP
*
* @description: Traverses VAD tree in order. Win2K/XP specific.
*
* @input: PMMVAD pVadNode
*
* @output: None
*
*--*/
VOID TraverseVadTreeInOrderWin2KXP( PMMVAD pVadNode )
{
    __try
    {
        if( MmIsAddressValid( pVadNode ) )
        {
            // Traverse left child
            TraverseVadTreeInOrderWin2KXP( pVadNode->LeftChild );
            
            // Get filename from file object
            if( MmIsAddressValid( pVadNode->ControlArea ) && MmIsAddressValid( pVadNode->ControlArea->FilePointer ) )
            {
                ULONG StartingVpn = 0;
                ULONG EndingVpn = 0;
                DLLLISTENTRY dllEntry = {0};

                // Get base and end addresses
                StartingVpn = pVadNode->StartingVpn << 12;
                EndingVpn = ( ( pVadNode->EndingVpn + 1 ) << 12 ) - 1;

                // Copy DLL info to list entry
                RtlZeroMemory( &dllEntry, sizeof( DLLLISTENTRY ) );
                dllEntry.dwBase = StartingVpn;
                RtlStringCchPrintfA( dllEntry.szDllName, ARKITLIB_STR_LEN, "%S", pVadNode->ControlArea->FilePointer->FileName.Buffer );

                // Add the DLL to our list
                AddListEntry( eDllList, &dllEntry, TRUE );

#ifdef ARKITDRV_DEBUG_PRINT
                DbgPrint( "TraverseVadTreeInOrderWin2KXP: Name: %S, Length: %d, StartingVpn: 0x%x, EndingVpn: 0x%x",
                          pVadNode->ControlArea->FilePointer->FileName.Buffer,
                          pVadNode->ControlArea->FilePointer->FileName.Length, StartingVpn, EndingVpn );
#endif // ARKITDRV_DEBUG_PRINT
            }
            
            // Traverse right child
            TraverseVadTreeInOrderWin2KXP( pVadNode->RightChild );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in TraverseVadTreeInOrderWin2KXP()" );
    }
}

/*++
* @method: GetDllByPeb
*
* @description: Gets all loaded DLLs by traversing InMemoryOrderModuleList in PEB
*
* @input: DWORD dwPid
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetDllByPeb( DWORD dwPid )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        // Get the EPROCESS pointer for this process
        PEPROCESS pEproc = NULL;
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

                // Get the address of PsGetProcessPeb
                RtlInitUnicodeString( &usMethodName, L"PsGetProcessPeb" );
                pPsGetProcessPeb = (PSGETPROCESSPB)MmGetSystemRoutineAddress( &usMethodName );

                // Get pointer to PEB of this process
                pPeb = MmIsAddressValid( pPsGetProcessPeb ) ? pPsGetProcessPeb( pEproc ) : (PPEB)( (PBYTE)pPeb + g_globalData.dwPebOffset );

                // Attach to process's stack
                KeStackAttachProcess( pEproc, pKapcState );

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
                    
                    // Walk thorugh DLL list
                    pDllListEntry = pDllListHead->Flink;
                    while( MmIsAddressValid( pDllListEntry ) && ( pDllListEntry != pDllListHead ) )
                    {
                        // Get each DLL list entry
                        pDll = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD( pDllListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
                        if( MmIsAddressValid( pDll ) )
                        {
                            // Copy DLL info to list entry
                            RtlZeroMemory( &dllEntry, sizeof( DLLLISTENTRY ) );
                            dllEntry.dwBase = (DWORD)pDll->DllBase;
                            RtlStringCchPrintfA( dllEntry.szDllName, ARKITLIB_STR_LEN, "%S", pDll->FullDllName.Buffer );

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
            // Dereference EPROCESS pointer
            ObDereferenceObject( pEproc );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetDllByPeb()" );
    }
    return retVal;
}

/*++
* @method: KillProcess
*
* @description: Wrapper to thread function to kill a process
*
* @input: DWORD dwPid
*
* @output: BOOLEAN
*
*--*/
BOOLEAN KillProcess( DWORD dwPid )
{
    BOOLEAN bKilled = FALSE;
    __try
    {
        // Create a thread to kill a process
        THRPARAMS stThrParams = {0};
        stThrParams.pParam = &dwPid;
        stThrParams.dwParamLen = sizeof( DWORD );
        if( STATUS_SUCCESS == ThreadSpooler( KillProcessThread, &stThrParams ) )
        {
            bKilled = stThrParams.bResult;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bKilled = FALSE;
        DbgPrint( "Exception caught in KillProcess()" );
    }
    return bKilled;
}

/*++
* @method: KillProcessThread
*
* @description: Kills a process
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID KillProcessThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) )
        {
            NTSTATUS retVal = STATUS_UNSUCCESSFUL;
            PTHRPARAMS pParams = (PTHRPARAMS)pThrParam;

            // Try killing process using NtTerminateProcess
            retVal = NtZwTerminateProcess( *(PDWORD)(pParams->pParam) );

            // If the above method fails, then try killing all
            // threads of the process
            if( STATUS_SUCCESS != retVal )
            {
                retVal = NtZwTerminateProcessByThreads( *(PDWORD)(pParams->pParam) );
            }

            // Set the result to true if we are able to kill process
            if( STATUS_SUCCESS == retVal )
            {
                ((PTHRPARAMS)pThrParam)->bResult = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in KillProcessThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}