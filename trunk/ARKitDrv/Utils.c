/*++
* @file: Utils.c
*
* @description: This file contains utility functions used by ARKit driver
*
*--*/

#include "Utils.h"
#include "ARKitDrv.h"

// Globals
PWCHAR g_wszMyDeviceName = L"\\Device\\ARKITDRV";
PWCHAR g_wszMyDeviceLink = L"\\DosDevices\\ARKITDRV";
PDRIVER_OBJECT g_pMyDriverObj = NULL;
OS_SPEC_DATA g_globalData = {0};
ARKNTAPI g_NtApiData = {0};
NTOSKRNLDATA g_NtOSKernel = {0};

/*++
* @method: ThreadSpooler
*
* @description: Thread spooler
*
* @input: PVOID pvFuncAddr, PTHRPARAMS pThrParam
*
* @output: NTSTATUS
*
* @remarks: Most of the functions in this driver are executed as a separate
*           system thread, because in system threads PreviousMode will be KernelMode
*
*--*/
NTSTATUS ThreadSpooler( PVOID pvFuncAddr, PTHRPARAMS pThrParam )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        HANDLE hThread = NULL;
        if( MmIsAddressValid( pvFuncAddr ) && MmIsAddressValid( pThrParam ) )
        {
            // Create a thread. Let the function execute in kernel mode context
            retVal = PsCreateSystemThread( &hThread,
                                           (ACCESS_MASK)0L,
                                           NULL, NULL, NULL,
                                           pvFuncAddr,
                                           (PVOID)pThrParam );
            if( STATUS_SUCCESS == retVal )
            {
                // Wait till thread completes
                retVal = ZwWaitForSingleObject( hThread, FALSE, NULL );

                // Set the return value based on thread's result
                if( STATUS_SUCCESS == retVal )
                {
                    retVal = ( FALSE != pThrParam->bResult ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
                }
                else
                {
#ifdef ARKITDRV_DEBUG_PRINT
                    DbgPrint( "ThreadSpooler: ZwWaitForSingleObject failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
                }
                ZwClose( hThread );
            }
            else
            {
#ifdef ARKITDRV_DEBUG_PRINT
                DbgPrint( "ThreadSpooler: PsCreateSystemThread failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in ThreadSpooler()" );
    }
    return retVal;
}

/*++
* @method: InitGlobals
*
* @description: Wrapper to InitGlobalsThread
*
* @input: PMYOSVERINFO pMyOsVerInfo
*
* @output: NTSTATUS
*
*--*/
NTSTATUS InitGlobals( PMYOSVERINFO pMyOsVerInfo )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        THRPARAMS stThrParams = {0};
        stThrParams.pParam = pMyOsVerInfo;
        stThrParams.dwParamLen = sizeof( PMYOSVERINFO );

        retVal = ThreadSpooler( InitGlobalsThread, &stThrParams );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in InitGlobals()" );
    }
    return retVal;
}

/*++
* @method: InitGlobalsThread
*
* @description: Thread to init OS specific data and offsets
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID InitGlobalsThread( PVOID pThrParam )
{
    __try
    {
        PMYOSVERINFO pMyOsVerInfo = NULL;
        if( MmIsAddressValid( pThrParam ) )
        {
            RtlZeroMemory( &g_globalData, sizeof( OS_SPEC_DATA ) );

            pMyOsVerInfo = ((PTHRPARAMS)pThrParam)->pParam;
            if( MmIsAddressValid( pMyOsVerInfo ) )
            {
                g_globalData.eOSVer = pMyOsVerInfo->osVer;
                g_globalData.eSPVer = pMyOsVerInfo->spVer;
            }

            switch( g_globalData.eOSVer )
            {
            case eOS_WIN_2K: // Win 2K
                {
                    g_globalData.dwFlinkOffset = 0x0a0;
                    g_globalData.dwPidOffset = 0x09c;
                    g_globalData.dwHandleTableOffset = 0x128;
                    g_globalData.dwHandleListOffset = 0x54;
                    g_globalData.dwEprocOffset = 0x10;
                    g_globalData.dwThreadsProcess = 0x8b;
                    g_globalData.dwCID = 0x78;
                    g_globalData.dwImageFilename = 0x7f;
                    g_globalData.dwCrossThreadFlags = 0;
                    g_globalData.dwSeAuditOffset = 0;
                    g_globalData.dwProcessFlagsOffset = 0x1aa;
                    g_globalData.dwCmKeyHiveOffset = 0x00c;
                    g_globalData.dwCmKeyCellOffset = 0x010;
                    g_globalData.dwCmNodeNameOffset = 0x04c;
                    g_globalData.dwCmNodeNameLenOffset = 0x048;
                    g_globalData.dwCmKcbLastWriteTime = 0; // Not present!!?
                    g_globalData.dwModEntryOffset = 0x14;
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
                break;

            case eOS_WIN_XP: // Win XP
                {
                    g_globalData.dwFlinkOffset = 0x088;
                    g_globalData.dwPidOffset = 0x084;
                    g_globalData.dwHandleTableOffset = 0xc4;
                    g_globalData.dwHandleListOffset = 0x1c;
                    g_globalData.dwEprocOffset = 0x08;
                    g_globalData.dwThreadsProcess = 0x088; // 0x220 byte offset
                    g_globalData.dwCID = 0x7b; // 0x1ec byte offset
                    g_globalData.dwImageFilename = 0x5d; // 0x174 byte offset
                    g_globalData.dwCrossThreadFlags = 0x92; // 0x248 byte offset
                    g_globalData.dwSeAuditOffset = 0x1f4;
                    g_globalData.dwProcessFlagsOffset = 0x248;
                    g_globalData.dwCmKeyHiveOffset = 0x010;
                    g_globalData.dwCmKeyCellOffset = 0x014;
                    g_globalData.dwCmNodeNameOffset = 0x04c;
                    g_globalData.dwCmNodeNameLenOffset = 0x048;
                    g_globalData.dwCmKcbLastWriteTime = 0x038;
                    g_globalData.dwModEntryOffset = 0;
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
                break;

            case eOS_WIN_2K3: // Win 2K3
                {
                    switch( g_globalData.eSPVer )
                    {
                    case eOS_SP_1:
                    case eOS_SP_2:
                        {
                            g_globalData.dwFlinkOffset = 0x098;
                            g_globalData.dwPidOffset = 0x094;
                            g_globalData.dwHandleTableOffset = 0x0d4;
                            g_globalData.dwHandleListOffset = 0x01c;
                            g_globalData.dwEprocOffset = 0x008;
                            g_globalData.dwThreadsProcess = 0x86; // 0x218 byte offset.
                            g_globalData.dwCID = 0x79; // 0x1e4 byte offset.
                            g_globalData.dwImageFilename = 0x59; // 0x164 byte offset.
                            g_globalData.dwCrossThreadFlags = 0x90; // 0x240 byte offset.
                            g_globalData.dwSeAuditOffset = 0x1e4;
                            g_globalData.dwProcessFlagsOffset = 0x240;
                            g_globalData.dwCmKeyHiveOffset = 0x010; // in _CM_KEY_CONTROL_BLOCK
                            g_globalData.dwCmKeyCellOffset = 0x014; // in _CM_KEY_CONTROL_BLOCK
                            g_globalData.dwCmNodeNameOffset = 0x04c; // in _CM_KEY_NODE
                            g_globalData.dwCmNodeNameLenOffset = 0x048; // in _CM_KEY_NODE
                            g_globalData.dwCmKcbLastWriteTime = 0x050; // in _CM_KEY_CONTROL_BLOCK
                            g_globalData.dwModEntryOffset = 0;
                        }
                        break;

                    case eOS_SP_0:
                    default:
                        {
                            g_globalData.dwFlinkOffset = 0x088;
                            g_globalData.dwPidOffset = 0x084;
                            g_globalData.dwHandleTableOffset = 0xc4;
                            g_globalData.dwHandleListOffset = 0x1c;
                            g_globalData.dwEprocOffset = 0x08;
                            g_globalData.dwThreadsProcess = 0x8a;
                            g_globalData.dwCID = 0x7d;
                            g_globalData.dwImageFilename = 0x55;
                            g_globalData.dwCrossThreadFlags = 0x94;
                            g_globalData.dwSeAuditOffset = 0x1d4;
                            g_globalData.dwProcessFlagsOffset = 0x248;
                            g_globalData.dwCmKeyHiveOffset = 0x010; // Offset not checked in SP0. Using SP1/SP2.
                            g_globalData.dwCmKeyCellOffset = 0x014; // Offset not checked in SP0.
                            g_globalData.dwCmNodeNameOffset = 0x04c; // Offset not checked in SP0.
                            g_globalData.dwCmNodeNameLenOffset = 0x048; // Offset not checked in SP0.
                            g_globalData.dwCmKcbLastWriteTime = 0x050; // Offset not checked in SP0.
                            g_globalData.dwModEntryOffset = 0;
                        }
                        break;
                    }
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
                break;

            case eOS_WIN_2K3R2: // Win 2K3 R2
                {
                    g_globalData.dwFlinkOffset = 0x098;
                    g_globalData.dwPidOffset = 0x094;
                    g_globalData.dwHandleTableOffset = 0x0d4;
                    g_globalData.dwHandleListOffset = 0x01c;
                    g_globalData.dwEprocOffset = 0x08;
                    g_globalData.dwThreadsProcess = 0x86; // 0x218 byte offset
                    g_globalData.dwCID = 0x79; // 0x1e4 is byte offset
                    g_globalData.dwImageFilename = 0x59; // 0x164 byte offset
                    g_globalData.dwCrossThreadFlags = 0x90; // 0x240 byte offset
                    g_globalData.dwSeAuditOffset = 0x1e4;
                    g_globalData.dwProcessFlagsOffset = 0x240;
                    g_globalData.dwCmKeyHiveOffset = 0x010;
                    g_globalData.dwCmKeyCellOffset = 0x014;
                    g_globalData.dwCmNodeNameOffset = 0x04c;
                    g_globalData.dwCmNodeNameLenOffset = 0x048;
                    g_globalData.dwCmKcbLastWriteTime = 0x050;
                    g_globalData.dwModEntryOffset = 0;
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
                break;

            case eOS_WIN_VISTA: // Vista SP1
                {
                    g_globalData.dwFlinkOffset = 0x0a0;
                    g_globalData.dwPidOffset = 0x09c;
                    g_globalData.dwHandleTableOffset = 0x0dc;
                    g_globalData.dwHandleListOffset = 0x010;
                    g_globalData.dwEprocOffset = 0x08;
                    g_globalData.dwThreadsProcess = 0; // Not present??!
                    g_globalData.dwCID = 0x83; // DWORD ptr offset
                    g_globalData.dwImageFilename = 0x53; // DWORD ptr offset
                    g_globalData.dwCrossThreadFlags = 0x98; // DWORD ptr offset
                    g_globalData.dwSeAuditOffset = 0x1cc;
                    g_globalData.dwProcessFlagsOffset = 0x228;
                    g_globalData.dwCmKeyHiveOffset = 0x010;
                    g_globalData.dwCmKeyCellOffset = 0x014;
                    g_globalData.dwCmNodeNameOffset = 0x04c;
                    g_globalData.dwCmNodeNameLenOffset = 0x048;
                    g_globalData.dwCmKcbLastWriteTime = 0x050;
                    g_globalData.dwModEntryOffset = 0;
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
                break;

            case eOS_WIN_7:
            default:
                {
                    ((PTHRPARAMS)pThrParam)->bResult = FALSE;
                }
                break;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in InitGlobalsThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: InitNtApiData
*
* @description: Wrapper to InitNtApiDataThread that saves NT API addresses
*
* @input: PARKNTAPI pNtApiData
*
* @output: NTSTATUS
*
*--*/
NTSTATUS InitNtApiData( PARKNTAPI pNtApiData )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        THRPARAMS stThrParams = {0};
        stThrParams.pParam = pNtApiData;
        stThrParams.dwParamLen = sizeof( PARKNTAPI );

        retVal = ThreadSpooler( InitNtApiDataThread, &stThrParams );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in InitNtApiData()" );
    }
    return retVal;
}

/*++
* @method: InitNtApiDataThread
*
* @description: Thread to initialize NT API addresses in our global struct
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID InitNtApiDataThread( PVOID pThrParam )
{
    __try
    {
        RtlZeroMemory( &g_NtApiData, sizeof( ARKNTAPI ) );
        if( MmIsAddressValid( pThrParam ) )
        {
            PARKNTAPI pNtApiData = (PARKNTAPI)((PTHRPARAMS)pThrParam)->pParam;
            if( MmIsAddressValid( pNtApiData ) )
            {
                // Copy NT API addresses to our global struct
                RtlCopyMemory( &g_NtApiData, pNtApiData, sizeof( ARKNTAPI ) );
                ((PTHRPARAMS)pThrParam)->bResult = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in InitNtApiDataThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: IsProcessAlive
*
* @description: Checks if process is alive or not
*
* @input: PEPROCESS pEproc
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsProcessAlive( PEPROCESS pEproc )
{
    BOOLEAN bIsAlive = FALSE;
    __try
    {
        if( MmIsAddressValid( pEproc ) &&
            MmIsAddressValid( (UINT*)((BYTE*)pEproc + g_globalData.dwProcessFlagsOffset) ) )
        {
            if( eOS_WIN_2K == g_globalData.eOSVer )
            {
                bIsAlive = !(*(BYTE*)((BYTE*)pEproc + g_globalData.dwProcessFlagsOffset));
            }
            else
            {
                if( !( (*(UINT*)( (BYTE*)pEproc + g_globalData.dwProcessFlagsOffset )) & PROCESS_STATE_EXITING ) &&
                    !( (*(UINT*)( (BYTE*)pEproc + g_globalData.dwProcessFlagsOffset )) & PROCESS_STATE_DELETED ) )
                {
                    bIsAlive = TRUE;
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bIsAlive = FALSE;
        DbgPrint( "Exception caught in IsProcessAlive()" );
    }
    return bIsAlive;
}

/*++
* @method: GetPid
*
* @description: Gets pid from EPROCESS
*
* @input: PEPROCESS pEproc
*
* @output: int
*
*--*/
int GetPid( PEPROCESS pEproc )
{
    int nPid = -1;
    __try
    {
        UNICODE_STRING usMethodName;
        PSGETPROCESSID pPsGetProcessId = NULL;
        if( MmIsAddressValid( pEproc ) )
        {
            // Use PsGetProcessId if it's exported
            RtlInitUnicodeString( &usMethodName, L"PsGetProcessId" );
            pPsGetProcessId = (PSGETPROCESSID)MmGetSystemRoutineAddress( &usMethodName );
            if( MmIsAddressValid( pPsGetProcessId ) )
            {
                nPid = (int)pPsGetProcessId( pEproc );
            }
            else
            {
                // Otherwise get pid manually
                nPid = *( (int*)((DWORD)pEproc + g_globalData.dwPidOffset) );
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        nPid = -1;
        DbgPrint( "Exception caught in GetPid()" );
    }
    return nPid;
}

/*++
* @method: GetProcessPathName
*
* @description: Gets process pathname from EPROCESS
*
* @input: PEPROCESS pEproc, char* szProcessImageName, UINT nStrLen
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetProcessPathName( PEPROCESS pEproc, char* szProcessImageName, UINT nStrLen )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        ANSI_STRING ansiImageName;
        PSE_AUDIT_PROCESS_CREATION_INFO pseAudit = NULL;

        if( MmIsAddressValid( pEproc ) )
        {
            RtlZeroMemory( szProcessImageName, nStrLen );

            switch( g_globalData.eOSVer )
            {
            case eOS_WIN_2K:
                {
                    // If Win2K, then get only process filename from EPROCESS
                    RtlStringCchCopyA( szProcessImageName, nStrLen,
                                       (char*)((PDWORD)pEproc + g_globalData.dwImageFilename) );
                    retVal = STATUS_SUCCESS;
                }
                break;

            default:
                {
                    // Try to get process full path from SE_AUDIT_PROCESS_CREATION_INFO
                    pseAudit = (PSE_AUDIT_PROCESS_CREATION_INFO)((PBYTE)pEproc + g_globalData.dwSeAuditOffset);
                    if( MmIsAddressValid( pseAudit ) && pseAudit->ImageFileName->Name.Length )
                    {
                        RtlUnicodeStringToAnsiString( &ansiImageName, &(pseAudit->ImageFileName->Name), 1 );
                        RtlStringCchCopyA( szProcessImageName, nStrLen, ansiImageName.Buffer );
                        RtlFreeAnsiString( &ansiImageName );
                    }
                    if( 0 == strlen( szProcessImageName ) )
                    {
                        // Otherwise get from EPROCESS
                        RtlStringCchCopyA( szProcessImageName, nStrLen,
                                           (char*)((PDWORD)pEproc + g_globalData.dwImageFilename) );
                    }
                    retVal = STATUS_SUCCESS;
                }
                break;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetProcessPathName()" );
    }
    return retVal;
}

/*++
* @method: GetTid
*
* @description: Gets tid from ETHREAD
*
* @input: PETHREAD pEthread
*
* @output: DWORD
*
*--*/
DWORD GetTid( PETHREAD pEthread )
{
    DWORD dwTid = 0;
    __try
    {
        if( MmIsAddressValid( pEthread ) )
        {
            dwTid = *( (DWORD*)pEthread + g_globalData.dwCID + 0x01 );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        dwTid = 0;
        DbgPrint( "Exception caught in GetTid()" );
    }
    return dwTid;
}

/*++
* @method: GetPidThr
*
* @description: Gets parent pid from ETHREAD
*
* @input: PETHREAD pEthread
*
* @output: DWORD
*
*--*/
DWORD GetPidThr( PETHREAD pEthread )
{
    DWORD dwPid = 0;
    __try
    {
        if( MmIsAddressValid( pEthread ) )
        {
            dwPid = *( (DWORD*)pEthread + g_globalData.dwCID );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        dwPid = 0;
        DbgPrint( "Exception caught in GetPidThr()" );
    }
    return dwPid;
}

/*++
* @method: GetEprocByPid
*
* @description: Get EPROCESS pointr from pid
*
* @input: DWORD dwPid
*
* @output: PEPROCESS
*
*--*/
PEPROCESS GetEprocByPid( DWORD dwPid )
{
    PEPROCESS pEproc = NULL;
    __try
    {
        BOOLEAN bFound = FALSE;
        NTSTATUS retVal = STATUS_UNSUCCESSFUL;
        if( eOS_ERR != g_globalData.eOSVer )
        {
            retVal = PsLookupProcessByProcessId( (HANDLE)dwPid, &pEproc );
            if( STATUS_SUCCESS == retVal )
            {
                if( IsProcessAlive( pEproc ) )
                {
                    bFound = TRUE;
                }
                ObDereferenceObject( pEproc );
            }
            else
            {
#ifdef ARKITDRV_DEBUG_PRINT
                DbgPrint( "GetEprocByPid: PsLookupProcessByProcessId failed, 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
            }
        }

        if( !bFound )
        {
            pEproc = NULL;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        pEproc = NULL;
        DbgPrint( "Exception caught in GetEprocByPid()" );
    }
    return pEproc;
}

/*++
* @method: IsEthreadValid
*
* @description: Check if ETHREAD pointer is valid
*
* @input: PETHREAD pEthread
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsEthreadValid( PETHREAD pEthread )
{
    BOOLEAN bValid = FALSE;
    __try
    {
        if( MmIsAddressValid( pEthread ) )
        {
            if( MmIsAddressValid( ( (DWORD*)pEthread + g_globalData.dwCID ) ) && 
                MmIsAddressValid( ( (DWORD*)pEthread + g_globalData.dwCID + 0x01 ) ) && 
                MmIsAddressValid( ( (DWORD*)pEthread + g_globalData.dwCrossThreadFlags ) ) )
            {
                bValid = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bValid = FALSE;
        DbgPrint( "Exception caught in IsEthreadValid()" );
    }
    return bValid;
}

/*++
* @method: IsThreadAlive
*
* @description: Check if thread is alive
*
* @input: PETHREAD pEthread
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsThreadAlive( PETHREAD pEthread )
{
    BOOLEAN bIsAlive = FALSE;
    __try
    {
        if( IsEthreadValid( pEthread ) )
        {
            if( !(*((DWORD*)pEthread + g_globalData.dwCrossThreadFlags) & THREAD_TERMINATED ) && // If thread is not terminated
                !(*((DWORD*)pEthread + g_globalData.dwCrossThreadFlags) & THREAD_DEAD ) ) // and not dead
            {
                bIsAlive = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bIsAlive = FALSE;
        DbgPrint( "Exception caught in IsThreadAlive()" );
    }
    return bIsAlive;
}

/*++
* @method: IsDrvNameKernelA
*
* @description: Check if given string is NT kernel's name
*
* @input: char* pszDrvName
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsDrvNameKernelA( char* pszDrvName )
{
    BOOLEAN bIsKernel = FALSE;
    __try
    {
        if( MmIsAddressValid( pszDrvName ) )
        {
            if( ( NULL != strstr( pszDrvName, "\\ntoskrnl.exe" ) ) ||
                ( NULL != strstr( pszDrvName, "\\ntkrnlpa.exe" ) ) ||
                ( NULL != strstr( pszDrvName, "\\ntkrnlmp.exe" ) ) )
            {
                bIsKernel = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bIsKernel = FALSE;
        DbgPrint( "Exception caught in IsDrvNameKernelA()" );
    }
    return bIsKernel;
}

/*++
* @method: IsDrvNameKernelW
*
* @description: Check if given wide string is NT kernel's name
*
* @input: wchar_t* pwszDrvName
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsDrvNameKernelW( wchar_t* pwszDrvName )
{
    BOOLEAN bIsKernel = FALSE;
    __try
    {
        if( MmIsAddressValid( pwszDrvName ) )
        {
            if( ( NULL != wcsstr( pwszDrvName, L"\\ntoskrnl.exe" ) ) ||
                ( NULL != wcsstr( pwszDrvName, L"\\ntkrnlpa.exe" ) ) ||
                ( NULL != wcsstr( pwszDrvName, L"\\ntkrnlmp.exe" ) ) )
            {
                bIsKernel = TRUE;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bIsKernel = FALSE;
        DbgPrint( "Exception caught in IsDrvNameKernelW()" );
    }
    return bIsKernel;
}

/*++
* @method: GetPsLoadedModuleList
*
* @description: Get PsLoadedModuleList
*
* @input: None
*
* @output: PDWORD
*
*--*/
PDWORD GetPsLoadedModuleList()
{
    PDWORD pdwAddress = NULL;
    __try
    {
        if( MmIsAddressValid( g_pMyDriverObj ) )
        {
            // DriverSection is the entry in PsLoadedModuleList
            pdwAddress = (PDWORD)(g_pMyDriverObj->DriverSection);
        }
        else
        {
            // If our driver object is invalid, then get it from KdVersionBlock
            __asm
            {
                mov eax, fs:[0x34];     // Get address of KdVersionBlock
                mov eax, [eax+0x18];    // Get address of PsLoadedModuleList
                mov pdwAddress, eax;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        pdwAddress = NULL;
        DbgPrint( "Exception caught in GetPsLoadedModuleList()" );
    }
    return pdwAddress;
}

/*++
* @method: IsDummyModuleEntry
*
* @description: Checks if a kernel module entry is valid or not
*
* @input: PLDR_MODULE pModuleToChk
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsDummyModuleEntry( PLDR_MODULE pModuleToChk )
{
    BOOLEAN bDummy = FALSE;
    __try
    {
        if( MmIsAddressValid( pModuleToChk ) )
        {
            if( ( 0 == pModuleToChk->FullDllName.Length ) ||
                ( 0 == pModuleToChk->SizeOfImage ) ||
                ( 0 == pModuleToChk->BaseAddress ) )
            {
                bDummy = TRUE;
            }
        }
        else
        {
            bDummy = TRUE;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bDummy = TRUE;
        DbgPrint( "Exception caught in IsDummyModuleEntry()" );
    }
    return bDummy;
}

/*++
* @method: IsDummyModuleEntry2
*
* @description: Checks if a kernel module entry is valid or not
*
* @input: PMODULE_ENTRY pModuleToChk
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsDummyModuleEntry2( PMODULE_ENTRY pModuleToChk )
{
    BOOLEAN bDummy = FALSE;
    __try
    {
        if( MmIsAddressValid( pModuleToChk ) )
        {
            if( ( 0 == pModuleToChk->drvPath.Length ) ||
                ( 0 == pModuleToChk->imageSize ) ||
                ( 0 == pModuleToChk->imageBase ) )
            {
                bDummy = TRUE;
            }
        }
        else
        {
            bDummy = TRUE;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bDummy = TRUE;
        DbgPrint( "Exception caught in IsDummyModuleEntry2()" );
    }
    return bDummy;
}

/*++
* @method: IsAddressInAnyDriver
*
* @description: Checks if a kernel mode address points inside a loaded driver
*
* @input: DWORD dwAddress, PDRIVERLISTENTRY pDrv
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsAddressInAnyDriver( DWORD dwAddress, PDRIVERLISTENTRY pDrv )
{
    BOOLEAN bAddrInDriver = FALSE;
    __try
    {
        if( dwAddress && MmIsAddressValid( pDrv ) )
        {
            UINT nIndex = 0;
            PDRIVERLISTENTRY pCurrent = NULL;
            while( STATUS_SUCCESS == GetListEntry( eDrvList, nIndex, &pCurrent ) )
            {
                if( MmIsAddressValid( pCurrent ) )
                {
                    if( ( pCurrent->dwBase <= dwAddress ) && ( pCurrent->dwEnd >= dwAddress ) )
                    {
                        pDrv->dwBase = pCurrent->dwBase;
                        pDrv->dwEnd = pCurrent->dwEnd;
                        RtlStringCchCopyA( pDrv->szDrvName, ARKITLIB_STR_LEN, pCurrent->szDrvName );
                        bAddrInDriver = TRUE;
                        break;
                    }
                    ++nIndex;
                }
                else
                {
                    break;
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {        
        bAddrInDriver = FALSE;
        DbgPrint( "Exception caught in IsAddressInAnyDriver()" );
    }    
    return bAddrInDriver;
}

/*++
* @method: DisableReadOnly
*
* @description: Disables read-only protection for MSR register
*
* @input: None
*
* @output: None
*
*--*/
VOID DisableReadOnly()
{
    _asm                                          //disable WP bit
    {
        mov eax,cr0                                 //move CR0 register into EAX
        and eax,not 000010000h                      //disable WP bit 
        mov cr0,eax                                 //write register back
    }
}

/*++
* @method: EnableReadOnly
*
* @description: Enables read-only protection for MSR register
*
* @input: None
*
* @output: None
*
*--*/
VOID EnableReadOnly()
{
    _asm                                          //enable WP bit
    {
        mov eax,cr0                                 //move CR0 register into EAX
        or eax,000010000h                           //enable WP bit         
        mov cr0,eax                                 //write register back           
    }
}

/*++
* @method: IsJumpOutsideKernel
*
* @description: Checks if address points outside NT kernel
*
* @input: DWORD dwJumpToAddr
*
* @output: TRUE if jump is outside kernel, otherwise FALSE
*
*--*/
BOOLEAN IsJumpOutsideKernel( DWORD dwJumpToAddr )
{
    BOOLEAN bJumpOutsideKernel = FALSE;

    // If kernel details are not yet loaded, then do it now
    if( ( 0 == g_NtOSKernel.dwBase ) || ( 0 == g_NtOSKernel.dwEnd ) )
    {
        ScanAndGetDriverCount();
        DelList( eDrvList );
    }

    // Check if the address is out of kernel range
    if( ( dwJumpToAddr < g_NtOSKernel.dwBase ) || ( dwJumpToAddr > g_NtOSKernel.dwEnd ) )
    {
        bJumpOutsideKernel = TRUE;
    }
    return bJumpOutsideKernel;
}

/*++
* @method: GetJumpToAddr
*
* @description: Gets the jump-to address from the assemby instruction
*
* @input: PBYTE pbSrcAddr, int nOpCode
*
* @output: DWORD
*
*--*/
DWORD GetJumpToAddr( PBYTE pbSrcAddr, int nOpCode )
{
    DWORD dwJumpTo = 0;
    __try
    {
        if( MmIsAddressValid( pbSrcAddr ) )
        {
            if( ( REL_JUMP_1 == nOpCode ) || ( REL_JUMP_2 == nOpCode ) )
            {
                dwJumpTo |= *(pbSrcAddr + 1) << 0;
                dwJumpTo |= *(pbSrcAddr + 2) << 8;
                dwJumpTo |= *(pbSrcAddr + 3) << 16;
                dwJumpTo |= *(pbSrcAddr + 4) << 24;
                dwJumpTo += 5 + (DWORD)pbSrcAddr;
            }
            else if( DIR_JUMP == nOpCode )
            {
                dwJumpTo |= *(pbSrcAddr + 1) << 0;
                dwJumpTo |= *(pbSrcAddr + 2) << 8;
                dwJumpTo |= *(pbSrcAddr + 3) << 16;
                dwJumpTo |= *(pbSrcAddr + 4) << 24;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        dwJumpTo = 0;
        DbgPrint( "Exception caught in GetJumpToAddr()" );
    }
    return dwJumpTo;
}