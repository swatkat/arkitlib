/*++
* @file: Utils.h
*
* @description: This file contains datatype definitions and utility function
*               declarations
*
*--*/

#ifndef __UTILS_H__
#define __UTILS_H__

#include "NtDefines.h"
#include "ARKitDefines.h"
#include "Lists.h"

#define ARKITDRV_DEBUG_PRINT

// Macros
#define VALIDATE_LIST_BUFF_SIZE( totalBuffSize, dataType, listType ) ( ( totalBuffSize / sizeof( dataType ) ) <= GetListCount( listType ) )

#define ARKIT_STR_UNKNOWN   "_unknown_"
#define BYTES_TO_DISASM     32
#define REL_JUMP_1          0xe8
#define REL_JUMP_2          0xe9
#define DIR_JUMP            0xea
#define LAST_RET            0xc2

// Structs
typedef struct _THRPARAMS {
    PVOID pParam;
    DWORD dwParamLen;
    BOOLEAN bResult;
} THRPARAMS, *PTHRPARAMS;

typedef struct _NTOSKRNLDATA {
    DWORD dwBase;
    DWORD dwEnd;
    DWORD dwEntryPoint;
} NTOSKRNLDATA, *PNTOSKRNLDATA;

typedef struct _OS_SPEC_DATA
{
    eOSVersion eOSVer;
    eOSServicePack eSPVer;
    DWORD dwFlinkOffset;
    DWORD dwPidOffset;
    DWORD dwHandleTableOffset;
    DWORD dwHandleListOffset;
    DWORD dwEprocOffset;
    DWORD dwThreadsProcess;
    DWORD dwCID;
    DWORD dwImageFilename;
    DWORD dwCrossThreadFlags;
    DWORD dwSeAuditOffset;
    DWORD dwProcessFlagsOffset;
    DWORD dwCmKeyHiveOffset;
    DWORD dwCmKeyCellOffset;
    DWORD dwCmNodeNameOffset;
    DWORD dwCmNodeNameLenOffset;
    DWORD dwCmKcbLastWriteTime;
    DWORD dwModEntryOffset;
} OS_SPEC_DATA, *POS_SPEC_DATA;

// Utility routines
NTSTATUS ThreadSpooler( PVOID pvFuncAddr, PTHRPARAMS pThrParam );
NTSTATUS InitGlobals( PMYOSVERINFO pMyOsVerInfo );
VOID InitGlobalsThread( PVOID pThrParam );
NTSTATUS InitNtApiData( PARKNTAPI pNtApiData );
VOID InitNtApiDataThread( PVOID pThrParam );
BOOLEAN IsProcessAlive( PEPROCESS pEproc );
BOOLEAN IsThreadAlive( PETHREAD pEthread );
BOOLEAN IsEthreadValid( PETHREAD pEthread );
int GetPid( PEPROCESS pEproc );
NTSTATUS GetProcessPathName( PEPROCESS pEproc, char* szProcessImageName, UINT nStrLen );
DWORD GetTid( PETHREAD pEthread );
DWORD GetPidThr( PETHREAD pEthread );
PEPROCESS GetEprocByPid( DWORD dwPid );
BOOLEAN IsDrvNameKernelA( char* pszDrvName );
BOOLEAN IsDrvNameKernelW( wchar_t* pwszDrvName );
PDWORD GetPsLoadedModuleList();
BOOLEAN IsDummyModuleEntry( PLDR_MODULE pModuleToChk );
BOOLEAN IsDummyModuleEntry2( PMODULE_ENTRY pModuleToChk );
BOOLEAN IsAddressInAnyDriver( DWORD dwAddress, PDRIVERLISTENTRY pDrv );
VOID DisableReadOnly();
VOID EnableReadOnly();
BOOLEAN IsJumpOutsideKernel( DWORD dwJumpToAddr );
DWORD GetJumpToAddr( PBYTE pbSrcAddr, int nOpCode );
NTSTATUS NtZwTerminateProcess( DWORD dwPid );
NTSTATUS NtZwTerminateProcessByThreads( DWORD dwPid );


#endif // __UTILS_H__