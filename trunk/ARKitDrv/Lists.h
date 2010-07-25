/*++
* @file: Lists.h
*
* @description: This file contains datatype definitions and function declarations
*               related to linked lists used by ARKit driver
*
*--*/

#ifndef __LISTS_H__
#define __LISTS_H__

#include "NtDefines.h"
#include "ARKitDefines.h"

typedef enum _eListType
{
    eInvalidList = 0,
    eProcList,
    eDllList,
    eDrvList,
    eSsdtList
} eListType, *PeListType;

#define ARKITLISTTAG    'TLRA' // ARKit List tag

typedef struct _PROCLISTENTRY {
    LIST_ENTRY lEntry;
    DWORD dwPID;
    char szProcName[ARKITLIB_STR_LEN];
} PROCLISTENTRY, *PPROCLISTENTRY;

typedef struct _DLLLISTENTRY {
    LIST_ENTRY lEntry;
    DWORD dwBase;
    char szDllName[ARKITLIB_STR_LEN];
} DLLLISTENTRY, *PDLLLISTENTRY;

typedef struct _DRIVERLISTENTRY {
    LIST_ENTRY lEntry;
    DWORD dwBase;
    DWORD dwEnd;
    DWORD dwEntryPoint;
    char szDrvName[ARKITLIB_STR_LEN];
} DRIVERLISTENTRY, *PDRIVERLISTENTRY;

typedef struct _SSDTHOOKLISTENTRY {
    LIST_ENTRY lEntry;
    UINT unIndex;
    DWORD dwHookAddr;
    DWORD dwBase;
    DWORD dwEnd;
    char szDrvName[ARKITLIB_STR_LEN];
} SSDTHOOKLISTENTRY, *PSSDTHOOKLISTENTRY;

typedef struct _LISTS_ARRAY {
    PLIST_ENTRY pProcListHead;
    PLIST_ENTRY pDllListHead;
    PLIST_ENTRY pDrvListHead;
    PLIST_ENTRY pSsdtListHead;
} LISTS_ARRAY, *PLISTS_ARRAY;

NTSTATUS InitList( eListType eTypeOfList );
NTSTATUS AddListEntry( eListType eTypeOfList, PVOID pItemToAdd, BOOLEAN bFind );
NTSTATUS GetListEntry( eListType eTypeOfList, UINT nPosition, VOID** ppvGotItem );
UINT GetListCount( eListType eTypeOfList );
BOOLEAN IsMyListEmpty( eListType eTypeOfList );
NTSTATUS DelAllLists();
NTSTATUS DelList( eListType eTypeOfList );
NTSTATUS FindEntry( eListType eTypeOfList, PVOID pItemToFind );

#endif // __LISTS_H__