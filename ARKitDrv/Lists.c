/*++
* @file: Lists.c
*
* @description: This file contains functions that implement linked list used by ARKit driver
*
*--*/

#include "Lists.h"
#include "Utils.h"

// Globals
LISTS_ARRAY g_lstArray = {0};

/*++
* @method: InitList
*
* @description: Initialize list head of specified type
*
* @input: eListType eTypeOfList
*
* @output: NTSTATUS
*
*--*/
NTSTATUS InitList( eListType eTypeOfList )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        // Allocate list entry head
        PLIST_ENTRY pHead = NULL;

        // Delete list if it is present already
        DelList( eTypeOfList );

        pHead = ExAllocatePoolWithTag( NonPagedPool,
                                       sizeof( LIST_ENTRY ),
                                       ARKITLISTTAG );

        // Free the old head and save new pointer based on type of list
        switch( eTypeOfList )
        {
        case eProcList:
            {
                if( MmIsAddressValid( g_lstArray.pProcListHead ) )
                {
                    ExFreePool( g_lstArray.pProcListHead );
                }
                g_lstArray.pProcListHead = pHead;
            }
            break;

        case eDllList:
            {
                if( MmIsAddressValid( g_lstArray.pDllListHead ) )
                {
                    ExFreePool( g_lstArray.pDllListHead );
                }
                g_lstArray.pDllListHead = pHead;
            }
            break;

        case eDrvList:
            {
                if( MmIsAddressValid( g_lstArray.pDrvListHead ) )
                {
                    ExFreePool( g_lstArray.pDrvListHead );
                }
                g_lstArray.pDrvListHead = pHead;
            }
            break;

        case eSsdtList:
            {
                if( MmIsAddressValid( g_lstArray.pSsdtListHead ) )
                {
                    ExFreePool( g_lstArray.pSsdtListHead );
                }
                g_lstArray.pSsdtListHead = pHead;
            }
            break;

        default:
            {
                pHead = NULL;
                retVal = STATUS_UNSUCCESSFUL;
            }
            break;
        }

        // Initialize list head
        if( pHead )
        {
            RtlZeroMemory( pHead, sizeof( LIST_ENTRY ) );
            InitializeListHead( pHead );
            retVal = STATUS_SUCCESS;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in InitList()" );
        retVal = STATUS_UNSUCCESSFUL;
    }
    return retVal;
}

/*++
* @method: AddListEntry
*
* @description: Add an entry to the list of specified type
*
* @input: eListType eTypeOfList, PVOID pItemToAdd, BOOLEAN bFind
*
* @output: NTSTATUS
*
*--*/
NTSTATUS AddListEntry( eListType eTypeOfList, PVOID pItemToAdd, BOOLEAN bFind )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        // Check if the entry is already present
        if( bFind && ( STATUS_SUCCESS == FindEntry( eTypeOfList, pItemToAdd ) ) )
        {
            retVal = STATUS_DUPLICATE_OBJECTID;
            return retVal;
        }

        // Insert into a list based on type of list
        switch( eTypeOfList )
        {
        case eProcList:
            {
                if( MmIsAddressValid( g_lstArray.pProcListHead ) )
                {
                    PPROCLISTENTRY pNewEntry = NULL;
                    pNewEntry = ExAllocatePoolWithTag( NonPagedPool,
                                                       sizeof( PROCLISTENTRY ),
                                                       ARKITLISTTAG );
                    if( pNewEntry )
                    {
                        RtlZeroMemory( pNewEntry, sizeof( PROCLISTENTRY ) );
                        pNewEntry->dwPID = ((PPROCLISTENTRY)pItemToAdd)->dwPID;
                        RtlStringCchCopyA( pNewEntry->szProcName, ARKITLIB_STR_LEN, ((PPROCLISTENTRY)pItemToAdd)->szProcName );
                        InsertHeadList( g_lstArray.pProcListHead, &( pNewEntry->lEntry ) );
                        retVal = STATUS_SUCCESS;
                    }
                }
            }
            break;

        case eDllList:
            {
                if( MmIsAddressValid( g_lstArray.pDllListHead ) )
                {
                    PDLLLISTENTRY pNewEntry = ExAllocatePoolWithTag( NonPagedPool,
                                                                     sizeof( DLLLISTENTRY ),
                                                                     ARKITLISTTAG );
                    if( pNewEntry )
                    {
                        RtlZeroMemory( pNewEntry, sizeof( DLLLISTENTRY ) );
                        pNewEntry->dwBase = ((PDLLLISTENTRY)pItemToAdd)->dwBase;
                        RtlStringCchCopyA( pNewEntry->szDllName, ARKITLIB_STR_LEN, ((PDLLLISTENTRY)pItemToAdd)->szDllName );
                        InsertHeadList( g_lstArray.pDllListHead, &( pNewEntry->lEntry ) );
                        retVal = STATUS_SUCCESS;
                    }
                }
            }
            break;

        case eDrvList:
            {
                if( MmIsAddressValid( g_lstArray.pDrvListHead ) )
                {
                    PDRIVERLISTENTRY pNewEntry = NULL;
                    pNewEntry = ExAllocatePoolWithTag( NonPagedPool,
                                                       sizeof( DRIVERLISTENTRY ),
                                                       ARKITLISTTAG );
                    if( pNewEntry )
                    {
                        RtlZeroMemory( pNewEntry, sizeof( DRIVERLISTENTRY ) );
                        pNewEntry->dwBase = ((PDRIVERLISTENTRY)pItemToAdd)->dwBase;
                        pNewEntry->dwEnd = ((PDRIVERLISTENTRY)pItemToAdd)->dwEnd;
                        pNewEntry->dwEntryPoint = ((PDRIVERLISTENTRY)pItemToAdd)->dwEntryPoint;
                        RtlStringCchCopyA( pNewEntry->szDrvName, ARKITLIB_STR_LEN, ((PDRIVERLISTENTRY)pItemToAdd)->szDrvName );
                        InsertHeadList( g_lstArray.pDrvListHead, &( pNewEntry->lEntry ) );
                        retVal = STATUS_SUCCESS;
                    }
                }
            }
            break;

        case eSsdtList:
            {
                if( MmIsAddressValid( g_lstArray.pSsdtListHead ) )
                {
                    PSSDTHOOKLISTENTRY pNewEntry = NULL;
                    pNewEntry = ExAllocatePoolWithTag( NonPagedPool,
                                                       sizeof( SSDTHOOKLISTENTRY ),
                                                       ARKITLISTTAG );
                    if( pNewEntry )
                    {
                        RtlZeroMemory( pNewEntry, sizeof( SSDTHOOKLISTENTRY ) );
                        pNewEntry->unIndex = ((PSSDTHOOKLISTENTRY)pItemToAdd)->unIndex;
                        pNewEntry->dwHookAddr = ((PSSDTHOOKLISTENTRY)pItemToAdd)->dwHookAddr;
                        pNewEntry->dwBase = ((PSSDTHOOKLISTENTRY)pItemToAdd)->dwBase;
                        pNewEntry->dwEnd = ((PSSDTHOOKLISTENTRY)pItemToAdd)->dwEnd;
                        RtlStringCchCopyA( pNewEntry->szDrvName, ARKITLIB_STR_LEN, ((PSSDTHOOKLISTENTRY)pItemToAdd)->szDrvName );
                        InsertHeadList( g_lstArray.pSsdtListHead, &( pNewEntry->lEntry ) );
                        retVal = STATUS_SUCCESS;
                    }
                }
            }
            break;

        default:
            {
                retVal = STATUS_UNSUCCESSFUL;
            }
            break;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in AddListEntry()" );
        retVal = STATUS_UNSUCCESSFUL;
    }
    return retVal;
}

/*++
* @method: GetListEntry
*
* @description: Gets an entry corresponding to specified position from a specified list
*
* @input: eListType eTypeOfList, UINT nPosition, VOID** ppvGotItem
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetListEntry( eListType eTypeOfList, UINT nPosition, VOID** ppvGotItem )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        PLIST_ENTRY pHead = NULL;

        *ppvGotItem = NULL;

        // Set the head based on type of list
        switch( eTypeOfList )
        {
        case eProcList:
            {
                pHead = g_lstArray.pProcListHead;
            }
            break;

        case eDllList:
            {
                pHead = g_lstArray.pDllListHead;
            }
            break;

        case eDrvList:
            {
                pHead = g_lstArray.pDrvListHead;
            }
            break;

        case eSsdtList:
            {
                pHead = g_lstArray.pSsdtListHead;
            }
            break;

        default:
            {
                pHead = NULL;
                retVal = STATUS_UNSUCCESSFUL;
            }
            break;
        }

        if( pHead )
        {
            // Loop through the list to get the required element
            UINT nIndex = 0;
            PLIST_ENTRY pEntry = pHead->Flink;
            do
            {
                if( MmIsAddressValid( pEntry ) )
                {
                    if( nIndex == nPosition )
                    {
                        switch( eTypeOfList )
                        {
                        case eProcList:
                            {
                                *ppvGotItem = CONTAINING_RECORD( pEntry, PROCLISTENTRY, lEntry );
                            }
                            break;

                        case eDllList:
                            {
                                *ppvGotItem = CONTAINING_RECORD( pEntry, DLLLISTENTRY, lEntry );
                            }
                            break;

                        case eDrvList:
                            {
                                *ppvGotItem = CONTAINING_RECORD( pEntry, DRIVERLISTENTRY, lEntry );
                            }
                            break;

                        case eSsdtList:
                            {
                                *ppvGotItem = CONTAINING_RECORD( pEntry, SSDTHOOKLISTENTRY, lEntry );
                            }
                            break;
                        }
                        break;
                    }
                    ++nIndex;
                    pEntry = pEntry->Flink;
                }
                else
                {
                    break;
                }
            }
            while( pEntry != pHead );
        }

        if( *ppvGotItem )
        {
            retVal = STATUS_SUCCESS;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        *ppvGotItem = NULL;
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetListEntry()" );
    }
    return retVal;
}

/*++
* @method: GetListCount
*
* @description: Gets the number of elements in a specified type of list
*
* @input: eListType eTypeOfList
*
* @output: UINT
*
*--*/
UINT GetListCount( eListType eTypeOfList )
{
    UINT nCnt = 0;
    __try
    {
        // Get the count by looping through the list
        PVOID pItem = NULL;
        while( STATUS_SUCCESS == GetListEntry( eTypeOfList, nCnt, &pItem ) )
        {
            ++nCnt;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in GetListCount()" );
        nCnt = 0;
    }
    return nCnt;
}

/*++
* @method: IsMyListEmpty
*
* @description: Checks if a specified list is empty or not
*
* @input: eListType eTypeOfList
*
* @output: BOOLEAN
*
*--*/
BOOLEAN IsMyListEmpty( eListType eTypeOfList )
{
    BOOLEAN bIsEmpty = TRUE;
    __try
    {
        // Set the head based on list type
        PLIST_ENTRY pHead = NULL;
        switch( eTypeOfList )
        {
        case eProcList:
            {
                pHead = g_lstArray.pProcListHead;
            }
            break;

        case eDllList:
            {
                pHead = g_lstArray.pDllListHead;
            }
            break;

        case eDrvList:
            {
                pHead = g_lstArray.pDrvListHead;
            }
            break;

        case eSsdtList:
            {
                pHead = g_lstArray.pSsdtListHead;
            }
            break;

        default:
            {
                pHead = NULL;
            }
            break;
        }

        // Check if the list is empty
        if( pHead )
        {
            bIsEmpty = IsListEmpty( pHead );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bIsEmpty = TRUE;
        DbgPrint( "Exception caught in IsMyListEmpty()" );
    }
    return bIsEmpty;
}

/*++
* @method: DelAllLists
*
* @description: Deletes all lists
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS DelAllLists()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        retVal = DelList( eProcList );
        retVal = DelList( eDllList );
        retVal = DelList( eDrvList );
        retVal = DelList( eSsdtList );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in DelAllLists()" );
    }
    return retVal;
}

/*++
* @method: DelList
*
* @description: Deletes a specified list
*
* @input: eListType eTypeOfList 
*
* @output: NTSTATUS
*
*--*/
NTSTATUS DelList( eListType eTypeOfList )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        PLIST_ENTRY pHead = NULL;
        PLIST_ENTRY pEntry = NULL;
        PVOID pCurrent = NULL;

        // Set the head based on list type
        switch( eTypeOfList )
        {
        case eProcList:
            {
                pHead = g_lstArray.pProcListHead;
            }
            break;

        case eDllList:
            {
                pHead = g_lstArray.pDllListHead;
            }
            break;

        case eDrvList:
            {
                pHead = g_lstArray.pDrvListHead;
            }
            break;

        case eSsdtList:
            {
                pHead = g_lstArray.pSsdtListHead;
            }
            break;

        default:
            {
                pHead = NULL;
            }
            break;
        }

        // Remove element from list
        while( MmIsAddressValid( pHead ) && !IsListEmpty( pHead ) )
        {
            pEntry = RemoveHeadList( pHead );
            if( pEntry )
            {
                pCurrent = NULL;
                switch( eTypeOfList )
                {
                case eProcList:
                    {
                        pCurrent = CONTAINING_RECORD( pEntry, PROCLISTENTRY, lEntry );
                    }
                    break;

                case eDllList:
                    {
                        pCurrent = CONTAINING_RECORD( pEntry, DLLLISTENTRY, lEntry );
                    }
                    break;

                case eDrvList:
                    {
                        pCurrent = CONTAINING_RECORD( pEntry, DRIVERLISTENTRY, lEntry );
                    }
                    break;

                case eSsdtList:
                    {
                        pCurrent = CONTAINING_RECORD( pEntry, SSDTHOOKLISTENTRY, lEntry );
                    }
                    break;
                }
                if( MmIsAddressValid( pCurrent ) )
                {
                    ExFreePool( pCurrent );
                }
            }
            if( pEntry == pHead )
            {
                retVal = STATUS_SUCCESS;
                break;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in DelList()" );
    }
    return retVal;
}

/*++
* @method: FindEntry
*
* @description: Finds a specified item in specified list
*
* @input: eListType eTypeOfList, PVOID pItemToFind
*
* @output: NTSTATUS
*
*--*/
NTSTATUS FindEntry( eListType eTypeOfList, PVOID pItemToFind )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        UINT i = 0;
        PVOID pCurrent = NULL;

        if( pItemToFind )
        {
            // Loop through the list to find required entry
            while( STATUS_SUCCESS == GetListEntry( eTypeOfList, i, &pCurrent ) )
            {
                ++i;
                if( pCurrent )
                {
                    switch( eTypeOfList )
                    {
                    case eProcList:
                        {
                            if( ((PPROCLISTENTRY)pCurrent)->dwPID == ((PPROCLISTENTRY)pItemToFind)->dwPID )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;

                    case eDllList:
                        {
                            if( ((PDLLLISTENTRY)pCurrent)->dwBase == ((PDLLLISTENTRY)pItemToFind)->dwBase )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;

                    case eDrvList:
                        {
                            if( ((PDRIVERLISTENTRY)pCurrent)->dwBase == ((PDRIVERLISTENTRY)pItemToFind)->dwBase )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;

                    case eSsdtList:
                        {
                            if( ((PSSDTHOOKLISTENTRY)pCurrent)->dwHookAddr == ((PSSDTHOOKLISTENTRY)pItemToFind)->dwHookAddr )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;

                    default:
                        {
                            retVal = STATUS_UNSUCCESSFUL;
                        }
                        break;
                    }
                }
                else
                {
                    break;
                }

                // Found entry
                if( STATUS_SUCCESS == retVal )
                {
                    break;
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in FindEntry()" );
        retVal = STATUS_UNSUCCESSFUL;
    }
    return retVal;
}