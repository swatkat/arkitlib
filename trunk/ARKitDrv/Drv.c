/*++
* @file: Drv.c
*
* @description: This file contains functions to detect loaded drivers in the system
*
*--*/

#include "ARKitDrv.h"

// Globals
extern PDRIVER_OBJECT g_pMyDriverObj;
extern OS_SPEC_DATA g_globalData;
extern NTOSKRNLDATA g_NtOSKernel;
extern ARKNTAPI g_NtApiData;

/*++
* @method: ScanAndGetDriverCount
*
* @description: Wrapper to thread function to get loaded drivers
*
* @input: None
*
* @output: UINT, number of loaded drivers found
*
*--*/
UINT ScanAndGetDriverCount()
{
    UINT numDrivers = 0;
    __try
    {
        // Create a thread to scan for loaded drivers
        THRPARAMS stThrParams = {0};
        if( STATUS_SUCCESS == ThreadSpooler( ScanAndGetDriverCountThread, &stThrParams ) )
        {
            numDrivers = GetListCount( eDrvList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        numDrivers = 0;
        DbgPrint( "Exception caught in ScanAndGetDriverCount()" );
    }
    return numDrivers;
}

/*++
* @method: ScanAndGetDriverCountThread
*
* @description: Invokes various routines to find loaded drivers
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID ScanAndGetDriverCountThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) )
        {
            // Initalize our internal driver linked list where we store results
            if( STATUS_SUCCESS == InitList( eDrvList ) )
            {
                if( eOS_ERR != g_globalData.eOSVer )
                {
                    // Get drivers by traversing PsLoadedModuleList
                    GetDriversByModuleEntryScan();

                    // Get drivers by traversing \Device\ directory in Object Manager
                    GetDriverByDeviceObjectScan( L"\\Device" );

                    // Get drivers by traversing \Driver\ directory in Object Manager
                    GetDriverByDriverObjectScan();

                    // Set result to true if we have found any drivers
                    ((PTHRPARAMS)pThrParam)->bResult = !IsMyListEmpty( eDrvList );
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanAndGetDriverCountThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: GetDriversByModuleEntryScan
*
* @description: Gets loaded drivers by traversing PsLoadedModuleList
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetDriversByModuleEntryScan()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        DRIVERLISTENTRY drvEntry;
        ANSI_STRING ansiDrvName;

        if( eOS_WIN_2K == g_globalData.eOSVer )
        {
            PMODULE_ENTRY pModEntryCurrent = *( (PMODULE_ENTRY*)( (DWORD)g_pMyDriverObj + g_globalData.dwModEntryOffset ) );
            PMODULE_ENTRY pModEntryFirst = pModEntryCurrent;
            do
            {
                if( MmIsAddressValid( pModEntryCurrent ) )
                {
                    if( IsDrvNameKernelW( pModEntryCurrent->drvPath.Buffer ) )
                    {
                        // Found NT kernel, save it
                        g_NtOSKernel.dwBase = pModEntryCurrent->imageBase;
                        g_NtOSKernel.dwEnd = pModEntryCurrent->imageBase + pModEntryCurrent->imageSize;
                        g_NtOSKernel.dwEntryPoint = pModEntryCurrent->entryPoint;
                    }

                    // Copy driver info to list entry
                    RtlZeroMemory( &drvEntry, sizeof( DRIVERLISTENTRY ) );
                    drvEntry.dwBase = pModEntryCurrent->imageBase;
                    drvEntry.dwEnd = pModEntryCurrent->imageBase + pModEntryCurrent->imageSize;
                    drvEntry.dwEntryPoint = pModEntryCurrent->entryPoint;
                    RtlUnicodeStringToAnsiString( &ansiDrvName, &( pModEntryCurrent->drvPath ), 1 );
                    RtlStringCchCopyA( drvEntry.szDrvName, ARKITLIB_STR_LEN, ansiDrvName.Buffer );
                    RtlFreeAnsiString( &ansiDrvName );
                    
                    // Add it to our list
                    retVal = AddListEntry( eDrvList, &drvEntry, TRUE );
                }
                else
                {
                    break;
                }
                pModEntryCurrent = (PMODULE_ENTRY)( pModEntryCurrent->link.Flink );
            }
            while( pModEntryCurrent != pModEntryFirst );
        }
        else
        {
            PLDR_MODULE pDrvModule = NULL;
            PLIST_ENTRY pModEntryCurrent = (PLIST_ENTRY)GetPsLoadedModuleList();
            PLIST_ENTRY pModEntryFirst = pModEntryCurrent;
            do
            {
                if( MmIsAddressValid( pModEntryCurrent ) )
                {
                    pDrvModule = (PLDR_MODULE)pModEntryCurrent;
                    if( !IsDummyModuleEntry( pDrvModule ) )
                    {
                        if( IsDrvNameKernelW( pDrvModule->FullDllName.Buffer ) )
                        {
                            // Found NT kernel, save it
                            g_NtOSKernel.dwBase = (DWORD)pDrvModule->BaseAddress;
                            g_NtOSKernel.dwEnd = (DWORD)pDrvModule->BaseAddress + pDrvModule->SizeOfImage;
                            g_NtOSKernel.dwEntryPoint = (DWORD)pDrvModule->EntryPoint;
                        }

                        // Copy driver info to list entry
                        RtlZeroMemory( &drvEntry, sizeof( DRIVERLISTENTRY ) );
                        drvEntry.dwBase = (DWORD)(pDrvModule->BaseAddress);
                        drvEntry.dwEnd = (DWORD)(pDrvModule->BaseAddress) + pDrvModule->SizeOfImage;
                        drvEntry.dwEntryPoint = (DWORD)(pDrvModule->EntryPoint);
                        RtlUnicodeStringToAnsiString( &ansiDrvName, &( pDrvModule->FullDllName ), 1 );
                        RtlStringCchCopyA( drvEntry.szDrvName, ARKITLIB_STR_LEN, ansiDrvName.Buffer );
                        RtlFreeAnsiString( &ansiDrvName );

                        // Add it to our list
                        retVal = AddListEntry( eDrvList, &drvEntry, TRUE );
                    }
                }
                else
                {
                    break;
                }
                pModEntryCurrent = pModEntryCurrent->Blink;
            }
            while( pModEntryCurrent != pModEntryFirst );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetDriversByModuleEntryScan()" );
    }
    
    return retVal;
}

/*++
* @method: GetDriverByDeviceObjectScan
*
* @description: Gets loaded drivers by browsing \Device\ directory in Object Manager
*
* @input: PWCHAR pwszDeviceObjBaseDirectory
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetDriverByDeviceObjectScan( PWCHAR pwszDeviceObjBaseDirectory )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        HANDLE hObjMgr = NULL;
        UNICODE_STRING usDeviceObj;
        OBJECT_ATTRIBUTES objAttr;
        PNTOPENDIRECTORYOBJECT pNtOpenDirectoryObject = NULL;
        PNTQUERYDIRECTORYOBJECT pNtQueryDirectoryObject = NULL;

        if( MmIsAddressValid( pwszDeviceObjBaseDirectory ) )
        {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetDriverByDeviceObjectScan: Device object base: %S", pwszDeviceObjBaseDirectory );
#endif
        }
        else
        {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetDriverByDeviceObjectScan: Invalid argument passed" );
#endif // ARKITDRV_DEBUG_PRINT
            return retVal;
        }

        // Open Object Manager
        RtlInitUnicodeString( &usDeviceObj, pwszDeviceObjBaseDirectory );
        InitializeObjectAttributes( &objAttr,
                                    &usDeviceObj,
                                    OBJ_CASE_INSENSITIVE,
                                    NULL, NULL );

        // Try to get addresses of NT APIs
        pNtOpenDirectoryObject = (PNTOPENDIRECTORYOBJECT)( (PBYTE)pNtOpenDirectoryObject + g_NtApiData.dwNtOpenDirectoryObject );
        pNtQueryDirectoryObject = (PNTQUERYDIRECTORYOBJECT)( (PBYTE)pNtQueryDirectoryObject + g_NtApiData.dwNtQueryDirectoryObject );

        if( MmIsAddressValid( pNtOpenDirectoryObject ) )
        {
            // Use NtOpenDirectoryObject if we have its address
            retVal = pNtOpenDirectoryObject( &hObjMgr,
                                             DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                             &objAttr );
        }
        else
        {
            // Otherwise, use ZwOpenDirectoryObject
            retVal = ZwOpenDirectoryObject( &hObjMgr,
                                            DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                            &objAttr );
        }

        if( STATUS_SUCCESS == retVal )
        {
            DRIVERLISTENTRY drvEntry;
            ULONG curPos = 0;
            ULONG actualLen = 0;
            char szBuffer[ARKITLIB_STR_LEN];
            WCHAR wszObjName[ARKITLIB_STR_LEN];
            PFILE_OBJECT pFileObj = NULL;
            PDEVICE_OBJECT pDevObj = NULL;
            PDRIVER_OBJECT pDrvObj = NULL;
            PMODULE_ENTRY pModEntry = NULL;
            PDIRECTORY_BASIC_INFORMATION pDirBasicInfo = NULL;
            ANSI_STRING ansiDrvName;

            while( 1 )
            {
                // Get one object
                RtlZeroMemory( szBuffer, ARKITLIB_STR_LEN );

                if( MmIsAddressValid( pNtQueryDirectoryObject ) )
                {
                    // Use NtQueryDirectoryObject if we have its address
                    retVal = pNtQueryDirectoryObject( hObjMgr,
                                                      szBuffer,
                                                      ARKITLIB_STR_LEN,
                                                      TRUE,
                                                      FALSE,
                                                      &curPos,
                                                      &actualLen );
                }
                else
                {
                    // Otherwise, use ZwQueryDirectoryObject
                    retVal = ZwQueryDirectoryObject( hObjMgr,
                                                     szBuffer,
                                                     ARKITLIB_STR_LEN,
                                                     TRUE,
                                                     FALSE,
                                                     &curPos,
                                                     &actualLen );
                }
                if( STATUS_SUCCESS == retVal )
                {
                    // Extract the device object name
                    pDirBasicInfo = (PDIRECTORY_BASIC_INFORMATION)szBuffer;
                    if( MmIsAddressValid( pDirBasicInfo ) && MmIsAddressValid( pDirBasicInfo->ObjectName.Buffer ) )
                    {
#ifdef ARKITDRV_DEBUG_PRINT
                        DbgPrint( "GetDriverByDeviceObjectScan: Object: %S, Type: %S",
                                   pDirBasicInfo->ObjectName.Buffer, pDirBasicInfo->ObjectTypeName.Buffer );
#endif // ARKITDRV_DEBUG_PRINT

                        // Construct name
                        RtlZeroMemory( wszObjName, ( sizeof( WCHAR )*ARKITLIB_STR_LEN ) );
                        RtlStringCchCopyW( wszObjName, ARKITLIB_STR_LEN, pwszDeviceObjBaseDirectory );
                        RtlStringCchCatW( wszObjName, ARKITLIB_STR_LEN, L"\\" );
                        RtlStringCchCatW( wszObjName, ARKITLIB_STR_LEN, pDirBasicInfo->ObjectName.Buffer );
                        RtlInitUnicodeString( &usDeviceObj, wszObjName );

                        // If the object type is Directory, then traverse it
                        if( 0 == _wcsicmp( pDirBasicInfo->ObjectTypeName.Buffer, L"Directory" ) )
                        {
                            GetDriverByDeviceObjectScan( wszObjName );
                            continue;
                        }
                        else if( _wcsicmp( pDirBasicInfo->ObjectTypeName.Buffer, L"Device" ) )
                        {
#ifdef ARKITDRV_DEBUG_PRINT
                            DbgPrint( "GetDriverByDeviceObjectScan: Ignoring Object: %S, Type: %S",
                                      pDirBasicInfo->ObjectName.Buffer, pDirBasicInfo->ObjectTypeName.Buffer );
#endif // ARKITDRV_DEBUG_PRINT
                            continue;
                        }

                        // Get device object pointer from device name
                        InitializeObjectAttributes( &objAttr,
                                                    &usDeviceObj,
                                                    OBJ_CASE_INSENSITIVE,
                                                    NULL, NULL );
                        retVal = IoGetDeviceObjectPointer( &usDeviceObj, FILE_READ_DATA, &pFileObj, &pDevObj );
                        if( STATUS_SUCCESS == retVal )
                        {
                            if( IsValidDeviceDriverObject( pDevObj ) )
                            {
                                // Get driver object from device object
                                pDrvObj = pDevObj->DriverObject;

                                // Now, go to DriverSection and read driver details
                                pModEntry = (PMODULE_ENTRY)pDrvObj->DriverSection;
                                if( !IsDummyModuleEntry2( pModEntry ) )
                                {
                                    // Copy driver details to our list entry
                                    RtlZeroMemory( &drvEntry, sizeof( DRIVERLISTENTRY ) );
                                    drvEntry.dwBase = pModEntry->imageBase;
                                    drvEntry.dwEnd = pModEntry->imageBase + pModEntry->imageSize;
                                    drvEntry.dwEntryPoint = pModEntry->entryPoint;
                                    RtlUnicodeStringToAnsiString( &ansiDrvName, &( pModEntry->drvPath ), 1 );
                                    RtlStringCchCopyA( drvEntry.szDrvName, ARKITLIB_STR_LEN, ansiDrvName.Buffer );
                                    RtlFreeAnsiString( &ansiDrvName );
                                    
                                    // Add it to our list
                                    retVal = AddListEntry( eDrvList, &drvEntry, TRUE );
                                }
                            }

                            // Dereference only file object
                            if( MmIsAddressValid( pFileObj ) )
                            {
                                ObDereferenceObject( pFileObj );
                                pFileObj = NULL;
                            }
                        }
                        else
                        {
#ifdef ARKITDRV_DEBUG_PRINT
                            DbgPrint( "GetDriverByDeviceObjectScan: IoGetDeviceObjectPointer for %S, failed: 0x%x",
                                      usDeviceObj.Buffer, retVal );
#endif // ARKITDRV_DEBUG_PRINT
                        }
                    }
                }
                else
                {
#ifdef ARKITDRV_DEBUG_PRINT
                    DbgPrint( "GetDriverByDeviceObjectScan: ZwQueryDirectoryObject failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
                    break;
                }
            }
            ZwClose( hObjMgr );
        }
        else
        {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetDriverByDeviceObjectScan: ZwOpenDirectoryObject failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetDriverByDeviceObjectScan()" );
    }
    return retVal;
}

/*++
* @method: GetDriverByDriverObjectScan
*
* @description: Gets loaded drivers by browsing \Driver\ directory in Object Manager
*
* @input: None
*
* @output: NTSTATUS
*
*--*/
NTSTATUS GetDriverByDriverObjectScan()
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    __try
    {
        HANDLE hObjMgr = NULL;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING usDriverObj;
        PNTOPENDIRECTORYOBJECT pNtOpenDirectoryObject = NULL;
        PNTQUERYDIRECTORYOBJECT pNtQueryDirectoryObject = NULL;

        // Try to get addresses of NT APIs
        pNtOpenDirectoryObject = (PNTOPENDIRECTORYOBJECT)( (PBYTE)pNtOpenDirectoryObject + g_NtApiData.dwNtOpenDirectoryObject );
        pNtQueryDirectoryObject = (PNTQUERYDIRECTORYOBJECT)( (PBYTE)pNtQueryDirectoryObject + g_NtApiData.dwNtQueryDirectoryObject );

        // Open Object Manager
        RtlInitUnicodeString( &usDriverObj, L"\\Driver" );
        InitializeObjectAttributes( &objAttr,
                                    &usDriverObj,
                                    OBJ_CASE_INSENSITIVE,
                                    NULL, NULL );

        if( MmIsAddressValid( pNtOpenDirectoryObject ) )
        {
            // Use NtOpenDirectoryObject if we have its address
            retVal = pNtOpenDirectoryObject( &hObjMgr,
                                             DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                             &objAttr );
        }
        else
        {
            // Otherwise, use ZwOpenDirectoryObject
            retVal = ZwOpenDirectoryObject( &hObjMgr,
                                            DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                            &objAttr );
        }
        
        if( STATUS_SUCCESS == retVal )
        {
            DRIVERLISTENTRY drvEntry;
            HANDLE hObject = NULL;
            PVOID pObject = NULL;
            PDRIVER_OBJECT pDrvObj = NULL;
            PMODULE_ENTRY pModEntry = NULL;
            char szBuffer[ARKITLIB_STR_LEN];
            WCHAR wszObjName[ARKITLIB_STR_LEN];
            ANSI_STRING ansiDrvName;
            PDIRECTORY_BASIC_INFORMATION pDirBasicInfo = NULL;
            ULONG actualLen = 0;
            ULONG curPos = 0;

            while( 1 )
            {
                // Get one object
                RtlZeroMemory( szBuffer, ARKITLIB_STR_LEN );

                if( MmIsAddressValid( pNtQueryDirectoryObject ) )
                {
                    // Use pNtQueryDirectoryObject if we have its address
                    retVal = pNtQueryDirectoryObject( hObjMgr,
                                                      szBuffer,
                                                      ARKITLIB_STR_LEN,
                                                      TRUE,
                                                      FALSE,
                                                      &curPos,
                                                      &actualLen );
                }
                else
                {
                    // Otherwise, use ZwQueryDirectoryObject
                    retVal = ZwQueryDirectoryObject( hObjMgr,
                                                     szBuffer,
                                                     ARKITLIB_STR_LEN,
                                                     TRUE,
                                                     FALSE,
                                                     &curPos,
                                                     &actualLen );
                }

                if( STATUS_SUCCESS == retVal )
                {
                    // Extract the driver object name
                    pDirBasicInfo = (PDIRECTORY_BASIC_INFORMATION)szBuffer;
                    if( MmIsAddressValid( pDirBasicInfo ) && MmIsAddressValid( pDirBasicInfo->ObjectName.Buffer ) )
                    {
                        // Construct name
                        RtlZeroMemory( wszObjName, ( sizeof( WCHAR )*ARKITLIB_STR_LEN ) );
                        RtlStringCchCopyW( wszObjName, ARKITLIB_STR_LEN, L"\\Driver\\" );
                        RtlStringCchCatW( wszObjName, ARKITLIB_STR_LEN, pDirBasicInfo->ObjectName.Buffer );
                        RtlInitUnicodeString( &usDriverObj, wszObjName );
                        InitializeObjectAttributes( &objAttr,
                                                    &usDriverObj,
                                                    OBJ_CASE_INSENSITIVE,
                                                    NULL, NULL );
                        // Open object
                        retVal = ObOpenObjectByName( &objAttr,
                                                     NULL,
                                                     KernelMode,
                                                     NULL,
                                                     0x80000000,
                                                     NULL,
                                                     &hObject );
                        if( STATUS_SUCCESS == retVal )
                        {
                            // Get object from handle
                            retVal = ObReferenceObjectByHandle( hObject,
                                                                0x80000000,
                                                                NULL,
                                                                KernelMode,
                                                                &pObject,
                                                                NULL );
                            if( STATUS_SUCCESS == retVal )
                            {
                                if( MmIsAddressValid( pObject ) )
                                {
                                    // Get driver object from device object
                                    pDrvObj = (PDRIVER_OBJECT)pObject;

                                    // Get DriverSection from driver object
                                    pModEntry = (PMODULE_ENTRY)pDrvObj->DriverSection;
                                    if( !IsDummyModuleEntry2( pModEntry ) )
                                    {
                                        // Copy driver details to our list entry
                                        RtlZeroMemory( &drvEntry, sizeof( DRIVERLISTENTRY ) );
                                        drvEntry.dwBase = pModEntry->imageBase;
                                        drvEntry.dwEnd = pModEntry->imageBase + pModEntry->imageSize;
                                        drvEntry.dwEntryPoint = pModEntry->entryPoint;
                                        RtlUnicodeStringToAnsiString( &ansiDrvName, &( pModEntry->drvPath ), 1 );
                                        RtlStringCchCopyA( drvEntry.szDrvName, ARKITLIB_STR_LEN, ansiDrvName.Buffer );
                                        RtlFreeAnsiString( &ansiDrvName );

                                        // Add it to our list
                                        retVal = AddListEntry( eDrvList, &drvEntry, TRUE );
                                    }
                                }

                                // Dereference the device object
                                ObDereferenceObject( pObject );
                                pObject = NULL;
                            }
                            else
                            {
#ifdef ARKITDRV_DEBUG_PRINT
                                DbgPrint( "GetDriverByDriverObjectScan: ObReferenceObjectByHandle for %S, failed: 0x%x",
                                          usDriverObj.Buffer, retVal );
#endif // ARKITDRV_DEBUG_PRINT
                            }
                            ZwClose( hObject );
                        }
                        else
                        {
#ifdef ARKITDRV_DEBUG_PRINT
                            DbgPrint( "GetDriverByDriverObjectScan: ObOpenObjectByName for %S, failed: 0x%x",
                                      usDriverObj.Buffer, retVal );
#endif // ARKITDRV_DEBUG_PRINT
                        }
                    }
                }
                else
                {
#ifdef ARKITDRV_DEBUG_PRINT
                    DbgPrint( "GetDriverByDriverObjectScan: ZwQueryDirectoryObject failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
                    break;
                }
            }
            ZwClose( hObjMgr );
        }
        else
        {
#ifdef ARKITDRV_DEBUG_PRINT
            DbgPrint( "GetDriverByDriverObjectScan: ZwOpenDirectoryObject failed: 0x%x", retVal );
#endif // ARKITDRV_DEBUG_PRINT
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in GetDriverByDriverObjectScan()" );
    }

    return retVal;
}