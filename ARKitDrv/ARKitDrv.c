/*++
* @file: ARKitDrv.c
*
* @description: This file contains ARKit driver routines.
*
*--*/

#include "ARKitDrv.h"

// Globals
extern PWCHAR g_wszMyDeviceName;
extern PWCHAR g_wszMyDeviceLink;
extern PDRIVER_OBJECT g_pMyDriverObj;
extern OS_SPEC_DATA g_globalData;
extern NTOSKRNLDATA g_NtOSKernel;
extern SSDT_MDL g_mdlSSDT;

/*++
* @method: DrvDispatch
*
* @description: IOCTL dispatch routine
*
* @input: IN PDEVICE_OBJECT pDevice, IN PIRP pIrp
*
* @output: NTSTATUS
*
*--*/
NTSTATUS DrvDispatch( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp )
{
    NTSTATUS retVal = STATUS_UNSUCCESSFUL;
    
    __try
    {
        UINT nIndex = 0;
        DWORD dwInBuffSize = 0;
        DWORD dwOutBuffSize = 0;
        PIO_STACK_LOCATION pIoStackIrp = NULL;

        if( MmIsAddressValid( pIrp ) )
        {
            pIoStackIrp = IoGetCurrentIrpStackLocation( pIrp );
        }

        if( MmIsAddressValid( pIoStackIrp ) )
        {
            dwInBuffSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
            dwOutBuffSize = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
        }

        switch( pIoStackIrp->Parameters.DeviceIoControl.IoControlCode )
        {
        case IOCTL_OS_VER_INFO:
            {
                // Set OS and SP versions got from usermode, in our globals
                PMYOSVERINFO pOSVerInfo = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pOSVerInfo ) )
                {
                    if( STATUS_SUCCESS == InitGlobals( pOSVerInfo ) )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwInBuffSize;
                    }
                }
            }
            break;

        case IOCTL_GET_DATA_CNT:
            {
                // Get the count of items requested by usermode
                PARKDATACOUNT pArkDataCout = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pArkDataCout ) )
                {
                    switch( pArkDataCout->typeOfArkData )
                    {
                    case eArkDataProcList:
                        {
                            // Get the count of running processes
                            pArkDataCout->dataCount = ScanAndGetProcessCount();
                        }
                        break;

                    case eArkDataDllList:
                        {
                            // Get the count of DLLs
                            pArkDataCout->dataCount = ScanAndGetDllCount( pArkDataCout->miscData );
                        }
                        break;

                    case eArkDataDriverList:
                        {
                            // Get the count of loaded drivers
                            pArkDataCout->dataCount = ScanAndGetDriverCount();
                        }
                        break;

                    case eArkDataSsdtList:
                        {
                            // Get the count of SSDT hooks
                            pArkDataCout->dataCount = ScanAndGetSSDTHooksCount();
                        }
                        break;

                    default:
                        {
                            pArkDataCout->dataCount = 0;
                        }
                        break;
                    }

                    // Set the IO status based on count of items
                    if( pArkDataCout->dataCount > 0 )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = sizeof( ARKDATACOUNT );
                    }
                }
            }
            break;

        case IOCTL_GET_PROCESS:
            {
                // Copy all processes info from our internal list to usermode array
                PARKPROCESS pArkProcData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pArkProcData ) && VALIDATE_LIST_BUFF_SIZE( dwOutBuffSize, ARKPROCESS, eProcList ) )
                {
                    PPROCLISTENTRY pProcListEntry = NULL;
                    while( STATUS_SUCCESS == GetListEntry( eProcList, nIndex, &pProcListEntry ) )
                    {
                        if( MmIsAddressValid( pProcListEntry ) )
                        {
                            pArkProcData[nIndex].procId = pProcListEntry->dwPID;
                            RtlStringCchCopyA( pArkProcData[nIndex].procName, ARKITLIB_STR_LEN, pProcListEntry->szProcName );
                            ++nIndex;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( nIndex > 0 )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }
                // Free our internal process list
                DelList( eProcList );
            }
            break;

        case IOCTL_GET_DLLS:
            {
                // Copy all DLLs info from our internal list to usermode array
                PARKDLL pArkDllData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pArkDllData ) && VALIDATE_LIST_BUFF_SIZE( dwOutBuffSize, ARKDLL, eDllList ) )
                {
                    PDLLLISTENTRY pDllListEntry = NULL;
                    while( STATUS_SUCCESS == GetListEntry( eDllList, nIndex, &pDllListEntry ) )
                    {
                        if( MmIsAddressValid( pDllListEntry ) )
                        {
                            pArkDllData[nIndex].baseAddr = pDllListEntry->dwBase;
                            RtlStringCchCopyA( pArkDllData[nIndex].dllName, ARKITLIB_STR_LEN, pDllListEntry->szDllName );
                            ++nIndex;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( nIndex > 0 )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }
                // Free our internal DLL list
                DelList( eDllList );
            }
            break;

        case IOCTL_GET_DRIVERS:
            {
                // Copy all drivers info from our internal list to usermode array
                PARKDRIVER pArkDrvData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pArkDrvData ) && VALIDATE_LIST_BUFF_SIZE( dwOutBuffSize, ARKDRIVER, eDrvList ) )
                {
                    PDRIVERLISTENTRY pDrvListEntry = NULL;
                    while( STATUS_SUCCESS == GetListEntry( eDrvList, nIndex, &pDrvListEntry ) )
                    {
                        if( MmIsAddressValid( pDrvListEntry ) )
                        {
                            pArkDrvData[nIndex].baseAddr = pDrvListEntry->dwBase;
                            pArkDrvData[nIndex].endAddr = pDrvListEntry->dwEnd;
                            pArkDrvData[nIndex].entryPoint = pDrvListEntry->dwEntryPoint;
                            RtlStringCchCopyA( pArkDrvData[nIndex].driverName, ARKITLIB_STR_LEN, pDrvListEntry->szDrvName );
                            ++nIndex;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( nIndex > 0 )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }
                // Free our internal driver list
                DelList( eDrvList );
            }
            break;

        case IOCTL_GET_SSDTHOOKS:
            {
                // Copy all SSDT hooks info from our internal list to usermode array
                PARKSSDTHOOK pArkSsdtData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pArkSsdtData ) && VALIDATE_LIST_BUFF_SIZE( dwOutBuffSize, ARKSSDTHOOK, eSsdtList ) )
                {
                    PSSDTHOOKLISTENTRY pSsdtListEntry = NULL;
                    while( STATUS_SUCCESS == GetListEntry( eSsdtList, nIndex, &pSsdtListEntry ) )
                    {
                        if( MmIsAddressValid( pSsdtListEntry ) )
                        {
                            pArkSsdtData[nIndex].unSsdtIndex = pSsdtListEntry->unIndex;
                            pArkSsdtData[nIndex].baseAddr = pSsdtListEntry->dwBase;
                            pArkSsdtData[nIndex].endAddr = pSsdtListEntry->dwEnd;
                            pArkSsdtData[nIndex].hookAddr = pSsdtListEntry->dwHookAddr;
                            RtlStringCchCopyA( pArkSsdtData[nIndex].driverName, ARKITLIB_STR_LEN, pSsdtListEntry->szDrvName );
                            ++nIndex;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( nIndex > 0 )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }
                // Free our internal driver and SSDT list
                DelList( eDrvList );
                DelList( eSsdtList );
            }
            break;

        case IOCTL_GET_SYSENTERHOOK:
            {
                // Copy sysenter hook data to usermode buffer
                PARKSYSENTERHOOK pSysenterHookData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pSysenterHookData ) )
                {
                    if( ScanAndGetSysenterHook( pSysenterHookData ) )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }

                // Free driver list
                DelList( eDrvList );
            }
            break;

        case IOCTL_GET_KINLINEHOOK:
            {
                PARKINLINEHOOK pKernelFuncData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pKernelFuncData ) )
                {
                    if( ScanFunctionInlineHook( pKernelFuncData ) )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwOutBuffSize;
                    }
                }
            }
            break;

        case IOCTL_NT_API_INFO:
            {
                PARKNTAPI pNtApiData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pNtApiData ) )
                {
                    if( STATUS_SUCCESS == InitNtApiData( pNtApiData ) )
                    {
                        retVal = STATUS_SUCCESS;
                        pIrp->IoStatus.Information = dwInBuffSize;
                    }
                }
            }
            break;

        case IOCTL_FIX_ISSUES:
            {
                PARKFIX pFixData = pIrp->AssociatedIrp.SystemBuffer;
                if( MmIsAddressValid( pFixData ) )
                {
                    switch( pFixData->eType )
                    {
                    case eArkKillProcess:
                        {
                            PDWORD pdwPid = (PDWORD)(pFixData->fixData);
                            if( KillProcess( pdwPid ) )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;

                    case eArkFixSsdtHook:
                        {
                            PARKFIXSSDT pFixSsdtHookData = (PARKFIXSSDT)(pFixData->fixData);
                            if( FixSSDTHook( pFixSsdtHookData ) )
                            {
                                retVal = STATUS_SUCCESS;
                            }
                        }
                        break;
                    }

                    if( STATUS_SUCCESS == retVal )
                    {
                        pIrp->IoStatus.Information = dwInBuffSize;
                    }
                }
            }
            break;

        default:
            {
                retVal = STATUS_UNSUCCESSFUL;
                pIrp->IoStatus.Information = 0;
            }
            break;
        }
        pIrp->IoStatus.Status = retVal;
        IoCompleteRequest( pIrp, IO_NO_INCREMENT );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in DrvDispatch()" );
    }
    return retVal;
}

/*++
* @method: DrvCreateClose
*
* @description: Create/close routine for the driver
*
* @input: IN PDEVICE_OBJECT pDevice, IN PIRP pIrp
*
* @output: NTSTATUS
*
*--*/
NTSTATUS DrvCreateClose( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp )
{
    NTSTATUS retVal = STATUS_SUCCESS;
    __try
    {
        // Do nothing
        pIrp->IoStatus.Information = 0;
        pIrp->IoStatus.Status = 0;
        IoCompleteRequest( pIrp, IO_NO_INCREMENT );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in DrvCreateClose()" );
    }
    return retVal;
}

/*++
* @method: DrvUnload
*
* @description: Unload routine for the driver
*
* @input: IN PDRIVER_OBJECT pDriver
*
* @output: None
*
*--*/
void DrvUnload( IN PDRIVER_OBJECT pDriver )
{    
    __try
    {
        PDEVICE_EXTENSION pDevExt;
        UNICODE_STRING devLink;

        // Free SSDT MDL
        DeInitSsdtMdl();

        // Delete all our internal lists
        DelAllLists();

        pDevExt = (PDEVICE_EXTENSION)(pDriver->DeviceObject->DeviceExtension);

        // Free up any buffer still held by this device
        if( NULL != pDevExt->deviceBuffer )
        {
            ExFreePool( pDevExt->deviceBuffer );
            pDevExt->deviceBuffer = NULL;
            pDevExt->deviceBufferSize = 0;
        }

        // Delete sym link
        RtlInitUnicodeString( &devLink, g_wszMyDeviceLink );
        IoDeleteSymbolicLink( &devLink );

        // Delete device
        IoDeleteDevice( pDriver->DeviceObject );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in DrvUnload()" );
    }
}

/*++
* @method: DriverEntry
*
* @description: Entry point for the driver
*
* @input: IN PDRIVER_OBJECT pDriver,IN PUNICODE_STRING pPath
*
* @output: NTSTATUS
*
*--*/
NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriver,IN PUNICODE_STRING pPath )
{
    NTSTATUS retVal = STATUS_SUCCESS;
    __try
    {
        PDEVICE_OBJECT pDevObject = NULL;
        PDEVICE_EXTENSION pDevExt = NULL;
        UNICODE_STRING devName;
        UNICODE_STRING devLink;

        RtlInitUnicodeString( &devName, g_wszMyDeviceName );
        RtlInitUnicodeString( &devLink, g_wszMyDeviceLink );
        retVal = IoCreateDevice( pDriver,
                                 sizeof( DEVICE_EXTENSION ), 
                                 &devName,
                                 FILE_DEVICE_UNKNOWN,
                                 0,
                                 TRUE,
                                 &pDevObject );
 
        // Announce that we will be working with a copy of the user's buffer
        pDevObject->Flags |= DO_BUFFERED_IO;
        
        // Initialize the Device Extension
        pDevExt = (PDEVICE_EXTENSION)( pDevObject->DeviceExtension );
        pDevExt->pDevice = pDevObject;
        pDevExt->ustrDeviceName = devName;
        pDevExt->deviceBuffer = NULL;
        pDevExt->deviceBufferSize = 0;
 
        // Create sym link
        IoCreateSymbolicLink( &devLink,&devName );

        // Set up driver routines
        pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatch;
        pDriver->MajorFunction[IRP_MJ_CREATE] = DrvCreateClose;
        pDriver->MajorFunction[IRP_MJ_CLOSE] = DrvCreateClose;
        pDriver->DriverUnload = DrvUnload;
 
        // Save driver object pointer in our global variable
        g_pMyDriverObj = pDriver;
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        retVal = STATUS_UNSUCCESSFUL;
        DbgPrint( "Exception caught in DriverEntry()" );
    }
    return retVal;
}
