/*++
* @file: ARKitDrv.h
*
* @description: This file contains declarations of ARKit driver functions.
*
*--*/

#ifndef __ARKITDRV_H__
#define __ARKITDRV_H__

#include "NtDefines.h"
#include "ARKitDefines.h"
#include "Lists.h"
#include "Utils.h"
#include "xde.h"

// Process routines
UINT ScanAndGetProcessCount();
VOID ScanAndGetProcessCountThread( PVOID pThrParam );
NTSTATUS GetProcByPidScan();
NTSTATUS GetProcByTidScan();
BOOLEAN KillProcess( DWORD dwPid );
VOID KillProcessThread( PVOID pThrParam );

// DLL routines
UINT ScanAndGetDllCount( DWORD dwPid );
VOID ScanAndGetDllCountThread( PVOID pThrParam );

// Driver routines
UINT ScanAndGetDriverCount();
VOID ScanAndGetDriverCountThread( PVOID pThrParam );
NTSTATUS GetDriversByModuleEntryScan();
NTSTATUS GetDriverByDeviceObjectScan();
NTSTATUS GetDriverByDriverObjectScan();

// SSDT routines
UINT ScanAndGetSSDTHooksCount();
VOID ScanAndGetSSDTHooksCountThread( PVOID pThrParam );

// Sysenter hook routines
BOOLEAN ScanAndGetSysenterHook( PARKSYSENTERHOOK pSysenterHookData );
VOID ScanAndGetSysenterHookThread( PVOID pThrParam );

// Kernel inline hook routines
BOOLEAN ScanFunctionInlineHook( PARKINLINEHOOK pFuncInlineHookData );
VOID ScanFunctionInlineHookThread( PVOID pThrParam );

// Driver routines
NTSTATUS DrvDispatch( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp );
NTSTATUS DrvCreateClose( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp );
void DrvUnload( IN PDRIVER_OBJECT pDriver );
NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriver,IN PUNICODE_STRING pPath );

#endif // __ARKITDRV_H__