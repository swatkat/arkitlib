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
NTSTATUS GetProcByHandleTableScan();
NTSTATUS GetProcByPidScan();
NTSTATUS GetProcByTidScan();
BOOLEAN KillProcess( PDWORD pdwPid );
VOID KillProcessThread( PVOID pThrParam );

// DLL routines
UINT ScanAndGetDllCount( DWORD dwPid );
VOID ScanAndGetDllCountThread( PVOID pThrParam );
NTSTATUS GetDllByPeb( DWORD dwPid );
NTSTATUS GetDllByVadTree( DWORD dwPid );
VOID TraverseVadTreeInOrderWin2KXP( PMMVAD pVadNode );
VOID TraverseVadTreeInOrderWin2K3Vista( PMMADDRESS_NODE pVadNode );

// Driver routines
UINT ScanAndGetDriverCount();
VOID ScanAndGetDriverCountThread( PVOID pThrParam );
NTSTATUS GetDriversByModuleEntryScan();
NTSTATUS GetDriverByDeviceObjectScan( PWCHAR pwszDeviceObjBaseDirectory );
NTSTATUS GetDriverByDriverObjectScan();

// SSDT routines
UINT ScanAndGetSSDTHooksCount();
VOID ScanAndGetSSDTHooksCountThread( PVOID pThrParam );
BOOLEAN FixSSDTHook( PARKFIXSSDT pFixSsdtHookData );
VOID FixSSDTHookThread( PVOID pThrParam );

// Sysenter hook routines
BOOLEAN ScanAndGetSysenterHook( PARKSYSENTERHOOK pSysenterHookData );
VOID ScanAndGetSysenterHookThread( PVOID pThrParam );

// Kernel inline hook routines
BOOLEAN ScanFunctionInlineHook( PARKINLINEHOOK pFuncInlineHookData );
VOID ScanFunctionInlineHookThread( PVOID pThrParam );
BOOLEAN FixInlineHook( PARKFIXINLINEHOOK pFixInlineHook );
VOID FixInlineHookThread( PVOID pThrParam );

// Driver routines
NTSTATUS DrvDispatch( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp );
NTSTATUS DrvCreateClose( IN PDEVICE_OBJECT pDevice, IN PIRP pIrp );
void DrvUnload( IN PDRIVER_OBJECT pDriver );
NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriver,IN PUNICODE_STRING pPath );

#endif // __ARKITDRV_H__