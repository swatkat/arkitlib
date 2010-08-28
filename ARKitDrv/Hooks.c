/*++
* @file: Hooks.c
*
* @description: This file contains functions to detect SSDT, Sysenter and kernel inline hooks
*
*--*/

#include "ARKitDrv.h"

// Globals
extern PDRIVER_OBJECT g_pMyDriverObj;
extern OS_SPEC_DATA g_globalData;
extern NTOSKRNLDATA g_NtOSKernel;
extern SSDT_MDL g_mdlSSDT;

/*++
* @method: ScanFunctionInlineHook
*
* @description: Wrapper to thread function to get function inline hook
*
* @input: PARKINLINEHOOK pFuncInlineHookData
*
* @output: BOOLEAN, true if hook is found, otherwise false.
*
*--*/
BOOLEAN ScanFunctionInlineHook( PARKINLINEHOOK pFuncInlineHookData )
{
    BOOLEAN foundHook = FALSE;
    __try
    {
        if( MmIsAddressValid( pFuncInlineHookData ) )
        {
            THRPARAMS stThrParams = {0};
            stThrParams.pParam = pFuncInlineHookData;
            stThrParams.dwParamLen = sizeof( ARKINLINEHOOK );

            // Create a thread to scan for kernel function inline hook
            if( STATUS_SUCCESS == ThreadSpooler( ScanFunctionInlineHookThread, &stThrParams ) )
            {
                foundHook = stThrParams.bResult;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        foundHook = FALSE;
        DbgPrint( "Exception caught in ScanFunctionInlineHook()" );
    }
    return foundHook;
}

/*++
* @method: ScanFunctionInlineHookThread
*
* @description: Finds function kernel inline hook
*
* @input: PVOID pThrParam
*
* @output: None
*
* @remarks: We use xde disassembling engine to find jump opcodes
*
* @preconditions: ScanAndGetDriverCount() should have been called earlier, and
*                 the driver list should be built before calling this function.
*                 This dependancy is handled from usermode ARKit library.
*
*--*/
VOID ScanFunctionInlineHookThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) )
        {
            PARKINLINEHOOK pFuncData = ((PTHRPARAMS)pThrParam)->pParam;
            if( MmIsAddressValid( pFuncData ) && !IsMyListEmpty( eDrvList ) )
            {
                UINT i = 0;
                PVOID pFuncPtr = NULL;
                int nInstrLen = 0;
                struct xde_instr instrDisAsm;
                ANSI_STRING asFuncName;
                UNICODE_STRING usFuncName;
                DRIVERLISTENTRY driverEntry;

                // Disable read-only protection
                DisableReadOnly();

                // If we have got kernel function address from usermode then use it.
                if( pFuncData->funcAddr )
                {
                    pFuncPtr = (PBYTE)pFuncPtr + pFuncData->funcAddr;
                }
                else if( MmIsAddressValid( pFuncData->funcName ) )
                {
                    // Otherwise, get the address by name
                    RtlInitAnsiString( &asFuncName, pFuncData->funcName );
                    RtlAnsiStringToUnicodeString( &usFuncName, &asFuncName, 1 );
                    pFuncPtr = MmGetSystemRoutineAddress( &usFuncName );
                    RtlFreeUnicodeString( &usFuncName );
                }

                // Disassemble first few bytes of the kernel function
                for( i = 0; ( i <= BYTES_TO_DISASM ) && MmIsAddressValid( pFuncPtr ); i++ )
                {
                    nInstrLen = xde_disasm( (PBYTE)pFuncPtr, &instrDisAsm );
                    pFuncData->jumpToAddr = GetJumpToAddr( (PBYTE)pFuncPtr, instrDisAsm.opcode );

                    // Check if the jump is outside kernel
                    if( IsJumpOutsideKernel( pFuncData->jumpToAddr ) )
                    {
                        // Get the driver name to which this jump points to
                        if( IsAddressInAnyDriver( pFuncData->jumpToAddr, &driverEntry ) )
                        {
                            if( IsDrvNameKernelA( driverEntry.szDrvName ) )
                            {
                                // False positive? Kernel hotpatching? Ignore this jump!
                                pFuncData->jumpToAddr = 0;
                            }
                            else
                            {
                                // We found the driver name to which jump points to
                                RtlStringCchCopyA( pFuncData->driverName, ARKITLIB_STR_LEN, driverEntry.szDrvName );
                            }
                        }
                        else
                        {
                            // We couldn't find the driver name to which jump points to
                            RtlStringCchCopyA( pFuncData->driverName, ARKITLIB_STR_LEN, ARKIT_STR_UNKNOWN );
                        }
                        break;
                    }
                    else
                    {
                        // Reset the jump-to address
                        pFuncData->jumpToAddr = 0;
                    }

                    // Go to next instruction
                    pFuncPtr = (PBYTE)pFuncPtr + nInstrLen;
                }

                // Enable read-only protection
                EnableReadOnly();

                // Set the result to true if we have found a jump outside kernel
                if( pFuncData->jumpToAddr )
                {
                    ((PTHRPARAMS)pThrParam)->bResult = TRUE;
                }
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanFunctionInlineHookThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: ScanAndGetSysenterHook
*
* @description: Wrapper to thread function to get Sysenter hook
*
* @input: PARKSYSENTERHOOK pSysenterHookData
*
* @output: BOOLEAN, true if hook is found, otherwise false.
*
*--*/
BOOLEAN ScanAndGetSysenterHook( PARKSYSENTERHOOK pSysenterHookData )
{
    BOOLEAN foundHook = FALSE;
    __try
    {
        if( MmIsAddressValid( pSysenterHookData ) )
        {
            THRPARAMS stThrParams = {0};
            RtlZeroMemory( pSysenterHookData, sizeof( ARKSYSENTERHOOK ) );
            stThrParams.pParam = pSysenterHookData;
            stThrParams.dwParamLen = sizeof( ARKSYSENTERHOOK );

            // Create a thread to scan for Sysenter hook
            if( STATUS_SUCCESS == ThreadSpooler( ScanAndGetSysenterHookThread, &stThrParams ) )
            {
                foundHook = stThrParams.bResult;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        foundHook = FALSE;
        DbgPrint( "Exception caught in ScanAndGetSysenterHook()" );
    }
    return foundHook;
}

/*++
* @method: ScanAndGetSysenterHookThread
*
* @description: Finds Sysenter hook
*
* @input: PVOID pThrParam
*
* @output: None
*
* @remarks: We use xde disassembling engine to find jump opcodes
*
*--*/
VOID ScanAndGetSysenterHookThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) && ScanAndGetDriverCount() )
        {
            BOOLEAN foundHook = FALSE;
            PARKSYSENTERHOOK pSysenterHookData = ((PTHRPARAMS)pThrParam)->pParam;
            if( MmIsAddressValid( pSysenterHookData ) )
            {
                int i = 0;
                int nInstrLen = 0;
                ULONG ulFastCallLoc = 0;
                PVOID pFastCallLocPtr = NULL;
                struct xde_instr instrDisAsm;
                DRIVERLISTENTRY driverEntry;

                // Read MSR register
                __asm
                {
                    mov ecx,0x176
                    rdmsr
                    mov ulFastCallLoc,eax
                }

                // Check if it is a direct register value replacement
                if( IsJumpOutsideKernel( (DWORD)ulFastCallLoc ) )
                {
                    foundHook = TRUE;
                }
                else
                {
                    // Check if the sysenter routine has inline jumpe outside kernel
                    DisableReadOnly();
                    pFastCallLocPtr = (PBYTE)pFastCallLocPtr + ulFastCallLoc;
                    ulFastCallLoc = 0;
                    for( i = 0; ( i <= BYTES_TO_DISASM ) && MmIsAddressValid( pFastCallLocPtr ); i++ )
                    {
                        // Disassemble instruction and check if it is a jump
                        nInstrLen = xde_disasm( (PBYTE)pFastCallLocPtr, &instrDisAsm );
                        ulFastCallLoc = GetJumpToAddr( (PBYTE)pFastCallLocPtr, instrDisAsm.opcode );
                        
                        // If we find hook, break
                        if( IsJumpOutsideKernel( (DWORD)ulFastCallLoc ) )
                        {
                            foundHook = TRUE;
                            break;
                        }

                        // Go to next instruction
                        ulFastCallLoc = 0;
                        pFastCallLocPtr = (PBYTE)pFastCallLocPtr + nInstrLen;
                    }
                    EnableReadOnly();
                }

                if( foundHook )
                {
                    if( IsAddressInAnyDriver( ulFastCallLoc, &driverEntry ) )
                    {
                        if( IsDrvNameKernelA( driverEntry.szDrvName ) )
                        {
                            // False positive? Kernel hotpatching?
                            foundHook = FALSE;
                        }
                        else
                        {
                            // We found driver name to which Sysenter jumps to.
                            pSysenterHookData->jumpToAddr = ulFastCallLoc;
                            RtlStringCchCopyA( pSysenterHookData->driverName, ARKITLIB_STR_LEN, driverEntry.szDrvName );
                        }
                    }
                    else
                    {
                        // We couldn't find driver name to which Sysenter jumps to.
                        pSysenterHookData->jumpToAddr = ulFastCallLoc;
                        RtlStringCchCopyA( pSysenterHookData->driverName, ARKITLIB_STR_LEN, ARKIT_STR_UNKNOWN );
                    }
                }
            }

            // Set the result to true if we found some hook
            ((PTHRPARAMS)pThrParam)->bResult = foundHook;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanAndGetSysenterHookThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: ScanAndGetSSDTHooksCount
*
* @description: Wrapper to thread function to get SSDT hooks
*
* @input: None
*
* @output: UINT, number of SSDT hooks found
*
*--*/
UINT ScanAndGetSSDTHooksCount()
{
    UINT numHooks = 0;
    __try
    {
        // Create a thread to scan for SSDT hooks
        THRPARAMS stThrParams = {0};
        if( STATUS_SUCCESS == ThreadSpooler( ScanAndGetSSDTHooksCountThread, &stThrParams ) )
        {
            numHooks = GetListCount( eSsdtList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        numHooks = 0;
        DbgPrint( "Exception caught in ScanAndGetSSDTHooksCount()" );
    }
    return numHooks;
}

/*++
* @method: ScanAndGetSSDTHooksCountThread
*
* @description: Finds SSDT hooks
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID ScanAndGetSSDTHooksCountThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) && ScanAndGetDriverCount() && ( STATUS_SUCCESS == InitList( eSsdtList ) ) )
        {
            if( g_NtOSKernel.dwBase && g_NtOSKernel.dwEnd )
            {
                UINT nIndex = 0;
                DRIVERLISTENTRY drvEntry;
                SSDTHOOKLISTENTRY ssdtEntry;

                // Loop through the SSDT table
                for( nIndex = 0; nIndex < KeServiceDescriptorTable.NumberOfServices; nIndex++ )
                {
                    // If any of SSDT entry points outside NT kernel range,
                    if( IsJumpOutsideKernel( (DWORD)KeServiceDescriptorTable.ServiceTableBase[nIndex] ) )
                    {
                        // then add it to our list
                        RtlZeroMemory( &drvEntry, sizeof( DRIVERLISTENTRY ) );
                        RtlZeroMemory( &ssdtEntry, sizeof( SSDTHOOKLISTENTRY ) );
                        if( IsAddressInAnyDriver( KeServiceDescriptorTable.ServiceTableBase[nIndex], &drvEntry ) )
                        {
                            if( !IsDrvNameKernelA( drvEntry.szDrvName ) )
                            {
                                ssdtEntry.unIndex = nIndex;
                                ssdtEntry.dwHookAddr = KeServiceDescriptorTable.ServiceTableBase[nIndex];
                                ssdtEntry.dwBase = drvEntry.dwBase;
                                ssdtEntry.dwEnd = drvEntry.dwEnd;
                                RtlStringCchCopyA( ssdtEntry.szDrvName, ARKITLIB_STR_LEN, drvEntry.szDrvName );

                                // Add SSDT hook info to our list
                                AddListEntry( eSsdtList, &ssdtEntry, TRUE );
                            }
                        }
                        else
                        {
                            // We couldn't find driver to which this hook jumps to! Avira like hooks!
                            ssdtEntry.unIndex = nIndex;
                            ssdtEntry.dwHookAddr = KeServiceDescriptorTable.ServiceTableBase[nIndex];
                            ssdtEntry.dwBase = 0;
                            ssdtEntry.dwEnd = 0;
                            RtlStringCchCopyA( ssdtEntry.szDrvName, ARKITLIB_STR_LEN, ARKIT_STR_UNKNOWN );

                            // Add SSDT hook info to our list
                            AddListEntry( eSsdtList, &ssdtEntry, TRUE );
                        }
                    }
                }
            }

            // Set the result to true if we found some SSDT hooks
            ((PTHRPARAMS)pThrParam)->bResult = !IsMyListEmpty( eSsdtList );
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in ScanAndGetSSDTHooksCountThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

/*++
* @method: FixSSDTHook
*
* @description: Wrapper to thread function to fix SSDT hook
*
* @input: PARKFIXSSDT pFixSsdtHookData
*
* @output: BOOLEAN
*
*--*/
BOOLEAN FixSSDTHook( PARKFIXSSDT pFixSsdtHookData )
{
    BOOLEAN bRetVal = FALSE;
    __try
    {
        if( MmIsAddressValid( pFixSsdtHookData ) )
        {
            // Create a thread to fix SSDT hook
            THRPARAMS stThrParams = {0};
            stThrParams.pParam = pFixSsdtHookData;
            stThrParams.dwParamLen = sizeof( PARKFIXSSDT );
            if( STATUS_SUCCESS == ThreadSpooler( FixSSDTHookThread, &stThrParams ) )
            {
                bRetVal = stThrParams.bResult;
            }
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        bRetVal = FALSE;
        DbgPrint( "Exception caught in FixSSDTHook()" );
    }
    return bRetVal;
}

/*++
* @method: FixSSDTHookThread
*
* @description: Fix SSDT hook
*
* @input: PVOID pThrParam
*
* @output: None
*
*--*/
VOID FixSSDTHookThread( PVOID pThrParam )
{
    __try
    {
        if( MmIsAddressValid( pThrParam ) )
        {
            NTSTATUS retVal = STATUS_UNSUCCESSFUL;
            PTHRPARAMS pParams = (PTHRPARAMS)pThrParam;
            PARKFIXSSDT pFixSsdtHookData = (PARKFIXSSDT)(pParams->pParam);

            DisableReadOnly();
            if( g_mdlSSDT.pmdlSSDT && g_mdlSSDT.ppvMappedSSDT )
            {
#ifdef ARKITDRV_DEBUG_PRINT
                DbgPrint( "FixSSDTHookThread: SSDT index %ld, Original address: 0x%x",
                          pFixSsdtHookData->dwSsdtIndex, pFixSsdtHookData->dwOrigAddr );
#endif // ARKITDRV_DEBUG_PRINT

                // Do an atomic exchange of SSDT address
                InterlockedExchange( (PLONG)&(g_mdlSSDT.ppvMappedSSDT)[pFixSsdtHookData->dwSsdtIndex],
                                     (LONG)(pFixSsdtHookData->dwOrigAddr) );
                pParams->bResult = TRUE;
            }
            EnableReadOnly();
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        DbgPrint( "Exception caught in FixSSDTHookThread()" );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}