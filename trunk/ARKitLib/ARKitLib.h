/*++
* @file: ARKitLib.h
*
* @description: This file contains prototype declaration of ARKitLib class. Applications using
*               ARKit library should include this file in their source.
*
*--*/

#ifndef __ARKITLIB_H__
#define __ARKITLIB_H__

// Standard header includes
#include <windows.h>
#include <Winsvc.h>
#include <winioctl.h>
#include <strsafe.h>
#include <string>
#include <list>

// ARKitLib specific includes
#include "ARKitDefines.h"

class ARKitLib
{
private:
    // Driver handle
    HANDLE m_drvHandle;

    // Driver file name
    std::string m_drvFileName;

    // Private utility method to load driver
    bool loadDriver();

    // Private utility method to unload driver
    bool unloadDriver();

    // Private utility method to send OS and SP info to driver
    bool sendOSVerInfo();

    // Private utility method to send info about unexported NT APIs to driver
    bool sendNtFunctionAddresses();

public:

    // Constructor
    ARKitLib();

    // Destructor
    virtual ~ARKitLib();

    // Method to get running processes
    bool getProcessList( std::list<ARKPROCESS>& procList );

    // Method to kill a process
    bool killProcess( DWORD dwPid );

    // Method to get DLLs loaded for a specified process
    bool getDllList( DWORD dwPid, std::list<ARKDLL>& dllList );

    // Method to get loaded drivers
    bool getDriverList( std::list<ARKDRIVER>& driverList );

    // Method to get SSDT hooks
    bool getSSDTHooksList( std::list<ARKSSDTHOOK>& ssdtHookList );

    // Methods to fix SSDT hook
    bool fixSsdtHook( UINT unSsdtIndex );
    bool fixSsdtHook( std::string& szHookedZwFuncName );

    // Method to get Sysenter hook data
    bool getSysenterHook( ARKSYSENTERHOOK& sysenterHookData );

    // Method to get kernel inline hooks
    bool getKernelInlineHooks( std::list<ARKINLINEHOOK>& hookList );
};

#endif