/*++
* @file: ARKitLib.cpp
*
* @description: This file implements ARKitLib class.
*
*--*/

#include "ARKitLib.h"
#include "ARKitLibUtils.h"
#include "ARKitLibDrvCmn.h"

/*++
* @method: ARKitLib::ARKitLib
*
* @description: constructor
*
* @input: none
*
* @output: none
*
*--*/
ARKitLib::ARKitLib():
m_drvFileName( ARKITLIB_DRIVER_FILENAME )
{
    // Load our ARKitDrv.sys driver
    loadDriver();
}

/*++
* @method: ARKitLib::~ARKitLib
*
* @description: destructor
*
* @input: none
*
* @output: none
*
*--*/
ARKitLib::~ARKitLib()
{
    // Unload our driver
    unloadDriver();
}

/*++
* @method: ARKitLib::loadDriver
*
* @description: Loads ARKitDrv.sys driver and starts the service
*
* @input: none
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::loadDriver()
{
    bool retVal = false;

    // Unload driver if it is loaded already
    unloadDriver();

    // Open SCM    
    SC_HANDLE hScMgr = ::OpenSCManager( 0, 0, SC_MANAGER_ALL_ACCESS );
    if( ARKITLIB_ISVALIDHANDLE( hScMgr ) )
    {
        // Build driver filepath, driver must be in the same
        // directory where this DLL exists
        char drvPath[ARKITLIB_STR_LEN];
        ::ZeroMemory( drvPath, ARKITLIB_STR_LEN );
        ::GetModuleFileName( 0, drvPath, ARKITLIB_STR_LEN );
        UINT pathLen = ::lstrlen( drvPath );
        while( 1 )
        {
            if( '\\' == drvPath[pathLen] )
            {
                break;
            }
            --pathLen;
        }
        ++pathLen;
        ::StringCchCopy( &drvPath[pathLen], ( ARKITLIB_STR_LEN - pathLen ), m_drvFileName.c_str() );

        // Create driver service
        SC_HANDLE hScDrv = ::CreateService( hScMgr,
                                            m_drvFileName.c_str(),
                                            m_drvFileName.c_str(),
                                            SERVICE_ALL_ACCESS,
                                            SERVICE_KERNEL_DRIVER,
                                            SERVICE_DEMAND_START,
                                            SERVICE_ERROR_NORMAL,
                                            drvPath,
                                            0,
                                            0,
                                            0,
                                            0,
                                            0 );
        if( !ARKITLIB_ISVALIDHANDLE( hScDrv ) )
        {
            // If service already exists, then just open it
            DWORD dwErr = ::GetLastError();
            if( ( ERROR_SERVICE_EXISTS == dwErr ) || ( ERROR_SERVICE_MARKED_FOR_DELETE == dwErr ) )
            {
                hScDrv = ::OpenService( hScMgr, m_drvFileName.c_str(), SERVICE_ALL_ACCESS );
            }
        }
        if( ARKITLIB_ISVALIDHANDLE( hScDrv ) )
        {
            // Start driver service
            if( FALSE != ::StartService( hScDrv, 0, 0 ) )
            {
                // Open device and get handle
                m_drvHandle = ::CreateFile( ARKITDRV_DEVICE_NAME,
                                            GENERIC_READ | GENERIC_WRITE,
                                            0, 0, OPEN_EXISTING,
                                            FILE_ATTRIBUTE_SYSTEM, 0 );
                if( ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
                {
                    // Now init driver with OS version info
                    retVal = sendOSVerInfo();
                }
            }
            ::CloseServiceHandle( hScDrv );
        }
        ::CloseServiceHandle( hScMgr );
    }

    return retVal;
}

/*++
* @method: ARKitLib::unloadDriver
*
* @description: Unload ARKitDrv.sys driver and stops the service
*
* @input: none
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::unloadDriver()
{
    bool retVal = false;
    
    if( ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        ::CloseHandle( m_drvHandle );
        m_drvHandle = NULL;
    }

    // Open SCM
    SC_HANDLE scMgr = ::OpenSCManager( 0, 0, SC_MANAGER_ALL_ACCESS );
    if( ARKITLIB_ISVALIDHANDLE( scMgr ) )
    {
        // Get a handle to our driver service
        SC_HANDLE scDrv = ::OpenService( scMgr, m_drvFileName.c_str(), SERVICE_ALL_ACCESS );
        if( ARKITLIB_ISVALIDHANDLE( scDrv ) )
        {
            DWORD retryCount = 0;
            DWORD waitHint = 0;
            SERVICE_STATUS srvcStatus = { 0 };

            // Stop the service
            ::ControlService( scDrv, SERVICE_CONTROL_STOP, &srvcStatus );
            while( retryCount < 500 )
            {
                ++retryCount;
                if( !::QueryServiceStatus( scDrv, &srvcStatus ) )
                {
                    break;
                }
                if( SERVICE_STOPPED == srvcStatus.dwCurrentState )
                {
                    break;
                }
                waitHint = srvcStatus.dwWaitHint / 10;
                if( waitHint < 1000 )
                {
                    waitHint = 1000;
                }
                else if( waitHint > 10000 )
                {
                    waitHint = 10000;
                }
                ::Sleep( waitHint );
            }

            // Delete service from SCM
            if( FALSE != ::DeleteService( scDrv ) )
            {
                retVal = true;
            }
            ::CloseServiceHandle( scDrv );
        }
        else
        {
            // Service doesn't exist
            retVal = true;
        }
        ::CloseServiceHandle( scMgr );
    }

    return retVal;
}

/*++
* @method: ARKitLib::sendOSVerInfo
*
* @description: Send OS and SP versions to driver
*
* @input: none
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::sendOSVerInfo()
{
    bool retVal = false;

    BOOL devIoRslt = FALSE;
    OSVERSIONINFOEX osViEx = {0};

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    osViEx.dwOSVersionInfoSize  = sizeof( OSVERSIONINFOEX );
    if( ::GetVersionEx( (LPOSVERSIONINFO)&osViEx ) )
    {
        MYOSVERINFO myOSVer;
        ::ZeroMemory( &myOSVer, sizeof( MYOSVERINFO ) );

        // Check OS version
        if( ( 5 == osViEx.dwMajorVersion ) && ( 0 == osViEx.dwMinorVersion ) )
        {
            myOSVer.osVer = eOS_WIN_2K;
        }
        else if( ( 5 == osViEx.dwMajorVersion ) && ( 1 == osViEx.dwMinorVersion ) )
        {
            myOSVer.osVer = eOS_WIN_XP;
        }
        else if( ( 5 == osViEx.dwMajorVersion ) && ( 2 == osViEx.dwMinorVersion ) )
        {
            // Check if this is Windows 2003 R2
            if( 0 == ::GetSystemMetrics( SM_SERVERR2 ) )
            {
                myOSVer.osVer = eOS_WIN_2K3;
            }
            else
            {
                myOSVer.osVer = eOS_WIN_2K3R2;
            }
        }
        else if( ( 6 == osViEx.dwMajorVersion ) && ( 0 == osViEx.dwMinorVersion ) )
        {
            myOSVer.osVer = eOS_WIN_VISTA;
        }
        
        // Check SP version
        if( 0 == osViEx.wServicePackMajor )
        {
            myOSVer.spVer = eOS_SP_0;
        }
        else if( 1 == osViEx.wServicePackMajor )
        {
            myOSVer.spVer = eOS_SP_1;
        }
        else if( 2 == osViEx.wServicePackMajor )
        {
            myOSVer.spVer = eOS_SP_2;
        }
        else if( 3 == osViEx.wServicePackMajor )
        {
            myOSVer.spVer = eOS_SP_3;
        }
        else if( 4 == osViEx.wServicePackMajor )
        {
            myOSVer.spVer = eOS_SP_4;
        }

        // Send this info to driver
        DWORD dwBytesRet = 0;
        devIoRslt = ::DeviceIoControl( m_drvHandle,
                                       IOCTL_OS_VER_INFO,
                                       &myOSVer,
                                       sizeof( MYOSVERINFO ),
                                       NULL,
                                       0,
                                       &dwBytesRet, NULL );

        if( devIoRslt )
        {
            // Now send few NT API address to driver
            retVal = sendNtFunctionAddresses();
        }
    }
    return retVal;
}

/*++
* @method: ARKitLib::sendNtFunctionAddresses
*
* @description: Send addresses of few unexported NT APIs to driver
*
* @input: none
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::sendNtFunctionAddresses()
{
    bool retVal = false;
    try
    {
        BOOL devIoRslt = FALSE;

        // Return false if we don't have our device handle
        if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
        {
            return false;
        }

        ARKNTAPI arkNtApiData;
        ARKitLibUtils objUtil;
        std::string tmpStr;
        UINT unIndex = 0;

        ::ZeroMemory( &arkNtApiData, sizeof( ARKNTAPI ) );

        // Get address of NtOpenProcess
        tmpStr.assign( "ZwOpenProcess" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtOpenProcess );

        // Get address of NtOpenThread
        tmpStr.assign( "ZwOpenThread" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtOpenThread );

        // Get address of NtTerminateProcess
        tmpStr.assign( "ZwTerminateProcess" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtTerminateProcess );

        // Get address of NtTerminateThread
        tmpStr.assign( "ZwTerminateThread" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtTerminateThread );

        // Get address of NtOpenDirectoryObject
        tmpStr.assign( "ZwOpenDirectoryObject" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtOpenDirectoryObject );

        // Get address of NtQueryDirectoryObject
        tmpStr.assign( "ZwQueryDirectoryObject" );
        objUtil.getNtFuncAddressByZwFuncName( tmpStr, tmpStr, arkNtApiData.dwNtQueryDirectoryObject );

        // Send this info to driver
        DWORD dwBytesRet = 0;
        devIoRslt = ::DeviceIoControl( m_drvHandle,
                                       IOCTL_NT_API_INFO,
                                       &arkNtApiData,
                                       sizeof( ARKNTAPI ),
                                       NULL,
                                       0,
                                       &dwBytesRet, NULL );

        retVal = devIoRslt ? true : false;
    }
    catch(...)
    {
        retVal = false;
    }
    return retVal;
}

/*++
* @method: ARKitLib::getProcessList
*
* @description: Returns process list obtained from ARKitDrv
*
* @input: std::list<ARKPROCESS>& procList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getProcessList( std::list<ARKPROCESS>& procList )
{
    bool retVal = false;

    // Clear the output list
    procList.clear();

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    // Get the count of processes found by driver
    DWORD bytesRet = 0;
    ARKDATACOUNT procCount;
    procCount.dataCount = 0;
    procCount.typeOfArkData = eArkDataProcList;
    BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                        IOCTL_GET_DATA_CNT,
                                        &procCount,
                                        sizeof( ARKDATACOUNT ),
                                        &procCount,
                                        sizeof( ARKDATACOUNT ),
                                        &bytesRet, NULL );
    if( devIoRslt && ( procCount.dataCount > 0 ) )
    {
        // Get all processes now
        PARKPROCESS pProcArray = new ARKPROCESS[ procCount.dataCount ];
        if( pProcArray )
        {
            // Now get all processes data
            ::ZeroMemory( pProcArray, ( sizeof( ARKPROCESS ) * procCount.dataCount ) );
            devIoRslt = ::DeviceIoControl( m_drvHandle,
                                           IOCTL_GET_PROCESS,
                                           NULL,
                                           0,
                                           pProcArray,
                                           ( sizeof( ARKPROCESS ) * procCount.dataCount ),
                                           &bytesRet, NULL );
            if( devIoRslt )
            {
                // Copy to caller supplied list
                ARKitLibUtils objUtil;
                std::string tempStr("");
                for( UINT i = 0; i < procCount.dataCount; i++ )
                {
                    // Trim the process name
                    tempStr.assign( pProcArray[i].procName );
                    objUtil.removeDeviceName( tempStr );
                    ::StringCchCopy( pProcArray[i].procName, ARKITLIB_STR_LEN, tempStr.c_str() );

                    // Push to caller supplied list
                    procList.push_back( pProcArray[i] );
                }
            }
            delete [] pProcArray;
            pProcArray = NULL;
        }
    }

    // Return true if we have managed to find any process
    retVal = !procList.empty();
    
    return retVal;
}

/*++
* @method: ARKitLib::killProcess
*
* @description: Kills a process
*
* @input: DWORD dwPid
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::killProcess( DWORD dwPid )
{
    bool retVal = false;

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    if( dwPid && ( dwPid != ::GetCurrentProcessId() ) )
    {
        DWORD bytesRet = 0;
        ARKFIX fixData;

        ::ZeroMemory( &fixData, sizeof( ARKFIX ) );
        fixData.eType = eArkKillProcess;
        ::CopyMemory( fixData.fixData, &dwPid, sizeof( DWORD ) );

        BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                            IOCTL_FIX_ISSUES,
                                            &fixData,
                                            sizeof( ARKFIX ),
                                            NULL,
                                            0,
                                            &bytesRet, NULL );
        retVal = devIoRslt ? true : false;
    }

    return retVal;
}

/*++
* @method: ARKitLib::getDllList
*
* @description: Returns DLL list obtained from ARKitDrv for a specific process
*
* @input: DWORD dwPid, std::list<ARKDLL>& dllList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getDllList( DWORD dwPid, std::list<ARKDLL>& dllList )
{
    bool retVal = false;

    dllList.clear();

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    // If this is a valid pid
    if( dwPid > 0 )
    {
        // Get the count of DLLs for this pid found by driver
        DWORD bytesRet = 0;
        ARKDATACOUNT dllCount;
        dllCount.dataCount = 0;
        dllCount.miscData = dwPid;
        dllCount.typeOfArkData = eArkDataDllList;
        BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                            IOCTL_GET_DATA_CNT,
                                            &dllCount,
                                            sizeof( ARKDATACOUNT ),
                                            &dllCount,
                                            sizeof( ARKDATACOUNT ),
                                            &bytesRet, NULL );
        if( devIoRslt && ( dllCount.dataCount > 0 ) )
        {
            // Get all DLLs now
            PARKDLL pDllArray = new ARKDLL[ dllCount.dataCount ];
            if( pDllArray )
            {
                // Now get all DLLs data
                ::ZeroMemory( pDllArray, ( sizeof( ARKDLL ) * dllCount.dataCount ) );
                devIoRslt = ::DeviceIoControl( m_drvHandle,
                                               IOCTL_GET_DLLS,
                                               NULL,
                                               0,
                                               pDllArray,
                                               ( sizeof( ARKDLL ) * dllCount.dataCount ),
                                               &bytesRet, NULL );
                if( devIoRslt )
                {
                    // Copy to caller supplied list
                    ARKitLibUtils objUtil;
                    std::string tempStr("");
                    for( UINT i = 0; i < dllCount.dataCount; i++ )
                    {
                        // Trim the DLL name
                        tempStr.assign( pDllArray[i].dllName );
                        objUtil.removeDeviceName( tempStr );
                        ::StringCchCopy( pDllArray[i].dllName, ARKITLIB_STR_LEN, tempStr.c_str() );

                        // Push to callier supplied list
                        dllList.push_back( pDllArray[i] );
                    }
                }
                delete [] pDllArray;
                pDllArray = NULL;
            }
        }
    }

    // Return true if we have managed to find any DLL
    retVal = !dllList.empty();

    return retVal;
}

/*++
* @method: ARKitLib::getDriverList
*
* @description: Returns driver list obtained from ARKitDrv
*
* @input: std::list<ARKDRIVER>& driverList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getDriverList( std::list<ARKDRIVER>& driverList )
{
    bool retVal = false;

    driverList.clear();

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    // Get the count of drivers found by driver
    DWORD bytesRet = 0;
    ARKDATACOUNT driverCount;
    driverCount.dataCount = 0;
    driverCount.typeOfArkData = eArkDataDriverList;
    BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                        IOCTL_GET_DATA_CNT,
                                        &driverCount,
                                        sizeof( ARKDATACOUNT ),
                                        &driverCount,
                                        sizeof( ARKDATACOUNT ),
                                        &bytesRet, NULL );
    if( devIoRslt && ( driverCount.dataCount > 0 ) )
    {
        // Get all drivers now
        PARKDRIVER pDriverArray = new ARKDRIVER[ driverCount.dataCount ];
        if( pDriverArray )
        {
            // Now get all driver data
            ::ZeroMemory( pDriverArray, ( sizeof( ARKDRIVER ) * driverCount.dataCount ) );
            devIoRslt = ::DeviceIoControl( m_drvHandle,
                                           IOCTL_GET_DRIVERS,
                                           NULL,
                                           0,
                                           pDriverArray,
                                           ( sizeof( ARKDRIVER ) * driverCount.dataCount ),
                                           &bytesRet, NULL );
            if( devIoRslt )
            {
                // Copy to caller supplied list
                ARKitLibUtils objUtil;
                std::string tempStr("");
                for( UINT i = 0; i < driverCount.dataCount; i++ )
                {
                    // Trim driver name
                    tempStr.assign( pDriverArray[i].driverName );
                    objUtil.removeDeviceName( tempStr );
                    ::StringCchCopy( pDriverArray[i].driverName, ARKITLIB_STR_LEN, tempStr.c_str() );

                    // Push to caller supplied list
                    driverList.push_back( pDriverArray[i] );
                }
            }
            delete [] pDriverArray;
            pDriverArray = NULL;
        }
    }

    // Return true if we have managed to find any driver
    retVal = !driverList.empty();

    return retVal;
}

/*++
* @method: ARKitLib::getSSDTHooksList
*
* @description: Returns SSDT hooks list obtained from ARKitDrv
*
* @input: std::list<ARKSSDTHOOK>& ssdtHookList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getSSDTHooksList( std::list<ARKSSDTHOOK>& ssdtHookList )
{
    bool retVal = false;

    ssdtHookList.clear();

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    // Get the count of drivers found by driver
    DWORD bytesRet = 0;
    ARKDATACOUNT ssdtHookCount;
    ssdtHookCount.dataCount = 0;
    ssdtHookCount.typeOfArkData = eArkDataSsdtList;
    BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                        IOCTL_GET_DATA_CNT,
                                        &ssdtHookCount,
                                        sizeof( ARKDATACOUNT ),
                                        &ssdtHookCount,
                                        sizeof( ARKDATACOUNT ),
                                        &bytesRet, NULL );
    if( devIoRslt && ( ssdtHookCount.dataCount > 0 ) )
    {
        // Get all drivers now
        PARKSSDTHOOK pSsdtHookArray = new ARKSSDTHOOK[ ssdtHookCount.dataCount ];
        if( pSsdtHookArray )
        {
            // Now get all SSDT hook data
            ::ZeroMemory( pSsdtHookArray, ( sizeof( ARKSSDTHOOK ) * ssdtHookCount.dataCount ) );
            devIoRslt = ::DeviceIoControl( m_drvHandle,
                                           IOCTL_GET_SSDTHOOKS,
                                           NULL,
                                           0,
                                           pSsdtHookArray,
                                           ( sizeof( ARKSSDTHOOK ) * ssdtHookCount.dataCount ),
                                           &bytesRet, NULL );
            if( devIoRslt )
            {
                // Copy to caller supplied list
                ARKitLibUtils objUtil;
                std::string tempStr("");
                for( UINT i = 0; i < ssdtHookCount.dataCount; i++ )
                {
                    // Trim the driver name
                    tempStr.assign( pSsdtHookArray[i].driverName );
                    objUtil.removeDeviceName( tempStr );
                    ::StringCchCopy( pSsdtHookArray[i].driverName, ARKITLIB_STR_LEN, tempStr.c_str() );

                    // Get ZwXxx name corresponding to hooked SSDT index
                    tempStr.assign( "" );
                    objUtil.getZwFuncNameBySsdtIndex( pSsdtHookArray[i].unSsdtIndex, tempStr );
                    ::StringCchCopy( pSsdtHookArray[i].ssdtFuncName, ARKITLIB_STR_LEN, tempStr.c_str() );

                    // Push to caller supplied list
                    ssdtHookList.push_back( pSsdtHookArray[i] );
                }
            }
            delete [] pSsdtHookArray;
            pSsdtHookArray = NULL;
        }
    }

    // Return true if we have managed to find any SSDT hook
    retVal = !ssdtHookList.empty();

    return retVal;
}

/*++
* @method: ARKitLib::getSysenterHook
*
* @description: Returns Sysenter hook
*
* @input: ARKSYSENTERHOOK& sysenterHookData
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getSysenterHook( ARKSYSENTERHOOK& sysenterHookData )
{
    bool retVal = false;

    ::ZeroMemory( &sysenterHookData, sizeof( ARKSYSENTERHOOK ) );
    
    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    // Get sysenter hook
    DWORD bytesRet = 0;
    BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                        IOCTL_GET_SYSENTERHOOK,
                                        &sysenterHookData,
                                        sizeof( ARKSYSENTERHOOK ),
                                        &sysenterHookData,
                                        sizeof( ARKSYSENTERHOOK ),
                                        &bytesRet, NULL );
    if( devIoRslt && sysenterHookData.jumpToAddr )
    {
        retVal = true;
    }

    return retVal;
}

/*++
* @method: ARKitLib::getKernelInlineHooks
*
* @description: Returns NT kernel function inline hooks
*
* @input: std::list<ARKINLINEHOOK>& hookList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLib::getKernelInlineHooks( std::list<ARKINLINEHOOK>& hookList )
{
    bool retVal = false;

    hookList.clear();

    // Return false if we don't have our device handle
    if( !ARKITLIB_ISVALIDHANDLE( m_drvHandle ) )
    {
        return retVal;
    }

    ARKitLibUtils objUtil;
    std::list<std::string> ntKernelExports;
    std::string ntKernelName;

    ntKernelExports.clear();
    objUtil.getNtKernelName( ntKernelName );

    // Get all functions exported by NT kernel
    if( objUtil.exportWalker( ntKernelName, ntKernelExports ) )
    {
        DWORD bytesRet = 0;
        
        // First tell driver to build drivers list, which
        // we will be using during kernel inline hook scan
        ARKDATACOUNT driverCount;
        driverCount.dataCount = 0;
        driverCount.typeOfArkData = eArkDataDriverList;
        BOOL devIoRslt = ::DeviceIoControl( m_drvHandle,
                                            IOCTL_GET_DATA_CNT,
                                            &driverCount,
                                            sizeof( ARKDATACOUNT ),
                                            &driverCount,
                                            sizeof( ARKDATACOUNT ),
                                            &bytesRet, NULL );

        if( devIoRslt )
        {
            // Now, loop through NT kernel exports and scan them
            std::string tempStr( "" );
            ARKINLINEHOOK funcInlineHookData;
            std::list<std::string>::iterator itFunc = ntKernelExports.begin();
            for( ; itFunc != ntKernelExports.end(); itFunc++ )
            {
                ::ZeroMemory( &funcInlineHookData, sizeof( ARKINLINEHOOK ) );

                // Copy kernel exported function name that is to be scanned
                ::StringCchCopy( funcInlineHookData.funcName, ARKITLIB_STR_LEN, itFunc->c_str() );
                devIoRslt = ::DeviceIoControl( m_drvHandle,
                                               IOCTL_GET_KINLINEHOOK,
                                               &funcInlineHookData,
                                               sizeof( ARKINLINEHOOK ),
                                               &funcInlineHookData,
                                               sizeof( ARKINLINEHOOK ),
                                               &bytesRet, NULL );
                if( devIoRslt && funcInlineHookData.jumpToAddr )
                {
                    // Trim driver name
                    tempStr.assign( funcInlineHookData.driverName );
                    objUtil.removeDeviceName( tempStr );
                    ::StringCchCopy( funcInlineHookData.driverName, ARKITLIB_STR_LEN, tempStr.c_str() );

                    // Push the kernel inline hook info to caller supplied list
                    hookList.push_back( funcInlineHookData );
                }
            }

            // Most of the NtXxx are not exported by kernel. Only
            // ZwXxx are exported. So, we would need to locate NtXxx
            // functions in NT kerenl image and scan them for inline hooks
            UINT unIndex = 0;
            DWORD dwNtAddress = 0;
            std::string szZwFuncName( "" );
            while( 1 )
            {
                dwNtAddress = 0;
                szZwFuncName.assign( "" );
                if( objUtil.getNtFuncAddressBySsdtIndex( unIndex, szZwFuncName, dwNtAddress ) )
                {
                    ::ZeroMemory( &funcInlineHookData, sizeof( ARKINLINEHOOK ) );

                    // Copy NtXxx function address that is to be scanned
                    funcInlineHookData.funcAddr = dwNtAddress;
                    ::StringCchCopy( funcInlineHookData.funcName, ARKITLIB_STR_LEN, szZwFuncName.c_str() );
                    devIoRslt = ::DeviceIoControl( m_drvHandle,
                                                   IOCTL_GET_KINLINEHOOK,
                                                   &funcInlineHookData,
                                                   sizeof( ARKINLINEHOOK ),
                                                   &funcInlineHookData,
                                                   sizeof( ARKINLINEHOOK ),
                                                   &bytesRet, NULL );
                    if( devIoRslt && funcInlineHookData.jumpToAddr )
                    {
                        // Trim driver name
                        tempStr.assign( funcInlineHookData.driverName );
                        objUtil.removeDeviceName( tempStr );
                        ::StringCchCopy( funcInlineHookData.driverName, ARKITLIB_STR_LEN, tempStr.c_str() );

                        // Push the kernel inline hook info to caller supplied list
                        hookList.push_back( funcInlineHookData );
                    }
                }
                else
                {
                    break;
                }
                unIndex++;
            }

            // Now, simply do a get drivers, so that ARKit driver deletes
            // its internal driver list that we built earlier
            PARKDRIVER pDriverArray = new ARKDRIVER[ driverCount.dataCount ];
            if( pDriverArray )
            {
                ::ZeroMemory( pDriverArray, ( sizeof( ARKDRIVER ) * driverCount.dataCount ) );
                devIoRslt = ::DeviceIoControl( m_drvHandle,
                                               IOCTL_GET_DRIVERS,
                                               NULL,
                                               0,
                                               pDriverArray,
                                               ( sizeof( ARKDRIVER ) * driverCount.dataCount ),
                                               &bytesRet, NULL );
                delete [] pDriverArray;
                pDriverArray = NULL;
            }
        }
    }

    retVal = !hookList.empty();
    
    return retVal;
}
