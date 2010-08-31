/*++
* @file: ARKitLib.cpp
*
* @description: This file implements ARKitLibUtils class.
*
*--*/

#include "ARKitLibUtils.h"

/*++
* @method: ARKitLibUtils::ARKitLibUtils
*
* @description: constructor
*
* @input: none
*
* @output: none
*
*--*/
ARKitLibUtils::ARKitLibUtils()
{
}

/*++
* @method: ARKitLibUtils::~ARKitLibUtils
*
* @description: destructor
*
* @input: none
*
* @output: none
*
*--*/
ARKitLibUtils::~ARKitLibUtils()
{
}

/*++
* @method: ARKitLibUtils::removeDeviceName
*
* @description: Replaces \Device\C\ with C:\
*
* @input: char* szImagePath, UINT nStrTotalLen
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::removeDeviceName( std::string& imagePath )
{
    bool retVal = false;
    try
    {
        if( ( imagePath.length() <= 0 ) || ( imagePath.length() >= ARKITLIB_STR_LEN ) )
        {
            return retVal;
        }
        
        int newPathIndex = 0;
        int oldPathIndex = 0;
        char szTempPath[ARKITLIB_STR_LEN];
        ::ZeroMemory( szTempPath, ARKITLIB_STR_LEN );

        if( std::string::npos != imagePath.find( "\\Device\\" ) )
        {
            DWORD drvMaskIndex = 1;
            DWORD dwLogDrivesMask = 0;
            char szDrvLetter[3] = "A:";
            char szDeviceName[ARKITLIB_STR_LEN];

            // Get bitmask of drive letters that are present in system
            dwLogDrivesMask = ::GetLogicalDrives();

            // Loop through all possible drive letters
            for( drvMaskIndex = 1; drvMaskIndex < 0x80000000; drvMaskIndex = ( drvMaskIndex * 0x2 ) )
            {
                // If we find a drive letter that exists,
                if( dwLogDrivesMask & drvMaskIndex )
                {
                    // then query its DOS device name ("HarddiskVolume1" etc.)
                    ::ZeroMemory( szDeviceName, ARKITLIB_STR_LEN );
                    if( ::QueryDosDevice( szDrvLetter, szDeviceName, ARKITLIB_STR_LEN ) )
                    {
                        // Check if this DOS device name is present in our path
                        if( std::string::npos != imagePath.find( szDeviceName ) )
                        {
                            // Copy drive letter with colon to szTempPath
                            ::StringCchPrintf( szTempPath, ARKITLIB_STR_LEN, "%s", szDrvLetter );
                            oldPathIndex = ::lstrlen( szDeviceName );
                            newPathIndex = ::lstrlen( szTempPath );
                            for( ; oldPathIndex < imagePath.length(); newPathIndex++, oldPathIndex++ )
                            {
                                szTempPath[newPathIndex] = imagePath[oldPathIndex];
                            }
                            szTempPath[newPathIndex] = '\0';
                            imagePath.assign( szTempPath );
                            retVal = true;
                            break;
                        }
                    }
                }

                // Try with next drive letter
                ++( szDrvLetter[0] );
            }
        }
        else if( std::string::npos != imagePath.find( "\\SystemRoot\\" ) )
        {
            char szExpandedStr[ARKITLIB_STR_LEN];
            ::ZeroMemory( szExpandedStr, ARKITLIB_STR_LEN );
            if( ::GetEnvironmentVariable( "SystemRoot", szExpandedStr, ARKITLIB_STR_LEN ) > 0 )
            {
                ::StringCchPrintf( szTempPath, ARKITLIB_STR_LEN, "%s\\", szExpandedStr );
                oldPathIndex = ::lstrlen( "\\SystemRoot\\" );
                newPathIndex = ::lstrlen( szTempPath );
                for( ; oldPathIndex < imagePath.length(); newPathIndex++, oldPathIndex++ )
                {
                    szTempPath[newPathIndex] = imagePath[oldPathIndex];
                }
                szTempPath[newPathIndex] = '\0';
                imagePath.assign( szTempPath );
                retVal = true;
            }
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::removeDeviceName: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getZwFuncNameBySsdtIndex
*
* @description: Finds the name of function corresponding to SSDT index
*
* @input: UINT unIndex, std::string& ssdtFuncName
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getZwFuncNameBySsdtIndex( UINT unIndex, std::string& zwFuncName )
{
    bool retVal = false;
    try
    {
        std::list<ARKUTILEXPORTENTRY> exportList;
        std::string ntDllName( NTDLL_IMAGE_NAME );

        exportList.clear();
        zwFuncName.assign( "" );

        // Get all exports from Ntdll
        if( exportWalker( ntDllName, exportList, false ) )
        {
            std::string tmpStr;
            std::vector<std::string> ssdtNames;

            ssdtNames.clear();
            std::list<ARKUTILEXPORTENTRY>::iterator itExport = exportList.begin();
            for( ; itExport != exportList.end(); itExport++ )
            {
                // Copy funtion name to a temporary string
                tmpStr.assign( itExport->szFuncName );

                // Now, copy all exports beginning with "Zw" to vector
                if( 0 == tmpStr.find( "Zw" ) )
                {
                    // These functions will be at the end of SSDT, but not in Ntdll export table.
                    if( ( std::string::npos == tmpStr.find( "ZwCreateKeyedEvent" ) ) &&
                        ( std::string::npos == tmpStr.find( "ZwOpenKeyedEvent" ) ) &&
                        ( std::string::npos == tmpStr.find( "ZwReleaseKeyedEvent" ) ) &&
                        ( std::string::npos == tmpStr.find( "ZwWaitForKeyedEvent" ) ) &&
                        ( std::string::npos == tmpStr.find( "ZwQueryPortInformationProcess" ) ) )
                    {
                        ssdtNames.push_back( tmpStr );
                    }
                }
            }

            // Push back remaining ZwXxx functions
            if( !ssdtNames.empty() )
            {
                ssdtNames.push_back( "ZwCreateKeyedEvent" );
                ssdtNames.push_back( "ZwOpenKeyedEvent" );
                ssdtNames.push_back( "ZwReleaseKeyedEvent" );
                ssdtNames.push_back( "ZwWaitForKeyedEvent" );
                ssdtNames.push_back( "ZwQueryPortInformationProcess" );
            }

            // Get the required name of required SSDT index
            if( unIndex < ssdtNames.size() )
            {
                zwFuncName.assign( ssdtNames[unIndex] );
                retVal = true;
            }
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getZwFuncNameBySsdtIndex: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getSsdtIndexByZwFuncName
*
* @description: Finds the SSDT index corresponding to ZwXxx funciton
*
* @input: std::string ssdtFuncName, UINT& unIndex
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getSsdtIndexByZwFuncName( std::string zwFuncName, UINT& unIndex )
{
    bool retVal = false;
    try
    {
        UINT i = 0;
        std::string tempStr;
        while( 1 )
        {
            tempStr.assign( "" );
            if( getZwFuncNameBySsdtIndex( i, tempStr ) )
            {
                if( tempStr == zwFuncName )
                {
                    unIndex = i;
                    retVal = true;
                    break;
                }
            }
            else
            {
                break;
            }
            i++;
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getSsdtIndexByZwFuncName: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::exportWalker
*
* @description: Walks the export table of given image
*
* @input: std::string& dllFileName, std::list<ARKUTILEXPORTENTRY>& expFuncList
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::exportWalker( std::string& dllFileName, std::list<ARKUTILEXPORTENTRY>& expFuncList, bool bReadFuncData )
{
    bool retVal = false;
    try
    {
        expFuncList.clear();

        if( dllFileName.length() )
        {
            // Load the library
            HMODULE hModBase = ::LoadLibraryEx( dllFileName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES );
            if( NULL != hModBase )
            {
                PIMAGE_NT_HEADERS pNtHeader = NULL;
                PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModBase;
                if( pDosHeader && ( IMAGE_DOS_SIGNATURE == pDosHeader->e_magic ) )
                {
                    // Get the pointer to IMAGE_NT_HEADERS
                    pNtHeader = (PIMAGE_NT_HEADERS)( (PBYTE)hModBase + pDosHeader->e_lfanew );
                }
                if( pNtHeader && ( IMAGE_NT_SIGNATURE == pNtHeader->Signature ) )
                {
                    // Get pointer to IMAGE_EXPORT_DIRECTORY
                    PIMAGE_EXPORT_DIRECTORY pExpTable = NULL;
                    pExpTable = (PIMAGE_EXPORT_DIRECTORY)( (PBYTE)hModBase + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress );
                    if( NULL != pExpTable )
                    {
                        // Get pointer to name and address tables of functions
                        PDWORD pdwAddressOfFunctions = (PDWORD)( (PBYTE)hModBase + pExpTable->AddressOfFunctions );
                        DWORD dwNumberOfFunctions = pExpTable->NumberOfFunctions;

                        PDWORD pdwAddressOfNames = (PDWORD)( (PBYTE)hModBase + pExpTable->AddressOfNames );
                        DWORD dwNumberOfNames = pExpTable->NumberOfNames;

                        DWORD dwLimit = ( dwNumberOfFunctions > dwNumberOfNames ) ? dwNumberOfNames : dwNumberOfFunctions;

                        // Loop through the names
                        ARKUTILEXPORTENTRY exportEntry;
                        for( UINT nFuncIndex = 0; nFuncIndex < dwLimit; nFuncIndex++ )
                        {
                            ::ZeroMemory( &exportEntry, sizeof( ARKUTILEXPORTENTRY ) );

                            // Get function name and address
                            ::StringCchPrintfA( exportEntry.szFuncName, ARKITLIB_STR_LEN, "%s",
                                                (char*)( (PBYTE)hModBase + pdwAddressOfNames[nFuncIndex] ) );
                            exportEntry.dwFuncAddress = (DWORD)::GetProcAddress( hModBase, exportEntry.szFuncName );

                            // If read-data flag is set, then read first few bytes
                            // of function from this image
                            if( bReadFuncData )
                            {
                                PBYTE pFuncPtr = (PBYTE)exportEntry.dwFuncAddress;
                                for( UINT i = 0; ( i < ARKITLIB_BYTES_TO_FIX ) && ( pFuncPtr + i ) ; i++ )
                                {
                                    exportEntry.cFuncData[i] = pFuncPtr[i];
                                }
                            }

                            // Push it to list
                            expFuncList.push_back( exportEntry );
                        }
                    }
                }
                ::FreeLibrary( hModBase );
            }
        }

        if( !expFuncList.empty() )
        {
            retVal = true;
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::exportWalker: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getNtKernelName
*
* @description: Gets the actual name of NT kernel image
*
* @input: std::string& ntKernelName
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getNtKernelName( std::string& ntKernelName )
{
    bool retVal = false;

    try
    {
        ntKernelName.assign( "" );
    
        // Get handle to NtDll
        HMODULE hNtDll = ::GetModuleHandle( NTDLL_IMAGE_NAME );
    
        // Get pointer to NtQuerySystemInformation
        NTQUERYSYSTEMINFORMATION pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)::GetProcAddress( hNtDll,
                                                                                      "ZwQuerySystemInformation" );
        if( pNtQuerySystemInformation )
        {
            // Query for loaded drivers. NT kernel is always the first one
            DWORD dwNeededSize = 0;
            PMODULES pModules = NULL;
            DWORD retCode = pNtQuerySystemInformation( SystemModuleInformation, pModules, dwNeededSize, &dwNeededSize );
            if( STATUS_INFO_LENGTH_MISMATCH == retCode )
            {
                pModules = (PMODULES)::GlobalAlloc( GPTR, dwNeededSize );
                retCode = pNtQuerySystemInformation( SystemModuleInformation, pModules, dwNeededSize, NULL );
            }

            // Get kernel name
            PCHAR pKernelName = pModules->smi.ModuleNameOffset + pModules->smi.ImageName;
            ntKernelName.assign( pKernelName );

            if( NULL != pModules )
            {
                ::GlobalFree( pModules );
            }
        }

        if( ntKernelName.length() )
        {
            retVal = true;
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getNtKernelName: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getNtFuncAddressByZwFuncName
*
* @description: Gets original address of NtXxx funtions.
*               ZwXxx funtions point to NtXxx functions, we need
*               NtXxx function address to restore SSDT hooks or to
*               scan NtXxx function inline hooks.
*
* @input: std::string zwFuncName, std::string& ntFuncName, DWORD& dwNtAddress
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getNtFuncAddressByZwFuncName( std::string zwFuncName, std::string& ntFuncName, DWORD& dwNtAddress )
{
    bool retVal = false;
    try
    {
        dwNtAddress = 0;
        UINT unIndex = 0;
        if( getSsdtIndexByZwFuncName( zwFuncName, unIndex ) )
        {
            retVal = getNtFuncAddressBySsdtIndex( unIndex, ntFuncName, dwNtAddress );
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getNtFuncAddressByZwFuncName: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getNtFuncAddressBySsdtIndex
*
* @description: Gets original address of NtXxx funtions.
*               ZwXxx funtions point to NtXxx functions, we need
*               NtXxx function address to restore SSDT hooks or to
*               scan NtXxx function inline hooks.
*
* @input: UINT unIndex, std::string& ntFuncName, DWORD& dwNtAddress
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getNtFuncAddressBySsdtIndex( UINT unIndex, std::string& ntFuncName, DWORD& dwNtAddress )
{
    bool retVal = false;
    try
    {
        dwNtAddress = 0;
        ntFuncName.assign( "" );

        // Return if the index is out of range
        if( !getZwFuncNameBySsdtIndex( unIndex, ntFuncName ) )
        {
            return retVal;
        }

        // The above function returns ZwXxx, change it to NtXxx
        ntFuncName.replace( 0, 2, "Nt" );

        // Get NT kernel name
        std::string ntKernelName( "" );
        getNtKernelName( ntKernelName );
        if( 0 == ntKernelName.length() )
        {
            return retVal;
        }

        // Load NT kernel
        HMODULE hKernel = ::LoadLibraryEx( ntKernelName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES );
        if( !ARKITLIB_ISVALIDHANDLE( hKernel ) )
        {
            return retVal;
        }

        // Get kernel module info
        MODULEINFO kernelInfo;
        ::ZeroMemory( &kernelInfo, sizeof( MODULEINFO ) );
        if( !::GetModuleInformation( ::GetCurrentProcess(), hKernel, &kernelInfo, sizeof( MODULEINFO ) ) )
        {
            return retVal;
        }

        // Calculate original kernel base and end addresses
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)( (DWORD)hKernel + ((PIMAGE_DOS_HEADER)hKernel)->e_lfanew );
        DWORD dwOrgKernelBase = pNtHeaders->OptionalHeader.ImageBase;
        DWORD dwOrgKernelEnd = dwOrgKernelBase + kernelInfo.SizeOfImage;

        // Get actual kernel base and end addresses
        DWORD dwActualKernelBase = (DWORD)hKernel;
        DWORD dwActualKernelEnd = dwActualKernelBase + kernelInfo.SizeOfImage;

        // Get NtXxx address of one kernel exported function, to use as a
        // reference to calculate address of any other ZwXxx/NtXxx function
        typedef struct _PilotFunction
        {
            char funcName[ARKITLIB_STR_LEN];
            UINT unSsdtIndex;
            DWORD dwNtAddress;
            DWORD dwSsdtAddress;
        } PilotFunction, *PPilotFunction;

        // NtCreateFile is our pilot function as it is exported by kernel
        PilotFunction pilotFunction;
        ::ZeroMemory( &pilotFunction, sizeof( PilotFunction ) );
        ::StringCchCopy( pilotFunction.funcName, ARKITLIB_STR_LEN, "NtCreateFile" );

        // Get the index of ZwCreateFile in SSDT
        std::string zwPilotFuncName( "ZwCreateFile" );
        getSsdtIndexByZwFuncName( zwPilotFuncName, pilotFunction.unSsdtIndex );

        // Get the address of NtCreateFile and calculate its offset address in our kernel image
        PVOID pFunction = (PVOID)::GetProcAddress( hKernel, pilotFunction.funcName );
        pilotFunction.dwNtAddress = (DWORD)pFunction - (DWORD)hKernel + dwOrgKernelBase;

        // Now, find offset adress of ZwCreateFile in our kernel image
        DWORD dwCurDword = 0;
        DWORD dwPrevDword = 0;
        DWORD dwNextDword = 0;
        for( PBYTE i = (PBYTE)dwActualKernelBase + sizeof(DWORD); i < (PBYTE)dwActualKernelEnd - sizeof(DWORD); i++ )
        {
            dwCurDword = *(PDWORD)i;
            dwPrevDword = *(PDWORD)( i - sizeof(DWORD) );
            dwNextDword = *(PDWORD)( i + sizeof(DWORD) );

            if( ( dwCurDword == pilotFunction.dwNtAddress ) &&
                ( ( dwPrevDword >= dwOrgKernelBase ) && ( dwPrevDword <= dwOrgKernelEnd ) ) &&
                ( ( dwNextDword >= dwOrgKernelBase ) && ( dwNextDword <= dwOrgKernelEnd ) ) )
            {
                pilotFunction.dwSsdtAddress = (DWORD)i;
                break;
            }
        }

        // Get system's NT kernel image base
        DWORD dwSystemNtKernelBase = 0;
        if( getDriverBaseAddress( ntKernelName, dwSystemNtKernelBase ) )
        {
            // Now, calculate NtXxx address of specified unction in system's NT kernel image
            DWORD dwSsdtAddress = pilotFunction.dwSsdtAddress + ( unIndex - pilotFunction.unSsdtIndex )*sizeof(DWORD);
            dwNtAddress = *(PDWORD)dwSsdtAddress - dwOrgKernelBase + dwSystemNtKernelBase;
        }

        ::FreeLibrary( hKernel );

        if( dwNtAddress )
        {
            retVal = true;
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getNtFuncAddressBySsdtIndex: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getDriverBaseAddress
*
* @description: Gets base address of any driver that is visible
*               to EnumDeviceDrivers()!
*
* @input: std::string& driverName, DWORD& dwBaseAddress
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getDriverBaseAddress( std::string& driverName, DWORD& dwBaseAddress )
{
    bool retVal = false;
    try
    {
        dwBaseAddress = 0;
        LPVOID driverInfo[ARKITLIB_STR_LEN];
        DWORD dwNeededBytes = 0;
        if( ::EnumDeviceDrivers( driverInfo, sizeof(driverInfo), &dwNeededBytes ) )
        {
            char szDriverName[ARKITLIB_STR_LEN];
            UINT driverCount = dwNeededBytes/sizeof(LPVOID);
            for( UINT i = 0; i < driverCount; i++ )
            {
                ::ZeroMemory( szDriverName, ARKITLIB_STR_LEN );
                ::GetDeviceDriverBaseName( driverInfo[i], szDriverName, ARKITLIB_STR_LEN );
                if( 0 == ::lstrcmpi( szDriverName, driverName.c_str() ) )
                {
                    dwBaseAddress = (DWORD)driverInfo[i];
                    retVal = true;
                    break;
                }
            }
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getDriverBaseAddress: Exception caught" );
    }
    return retVal;
}

/*++
* @method: ARKitLibUtils::getFuncDataByName
*
* @description: Gets first few bytes of a function from image
*
* @input: std::string& funcName, PBYTE pFuncData, UINT unFuncDataSize
*
* @output: true if success, otherwise false
*
*--*/
bool ARKitLibUtils::getFuncDataByName( std::string& funcName, PBYTE pFuncData, UINT unFuncDataSize )
{
    bool retVal = false;
    try
    {
        if( funcName.length() && pFuncData && unFuncDataSize )
        {
            ARKitLibUtils objUtil;
            std::list<ARKUTILEXPORTENTRY> exportList;
            std::string ntKernelName;

            exportList.clear();
            objUtil.getNtKernelName( ntKernelName );

            // Get all functions exported by NT kernel
            if( objUtil.exportWalker( ntKernelName, exportList, true ) )
            {
                std::list<ARKUTILEXPORTENTRY>::iterator itExport = exportList.begin();
                for( ; itExport != exportList.end(); itExport++ )
                {
                    // Find the required function in the export list
                    if( 0 == funcName.compare( itExport->szFuncName ) )
                    {
                        // Copy the data
                        unFuncDataSize = ( unFuncDataSize > ARKITLIB_BYTES_TO_FIX ) ? ARKITLIB_BYTES_TO_FIX : unFuncDataSize;
                        ::CopyMemory( pFuncData, itExport->cFuncData, unFuncDataSize );
                        retVal = true;
                        break;
                    }
                }
            }
        }
    }
    catch(...)
    {
        retVal = false;
        ::OutputDebugString( "ARKitLibUtils::getFuncDataByName: Exception caught" );
    }
    return retVal;
}