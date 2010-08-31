/*++
* @file: ARKitLibUtils.h
*
* @description: This file contains prototype declaration of ARKitLibUtils class. 
*
*--*/

#ifndef __ARKITLIBUTILS_H__
#define __ARKITLIBUTILS_H__

// Standard header includes
#include <windows.h>
#include <Winsvc.h>
#include <winioctl.h>
#include <strsafe.h>
#include <Winternl.h>
#include <psapi.h>

#include <string>
#include <list>
#include <vector>

// ARKitLib specific includes
#include "ARKitDefines.h"

// Some common macros
#define ARKITLIB_ISVALIDHANDLE( handle )   ( handle && ( INVALID_HANDLE_VALUE != handle ) )
#define NTDLL_IMAGE_NAME                   "ntdll.dll"

typedef LONG NTSTATUS;

#define SystemModuleInformation             11
#define STATUS_INFO_LENGTH_MISMATCH        ((NTSTATUS)0xC0000004L)

typedef struct _SYSTEM_MODULE_INFORMATION { // SystemInformationClass 11
    ULONG    Reserved[2];
    PVOID    Base;
    ULONG    Size;
    ULONG    Flags;
    USHORT    Index;
    USHORT    Unknown;
    USHORT    LoadCount;
    USHORT    ModuleNameOffset;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef struct _MODULES {
    DWORD dwNumberOfModules;
    SYSTEM_MODULE_INFORMATION smi;
} MODULES, *PMODULES;

/*
NTSTATUS WINAPI NtQuerySystemInformation( __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                          __inout    PVOID SystemInformation,
                                          __in       ULONG SystemInformationLength,
                                          __out_opt  PULONG ReturnLength );
*/
typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)( UINT,
                                                     PVOID,
                                                     ULONG,
                                                     PULONG );

typedef struct _ARKUTILEXPORTENTRY
{
    char szFuncName[ARKITLIB_STR_LEN];
    DWORD dwFuncAddress;
    BYTE cFuncData[ARKITLIB_BYTES_TO_FIX];
}  ARKUTILEXPORTENTRY, *PARKUTILEXPORTENTRY;

class ARKitLibUtils
{
public:
    // Constructor
    ARKitLibUtils();   

    // Destructor
    virtual ~ARKitLibUtils();

    // Trims filename by expanding environment variables in the name
    bool removeDeviceName( std::string& imagePath );

    // Gets SSDT index corresponding to a ZwXxx function
    bool getZwFuncNameBySsdtIndex( UINT unIndex, std::string& zwFuncName );

    // Gets ZwXxx function name corresponding to a SSDT index
    bool getSsdtIndexByZwFuncName( std::string zwFuncName, UINT& unIndex );

    // Gets address of NtXxx function corresponding to a SSDT index
    bool getNtFuncAddressBySsdtIndex( UINT unIndex, std::string& ntFuncName, DWORD& dwNtAddress );

    // Gets address of NtXxx function corresponding to ZwXxx function
    bool getNtFuncAddressByZwFuncName( std::string zwFuncName, std::string& ntFuncName, DWORD& dwNtAddress );

    // Walks export table of a DLL
    bool exportWalker( std::string& dllFileName, std::list<ARKUTILEXPORTENTRY>& expFuncList, bool bReadFuncData );

    // Gets NT kernel name of the system
    bool getNtKernelName( std::string& ntKernelName );

    // Gets base address of a loaded driver
    bool getDriverBaseAddress( std::string& driverName, DWORD& dwBaseAddress );

    // Gets first few bytes of a function from image
    bool getFuncDataByName( std::string& funcName, PBYTE pFuncData, UINT unFuncDataSize );
};

#endif // __ARKITLIBUTILS_H__