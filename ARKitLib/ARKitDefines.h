/*++
* @file: ARKitDefines.h
*
* @description: This file contains datatype definitions that are used by ARKit library
*               and applications using this library.
*
* @remarks: This file should be included in the applications that use ARKit library.
*
*--*/

#ifndef __ARKITDEFINES_H__
#define __ARKITDEFINES_H__

// Common defines
#define ARKITLIB_STR_LEN                    MAX_PATH
#define ARKITLIB_FIXDATA_LEN                (ARKITLIB_STR_LEN*2)
#define ARKITLIB_BYTES_TO_FIX               32

// Data structures used between ARKitLib and apps using this lib
typedef struct _ARKPROCESS {
    DWORD procId; /* Out */
    char procName[ARKITLIB_STR_LEN]; /* Out */
} ARKPROCESS, *PARKPROCESS;

typedef struct _ARKDLL {
    DWORD baseAddr; /* Out */
    char dllName[ARKITLIB_STR_LEN]; /* Out */
} ARKDLL, *PARKDLL;

typedef struct _ARKDRIVER {
    DWORD baseAddr; /* Out */
    DWORD endAddr; /* Out */
    DWORD entryPoint; /* Out */
    char driverName[ARKITLIB_STR_LEN]; /* Out */
} ARKDRIVER, *PARKDRIVER;

typedef struct _ARKSSDTHOOK {
    UINT unSsdtIndex; /* Out */
    DWORD baseAddr; /* Out */
    DWORD endAddr; /* Out */
    DWORD hookAddr; /* Out */
    char ssdtFuncName[ARKITLIB_STR_LEN]; /* Out */
    char driverName[ARKITLIB_STR_LEN]; /* Out */
} ARKSSDTHOOK, *PARKSSDTHOOK;

typedef struct _ARKSYSENTERHOOK {
    DWORD jumpToAddr; /* Out */
    char driverName[ARKITLIB_STR_LEN]; /* Out */
} ARKSYSENTERHOOK, *PARKSYSENTERHOOK;

typedef struct _ARKINLINEHOOK {
    DWORD funcAddr; /* Internal Use Only */
    DWORD jumpToAddr; /* Out */
    char funcName[ARKITLIB_STR_LEN]; /* In */
    char driverName[ARKITLIB_STR_LEN]; /* Out */
} ARKINLINEHOOK, *PARKINLINEHOOK;

#endif // __ARKITDEFINES_H__