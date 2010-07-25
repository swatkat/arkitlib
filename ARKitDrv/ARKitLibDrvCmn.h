/*++
* @file: ARKitLibDrvCmn.h
*
* @description: This file contains definitions and datatypes used by ARKit library and driver.
*
*--*/

#ifndef __ARKITLIBDRVCMN_H__
#define __ARKITLIBDRVCMN_H__

// ARKitDrv driver IOCTL defines
#define FILE_DEVICE_UNKNOWN     0x00000022
#define IOCTL_UNKNOWN_BASE      FILE_DEVICE_UNKNOWN
#define IOCTL_OS_VER_INFO       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_DATA_CNT      CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_PROCESS       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_DRIVERS       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_SSDTHOOKS     CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_SYSENTERHOOK  CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_DLLS          CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_KINLINEHOOK   CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NT_API_INFO       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


// ARKitDrv related defines
#define ARKITLIB_DRIVER_FILENAME           "ARKitDrv.sys"
#define ARKITDRV_DEVICE_NAME                "\\\\.\\ARKITDRV"

// Windows 2003 R2 identifier
#ifndef SM_SERVERR2
#define SM_SERVERR2 89
#endif

// Data structures used between ARKitLib and ARKitDrv
typedef enum _eArkDataType
{
    eArkDataInvalid = 0,
    eArkDataProcList,
    eArkDataDllList,
    eArkDataDriverList,
    eArkDataSsdtList
} eArkDataType;

typedef enum _eOSServicePack
{
    eOS_SP_UNKNOWN = 0,
    eOS_SP_0,
    eOS_SP_1,
    eOS_SP_2,
    eOS_SP_3,
    eOS_SP_4
} eOSServicePack;

typedef enum _eOSVerion
{
    eOS_ERR = 0,
    eOS_WIN_2K,
    eOS_WIN_XP,
    eOS_WIN_2K3,
    eOS_WIN_2K3R2,
    eOS_WIN_VISTA,
    eOS_WIN_7
} eOSVersion;

typedef struct _MYOSVERINFO {
    eOSVersion osVer;
    eOSServicePack spVer;
} MYOSVERINFO, *PMYOSVERINFO;

typedef struct _ARKDATACOUNT {
    DWORD miscData;
    UINT dataCount;
    eArkDataType typeOfArkData;
} ARKDATACOUNT, *PARKDATACOUNT;

typedef struct _ARKNTAPI {
    DWORD dwNtOpenProcess;
    DWORD dwNtTerminateProcess;
    DWORD dwNtOpenDirectoryObject;
    DWORD dwNtQueryDirectoryObject;
    DWORD dwNtOpenThread;
    DWORD dwNtTerminateThread;
} ARKNTAPI, *PARKNTAPI;

#endif // __ARKITLIBDRVCMN_H__