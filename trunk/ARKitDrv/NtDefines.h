/*++
* @file: NtDefines.h
*
* @description: This file contains datatype definitions and function pointers
*               that are not exported by NT kernel.
*
*--*/

#ifndef __MY_NTDEFINES_H__
#define __MY_NTDEFINES_H__

#include "ntddk.h"
#include <ntstrsafe.h>
#include <windef.h>
#include "ARKitLibDrvCmn.h"

// Some defines
#define ARKIT_NT_PROCESS_LIMIT          0x4e1c //0x41dc
#define PROCESS_STATE_EXITING           0x04 //0x000000fb
#define PROCESS_STATE_DELETED           0x08 //0x000000f7
#define THREAD_TERMINATED               1
#define THREAD_DEAD                     2

// Imports
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

// NT structures
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT pDevice;
    UNICODE_STRING ustrDeviceName;  // internal name
    UNICODE_STRING ustrSymLinkName; // external name
    PVOID deviceBuffer;
    ULONG deviceBufferSize;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    POBJECT_NAME_INFORMATION ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _MODULE_ENTRY {
    LIST_ENTRY link;        // Flink, Blink
    BYTE unknown1[16];
    DWORD imageBase;
    DWORD entryPoint;
    DWORD imageSize;
    UNICODE_STRING drvPath;
    UNICODE_STRING drvName;
    //...
} MODULE_ENTRY, *PMODULE_ENTRY;

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _DIRECTORY_BASIC_INFORMATION
{
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

typedef struct _KAPC_STATE
{
    LIST_ENTRY ApcListHead[2];
    struct _KPROCESS *Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *RESTRICTED_POINTER PRKAPC_STATE;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    BYTE Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    /*PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;*/
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

#define SystemHandleInformation         16

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

// NT function forward declarations
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject (
                       IN HANDLE Handle,
                       IN BOOLEAN Alertable,
                       IN PLARGE_INTEGER Timeout OPTIONAL
                       );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
                           IN HANDLE ProcessId,
                           OUT PEPROCESS *Process
                           );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
                         IN HANDLE ThreadId,
                         OUT PETHREAD *Thread
                         );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
                      OUT PHANDLE DirectoryHandle,
                      IN ACCESS_MASK DesiredAccess,
                      IN POBJECT_ATTRIBUTES 
                      ObjectAttributes
                      );

typedef NTSTATUS (NTAPI *PNTOPENDIRECTORYOBJECT)(
                                                 OUT PHANDLE DirectoryHandle,
                                                 IN ACCESS_MASK DesiredAccess,
                                                 IN POBJECT_ATTRIBUTES 
                                                 ObjectAttributes
                                                 );
NTSYSAPI
NTSTATUS
NTAPI 
ZwQueryDirectoryObject(
                       IN HANDLE  DirectoryHandle, 
                       OUT PVOID  Buffer, 
                       IN ULONG   BufferLength, 
                       IN BOOLEAN ReturnSingleEntry, 
                       IN BOOLEAN RestartScan, 
                       IN OUT PULONG  Context, 
                       OUT PULONG ReturnLength OPTIONAL
                       );

typedef NTSTATUS (NTAPI *PNTQUERYDIRECTORYOBJECT)(
                                                  IN HANDLE  DirectoryHandle, 
                                                  OUT PVOID  Buffer, 
                                                  IN ULONG   BufferLength, 
                                                  IN BOOLEAN ReturnSingleEntry, 
                                                  IN BOOLEAN RestartScan, 
                                                  IN OUT PULONG  Context, 
                                                  OUT PULONG ReturnLength OPTIONAL
                                                  );

NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByName (
                    IN POBJECT_ATTRIBUTES ObjectAttributes,
                    IN POBJECT_TYPE ObjectType OPTIONAL, 
                    IN KPROCESSOR_MODE AccessMode,
                    IN OUT PACCESS_STATE AccessState OPTIONAL, 
                    IN ACCESS_MASK DesiredAccess OPTIONAL,
                    IN OUT PVOID ParseContext OPTIONAL, 
                    OUT PHANDLE Handle);

HANDLE PsGetProcessId( IN PEPROCESS Process );
typedef HANDLE (*PSGETPROCESSID)( IN PEPROCESS Process );

VOID KeStackAttachProcess( IN PEPROCESS  Process,
                           OUT PKAPC_STATE  ApcState );
typedef VOID (*KESTACKATTACHPROCESS)( IN PEPROCESS  Process,
                                      OUT PKAPC_STATE ApcState );

PPEB PsGetProcessPeb( IN PEPROCESS Process );
typedef PPEB (*PSGETPROCESSPB)( IN PEPROCESS Process );

VOID KeUnstackDetachProcess( IN PKAPC_STATE ApcState );
typedef VOID (*KEUNSTACKDETACHPROCESS)( IN PKAPC_STATE  ApcState );

NTSYSAPI
NTSTATUS
NTAPI 
ZwOpenProcess(
              OUT PHANDLE ProcessHandle, 
              IN ACCESS_MASK DesiredAccess, 
              IN POBJECT_ATTRIBUTES ObjectAttributes, 
              IN PCLIENT_ID ClientId OPTIONAL
              );
typedef NTSTATUS (NTAPI *PNTOPENPROCESS)(
                                         OUT PHANDLE ProcessHandle, 
                                         IN ACCESS_MASK DesiredAccess, 
                                         IN POBJECT_ATTRIBUTES ObjectAttributes, 
                                         IN PCLIENT_ID ClientId OPTIONAL
                                         );

NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess(
                   IN HANDLE   ProcessHandle OPTIONAL,
                   IN NTSTATUS ExitStatus
                   );
typedef NTSTATUS (NTAPI *PNTTERMINATEPROCESS)( 
                                              IN HANDLE   ProcessHandle OPTIONAL,
                                              IN NTSTATUS ExitStatus
                                              );

typedef NTSTATUS (NTAPI *PNTOPENTHREAD)( OUT PHANDLE ThreadHandle,
                                         IN ACCESS_MASK DesiredAccess,
                                         IN POBJECT_ATTRIBUTES ObjectAttributes,
                                         IN PCLIENT_ID ClientId OPTIONAL 
                                         );

typedef NTSTATUS (NTAPI *PNTTERMINATETHREAD)( IN HANDLE ThreadHandle,
                                              IN NTSTATUS ExitStatus
                                              );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation( IN UINT SystemInformationClass, // SYSTEM_INFORMATION_CLASS
                          IN OUT PVOID SystemInformation,
                          IN ULONG SystemInformationLength,
                          OUT PULONG ReturnLength
                         );
typedef NTSTATUS (NTAPI *PNTQUERYSYSTEMINFORMATION)( IN UINT SystemInformationClass, // SYSTEM_INFORMATION_CLASS
                                                     IN OUT PVOID SystemInformation,
                                                     IN ULONG SystemInformationLength,
                                                     OUT PULONG ReturnLength
                                                    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryObject( IN HANDLE Handle,
               IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
               IN OUT PVOID ObjectInformation,
               IN ULONG ObjectInformationLength,
               IN OUT PULONG ReturnLength
              );
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject( IN HANDLE Handle,
               IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
               IN OUT PVOID ObjectInformation,
               IN ULONG ObjectInformationLength,
               IN OUT PULONG ReturnLength
              );
typedef NTSTATUS (NTAPI *PNTQUERYOBJECT)( IN HANDLE Handle,
                                          IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
                                          IN OUT PVOID ObjectInformation,
                                          IN ULONG ObjectInformationLength,
                                          IN OUT PULONG ReturnLength
                                         );

NTSYSAPI
NTSTATUS
NTAPI
ObQueryNameString( IN PVOID Object,
                   IN OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
                   IN ULONG Length,
                   OUT PULONG ReturnLength
                  );

#endif // __MY_NTDEFINES_H__
