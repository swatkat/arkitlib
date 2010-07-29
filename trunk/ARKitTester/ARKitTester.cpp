#include "ARKitLib.h"

int main()
{
    ARKitLib obj;

    // Get process list
    {
        int i = 0;
        std::list<ARKPROCESS> procList;
        obj.getProcessList( procList );

        printf( "\n\nGot %d processes", procList.size() );
        std::list<ARKPROCESS>::iterator itProc = procList.begin();
        for( ; itProc != procList.end(); itProc++ )
        {
            ++i;
            printf( "\n%d] %s - %d", i, itProc->procName, itProc->procId );
        }
    }

    // Get driver list
    {
        int i = 0;
        std::list<ARKDRIVER> driverList;
        obj.getDriverList( driverList );

        printf( "\n\nGot %d drivers", driverList.size() );
        std::list<ARKDRIVER>::iterator itDrv = driverList.begin();
        for( ; itDrv != driverList.end(); itDrv++ )
        {
            ++i;
            printf( "\n%d] %s - 0x%x", i, itDrv->driverName, itDrv->baseAddr );
        }
    }

    // Get SSDT hooks list
    {
        int i = 0;
        std::list<ARKSSDTHOOK> ssdtHookList;
        obj.getSSDTHooksList( ssdtHookList );

        printf( "\n\nGot %d SSDT hooks", ssdtHookList.size() );
        std::list<ARKSSDTHOOK>::iterator itSsdtHook = ssdtHookList.begin();
        for( ; itSsdtHook != ssdtHookList.end(); itSsdtHook++ )
        {
            ++i;
            printf( "\n%d] %s - %s - 0x%x", i, itSsdtHook->driverName, itSsdtHook->ssdtFuncName, itSsdtHook->hookAddr );
        }
    }

    // Get DLLs loaded in current process
    {
        int i = 0;
        std::list<ARKDLL> dllList;
        obj.getDllList( ::GetCurrentProcessId(), dllList );

        printf( "\n\nGot %d DLLs", dllList.size() );
        std::list<ARKDLL>::iterator itDlls = dllList.begin();
        for( ; itDlls != dllList.end(); itDlls++ )
        {
            ++i;
            printf( "\n%d] %s - 0x%x", i, itDlls->dllName, itDlls->baseAddr );
        }
    }

    // Get kernel inline hooks
    {
        int i = 0;
        std::list<ARKINLINEHOOK> inlineHookList;
        obj.getKernelInlineHooks( inlineHookList );

        printf( "\n\nGot %d inline hooks", inlineHookList.size() );
        std::list<ARKINLINEHOOK>::iterator itHooks = inlineHookList.begin();
        for( ; itHooks != inlineHookList.end(); itHooks++ )
        {
            ++i;
            printf( "\n%d] %s - %s - 0x%x", i, itHooks->funcName, itHooks->driverName, itHooks->jumpToAddr );
        }
    }

    // Kill a process
    {
        DWORD dwPid = 0;
        printf( "\n\n\nEnter pid to kill: " );
        scanf( "%d", &dwPid );
        if( obj.killProcess( dwPid ) )
        {
            printf( "\nProcess killed successfully!\n" );
        }
        else
        {
            printf( "\nFailed to kill process\n" );
        }
    }
    
    return 0;
}
