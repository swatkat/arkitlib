## Introduction ##
<b>ARKit</b> is an open-source rootkit detection library for Microsoft Windows. ARKit has two components:
  * ARKitLib.lib - A Win32/C++ static library that exposes various methods to scan system and detect rootkits
  * ARKitDrv.sys - A device driver that actually implements methods to scan and detect rootkits

## Features ##
Currently, ARKit library has following features:
  * Process scanning – Detect all running processes (hidden and visible)
  * DLL scanning – Detect DLLs loaded in a process
  * Driver scanning – Detect all loaded drivers (hidden and visible)
  * SSDT hook detection and restoration
  * Sysenter hook detection
  * Kernel inline hook detection and restoration

## Supported Operating Systems ##
ARKit works on 32-bit flavors of Windows 2000, XP, 2003 and Vista. It has not been tested on Windows 2008 and Windows 7 yet.
<br>
<h2>Summary of detection techniques in ARKit</h2>
Process detection methods:<br>
<ul><li>PID brute force (PsLookupProcessByProcessId)<br>
</li><li>TID brute force (PsLookupThreadByThreadId)<br>
</li><li>Handle table traversing (NtQuerySystemInformation)</li></ul>

DLL detection methods:<br>
<ul><li>InMemoryOrderModuleList traversal in process' PEB<br>
</li><li>VAD tree walking</li></ul>

Process termination methods:<br>
<ul><li>NtTerminateProcess/ZwTerminateProcess<br>
</li><li>NtTerminateThread/ZwTerminateThread for all threads of a process</li></ul>

Driver detection methods:<br>
<ul><li>PsLoadedModuleList traversing<br>
</li><li>\Driver\ directory traversing in Object Manager<br>
</li><li>\Device\ directory traversing in Object Manager</li></ul>

<h2>Source Code</h2>
<ul><li><i>ARKitLib.lib</i>: ARKitLib directory in <i>Source</i> section<br>
</li><li><i>ARKitDrv.sys</i>: ARKitDrv directory in <i>Source</i> section<br>
</li><li><i>ARKitTester.exe</i>: ARKitTester directory in <i>Source</i> section. An executable is available in <i>Downloads</i> section<br>
Use SVN tools such as <a href='http://tortoisesvn.tigris.org/'>TortoiseSVN</a> to checkout/download source code.</li></ul>

<h2>Using ARKit</h2>
Using ARKit library is quite simple:<br>
<ul><li>Include <b>ARKitLib.h</b> and <b>ARKitDefines.h</b> header files in your application source<br>
</li><li>Link to <b>ARKitLib.lib</b> and <b>Psapi.lib</b>
</li><li>Instantiate an object of <b>ARKitLib</b> class and use various member functions to gather system data<br>
</li><li>While running your application, make sure that <b>ARKitDrv.sys</b> driver is in the same directory where application is present</li></ul>

Take a look at <b><i>ARKitTester</i></b>, an example application that shows how to make use of ARKit.<br>
<br>
<h2>Todo list</h2>
<ul><li>Methods to disable drivers<br>
</li><li>Boot sector rootkit detection</li></ul>

<h2>Note</h2>
<ul><li>Windows DDK or WDK is needed to compile and build ARKitDrv.sys. You can get it <a href='https://www.microsoft.com/whdc/Devtools/wdk/default.mspx'>here</a>.<br>
</li><li>ARKitLib.lib component uses few Psapi APIs. So, applications using ARKitLib.lib should link with Psapi.lib<br>
</li><li>ARKit uses open-source XDE disassembling engine. More information about XDE can be found <a href='http://z0mbie.daemonlab.org/'>here</a>.