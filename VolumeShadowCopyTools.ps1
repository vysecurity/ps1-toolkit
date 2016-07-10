function Get-VolumeShadowCopy
{
<#
.SYNOPSIS

    Lists the device paths of all local volume shadow copies.

    PowerSploit Function: Get-VolumeShadowCopy
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>
    ${83f9ee88d8954f24b68d6b55e6939fcf} = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not ${83f9ee88d8954f24b68d6b55e6939fcf}.IsInRole([Security.Principal.WindowsBuiltInRole]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgA=')))))
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcgB1AG4AIABHAGUAdAAtAFYAbwBsAHUAbQBlAFMAaABhAGQAbwB3AEMAbwBwAHkAIABmAHIAbwBtACAAYQBuACAAZQBsAGUAdgBhAHQAZQBkACAAYwBvAG0AbQBhAG4AZAAgAHAAcgBvAG0AcAB0AC4A')))
    }
    gwmi -Namespace root\cimv2 -Class Win32_ShadowCopy | % { $_.DeviceObject }
}
function New-VolumeShadowCopy
{
    Param(
        [Parameter(Mandatory = $True)]
        [ValidatePattern('^\w:\\')]
        [String]
        ${e89ed31dbd63491c838e0d48707f3a3d},
        [Parameter(Mandatory = $False)]
        [ValidateSet("ClientAccessible")]
        [String]
        ${d8e1cf8ac8274a41a641f08c00759624} = "ClientAccessible"
    )
    ${83f9ee88d8954f24b68d6b55e6939fcf} = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not ${83f9ee88d8954f24b68d6b55e6939fcf}.IsInRole([Security.Principal.WindowsBuiltInRole]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgA=')))))
    {
        Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcgB1AG4AIABHAGUAdAAtAFYAbwBsAHUAbQBlAFMAaABhAGQAbwB3AEMAbwBwAHkAIABmAHIAbwBtACAAYQBuACAAZQBsAGUAdgBhAHQAZQBkACAAYwBvAG0AbQBhAG4AZAAgAHAAcgBvAG0AcAB0AC4A')))
    }
    ${4780257d8a374310937b15028877a618} = (gsv -Name VSS).Status
    ${feb66c69d4724532bf70a30729489a3e} = [WMICLASS]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGMAaQBtAHYAMgA6AHcAaQBuADMAMgBfAHMAaABhAGQAbwB3AGMAbwBwAHkA')))
    ${44bb39c517ad4ac38d11950420929a61} = ${feb66c69d4724532bf70a30729489a3e}.create("${e89ed31dbd63491c838e0d48707f3a3d}", "${d8e1cf8ac8274a41a641f08c00759624}")
    switch(${44bb39c517ad4ac38d11950420929a61}.returnvalue)
    {
        1 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAIABkAGUAbgBpAGUAZAAuAA=='))); break}
        2 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAGEAcgBnAHUAbQBlAG4AdAAuAA=='))); break}
        3 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAGUAYwBpAGYAaQBlAGQAIAB2AG8AbAB1AG0AZQAgAG4AbwB0ACAAZgBvAHUAbgBkAC4A'))); break}
        4 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAGUAYwBpAGYAaQBlAGQAIAB2AG8AbAB1AG0AZQAgAG4AbwB0ACAAcwB1AHAAcABvAHIAdABlAGQALgA='))); break}
        5 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAHMAdQBwAHAAbwByAHQAZQBkACAAcwBoAGEAZABvAHcAIABjAG8AcAB5ACAAYwBvAG4AdABlAHgAdAAuAA=='))); break}
        6 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABzAHQAbwByAGEAZwBlAC4A'))); break}
        7 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGwAdQBtAGUAIABpAHMAIABpAG4AIAB1AHMAZQAuAA=='))); break}
        8 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQAgAG4AdQBtAGIAZQByACAAbwBmACAAcwBoAGEAZABvAHcAIABjAG8AcABpAGUAcwAgAHIAZQBhAGMAaABlAGQALgA='))); break}
        9 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AdABoAGUAcgAgAHMAaABhAGQAbwB3ACAAYwBvAHAAeQAgAG8AcABlAHIAYQB0AGkAbwBuACAAaQBzACAAYQBsAHIAZQBhAGQAeQAgAGkAbgAgAHAAcgBvAGcAcgBlAHMAcwAuAA=='))); break}
        10 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAZABvAHcAIABjAG8AcAB5ACAAcAByAG8AdgBpAGQAZQByACAAdgBlAHQAbwBlAGQAIAB0AGgAZQAgAG8AcABlAHIAYQB0AGkAbwBuAC4A'))); break}
        11 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAZABvAHcAIABjAG8AcAB5ACAAcAByAG8AdgBpAGQAZQByACAAbgBvAHQAIAByAGUAZwBpAHMAdABlAHIAZQBkAC4A'))); break}
        12 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAZABvAHcAIABjAG8AcAB5ACAAcAByAG8AdgBpAGQAZQByACAAZgBhAGkAbAB1AHIAZQAuAA=='))); break}
        13 {Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAgAGUAcgByAG8AcgAuAA=='))); break}
        default {break}
    }
    if(${4780257d8a374310937b15028877a618} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABwAGUAZAA='))))
    {
        spsv -Name VSS
    }
}
function Remove-VolumeShadowCopy
{
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
        [String]
        ${e4e586706d42432db96f566c36be403d}
    )
    PROCESS
    {
        if($PSCmdlet.ShouldProcess("The VolumeShadowCopy at DevicePath ${e4e586706d42432db96f566c36be403d} will be removed"))
        {
            (gwmi -Namespace root\cimv2 -Class Win32_ShadowCopy | ? {$_.DeviceObject -eq ${e4e586706d42432db96f566c36be403d}}).Delete()
        }
    }
}
function Mount-VolumeShadowCopy
{
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${b226ae46a4884833bfb8db0ef02d3e00},
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
        [String[]]
        ${e4e586706d42432db96f566c36be403d}
    )
    BEGIN
    {
        ${83f9ee88d8954f24b68d6b55e6939fcf} = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not ${83f9ee88d8954f24b68d6b55e6939fcf}.IsInRole([Security.Principal.WindowsBuiltInRole]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgA=')))))
        {
            Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcgB1AG4AIABHAGUAdAAtAFYAbwBsAHUAbQBlAFMAaABhAGQAbwB3AEMAbwBwAHkAIABmAHIAbwBtACAAYQBuACAAZQBsAGUAdgBhAHQAZQBkACAAYwBvAG0AbQBhAG4AZAAgAHAAcgBvAG0AcAB0AC4A')))
        }
        ls ${b226ae46a4884833bfb8db0ef02d3e00} -ErrorAction Stop | Out-Null
        ${b1b1aba9dae94768bdc412a109806796} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBTAFMAVQB0AGkAbAA='))))
        ${29faa606c8f24471920596f3410cf7b8} = [AppDomain]::CurrentDomain.DefineDynamicAssembly(${b1b1aba9dae94768bdc412a109806796}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${4542515b539e4ed5bde7ff54512d0814} = ${29faa606c8f24471920596f3410cf7b8}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBTAFMAVQB0AGkAbAA='))), $False)
        ${a4d92881f6dd44bbbb483c140489d796} = ${4542515b539e4ed5bde7ff54512d0814}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBTAFMALgBLAGUAcgBuAGUAbAAzADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEMAbABhAHMAcwA='))))
        ${b4fd4dbc9c854e8189eb585c4174cc1a} = ${a4d92881f6dd44bbbb483c140489d796}.DefinePInvokeMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwB5AG0AYgBvAGwAaQBjAEwAaQBuAGsA'))),
                                                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))),
                                                            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                                                            [Reflection.CallingConventions]::Standard,
                                                            [Bool],
                                                            [Type[]]@([String], [String], [UInt32]),
                                                            [Runtime.InteropServices.CallingConvention]::Winapi,
                                                            [Runtime.InteropServices.CharSet]::Auto)
        ${0e80b38d1c474dedaf867d557feda64c} = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        ${418b7351860040e882ef1847d703ccb4} = [Runtime.InteropServices.DllImportAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
        ${e3c67543c2ee4082a819b7bf7a3868ba} = New-Object Reflection.Emit.CustomAttributeBuilder(${0e80b38d1c474dedaf867d557feda64c},
                                                                                         @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA')))),
                                                                                         [Reflection.FieldInfo[]]@(${418b7351860040e882ef1847d703ccb4}),
                                                                                         @($true))
        ${b4fd4dbc9c854e8189eb585c4174cc1a}.SetCustomAttribute(${e3c67543c2ee4082a819b7bf7a3868ba})
        ${79171bc3525f4b539968569680f9f24e} = ${a4d92881f6dd44bbbb483c140489d796}.CreateType()
    }
    PROCESS
    {
        foreach (${e89ed31dbd63491c838e0d48707f3a3d} in ${e4e586706d42432db96f566c36be403d})
        {
            ${e89ed31dbd63491c838e0d48707f3a3d} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAFwAXABcAFwAPwBcAFwARwBMAE8AQgBBAEwAUgBPAE8AVABcAFwARABlAHYAaQBjAGUAXABcACgAPwA8AEwAaQBuAGsATgBhAG0AZQA+AEgAYQByAGQAZABpAHMAawBWAG8AbAB1AG0AZQBTAGgAYQBkAG8AdwBDAG8AcAB5AFsAMAAtADkAXQB7ADEALAAzAH0AKQAkAA=='))) | Out-Null
            ${48dbab63fb76438c97049129a14e2b82} = Join-Path ${b226ae46a4884833bfb8db0ef02d3e00} $Matches.LinkName
            if (Test-Path ${48dbab63fb76438c97049129a14e2b82})
            {
                Write-Warning "'${48dbab63fb76438c97049129a14e2b82}' already exists."
                continue
            }
            if (-not ${79171bc3525f4b539968569680f9f24e}::CreateSymbolicLink(${48dbab63fb76438c97049129a14e2b82}, "$(${e89ed31dbd63491c838e0d48707f3a3d})\", 1))
            {
                Write-Error "Symbolic link creation failed for '${e89ed31dbd63491c838e0d48707f3a3d}'."
                continue
            }
            gi ${48dbab63fb76438c97049129a14e2b82}
        }
    }
    END
    {
    }
}
